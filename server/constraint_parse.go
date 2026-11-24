package server

// 自然语言 → 操作约束（V12-CREATE-UNIFY）。
//
//	POST /api/constraints/parse
//	body: {"text":"..."}
//	resp: {"constraints":[{"kind":"allow|deny","text":"..."}]}
//
// 创建项目/任务时，用户在约束框里写一段自然语言，点「解析」调本接口拿结构化
// 条目，前端可再编辑后随创建请求提交。纯读取：不落库、不建任务、不碰目标。
// 复用全局激活 LLM（或指定 profile），与报告模板的 JSON 补丁接口同一套调用方式。

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

const constraintParsePrompt = `你是渗透测试「操作约束」抽取器。用户会给一段自然语言（测试目的、目标范围、口头要求），
请把它拆成结构化的操作约束条目。

约束只有两种：
- allow：允许 / 限定做某类操作（例：「被动侦察」「仅测 443 端口」「仅修改自身新增的内容」）。
- deny：禁止做某类操作（例：「密码爆破」「修改目标系统已有数据」「扫描 443 以外的端口」）。

规则：
1. 只抽取用户**明确写出或强调**的要求，严禁臆造。没有约束就返回空数组。
2. text 只写**动作本身**，一律用肯定式；禁止/允许的极性由 kind 表达，不要重复表达。
   text 里禁止出现「不允许 / 禁止 / 不得 / 不能 / 不要 / 严禁 / 切勿 / 请勿」等否定词。
   反例：{"kind":"deny","text":"不允许直连目标数据库"}（读起来是「禁止 不允许…」，双重否定）
   正例：{"kind":"deny","text":"直连目标数据库"}
3. 用**通用表述**指代测试对象，不要写具体 IP / 域名 / 主机名 / URL，统一写「资产」「目标资产」。
   约束会随任务下发，落到哪个资产上就指哪个资产；端口、协议、路径这类与资产无关的限定可以保留具体值。
4. 约束是操作边界，不是测试步骤、不是目标、不是漏洞类型。
5. 同义合并；最多 30 条；每条一句话，不超过 80 字。
6. 输出**严格 JSON**，不要 Markdown 代码块、不要解释：
{"constraints":[{"kind":"allow","text":"..."},{"kind":"deny","text":"..."}]}`

type constraintParseReq struct {
	Text         string `json:"text"`
	LLMProfileID int64  `json:"llm_profile_id,omitempty"`
}

// parseConstraints POST /api/constraints/parse。
func (s *Server) parseConstraints(w http.ResponseWriter, r *http.Request) {
	var req constraintParseReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	text := strings.TrimSpace(req.Text)
	if text == "" {
		writeErr(w, 400, "请先填写约束描述")
		return
	}
	if len(text) > 8000 {
		text = text[:8000]
	}
	prov, _, ok := s.globalProvider()
	if req.LLMProfileID > 0 {
		prov, _, ok = s.providerForProfile(req.LLMProfileID)
	}
	if !ok || prov == nil {
		writeErr(w, 503, "LLM 未配置：请先在「系统 → LLM」配置模型")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	msg, _, _, err := prov.Complete(ctx, llm.CompletionRequest{
		System:    []string{constraintParsePrompt},
		Messages:  []llm.Message{llm.UserText("用户原文：\n" + text)},
		MaxTokens: 3000,
		Thinking:  "disabled",
	})
	if err != nil {
		writeErr(w, 502, "LLM 调用失败："+err.Error())
		return
	}
	items, err := decodeConstraintJSON(msg.Text())
	if err != nil {
		writeErr(w, 502, "模型输出无法解析为约束："+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"constraints": items})
}

// decodeConstraintJSON 宽松解析模型输出：剥掉可能的 Markdown 代码块，取第一个
// { 到最后一个 } 之间的内容。非法条目丢弃（不因一条坏数据整批失败）。
func decodeConstraintJSON(out string) ([]db.ConstraintInput, error) {
	s := strings.TrimSpace(out)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end <= start {
		return nil, errNoJSON
	}
	var payload struct {
		Constraints []struct {
			Kind string `json:"kind"`
			Text string `json:"text"`
		} `json:"constraints"`
	}
	if err := json.Unmarshal([]byte(s[start:end+1]), &payload); err != nil {
		return nil, err
	}
	items := make([]db.ConstraintInput, 0, len(payload.Constraints))
	seen := map[string]bool{}
	for _, c := range payload.Constraints {
		kind := strings.ToLower(strings.TrimSpace(c.Kind))
		text := strings.TrimSpace(c.Text)
		if (kind != "allow" && kind != "deny") || text == "" {
			continue
		}
		text = stripConstraintNegation(text)
		if text == "" {
			continue
		}
		key := kind + "\x00" + text
		if seen[key] {
			continue
		}
		seen[key] = true
		items = append(items, db.ConstraintInput{Kind: kind, Text: text})
	}
	return items, nil
}

// constraintNegationPrefixes 是 deny 条目里多余的否定前缀。kind 已经表达了
// 「禁止」，text 再写「不允许…」在界面上会读成「禁止 不允许…」= 双重否定。
// 只剥开头一层，句中/条件从句不动（「无法回滚时不允许新增」不能被机械改写）。
var constraintNegationPrefixes = []string{
	"不允许", "禁止", "严禁", "不得", "不能", "不要", "不可", "切勿", "请勿", "不准", "不许",
}

// stripConstraintNegation 去掉条目开头的否定词，保留后面的动作短语。
// 剥完过短（<2 字）或本来就是肯定式时原样返回。
func stripConstraintNegation(text string) string {
	for _, prefix := range constraintNegationPrefixes {
		if !strings.HasPrefix(text, prefix) {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(text, prefix))
		if utf8.RuneCountInString(rest) < 2 {
			return text
		}
		return rest
	}
	return text
}

// errNoJSON 是「输出里完全没有 JSON 结构」的哨兵，调用方转 502。
var errNoJSON = &jsonDecodeError{"输出里没有 JSON 对象"}

type jsonDecodeError struct{ msg string }

func (e *jsonDecodeError) Error() string { return e.msg }
