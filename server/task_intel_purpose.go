package server

// 接口用途的模型补充（V9-PURPOSE）。
//
// 背景：规则抽取把「关联 finding 的标题」直接当接口用途，出现
// 「DVWA Command Injection (exec.php ip 参数未过滤)」这种把具体漏洞当用途、
// 还会串到相邻接口。用途应是抽象归类（"登录入口" / "命令执行验证点"），
// 这是规则给不出的语义，交给大模型；其余字段（参数/状态码/鉴权/主机）仍由
// 规则抽取，不经过模型。
//
// 成本与幂等：
//   - 一个任务一次批量调用（≤30 条接口），不是逐接口调用；
//   - 终态首次生成 / rebuild 才调用；已标 purpose_source=model 的行直接沿用，
//     不重复请求（rebuild ?force_purpose=1 显式强制除外）；
//   - 无 LLM 配置 / 调用失败 / 超时 / JSON 解析两次失败：保留规则用途并标
//     purpose_source=rule，只记日志，不影响情报表生成。
//
// 并发：调用点是任务终态钩子（emitTaskTerminal 已在后台 goroutine 里跑），
// 模型耗时不会阻塞任务状态写入；rebuild 是用户显式触发的同步入口。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

const (
	// intelPurposeMaxEndpoints 是单任务单次最多送模型的接口数；其余保留规则值。
	intelPurposeMaxEndpoints = 30
	// intelPurposeMaxRunes 是一句用途的长度上限（字符，不是字节）。
	intelPurposeMaxRunes = 24
)

// intelPurposeTimeout 是单次模型调用的超时预算。变量形式便于测试注入短超时。
var intelPurposeTimeout = 30 * time.Second

// intelPurposePrompt 是接口用途归纳的系统提示词。单独常量，便于审计与调参。
const intelPurposePrompt = `你是渗透测试任务情报的「接口用途归纳器」。输入是任务目标，以及一批接口的客观属性（方法/路径/参数/状态码/是否需登录）和关联漏洞标题（仅作线索）。
任务：为每个接口写一句用途，回答「这个接口在系统里是干什么的」。
纪律（必须全部遵守）：
1. 用途是抽象归类，不是漏洞标题复述；不得照抄关联漏洞标题里的漏洞名、参数名或具体攻击细节。例：不要写「DVWA Command Injection (exec.php ip 参数未过滤)」，应写「命令执行验证点」。
2. 不得包含主机名、IP、端口、域名、路径或任何资产标识。
3. 每条用途不超过 24 个字（含标点），用中文短句。
4. 无法判断时写「用途不明」。
5. 只输出一个 JSON 数组，不要解释、不要 Markdown 代码围栏，形如：
[{"key":"post /vulnerabilities/exec/","purpose":"命令执行验证点"}]
6. key 必须原样回填输入中的 key；每条输入都要有一条输出。`

// intelPurposeAnswer 是模型返回数组的元素。JSON 契约固定在 [{"key","purpose"}]。
type intelPurposeAnswer struct {
	Key     string `json:"key"`
	Purpose string `json:"purpose"`
}

// intelPurposeEndpoint 是送给模型的单条接口事实（不含主机）。
type intelPurposeEndpoint struct {
	Key         string
	Method      string
	Path        string
	Params      []string
	StatusCodes []int
	Auth        bool
	VulnTitles  []string
}

// annotateIntelPurposeRules 把规则抽出的 purpose 复制到 purpose_rule，并给
// 每个 endpoint 行标 purpose_source=rule。纯函数（原地改 Detail）。
func annotateIntelPurposeRules(rows []db.TaskIntel) {
	for i := range rows {
		if rows[i].Kind != db.IntelKindEndpoint {
			continue
		}
		d := intelDetailMapOf(rows[i])
		rule, _ := d["purpose"].(string)
		if prev, ok := d["purpose_rule"].(string); ok && prev != "" {
			rule = prev
		}
		rule = strings.TrimSpace(rule)
		if rule != "" {
			d["purpose_rule"] = rule
		} else {
			delete(d, "purpose")
		}
		d["purpose_source"] = "rule"
		rows[i].Detail = intelDetailJSON(d)
	}
}

// fillIntelEndpointPurposes 是模型补充的唯一入口：保留已有模型用途、对尚未
// 模型化的接口做一次批量调用、把结果写回 detail.purpose / purpose_source。
// 失败只记日志并保留规则值（调用方不感知错误）。
func (s *Server) fillIntelEndpointPurposes(ctx context.Context, t *db.Task, findings []db.IntelFinding, prev, rows []db.TaskIntel, force bool) {
	if len(rows) == 0 {
		return
	}
	prevModel := intelModelPurposes(prev)
	titles := intelFindingTitles(findings)

	var cands []intelPurposeCandidate

	for i := range rows {
		if rows[i].Kind != db.IntelKindEndpoint {
			continue
		}
		d := intelDetailMapOf(rows[i])
		key := rows[i].Key
		if !force {
			if p := prevModel[strings.ToLower(strings.TrimSpace(key))]; p != "" {
				d["purpose"] = p
				d["purpose_source"] = "model"
				rows[i].Detail = intelDetailJSON(d)
				continue
			}
		}
		// 未命中已有模型值：先保持规则值，进入候选队列。
		d["purpose_source"] = "rule"
		rows[i].Detail = intelDetailJSON(d)

		method, path := splitEndpointKey(key)
		var hint []string
		if ids, ok := d["finding_ids"].([]any); ok {
			for _, raw := range ids {
				if f, ok := raw.(float64); ok {
					if title := titles[int64(f)]; title != "" {
						hint = append(hint, title)
					}
				}
			}
		}
		cands = append(cands, intelPurposeCandidate{
			index: i,
			ep: intelPurposeEndpoint{
				Key: key, Method: method, Path: path,
				Params:      intelDetailStringSlice(d["params"]),
				StatusCodes: intelDetailIntSlice(d["status_codes"]),
				Auth:        intelDetailBool(d["auth_required"]),
				VulnTitles:  hint,
			},
		})
	}
	if len(cands) == 0 {
		return
	}
	// 单任务最多 30 条：多出的接口保留规则值，不扩成多次调用。
	if len(cands) > intelPurposeMaxEndpoints {
		cands = cands[:intelPurposeMaxEndpoints]
	}

	prov, ok := s.intelPurposeProvider(t)
	if !ok {
		log.Printf("[task-intel] task %d 未找到可用 LLM 配置，接口用途保留规则值", taskIDOf(t, rows))
		return
	}
	goal := ""
	if t != nil {
		goal = strings.TrimSpace(t.Goal)
	}
	prompt := intelPurposeUserPrompt(goal, cands)
	answers, err := callIntelPurposeModel(ctx, prov, prompt)
	if err != nil {
		log.Printf("[task-intel] task %d WARN 接口用途模型补充失败，保留规则值: %v", taskIDOf(t, rows), err)
		return
	}
	applied := 0
	for _, c := range cands {
		p := answers[strings.ToLower(strings.TrimSpace(c.ep.Key))]
		if p == "" {
			continue
		}
		d := intelDetailMapOf(rows[c.index])
		d["purpose"] = p
		d["purpose_source"] = "model"
		rows[c.index].Detail = intelDetailJSON(d)
		applied++
	}
	log.Printf("[task-intel] task %d 接口用途模型补充完成：%d/%d 条", taskIDOf(t, rows), applied, len(cands))
}

// intelPurposeProvider 解析任务当前 LLM 配置：任务链的激活配置优先，任务没有
// 配置链时回退全局激活配置。任务链存在但已耗尽（ActiveID=nil）按"找不到配置"
// 处理——不偷偷改用全局配置，避免与任务自身语义不一致。
func (s *Server) intelPurposeProvider(t *db.Task) (llm.Provider, bool) {
	if s == nil {
		return nil, false
	}
	if t != nil && len(t.LLMProfileIDs) > 0 {
		if s.m == nil || s.m.pg == nil || t.ActiveLLMProfileID == nil {
			return nil, false
		}
		prov, _, ok := s.providerForProfile(*t.ActiveLLMProfileID)
		return prov, ok
	}
	prov, _, ok := s.globalProvider()
	return prov, ok
}

// callIntelPurposeModel 调一次模型（解析失败重试 1 次）。每次调用独立超时，
// 避免第二次重试复用已耗尽的时间预算。调用错误（含超时）不重试，直接回退。
func callIntelPurposeModel(ctx context.Context, prov llm.Provider, prompt string) (map[string]string, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		callCtx, cancel := context.WithTimeout(ctx, intelPurposeTimeout)
		req := llm.CompletionRequest{
			System:    []string{intelPurposePrompt},
			Messages:  []llm.Message{llm.UserText(prompt)},
			MaxTokens: 1200,
			Thinking:  "disabled",
		}
		msg, _, _, err := prov.Complete(callCtx, req)
		cancel()
		if err != nil {
			return nil, err
		}
		if m, ok := parseIntelPurposes(msg.Text()); ok {
			return m, nil
		}
		lastErr = fmt.Errorf("模型输出不是合法 JSON 数组")
		if attempt == 0 {
			log.Printf("[task-intel] WARN 接口用途模型输出解析失败，重试一次")
		}
	}
	return nil, lastErr
}

// intelPurposePromptItem 是提示词里的接口事实（JSON 输入，避免 key 里含空格
// 造成分隔歧义）。
type intelPurposePromptItem struct {
	Key         string   `json:"key"`
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Params      []string `json:"params,omitempty"`
	StatusCodes []int    `json:"status_codes,omitempty"`
	Auth        bool     `json:"auth"`
	VulnTitles  []string `json:"vuln_titles,omitempty"`
}

// intelPurposeUserPrompt 把任务目标与接口事实压成紧凑输入。绝不包含主机：
// 模型被要求只按方法与路径做抽象归类。
func intelPurposeUserPrompt(goal string, cands []intelPurposeCandidate) string {
	items := make([]intelPurposePromptItem, 0, len(cands))
	for _, c := range cands {
		items = append(items, intelPurposePromptItem{
			Key: c.ep.Key, Method: c.ep.Method, Path: c.ep.Path,
			Params: c.ep.Params, StatusCodes: c.ep.StatusCodes,
			Auth: c.ep.Auth, VulnTitles: c.ep.VulnTitles,
		})
	}
	raw, _ := json.Marshal(items)
	var b strings.Builder
	if goal != "" {
		fmt.Fprintf(&b, "任务目标：%s\n", intelClipRunes(goal, 200))
	}
	fmt.Fprintf(&b, "接口清单（JSON，共 %d 条）:\n%s\n", len(items), raw)
	b.WriteString("请按约定 JSON 数组输出每个接口的用途。")
	return b.String()
}

// parseIntelPurposes 解析模型输出。容忍 Markdown 围栏/前后废话，只认合法
// JSON 数组；purpose 截到 24 字，空 key/空用途丢弃。返回 ok=false 表示整段
// 不可用（调用方据此重试/回退）。
func parseIntelPurposes(raw string) (map[string]string, bool) {
	body, ok := extractIntelPurposeJSON(raw)
	if !ok {
		return nil, false
	}
	var items []intelPurposeAnswer
	if err := json.Unmarshal([]byte(body), &items); err != nil {
		return nil, false
	}
	out := make(map[string]string, len(items))
	for _, it := range items {
		key := strings.ToLower(strings.TrimSpace(it.Key))
		p := intelClipRunes(it.Purpose, intelPurposeMaxRunes)
		if key == "" || p == "" {
			continue
		}
		out[key] = p
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// extractIntelPurposeJSON 从自由文本里取 JSON 数组：优先围栏块，其次首个 '['
// 到末个 ']'。围栏未闭合时取到结尾抢救（模型被 max_tokens 截断的常见形态）。
func extractIntelPurposeJSON(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	for {
		i := strings.Index(s, "```")
		if i < 0 {
			break
		}
		rest := s[i+3:]
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			rest = rest[nl+1:]
		}
		j := strings.Index(rest, "```")
		var block string
		if j >= 0 {
			block = strings.TrimSpace(rest[:j])
			s = rest[j+3:]
		} else {
			block = strings.TrimSpace(rest)
			s = ""
		}
		if strings.HasPrefix(block, "[") && json.Valid([]byte(block)) {
			return block, true
		}
	}
	if start := strings.IndexByte(s, '['); start >= 0 {
		if end := strings.LastIndexByte(s, ']'); end > start {
			body := strings.TrimSpace(s[start : end+1])
			if json.Valid([]byte(body)) {
				return body, true
			}
		}
	}
	return "", false
}

// intelModelPurposes 取旧表里 purpose_source=model 的接口 → 用途，用于 rebuild
// 幂等沿用（不重复请求模型）。
func intelModelPurposes(rows []db.TaskIntel) map[string]string {
	out := map[string]string{}
	for i := range rows {
		if rows[i].Kind != db.IntelKindEndpoint {
			continue
		}
		d := intelDetailMapOf(rows[i])
		if src, _ := d["purpose_source"].(string); src != "model" {
			continue
		}
		p, _ := d["purpose"].(string)
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(rows[i].Key))] = p
	}
	return out
}

// intelFindingTitles 是 finding id → 标题（接口的关联漏洞线索）。
func intelFindingTitles(findings []db.IntelFinding) map[int64]string {
	out := make(map[int64]string, len(findings))
	for _, f := range findings {
		title := strings.TrimSpace(f.Name)
		if title == "" {
			title = strings.TrimSpace(f.VulnClass)
		}
		if title != "" {
			out[f.ID] = title
		}
	}
	return out
}

// intelPurposeCandidate 是候选接口（candidate 结构在函数内定义会丢失类型名，
// 这里用轻量包级类型供提示词构造函数复用）。
type intelPurposeCandidate struct {
	index int
	ep    intelPurposeEndpoint
}

// intelDetailMapOf 解码 detail；空/非法返回空 map（可安全赋值后重新编码）。
func intelDetailMapOf(r db.TaskIntel) map[string]any {
	m := map[string]any{}
	if len(r.Detail) > 0 {
		_ = json.Unmarshal(r.Detail, &m)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m
}

// intelDetailJSON 编码 detail；失败返回 {}（保证 upsert 的 JSON 合法性）。
func intelDetailJSON(m map[string]any) json.RawMessage {
	raw, err := json.Marshal(m)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(raw)
}

func intelDetailStringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func intelDetailIntSlice(v any) []int {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]int, 0, len(raw))
	for _, item := range raw {
		if f, ok := item.(float64); ok {
			out = append(out, int(f))
		}
	}
	return out
}

func intelDetailBool(v any) bool {
	b, _ := v.(bool)
	return b
}

// taskIDOf 取日志用的任务 id：优先入参任务，其次行里的 task_id（测试直接传
// rows 时也能打对 id）。
func taskIDOf(t *db.Task, rows []db.TaskIntel) int64 {
	if t != nil {
		return t.ID
	}
	for _, r := range rows {
		if r.TaskID > 0 {
			return r.TaskID
		}
	}
	return 0
}
