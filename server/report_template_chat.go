package server

// T20（N1-B）报告模板「对话式调整」端点 + 输出护栏。
//
//   POST /api/report-templates/{id}/chat
//   req  {messages:[{role,content}], template:<当前完整模板JSON>, llm_profile_id?, locale?}
//   resp {reply, patch, template(合并后全量), warnings[]}
//
// 一次性非流式 LLM 调用（globalProvider 链 / llm_profile_id 指定配置），
// 60s 超时。system prompt 内嵌模板 schema 说明 + **全量替换纪律**（骨架/
// 样式小对象整值替换，无 JSON Patch 路径拼接歧义）。LLM 失败 → 502，模板不动。
// **不自动落库**：合并态回给前端进 draft，用户点保存走既有 PATCH。
//
// 护栏=纯函数 parseChatPatch（无库单测 ≥8 例）：剥 markdown 围栏 →
// 提取 JSON → 解包 {reply,patch} 或裸 patch 两形态 → skeleton 校验（非法
// 整键丢弃）→ 未知 style 键透传但 warnings 提示 → 与请求 template 合并出
// 全量。reply 兜底：模型只吐 patch 没吐 reply 时给一句通用说明。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

// chatMaxReplyRunes reply 入库/回传前的截断上限（防模型跑飞刷屏前端）。
const chatMaxReplyRunes = 4000

// templateChatSystemPrompt 内嵌 schema 说明与全量替换纪律（设计 §1.2B 定稿
// 文案的结构化版本）。STYLE 已知键=前端 STYLE_FIELDS 六键（page.tsx 口径），
// pybuilder 消费；未知键透传无害但给 warning。
const templateChatSystemPrompt = `你是渗透测试报告模板的编辑助手。用户会用自然语言描述想改的模板设定，你输出一个 JSON 补丁。

模板 JSON 的字段 schema：
- name: 字符串，模板名
- output_lang: "zh-CN"|"en-US"
- skeleton: 章节数组，按渲染顺序排列，元素 {key,title,enabled}。key 只能是 cover|statement|targets|summary|vuln_detail|conclusion 之一；title=章节标题（字符串）；enabled=该章是否出现。
- style: 对象，已知键 body_font/west_font/head_font（字符串字体名）、body_size/h1_size/vuln_size（数字磅号）。
- prompts: 对象，键=章节 key，值=该章的 AI 叙述提示词。
- issuer: 出具方名称（字符串）；personnel: [{name,role,contact}] 数组；cvss_enabled: 布尔；remark: 备注字符串。（logo 图片不走对话补丁，由模板上传通道管理。）

输出纪律（必须遵守）：
1. 只输出一个 JSON 对象，包在 \u0060\u0060\u0060json 代码围栏里，不要输出围栏以外的任何文字。格式：
{"reply":"给用户看的简短中文说明（改了什么、为何这么改）","patch":{...}}
2. patch 里只放**要改的字段**，每个字段值=该字段的**全量新值**（不做局部 diff）：改 skeleton 就给出完整章节数组（含没动的章节）；改 style 就给出完整 style 对象（含没动的键，把当前值抄全）。
3. 不得虚构 issuer、人员真实信息；用户没说的值保持请求 template 里的原样。
4. 诉求与 schema 无关或做不到（如"改成 PDF 交付"），patch 给 {}，在 reply 里说明原因。但「按现有数据/示例数据重新生成、渲染、预览一份报告」不是做不到：平台会在本轮自动执行渲染并把预览一并回传，不要拒绝；你只需在 reply 里确认，并按需给出模板 patch（无需改模板则 patch 给 {}）。
5. 用户只想聊天/提问而没有要改的内容时，patch 给 {}。`

// reportTemplateChat POST /api/report-templates/{id}/chat。
func (s *Server) reportTemplateChat(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "非法模板 id")
		return
	}
	tmpl, err := s.m.pg.GetReportTemplate(id)
	if err != nil {
		writeErr(w, 500, "读取模板失败: "+err.Error())
		return
	}
	if tmpl == nil {
		writeErr(w, 404, "模板不存在")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB：模板 JSON + 会话轮次上限兜底
	var body struct {
		Messages     []chatMessage   `json:"messages"`
		Template     json.RawMessage `json:"template"`
		LLMProfileID int64           `json:"llm_profile_id"`
		Locale       string          `json:"locale"`
		// R3：预览上下文（前端把当前预览源带上来：示例/任务/项目）。用户说
		// 「按现有数据渲染」时服务端据此渲染 HTML 预览随回复返回。
		Preview *chatPreviewInput `json:"preview"`
		// WantRender 显式要求渲染（测试/脚本用；普通对话由 wantsRenderIntent 判定）。
		WantRender bool `json:"want_render"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "请求格式错误: "+err.Error())
		return
	}
	// 只留 user/assistant 两类角色、非空内容，最多 40 条（前端会话无限滚则截尾）。
	msgs := normalizeChatMessages(body.Messages, 40)
	if len(msgs) == 0 || msgs[len(msgs)-1].Role != "user" {
		writeErr(w, 400, "messages 必须非空且以 user 结尾")
		return
	}
	userText := msgs[len(msgs)-1].Content
	// 基准模板=请求里的当前 draft（编辑未保存态），缺省回退 DB 行。
	base := tmpl
	if len(body.Template) > 0 {
		var draft *db.ReportTemplate
		// 宽松解析：draft 允许缺 id/is_default 等只读键。
		raw := struct {
			Name        string             `json:"name"`
			OutputLang  string             `json:"output_lang"`
			Skeleton    []db.ReportSection `json:"skeleton"`
			Style       json.RawMessage    `json:"style"`
			Prompts     json.RawMessage    `json:"prompts"`
			Issuer      string             `json:"issuer"`
			Personnel   json.RawMessage    `json:"personnel"`
			CVSSEnabled bool               `json:"cvss_enabled"`
			Remark      string             `json:"remark"`
		}{}
		if err := json.Unmarshal(body.Template, &raw); err != nil {
			writeErr(w, 400, "template 不是合法 JSON 对象: "+err.Error())
			return
		}
		draft = &db.ReportTemplate{ID: tmpl.ID, Name: raw.Name, OutputLang: raw.OutputLang, Skeleton: raw.Skeleton, Style: raw.Style, Prompts: raw.Prompts, Issuer: raw.Issuer, Personnel: raw.Personnel, CVSSEnabled: raw.CVSSEnabled, Remark: raw.Remark}
		base = draft
	}

	prov, _, ok := s.globalProvider()
	if body.LLMProfileID > 0 {
		prov, _, ok = s.providerForProfile(body.LLMProfileID)
	}
	if !ok || prov == nil {
		writeErr(w, 503, "LLM 未配置：请先配置全局模型或指定 llm_profile_id")
		return
	}

	// 用户侧消息序列 = 历史对话 + 当前模板全量 JSON（放最后一条 user 前缀，
	// 模型对"末尾上下文"遵循度最高）。
	sys := templateChatSystemPrompt
	if loc := strings.TrimSpace(body.Locale); loc != "" {
		sys += "\n6. reply 使用语言：" + loc + "。"
	}
	chatMsgs := make([]llm.Message, 0, len(msgs)+1)
	for _, m := range msgs {
		if m.Role == "assistant" {
			chatMsgs = append(chatMsgs, llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(m.Content)}})
		} else {
			chatMsgs = append(chatMsgs, llm.UserText(m.Content))
		}
	}
	// 把当前模板 JSON 附在最后一条用户消息里（不新增 user 轮，保持语义是
	// 「用户这句话+当前模板」→「补丁」）。校验已保证末尾是 user 轮。
	last := chatMsgs[len(chatMsgs)-1]
	tmplJSON, _ := json.Marshal(templateDraftView(base))
	chatMsgs[len(chatMsgs)-1] = llm.UserText(last.Text() + "\n\n当前模板 JSON：\n" + string(tmplJSON))

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	req := llm.CompletionRequest{
		System:    []string{sys},
		Messages:  chatMsgs,
		MaxTokens: 4000,
		Thinking:  "disabled", // 确定性 JSON 产出任务，关思考省一半往返
	}
	msg, _, usage, callErr := prov.Complete(ctx, req)
	if callErr != nil {
		writeErr(w, 502, "LLM 调用失败: "+callErr.Error())
		return
	}
	_ = usage

	patch, reply, warnings, perr := parseChatPatch(msg.Text(), base)
	if perr != nil {
		// 模型输出整体不可用：如实报错，前端提示重试；模板不动。
		writeErr(w, 502, "模型输出无法解析为补丁: "+perr.Error())
		return
	}
	merged := mergeTemplateDraft(base, patch)
	resp := map[string]any{
		"reply":    reply,
		"patch":    patch,
		"template": templateDraftView(merged),
		"warnings": warnings,
	}
	// R3：对话里允许「按现有数据渲染预览」。判定=用户明确提到渲染/预览/生成
	// 报告（或请求体显式 want_render）。渲染失败不打断对话（模板修改照常返回）。
	if body.WantRender || chatRequestsRender(userText) {
		rctx, rcancel := context.WithTimeout(r.Context(), 30*time.Second)
		pres, rerr := s.renderChatPreview(rctx, merged, body.Preview, r)
		rcancel()
		if rerr != nil {
			warnings = append(warnings, "预览渲染失败: "+rerr.Error())
			reply += "\n\n（本轮预览渲染失败：" + rerr.Error() + "）"
		} else {
			resp["preview"] = pres
			reply += "\n\n（已按「" + pres.Label + "」渲染预览，见下方预览卡片；可继续对话调整模板。）"
		}
		resp["reply"] = reply
		resp["warnings"] = warnings
	}
	writeJSON(w, 200, resp)
}

// templateDraftView 把模板行投影成前端 draft 形态（去掉 DB 只读元键；
// skeleton/style/prompts/personnel 原样透传 JSON 值）。
func templateDraftView(t *db.ReportTemplate) map[string]any {
	skel, _ := json.Marshal(t.Skeleton)
	return map[string]any{
		"id":           t.ID,
		"name":         t.Name,
		"output_lang":  t.OutputLang,
		"skeleton":     json.RawMessage(skel),
		"style":        t.Style,
		"prompts":      t.Prompts,
		"issuer":       t.Issuer,
		"personnel":    t.Personnel,
		"cvss_enabled": t.CVSSEnabled,
		"remark":       t.Remark,
		"docx_path":    t.DocxPath,
	}
}

// chatMessage 是请求体里的会话轮次。
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatPreviewInput 是对话渲染的数据源上下文（R3）。Demo=true 或无任务/项目时
// 用内置示例数据；否则用指定任务/项目真实数据渲染（与 render-draft 同管道）。
type chatPreviewInput struct {
	Demo       bool    `json:"demo"`
	Scope      string  `json:"scope"`
	TaskID     int64   `json:"task_id"`
	ProjectID  int64   `json:"project_id"`
	FindingIDs []int64 `json:"finding_ids"`
	Locale     string  `json:"locale"`
}

// chatRenderResult 是随对话返回的预览（HTML 片段/整页，前端 iframe 直接嵌入）。
type chatRenderResult struct {
	HTML    string `json:"html"`
	Label   string `json:"label"`  // 示例数据 / 任务#N / 项目#N
	Source  string `json:"source"` // demo | task | project
	Warning string `json:"warning,omitempty"`
}

// chatRequestsRender 判定用户这句话是否在要求「渲染/预览报告」。纯函数：
//   - 否定词（不要渲染/别预览…）优先，避免用户明确拒绝时误渲染；
//   - 命中渲染/预览/看效果/生成报告 等意图才渲染。
func chatRequestsRender(text string) bool {
	t := strings.ToLower(strings.TrimSpace(text))
	if t == "" {
		return false
	}
	for _, neg := range []string{"不要渲染", "别渲染", "无需渲染", "不用渲染", "不要预览", "别预览", "不用预览", "无需预览"} {
		if strings.Contains(t, neg) {
			return false
		}
	}
	for _, kw := range []string{"渲染", "预览", "看效果", "看下效果", "生成报告", "生成一份报告", "出一份报告", "出报告", "按现有数据", "重新生成一份报告"} {
		if strings.Contains(t, kw) {
			return true
		}
	}
	return false
}

// normalizeChatMessages 过滤非法角色/空内容并按 max 截尾。
func normalizeChatMessages(in []chatMessage, max int) []chatMessage {
	out := make([]chatMessage, 0, len(in))
	for _, m := range in {
		if (m.Role != "user" && m.Role != "assistant") || strings.TrimSpace(m.Content) == "" {
			continue
		}
		out = append(out, m)
	}
	if max > 0 && len(out) > max {
		out = out[len(out)-max:]
	}
	return out
}

// ---------- 输出护栏（纯函数，无库可单测） ----------

// chatGuardMaxPatchBytes patch 序列化后的大小上限。
const chatGuardMaxPatchBytes = 256 << 10

// parseChatPatch 解析模型输出为 {reply, patch}。返回 patch 为各字段的原始
// JSON（键缺省=不改该字段）；reply 缺省时给兜底文案。perr 非 nil=输出整体
// 不可用（无 JSON 可解）。字段级非法（skeleton 坏/style 非对象等）不报错，
// 丢弃该键并记入 warnings——一次跑飞不该废掉整轮对话。
func parseChatPatch(raw string, base *db.ReportTemplate) (map[string]json.RawMessage, string, []string, error) {
	warnings := []string{}
	body, ok := extractFencedJSON(raw)
	if !ok {
		return nil, "", nil, fmt.Errorf("输出里找不到 JSON 代码块")
	}
	if len(body) > chatGuardMaxPatchBytes {
		return nil, "", nil, fmt.Errorf("输出超过 %d 字节上限", chatGuardMaxPatchBytes)
	}
	// 两形态：{"reply":...,"patch":{...}} 或直接就是 patch 对象（无包装）。
	var wrapped struct {
		Reply string                     `json:"reply"`
		Patch map[string]json.RawMessage `json:"patch"`
	}
	var patch map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &wrapped) == nil && wrapped.Patch != nil {
		patch = wrapped.Patch
	} else if json.Unmarshal([]byte(body), &patch) == nil && patch != nil {
		warnings = append(warnings, "模型未包 {reply,patch} 外壳，已按裸 patch 处理")
	} else {
		return nil, "", nil, fmt.Errorf("JSON 不是合法的补丁对象")
	}

	reply := strings.TrimSpace(wrapped.Reply)
	if r := []rune(reply); len(r) > chatMaxReplyRunes {
		reply = string(r[:chatMaxReplyRunes]) + "…"
		warnings = append(warnings, "reply 过长已截断")
	}

	// 逐键清洗：白名单外的键丢弃；各键按 schema 校验。
	out := map[string]json.RawMessage{}
	for k, v := range patch {
		switch k {
		case "name":
			var s string
			if json.Unmarshal(v, &s) != nil {
				warnings = append(warnings, "name 非字符串，已忽略")
				continue
			}
			out[k] = v
		case "output_lang":
			var s string
			if json.Unmarshal(v, &s) != nil || (s != "zh-CN" && s != "en-US") {
				warnings = append(warnings, `output_lang 仅支持 zh-CN|en-US，已忽略`)
				continue
			}
			out[k] = v
		case "skeleton":
			var secs []db.ReportSection
			if json.Unmarshal(v, &secs) != nil {
				warnings = append(warnings, "skeleton 不是数组，已忽略")
				continue
			}
			if err := db.ValidateSkeleton(secs); err != nil {
				warnings = append(warnings, "skeleton 非法: "+err.Error())
				continue
			}
			norm, _ := json.Marshal(db.NormalizeSkeleton(secs))
			out[k] = norm
		case "style":
			var m map[string]any
			if json.Unmarshal(v, &m) != nil {
				warnings = append(warnings, "style 不是对象，已忽略")
				continue
			}
			// V2 实跑观察项：纪律要求 AI 把未动键抄全（全量替换语义），存量
			// 扩展键会每轮被报未知键刷屏。降噪：只对**本轮新引入**（base 里
			// 原本没有）的未知键报 warning；存量透传键不报。语义不变。
			baseKeys := baseStyleKeySet(base)
			for _, unknown := range unknownStyleKeys(m) {
				if baseKeys[unknown] {
					continue
				}
				warnings = append(warnings, fmt.Sprintf("style 含未知键 %q（交付端忽略该键）", unknown))
			}
			out[k] = v // 未知键透传（pybuilder 忽略未知键，无害）
		case "prompts":
			var m map[string]json.RawMessage
			if json.Unmarshal(v, &m) != nil {
				warnings = append(warnings, "prompts 不是对象，已忽略")
				continue
			}
			out[k] = v
		case "issuer":
			var s string
			if json.Unmarshal(v, &s) != nil {
				warnings = append(warnings, "issuer 非字符串，已忽略")
				continue
			}
			out[k] = v
		case "personnel":
			var arr []any
			if json.Unmarshal(v, &arr) != nil {
				warnings = append(warnings, "personnel 不是数组，已忽略")
				continue
			}
			out[k] = v
		case "cvss_enabled":
			var b bool
			if json.Unmarshal(v, &b) != nil {
				warnings = append(warnings, "cvss_enabled 非布尔，已忽略")
				continue
			}
			out[k] = v
		case "remark":
			var s string
			if json.Unmarshal(v, &s) != nil {
				warnings = append(warnings, "remark 非字符串，已忽略")
				continue
			}
			out[k] = v
		default:
			warnings = append(warnings, fmt.Sprintf("未知补丁键 %q 已忽略", k))
		}
	}
	if len(out) == 0 && reply == "" {
		reply = "本轮没有可用的模板修改。"
	}
	if reply == "" {
		reply = "已按你的要求给出模板修改。"
	}
	return out, reply, warnings, nil
}

// extractFencedJSON 剥 markdown 围栏取第一个可解 JSON 对象：优先 ```json
// 块；无围栏时退而求其次找整体裸 JSON（部分模型会漏围栏）。返回 (body, ok)。
func extractFencedJSON(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	// 1) 围栏块：```json … ``` / ``` … ```
	for {
		i := strings.Index(s, "```")
		if i < 0 {
			break
		}
		rest := s[i+3:]
		// 语言标注行（json / JSON / 空）到首个换行。
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			rest = rest[nl+1:]
		}
		j := strings.Index(rest, "```")
		var block string
		if j >= 0 {
			block = strings.TrimSpace(rest[:j])
			s = rest[j+3:] // 继续找下一块（首块可能截半）
		} else {
			// 未闭合围栏（输出被 max_tokens 切断）：取到结尾抢救。
			block = strings.TrimSpace(rest)
			s = ""
		}
		if strings.HasPrefix(block, "{") && json.Valid([]byte(block)) {
			return block, true
		}
	}
	// 2) 裸 JSON：整体以 { 开头且合法。
	if strings.HasPrefix(s, "{") && json.Valid([]byte(s)) {
		return s, true
	}
	return "", false
}

// knownStyleKeys = 前端 STYLE_FIELDS 六键（page.tsx:623 口径，pybuilder
// _configure_styles 消费）。
var knownStyleKeys = map[string]bool{
	"body_font": true, "west_font": true, "head_font": true,
	"body_size": true, "h1_size": true, "vuln_size": true,
}

func unknownStyleKeys(m map[string]any) []string {
	var out []string
	for k := range m {
		if !knownStyleKeys[k] {
			out = append(out, k)
		}
	}
	return out
}

// baseStyleKeySet 解析 base 模板 style 的既有键集（解析失败=空集，退化为
// 全报 warning 的旧行为，宁多报不漏报）。
func baseStyleKeySet(base *db.ReportTemplate) map[string]bool {
	set := map[string]bool{}
	if base == nil || len(base.Style) == 0 {
		return set
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(base.Style, &m) != nil {
		return set
	}
	for k := range m {
		set[k] = true
	}
	return set
}

// mergeTemplateDraft 把 patch 合并进 base 得全量模板（全量替换语义：键在
// patch 里=整值覆盖）。返回新对象，不改 base。
func mergeTemplateDraft(base *db.ReportTemplate, patch map[string]json.RawMessage) *db.ReportTemplate {
	m := *base
	if v, ok := patch["name"]; ok {
		_ = json.Unmarshal(v, &m.Name)
	}
	if v, ok := patch["output_lang"]; ok {
		_ = json.Unmarshal(v, &m.OutputLang)
	}
	if v, ok := patch["skeleton"]; ok {
		_ = json.Unmarshal(v, &m.Skeleton)
	}
	if v, ok := patch["style"]; ok {
		m.Style = json.RawMessage(v)
	}
	if v, ok := patch["prompts"]; ok {
		m.Prompts = json.RawMessage(v)
	}
	if v, ok := patch["issuer"]; ok {
		_ = json.Unmarshal(v, &m.Issuer)
	}
	if v, ok := patch["personnel"]; ok {
		m.Personnel = json.RawMessage(v)
	}
	if v, ok := patch["cvss_enabled"]; ok {
		_ = json.Unmarshal(v, &m.CVSSEnabled)
	}
	if v, ok := patch["remark"]; ok {
		_ = json.Unmarshal(v, &m.Remark)
	}
	return &m
}
