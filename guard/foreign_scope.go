package guard

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
)

// V9-SCOPE 内置规则：阅读者把「被勾连任务的资产」以经验 hint 暴露给发起方
// 规划者后，规划者可能顺着 hint 直接打对方的资产（越权到别的任务/项目）。
//
// 三道防线里这一道是【执行层】：
//  1. 数据：adopt 时把被勾连任务情报表里的资产 host 写入 task_foreign_assets；
//  2. 提示：hint 标 reference_only + foreign_hosts，planner 系统提示写明禁止；
//  3. 本规则：工具调用里提取 host，命中外部资产且不在本任务 assets 里 → deny。
//
// 它刻意【不进 DB 规则表】：DB 规则可被持 JWT 者一键 toggle/删除，而这条规则
// 保护的是「跨任务授权边界」，必须无法在运行期关掉。判定顺序在 applyIntercept
// 最前面（先于短路表与 DB 规则），命中 deny 后不再送判官。

const (
	// foreignScopeRuleName 进审计链的规则名。前缀 [代码内置] 是 db.interceptSource
	// 识别 decision_source=builtin_foreign_scope 的约定标记，勿改。
	foreignScopeRuleName = "[代码内置] 外部任务资产范围"
	// foreignScopeDenyMessage 是给模型看的固定文案（不含 host，避免把扫描目标
	// 写进历史时被误当成「可用地址」）。
	foreignScopeDenyMessage = "该地址来自其它任务的经验参考，不在本任务授权范围；如确需测试，请先在本任务登记该资产并由人工确认"
)

// ScopeResolver 提供内置规则需要的两组 host：
//   - ForeignHosts：task_foreign_assets 里记录的、属于其它任务的 host；
//   - OwnHosts：本任务 assets 的 host（命中这些一律放行，保证不误伤）。
//
// 由 server 注入（生产实现查 PG）；nil 时规则整体不生效 —— 无库环境（单元
// 测试 / 嵌入）保持原行为，不引入新的假阳性。
type ScopeResolver interface {
	ForeignHosts(ctx context.Context, taskID int64) ([]string, error)
	OwnHosts(ctx context.Context, taskID int64) ([]string, error)
}

// SetScopeResolver installs the DB-backed host scope lookup. Safe to call before
// the guard is handed to a session; nil disables the builtin foreign-scope rule.
func (g *Guard) SetScopeResolver(r ScopeResolver) { g.scope = r }

// SetScopeOnly 让该 Guard 只执行内置外部资产范围规则，跳过短路表 / DB 规则 /
// 判官。用于规划者：它此前完全不挂 hooks，只补这一条跨任务边界，避免把写意图
// 正文里的危险命令样例误拦（见 applyIntercept 注释）。
func (g *Guard) SetScopeOnly(v bool) { g.scopeOnly = v }

// scopeRegistrationTools 是「把 host 登记成本任务资产」的工具。它们是本规则的
// 合法出口（deny 文案要求「先在本任务登记该资产」），因此不能因为参数里出现
// 外部 host 就把登记动作本身拦掉。
var scopeRegistrationTools = map[string]bool{
	"add_task_scope":    true,
	"add_company_scope": true,
	"insert_assets":     true,
}

// checkForeignScope 是内置规则本体。返回非 nil 表示已 deny（调用方直接返回）。
//
// 宁可漏也不误伤：
//   - 解析不出 host / 没有 host → 放行；
//   - 查询失败 → 放行（不能因 DB 抖动把正常测试全停掉）；
//   - host 在本任务 assets 里 → 放行（即使它同时出现在别人的任务里）。
func (g *Guard) checkForeignScope(ctx context.Context, ev hook.Event) *hook.Result {
	if g.scope == nil {
		return nil
	}
	if scopeRegistrationTools[ev.ToolName] {
		return nil
	}
	taskID, err := strconv.ParseInt(intercept.TaskIDFromContext(ctx), 10, 64)
	if err != nil || taskID <= 0 {
		return nil
	}
	hosts := hostsInToolInput(ev.ToolName, ev.Input)
	if len(hosts) == 0 {
		return nil
	}
	foreign, err := g.scope.ForeignHosts(ctx, taskID)
	if err != nil || len(foreign) == 0 {
		return nil
	}
	own, err := g.scope.OwnHosts(ctx, taskID)
	if err != nil {
		return nil
	}
	ownSet := normalizeHostSet(own)
	set := normalizeHostSet(foreign)
	for _, h := range hosts {
		h = normalizeHost(h)
		if h == "" {
			continue
		}
		if _, ok := ownSet[h]; ok {
			continue
		}
		if _, ok := set[h]; !ok {
			continue
		}
		dec := intercept.Decision{
			Action:   "deny",
			RuleName: foreignScopeRuleName,
			Message:  foreignScopeDenyMessage,
		}
		if g.interceptor != nil {
			logCtx := intercept.WithCall(ctx, ev.ToolName, ev.Input)
			g.interceptor.Log(logCtx, intercept.ConvIDFromContext(logCtx), dec, ev.ToolName, ev.Input, "denied")
		}
		g.record(ev.ToolName, "block", dec.Message, "")
		res := g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
		return &res
	}
	return nil
}

func normalizeHostSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, h := range in {
		if h = normalizeHost(h); h != "" {
			out[h] = struct{}{}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// host 提取与归一化
// ---------------------------------------------------------------------------

// hostLikeKeys 是「值一定是地址」的参数名（HTTP 工具的 url、MCP 的 target/
// address 等）。只看这些键，避免把任意文本里的 IP 误当扫描目标。
var hostLikeKeys = map[string]bool{
	"url": true, "uri": true, "endpoint": true, "host": true, "hostname": true,
	"target": true, "target_url": true, "targeturl": true, "address": true, "addr": true,
	"domain": true, "base_url": true, "baseurl": true, "ip": true, "server": true,
	// 复数/列表参数（MCP 常见的 targets/hosts/urls）。
	"targets": true, "hosts": true, "urls": true, "ips": true, "addresses": true, "endpoints": true,
}

// tokenTrim 去掉 shell 引号与常见分隔符，保留 : / [ ] . 等地址字符。
var tokenTrim = `"'` + "`" + `,;()<>|&`

// hostsInToolInput 从工具入参里提取 host（可能多个）。覆盖：
//   - Bash / shell_open 的 command、shell_send 的 text 里的 URL、host:port、裸 IP；
//   - 任意 JSON 对象中键名像地址的字段（url / host / target / address …）；
//   - 值为带 scheme 的 URL（即使键名不认识）。
//
// 解析不出就返回空 —— 调用方据此放行（宁漏不误伤）。
func hostsInToolInput(tool string, input []byte) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(h string) {
		h = normalizeHost(h)
		if h == "" {
			return
		}
		if _, ok := seen[h]; ok {
			return
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}

	switch tool {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(input, &in) == nil {
			for _, h := range hostsInText(in.Command) {
				add(h)
			}
		}
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(input, &in) == nil {
			for _, h := range hostsInText(in.Text) {
				add(h)
			}
		}
	}

	var v any
	if json.Unmarshal(input, &v) == nil {
		walkHostFields(v, add)
	}
	return out
}

func walkHostFields(v any, add func(string)) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			key := strings.ToLower(strings.TrimSpace(k))
			if hostLikeKeys[key] {
				switch cv := child.(type) {
				case string:
					for _, h := range hostsInValue(cv) {
						add(h)
					}
				case []any:
					for _, el := range cv {
						if s, ok := el.(string); ok {
							for _, h := range hostsInValue(s) {
								add(h)
							}
						}
					}
				}
				continue
			}
			// 不再扫「任意字符串里的 URL」：add_intent / add_hint 的 summary/text
			// 常引用地址，按内容匹配会把「写意图」误拦。只认键名像地址的字段
			//（宁漏不误伤），Bash 的命令串单独解析。
			walkHostFields(child, add)
		}
	case []any:
		for _, child := range t {
			walkHostFields(child, add)
		}
	}
}

// hostsInValue 处理「键名已确认是地址」的值：裸域名也接受（这里不存在把
// 普通单词当域名的风险，因为只看 url/host/target 这类键）。
func hostsInValue(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if h := hostFromURL(s); h != "" {
		return []string{h}
	}
	// 可能是 host:port 或裸 host/IP（含 IPv6）。
	s = strings.Trim(s, tokenTrim+"[]")
	if h := hostFromHostPort(s); h != "" {
		return []string{h}
	}
	if looksLikeHostname(s) || strings.EqualFold(s, "localhost") {
		return []string{s}
	}
	return nil
}

// hostsInText 从一段 shell 命令里提取地址。只认三类，降低误伤：
// 带 scheme 的 URL、host:port、裸 IP（IPv4/IPv6）。
func hostsInText(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '"', '\'', '`', ';', '|', '&', '(', ')', '<', '>', ',':
			return true
		}
		return false
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.Trim(f, tokenTrim)
		if f == "" {
			continue
		}
		if h := hostFromURL(f); h != "" {
			out = append(out, h)
			continue
		}
		// curl 10.0.0.9/x / //host:port → 截掉路径后再判断。
		hp := f
		if strings.HasPrefix(hp, "//") {
			hp = hp[2:]
		}
		if i := strings.IndexByte(hp, '/'); i >= 0 {
			hp = hp[:i]
		}
		if h := hostFromHostPort(hp); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// hostFromURL 解析带 scheme 的 URL（含 http://[::1]:80/x）。
func hostFromURL(s string) string {
	if !strings.Contains(s, "://") {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return normalizeHost(u.Hostname())
}

// hostFromHostPort 处理 host:port / 裸 IP / 括号 IPv6。
// 不带端口的域名不在这里接受（shell 里裸域名无法与文件名区分）。
func hostFromHostPort(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return normalizeHost(host)
	}
	// 括号 IPv6 无端口：[::1]
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return normalizeHost(s[1 : len(s)-1])
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	// IPv6 带端口但无括号：::1:8080 无法可靠切分，直接当 IP 试一次。
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return ""
}

var hostnameRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// looksLikeHostname 只用于「键名已确认是地址」的值，避免把单词当域名。
func looksLikeHostname(s string) bool {
	if len(s) > 253 {
		return false
	}
	return hostnameRe.MatchString(s)
}

// NormalizeHost 把各种写法收敛成可比较的 host：小写、去端口、去括号、
// IPv6 压缩形式。解析失败返回空串（调用方据此跳过，不误伤）。
//
// 这是 adopt 落库与执行期匹配共用的唯一口径 —— 两边必须一致，否则
// task_foreign_assets 里存 10.0.0.9:8080 而命令里是 10.0.0.9 就漏拦。
func NormalizeHost(raw string) string { return normalizeHost(raw) }

func normalizeHost(raw string) string {
	s := strings.TrimSpace(strings.Trim(raw, tokenTrim))
	if s == "" {
		return ""
	}
	if h := hostFromURL(s); h != "" {
		return h
	}
	// 去 userinfo（user:pass@host）后重试。
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	if h := hostFromHostPort(s); h != "" {
		return h
	}
	s = strings.ToLower(strings.Trim(s, "[]"))
	s = strings.TrimSuffix(s, ".")
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	// 非 IP：只接受看起来像域名的串；其余（路径/单词/乱码）视为解析失败。
	if looksLikeHostname(s) || s == "localhost" {
		return s
	}
	return ""
}
