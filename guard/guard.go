// Package guard implements the safety boundary layer (docs §11): an audit log,
// user-configured intercept-rule evaluation, and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// (The RoE authorization-scope mechanism was removed; a replacement may be added
// later.) Destructive/exfil gating is no longer hard-coded here — it lives in the
// DB intercept rules (seeded as ordinary [内置] rules, so users can disable or
// delete them), evaluated via applyIntercept.
package guard

import (
	"context"
	"encoding/json"
	"log"
	"regexp"
	"sync"
	"time"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
)

// AuditEntry records one gated tool call.
type AuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"` // allow|block
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// interceptorAPI 是 guard 用到的 intercept 能力面。生产实现恒为
// *intercept.Interceptor；抽成接口只为让「规则表 → 白名单 → 判官」的路由能在
// 无数据库环境里用假实现钉死（与 externalProbe 同一种测试缝）。
type interceptorAPI interface {
	IsToolEnabled(string) bool
	JudgeAllToolsEnabled() bool
	IsToolExternal(string) bool
	Match(string, []byte) (intercept.Decision, bool)
	Judge(context.Context, string, json.RawMessage) (intercept.Decision, bool)
	JudgeAskVerdict(context.Context, intercept.Decision, string, json.RawMessage) (intercept.Decision, bool)
	AskBurstExceeded(context.Context, string) bool
	HandleAsk(context.Context, int64, intercept.Decision, string, []byte) bool
	Log(context.Context, int64, intercept.Decision, string, []byte, string)
	AppendDecisionEvent(context.Context, intercept.Decision, string, []byte, string)
}

// Guard enforces the side-effect policy via agent-core hooks.
type Guard struct {
	mu            sync.Mutex
	audit         []AuditEntry
	attrib        map[string]int // failure attribution counts (Observer / G5)
	reg           *hook.Registry
	interceptor   interceptorAPI     // optional; nil disables user-configured rules
	judgeCache    *judgeVerdictCache // 白名单外工具的判官结论缓存（见 judge_all.go）
	externalProbe func(string) bool  // 测试注入的工具外部性分类器；nil 走 interceptor
	scope         ScopeResolver      // V9-SCOPE 内置外部资产范围规则；nil 关闭（见 foreign_scope.go）
	scopeOnly     bool               // 只跑内置外部资产范围规则（planner 专用，见 SetScopeOnly）
}

// New creates a Guard without user-configured intercept rules (used for pentest
// tasks where the Interceptor is not yet available).
func New() *Guard { return newGuard(nil) }

// NewWithInterceptor creates a Guard with user-configured intercept rules.
func NewWithInterceptor(ic *intercept.Interceptor) *Guard { return newGuard(ic) }

func newGuard(ic *intercept.Interceptor) *Guard {
	// V6-CFG：短路表在首个 Guard 初始化时读一次 <dataDir>/shortcircuit_rules.json。
	// 加载失败时 main 会拒绝启动（见 cmd/artex）；这里只留下日志，运行期由
	// shortCircuit 的 fail-closed 分支兜底。
	if err := InitShortCircuit(); err != nil {
		log.Printf("[guard] ⚠ 短路规则配置加载失败（将按 fail-closed 全拒）: %v", err)
	}
	g := &Guard{
		attrib:     map[string]int{},
		judgeCache: newJudgeVerdictCache(time.Now, judgeVerdictTTL, judgeVerdictCacheCap),
	}
	// 逐值赋值：把 (*intercept.Interceptor)(nil) 塞进接口会得到非 nil 接口，
	// 下面所有 `g.interceptor == nil` 的无规则快路径就全失效了。
	if ic != nil {
		g.interceptor = ic
	}
	g.reg = hook.NewRegistry().
		On(hook.PreToolUse, g.preToolUse).
		On(hook.PostToolUse, g.postToolUse)
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) hook.Result {
	// Extract the shell-command surface for the audit log: Bash + the interactive-shell
	// tools (shell_open's command, shell_send's text). Destructive/exfil gating is no
	// longer hard-coded here — it now lives in the DB intercept rules, evaluated by
	// applyIntercept below. Other tools record an empty command.
	var cmd string
	switch ev.ToolName {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Command
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Text
	}
	g.record(ev.ToolName, "allow", "", cmd)
	return g.applyIntercept(ctx, ev)
}

// applyIntercept evaluates user-configured intercept rules against the tool call.
// Both rules and the fallback judge receive the complete tool input.
func (g *Guard) applyIntercept(ctx context.Context, ev hook.Event) hook.Result {
	// V9-SCOPE：外部任务资产范围是【代码内置规则】，不进 DB 规则表、不提供
	// 运行期开关。放在最前面（先于短路表与 DB 规则），命中即终局，不再送判官。
	if res := g.checkForeignScope(ctx, ev); res != nil {
		return *res
	}
	// 规划者专用护栏只做这一条规则：规划者在 V9-SCOPE 之前不挂任何 hooks，
	// 直接接入完整规则表会让 add_intent 正文里的 rm -rf/凭据路径被误拦。外部
	// 资产范围是本次新增的唯一约束，其余判官/DB 规则保持规划者原行为。
	if g.scopeOnly {
		return hook.Result{}
	}
	// 短路表须先于规则匹配求值：它是代码常量红线，对全部工具生效，命中即终局。
	if dec := shortCircuit(ev.ToolName, ev.Input); dec != nil {
		switch dec.Action {
		case "allow":
			// 显式放行也要留痕：平台工具调用量小，进审计链无压力；
			// 事后要能回答「谁在何时建过什么」。
			if g.interceptor != nil {
				logCtx := intercept.WithCall(ctx, ev.ToolName, ev.Input)
				g.interceptor.Log(logCtx, intercept.ConvIDFromContext(logCtx), *dec, ev.ToolName, ev.Input, "allowed")
				g.interceptor.AppendDecisionEvent(logCtx, *dec, ev.ToolName, ev.Input, "allow")
			}
			g.record(ev.ToolName, "allow", dec.Message, "")
			return hook.Result{}
		case "ask":
			// 审批防疲劳：同一 agent 在窗口内反复对同一高危面请求审批，
			// 达阈值后直接拒绝，不再打扰人（也堵住「疲劳点 allow」的循环）。
			if g.interceptor != nil && g.interceptor.AskBurstExceeded(ctx, ev.ToolName) {
				esc := *dec
				esc.Action = "deny"
				esc.RuleName = "[代码常量] 审批请求超阈值（同一 agent 重复请求）"
				esc.Message = "同一 agent 在时间窗内对本工具的审批请求已超阈值，按防疲劳策略直接拒绝。"
				logCtx := intercept.WithCall(ctx, ev.ToolName, ev.Input)
				g.interceptor.Log(logCtx, intercept.ConvIDFromContext(logCtx), esc, ev.ToolName, ev.Input, "denied")
				g.interceptor.AppendDecisionEvent(logCtx, esc, ev.ToolName, ev.Input, "denied")
				g.record(ev.ToolName, "block", esc.Message, "")
				return g.block(ev.ToolName, systemBlockMessage(esc.Message), "")
			}
			if g.interceptor == nil {
				return g.block(ev.ToolName, systemBlockMessage("人工审批通道不可用（"+dec.Message+"）"), "")
			}
			ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
			if !g.interceptor.HandleAsk(ctx, intercept.ConvIDFromContext(ctx), *dec, ev.ToolName, ev.Input) {
				return g.block(ev.ToolName, systemBlockMessage("人工审批未通过（用户拒绝或审批超时）"), "")
			}
			return hook.Result{}
		default:
			// 短路表的 deny 也要落库。此前它只进内存 audit 切片（上限 2000、
			// 进程退出即失），于是「谁在何时想干什么」查无实据 —— 而短路表
			// 恰恰是唯一一道不受 DB 热改面影响的防线，最需要留痕。
			// Log 是 best-effort：DB 写失败不影响本次调用结果。
			if g.interceptor != nil {
				logCtx := intercept.WithCall(ctx, ev.ToolName, ev.Input)
				g.interceptor.Log(logCtx, intercept.ConvIDFromContext(logCtx), *dec, ev.ToolName, ev.Input, "denied")
			}
			g.record(ev.ToolName, "block", dec.Message, "")
			return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
		}
	}
	if g.interceptor == nil {
		return hook.Result{}
	}
	// 规则表对【全部】工具生效：Match 本身按规则的 MatchTarget（tool_name /
	// tool_input）比对，与白名单无关。此前先判 IsToolEnabled 再 Match，白名单
	// 外的 MCP / 自定义工具根本不过规则表 —— 一条 tool_input=deny 的规则（如
	// 内置 rm -rf、凭据读写）对它们永不生效，用户在 UI 里给 mcp__xxx__run 建的
	// tool_name 规则同样形同虚设。白名单现在只决定「无规则命中后送不送判官」。
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	dec, matched := g.interceptor.Match(ev.ToolName, ev.Input)
	if !matched {
		// 无规则命中。白名单外：
		//   - 内置平台工具（kind=builtin，record_fact / graph_overview 等）不送
		//     判官 —— 它们不执行代码也不触外部系统，判官没有可拦的面，送判只
		//     是每轮多烧 2-3k token + 1-3s（V5-B2）。
		//   - MCP / 自定义（command|script|http）/ 未知工具名仍必送：这些才是
		//     V5-B 要覆盖的面（见 intercept.IsToolExternal）。
		//   - intercept_judge_all_tools=false 时整体退回旧行为，全部放行。
		if !g.interceptor.IsToolEnabled(ev.ToolName) {
			return g.judgeOutsideWhitelist(ctx, ev, g.interceptor.JudgeAllToolsEnabled(), g.interceptor.Judge)
		}
		// 白名单内无规则命中：Ask the LLM fallback judge (if enabled); when it is
		// off or unwired, keep current behavior and allow.
		d, judged := g.interceptor.Judge(ctx, ev.ToolName, ev.Input)
		if !judged {
			return hook.Result{}
		}
		dec = d
	} else if dec.Action == "ask" {
		// V4-D 修复1：ask 规则命中且判官开启时，先交模型快速裁决，人工只兜底。
		// 判官 allow→放行、deny→拒绝（均 decision_source=model 留痕）；判官
		// 故障/超时/不可解析或判官本身转人工 → 回落现 ask 语义（pending +
		// 规则超时 60s→deny，fail-closed 不变）。判官未开启时 JudgeAskVerdict
		// 直接返回 false，行为与改动前逐字节一致。
		// 【只有 ask 这一档改变路由】：deny 是硬规则不因模型翻案，allow 照旧。
		if d, ok := g.interceptor.JudgeAskVerdict(ctx, dec, ev.ToolName, ev.Input); ok {
			dec = d
		}
	}
	return g.applyDecision(ctx, ev, dec)
}

// judgeOutsideWhitelist 给白名单外、且【规则表未命中】的工具调用补判官（V5-B）。
//
// 调用方只在 Match 返回未命中后才走到这里：规则表对全部工具生效（含 MCP /
// 自定义工具），所以到这里意味着确实没有规则可依，只剩模型这一道兜底。反过来，
// 规则命中 deny/allow 时它是权威结论，不再额外送判（省 token，也不让模型推翻
// 硬规则）；命中 ask 才走 JudgeAskVerdict 交模型裁决。
//
// 判官仍然是全覆盖的安全兜底：模型 allow/deny 照常执行并落库
// （decision_source=model，由 reason 的 [模型] 前缀 + RuleID=0 归类），ask 走
// 人工审批（判官 ask verdict 自带超时）。判官未开启/未接线时 Judge 返回
// judged=false，保持改动前的放行语义。
//
// 「白名单外」不等于「都送判」：平台内置工具（kind=builtin）在这里被
// toolIsExternal 挡掉（V5-B2）；只有 MCP、自定义（command|script|http）与
// 未知工具名才真正落到判官。
//
// 缓存：同一次会话内 (tool, sha256(input)) 相同的调用复用结论（TTL 5 分钟、
// 上限 500、LRU），命中时不重复调模型，但每次都落库留痕（applyDecision 里
// 的 Log），审计链不缺条目。
//
// enabled/judge 由调用方传入，是为了让这条路由能在没有数据库的环境里用假
// 判官测（见 judge_all_test.go）。
func (g *Guard) judgeOutsideWhitelist(ctx context.Context, ev hook.Event, enabled bool, judge judgeFunc) hook.Result {
	if !shouldJudgeBeyondWhitelist(enabled, ev.ToolName, func() bool { return g.toolIsExternal(ev.ToolName) }) {
		return hook.Result{}
	}
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	key := judgeCacheKey(ctx, ev.ToolName, ev.Input)
	if dec, ok := g.judgeCache.get(key); ok {
		log.Printf("[judge] nonwhitelist=1 cache=hit tool=%s action=%s", ev.ToolName, dec.Action)
		return g.applyDecision(ctx, ev, dec)
	}
	dec, judged := judge(ctx, ev.ToolName, ev.Input)
	if !judged {
		return hook.Result{}
	}
	if cacheableJudgeVerdict(dec) {
		g.judgeCache.put(key, dec)
	}
	log.Printf("[judge] nonwhitelist=1 cache=miss tool=%s action=%s model_fallback=%t",
		ev.ToolName, dec.Action, dec.ModelFallback)
	return g.applyDecision(ctx, ev, dec)
}

// applyDecision 把一条判定落到工具调用上（规则命中与判官裁决共用）。
func (g *Guard) applyDecision(ctx context.Context, ev hook.Event, dec intercept.Decision) hook.Result {
	switch dec.Action {
	case "deny":
		// 观测:deny 命中不阻塞审批,直接记一条 denied（历史/任务拦截页可见）。
		if g.interceptor != nil {
			g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "denied")
		}
		return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		if g.interceptor != nil {
			g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "allowed")
		}
		return hook.Result{}
	case "ask":
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(ev.ToolName, systemBlockMessage("工作已取消，平台安全管控阻止执行"), "")
		}
		convID := intercept.ConvIDFromContext(ctx)
		if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
			return g.block(ev.ToolName, systemBlockMessage("人工审批未通过（用户拒绝或审批超时）"), "")
		}
		return hook.Result{}
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as an ARTEX platform-governance
// decision so the agent does not mistake it for a target-side defense.
//
// The bare reasons ("禁止执行此工具" / "用户拒绝") read exactly like a WAF/403 on
// the target, so a pentest agent's instinct is to bypass them — rewrite the
// command, swap the payload, re-encode, retry. That is both futile (the platform
// blocks the class of action, not one string) and wrong (it's a policy decision,
// not an obstacle to defeat). This prefix states plainly that the block comes
// from the platform, is not the target's protection, and that the operation is
// forbidden — so the agent pivots to another approach instead of evading it.
// Audit/history rows keep the raw reason (see Interceptor.Log); only the
// model-facing tool_result carries this framing.
func systemBlockMessage(reason string) string {
	return "【ARTEX 平台管控·非目标防御】此调用被平台拦截。" +
		"原因：" + reason + "。此操作被禁止。"
}

var reBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b`)

// postToolUse is the Observer failure-attribution hook (G5): it classifies tool
// results into blocked / error / ok so the planner can change strategy instead
// of giving up at a WAF.
func (g *Guard) postToolUse(_ context.Context, ev hook.Event) hook.Result {
	if ev.ToolName != "Bash" {
		return hook.Result{}
	}
	class := "ok"
	switch {
	case reBlocked.Match(ev.Result):
		class = "blocked"
	case ev.IsError:
		class = "error"
	}
	g.mu.Lock()
	g.attrib[class]++
	g.mu.Unlock()
	return hook.Result{}
}

// Attributions returns failure-attribution counts (Observer / G5).
func (g *Guard) Attributions() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.attrib))
	for k, v := range g.attrib {
		out[k] = v
	}
	return out
}

func (g *Guard) block(tool, reason, cmd string) hook.Result {
	g.record(tool, "block", reason, cmd)
	return hook.Result{Decision: "block", Message: reason}
}

func (g *Guard) record(tool, action, reason, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, AuditEntry{TS: time.Now().Unix(), Tool: tool, Action: action, Reason: reason, Command: cmd})
	if len(g.audit) > 2000 {
		g.audit = g.audit[len(g.audit)-2000:]
	}
}

// Audit returns a snapshot of recent gated calls (most recent last).
func (g *Guard) Audit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}
