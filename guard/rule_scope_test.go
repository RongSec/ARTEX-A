package guard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/intercept"
)

// ============================================================================
// V5-I：规则表的作用域 —— 规则对所有工具生效，白名单只决定「无规则命中时
// 送不送判官」。
//
// 缺陷原状：applyIntercept 先判 IsToolEnabled 再 Match，白名单外的 MCP /
// 自定义工具整段跳过规则表，只走判官。于是 tool_input 类规则（内置 rm -rf、
// 凭据读写）与 UI 里为 mcp__xxx__run 建的 tool_name 规则对它们永不生效。
//
// 这组用例用假规则引擎（interceptorAPI 的最小实现）把路由矩阵钉在无库环境里：
// 规则命中 deny/allow 是权威结论（判官 0 次），只有未命中才按白名单决定是否
// 额外送判（V5-B 的覆盖面不回归）。
// ============================================================================

type fakeRule struct {
	name    string
	target  string // tool_name | tool_input
	pattern string
	action  string
}

type fakeEngine struct {
	rules    []fakeRule
	enabled  map[string]bool
	judgeAll bool

	judgeCalls int
	askCalls   int
	// handleAskCalls 统计真正进入人工审批的次数（V6-AUTO：判官 ask 自主
	// 落定后必须为 0）。
	handleAskCalls int
	judgeDec       intercept.Decision
	judgeOK        bool
	askDec         intercept.Decision
	askOK          bool
}

func (f *fakeEngine) IsToolEnabled(name string) bool { return f.enabled[name] }
func (f *fakeEngine) JudgeAllToolsEnabled() bool     { return f.judgeAll }
func (f *fakeEngine) IsToolExternal(string) bool     { return true }

func (f *fakeEngine) AskBurstExceeded(context.Context, string) bool { return false }

func (f *fakeEngine) HandleAsk(context.Context, int64, intercept.Decision, string, []byte) bool {
	f.handleAskCalls++
	return false
}

func (f *fakeEngine) Log(context.Context, int64, intercept.Decision, string, []byte, string) {}

func (f *fakeEngine) AppendDecisionEvent(context.Context, intercept.Decision, string, []byte, string) {
}

func (f *fakeEngine) Match(tool string, input []byte) (intercept.Decision, bool) {
	for _, r := range f.rules {
		subject := tool
		if r.target == "tool_input" {
			subject = string(input)
		}
		if strings.Contains(subject, r.pattern) {
			return intercept.Decision{
				RuleName: r.name,
				Action:   r.action,
				Message:  "[规则] " + r.name + " 命中",
			}, true
		}
	}
	return intercept.Decision{}, false
}

func (f *fakeEngine) Judge(context.Context, string, json.RawMessage) (intercept.Decision, bool) {
	f.judgeCalls++
	return f.judgeDec, f.judgeOK
}

func (f *fakeEngine) JudgeAskVerdict(_ context.Context, rule intercept.Decision, _ string, _ json.RawMessage) (intercept.Decision, bool) {
	f.askCalls++
	if !f.askOK {
		return intercept.Decision{}, false
	}
	dec := f.askDec
	dec.RuleName = rule.RuleName
	return dec, true
}

func newFakeGuard(f *fakeEngine) *Guard {
	g := New()
	g.interceptor = f
	return g
}

// 规则命中（非 ask）时判官与交裁都不得被调用。
func assertJudgeUntouched(t *testing.T, f *fakeEngine) {
	t.Helper()
	if f.judgeCalls != 0 {
		t.Fatalf("规则命中时不应送判官，实际 %d 次", f.judgeCalls)
	}
	if f.askCalls != 0 {
		t.Fatalf("非 ask 规则不应交裁，实际 %d 次", f.askCalls)
	}
}

// 1) MCP 工具命中 tool_input 规则：改前永不生效，改后必须拦。
// 用内置 rm 规则的形态（tool_input + deny）打 mcp__shell__run —— 这就是
// 「规则表对所有工具生效」的直接实证。
func TestMCPToolHitsToolInputRule(t *testing.T) {
	f := &fakeEngine{
		enabled: map[string]bool{"Bash": true}, // MCP 不在白名单
		rules: []fakeRule{
			{name: "[内置] 递归删除生产目录", target: "tool_input", pattern: "rm -rf", action: "deny"},
		},
		judgeAll: true,
		judgeDec: intercept.Decision{Action: "allow"},
		judgeOK:  true,
	}
	g := newFakeGuard(f)
	input := json.RawMessage(`{"command":"rm -rf /var/www/html"}`)
	blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "mcp__shell__run", input)
	if !blocked {
		t.Fatal("MCP 工具命中 tool_input deny 规则必须被拦截")
	}
	if !strings.Contains(msg, "递归删除生产目录") {
		t.Fatalf("拦截消息应带规则名，得到 %q", msg)
	}
	assertJudgeUntouched(t, f)
}

// 2) MCP 工具命中 tool_name 规则：UI 里给 mcp__db__query 建的规则必须生效。
func TestMCPToolHitsToolNameRule(t *testing.T) {
	f := &fakeEngine{
		enabled:  map[string]bool{"Bash": true},
		rules:    []fakeRule{{name: "禁止 MCP 直连生产库", target: "tool_name", pattern: "mcp__db__query", action: "deny"}},
		judgeAll: true,
		judgeDec: intercept.Decision{Action: "allow"},
		judgeOK:  true,
	}
	g := newFakeGuard(f)
	blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "mcp__db__query", json.RawMessage(`{"sql":"select 1"}`))
	if !blocked {
		t.Fatal("MCP 工具命中 tool_name deny 规则必须被拦截")
	}
	if !strings.Contains(msg, "禁止 MCP 直连生产库") {
		t.Fatalf("拦截消息应带规则名，得到 %q", msg)
	}
	assertJudgeUntouched(t, f)
}

// 3) MCP 工具无规则命中 → 仍送判官（V5-B 覆盖面不回归），且缓存生效。
func TestMCPToolWithoutRuleStillReachesJudge(t *testing.T) {
	f := &fakeEngine{
		enabled:  map[string]bool{"Bash": true},
		judgeAll: true,
		judgeDec: intercept.Decision{Action: "allow", Message: "只读"},
		judgeOK:  true,
	}
	g := newFakeGuard(f)
	ev := json.RawMessage(`{"path":"/var/log/nginx/access.log"}`)
	for i := 0; i < 2; i++ {
		if blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "mcp__fs__read_file", ev); blocked {
			t.Fatalf("判官 allow 不应阻塞（第 %d 次），消息 %q", i+1, msg)
		}
	}
	if f.judgeCalls != 1 {
		t.Fatalf("首次送判、第二次命中缓存，判官应只被调用 1 次，实际 %d", f.judgeCalls)
	}
}

// 4) 内置平台工具无规则命中 → 判官 0 次（V5-B2 收敛不回归）。
func TestBuiltinToolWithoutRuleSkipsJudge(t *testing.T) {
	f := &fakeEngine{
		enabled:  map[string]bool{"Bash": true},
		judgeAll: true,
		judgeDec: intercept.Decision{Action: "deny", Message: "不该被调用"},
		judgeOK:  true,
	}
	g := newFakeGuard(f)
	g.externalProbe = builtinProbe
	if blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "record_fact", json.RawMessage(`{"task_id":"t1"}`)); blocked {
		t.Fatalf("内置平台工具不应被拦，消息 %q", msg)
	}
	if f.judgeCalls != 0 {
		t.Fatalf("内置平台工具不得送判官，实际 %d 次", f.judgeCalls)
	}
}

// 5) 白名单内工具无规则命中 → 判官 1 次（原行为不变）。
func TestWhitelistedToolWithoutRuleReachesJudge(t *testing.T) {
	f := &fakeEngine{
		enabled:  map[string]bool{"Bash": true},
		judgeAll: true,
		judgeDec: intercept.Decision{Action: "allow", Message: "只读"},
		judgeOK:  true,
	}
	g := newFakeGuard(f)
	if blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash", json.RawMessage(`{"command":"ls -la /tmp"}`)); blocked {
		t.Fatalf("判官 allow 不应阻塞，消息 %q", msg)
	}
	if f.judgeCalls != 1 {
		t.Fatalf("白名单内无规则命中应送判官 1 次，实际 %d", f.judgeCalls)
	}
}

// 6) MCP 工具命中 ask 规则 → 走 JudgeAskVerdict：allow 放行、deny 拦截。
func TestMCPToolAskRuleGoesToJudgeVerdict(t *testing.T) {
	rule := fakeRule{name: "MCP 写操作需确认", target: "tool_name", pattern: "mcp__fs__write", action: "ask"}
	ev := json.RawMessage(`{"path":"/tmp/x","content":"y"}`)

	t.Run("判官 allow 放行", func(t *testing.T) {
		f := &fakeEngine{
			enabled:  map[string]bool{"Bash": true},
			rules:    []fakeRule{rule},
			judgeAll: true,
			askDec:   intercept.Decision{Action: "allow", Message: "写入 /tmp 无风险"},
			askOK:    true,
		}
		g := newFakeGuard(f)
		if blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "mcp__fs__write", ev); blocked {
			t.Fatalf("判官 allow 应放行，消息 %q", msg)
		}
		if f.askCalls != 1 {
			t.Fatalf("ask 规则命中应交裁 1 次，实际 %d", f.askCalls)
		}
		if f.judgeCalls != 0 {
			t.Fatalf("ask 规则命中不应再走无规则判官路径，实际 %d 次", f.judgeCalls)
		}
		if f.handleAskCalls != 0 {
			t.Fatalf("判官给 allow 后不得再进人工审批，实际 %d 次", f.handleAskCalls)
		}
	})

	t.Run("判官 deny 拦截", func(t *testing.T) {
		f := &fakeEngine{
			enabled:  map[string]bool{"Bash": true},
			rules:    []fakeRule{rule},
			judgeAll: true,
			askDec:   intercept.Decision{Action: "deny", Message: "写入系统配置目录"},
			askOK:    true,
		}
		g := newFakeGuard(f)
		blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "mcp__fs__write", ev)
		if !blocked {
			t.Fatal("判官 deny 必须拦截")
		}
		if !strings.Contains(msg, "写入系统配置目录") {
			t.Fatalf("拦截消息应带判官理由，得到 %q", msg)
		}
		if f.askCalls != 1 {
			t.Fatalf("ask 规则命中应交裁 1 次，实际 %d", f.askCalls)
		}
		if f.handleAskCalls != 0 {
			t.Fatalf("判官给 deny 后不得再进人工审批，实际 %d 次", f.handleAskCalls)
		}
	})

	// V6-AUTO：判官自己拿不准时按规则超时策略合成的终局（[自主]）走同一条
	// applyDecision 路径，不得再进 HandleAsk / pending。
	t.Run("判官不确定 → 自主落定不进人工", func(t *testing.T) {
		f := &fakeEngine{
			enabled:  map[string]bool{"Bash": true},
			rules:    []fakeRule{rule},
			judgeAll: true,
			askDec: intercept.Decision{
				Action:   "deny",
				RuleName: rule.name + "·判官不确定",
				Message:  "[自主] 判官无法确定该操作，按规则的超时策略「拦截」直接执行",
			},
			askOK: true,
		}
		g := newFakeGuard(f)
		blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "mcp__fs__write", ev)
		if !blocked {
			t.Fatal("自主落定的 deny 必须拦截")
		}
		if !strings.Contains(msg, "[自主]") {
			t.Fatalf("拦截消息应保留 [自主] 留痕，得到 %q", msg)
		}
		if f.handleAskCalls != 0 {
			t.Fatalf("自主落定不得进人工审批，实际 %d 次", f.handleAskCalls)
		}
	})
}

// MatchToolName 只跑 tool_name 规则（纯记录类工具用；判据与 Match 同源）。
func (f *fakeEngine) MatchToolName(tool string) (intercept.Decision, bool) {
	for _, r := range f.rules {
		if r.target != "tool_name" {
			continue
		}
		if strings.Contains(tool, r.pattern) {
			return intercept.Decision{
				RuleName: r.name,
				Action:   r.action,
				Message:  "[规则] " + r.name + " 命中",
			}, true
		}
	}
	return intercept.Decision{}, false
}
