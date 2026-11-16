package guard

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/intercept"
)

// V9-SCOPE：内置外部资产范围规则。三个分支 + host 解析口径。
//
// 背景：阅读者把被勾连任务的图（含资产）以 hint 暴露给发起方规划者后，规划者
// 可能直接对对方资产发起攻击。规则在 PreToolUse 最前面拦：host 命中
// task_foreign_assets 且不在本任务 assets 里 → deny；本任务自己的资产放行。

type scopeStub struct {
	foreign []string
	own     []string
	err     error
}

func (s scopeStub) ForeignHosts(context.Context, int64) ([]string, error) {
	return s.foreign, s.err
}
func (s scopeStub) OwnHosts(context.Context, int64) ([]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.own, nil
}

// logCapture 记录内置规则写进审计链的 Decision。
type logCapture struct {
	*fakeEngine
	logged []intercept.Decision
}

func (l *logCapture) Log(_ context.Context, _ int64, dec intercept.Decision, _ string, _ []byte, status string) {
	l.logged = append(l.logged, dec)
}

func scopeGuard(scope ScopeResolver) (*Guard, *logCapture) {
	cap := &logCapture{fakeEngine: &fakeEngine{enabled: map[string]bool{"Bash": true}}}
	g := New()
	g.interceptor = cap
	g.SetScopeResolver(scope)
	return g, cap
}

func taskCtx(id string) context.Context {
	return intercept.WithTaskContext(context.Background(), id, "worker", nil)
}

// 内置规则先于 DB 规则：即使 DB 规则显式 allow，外部资产仍 deny，且不再送判官。
func TestForeignScopePrecedesDBRules(t *testing.T) {
	cap := &logCapture{fakeEngine: &fakeEngine{
		enabled: map[string]bool{"Bash": true},
		rules: []fakeRule{{
			name: "[内置] 允许只读 curl", target: "tool_input", pattern: "curl", action: "allow",
		}},
		judgeAll: true, judgeDec: intercept.Decision{Action: "allow"}, judgeOK: true,
	}}
	g := New()
	g.interceptor = cap
	g.SetScopeResolver(scopeStub{foreign: []string{"10.0.0.9"}})
	blocked, msg, _ := g.Hooks().PreToolUse(taskCtx("100"), "Bash",
		json.RawMessage(`{"command":"curl http://10.0.0.9/x"}`))
	if !blocked {
		t.Fatalf("DB 规则 allow 不得翻过内置外部资产红线: %s", msg)
	}
	if cap.judgeCalls != 0 || cap.askCalls != 0 {
		t.Fatalf("内置 deny 后不得再送判官/交裁: judge=%d ask=%d", cap.judgeCalls, cap.askCalls)
	}
}

// 规划者专用 scope-only 模式：只跑外部资产范围，DB 规则/判官保持原行为（不接入），
// 避免 add_intent 正文被规则误拦；同时外部资产仍然 deny。
func TestForeignScopeScopeOnly(t *testing.T) {
	cap := &logCapture{fakeEngine: &fakeEngine{
		enabled:  map[string]bool{"Bash": true},
		rules:    []fakeRule{{name: "[内置] 任意命令", target: "tool_input", pattern: ".", action: "deny"}},
		judgeAll: true, judgeDec: intercept.Decision{Action: "deny"}, judgeOK: true,
	}}
	g := New()
	g.interceptor = cap
	g.SetScopeResolver(scopeStub{foreign: []string{"10.0.0.9"}})
	g.SetScopeOnly(true)

	if blocked, msg, _ := g.Hooks().PreToolUse(taskCtx("100"), "Bash",
		json.RawMessage(`{"command":"curl http://10.0.0.9/x"}`)); !blocked {
		t.Fatalf("scope-only 仍必须拦外部资产: %s", msg)
	}
	if blocked, msg, _ := g.Hooks().PreToolUse(taskCtx("100"), "Bash",
		json.RawMessage(`{"command":"ls -la"}`)); blocked {
		t.Fatalf("scope-only 不应触发 DB 规则: %s", msg)
	}
}

// 分支 A：采纳了任务 B（B 的 host=10.0.0.9），对本任务没有的 10.0.0.9 发起
// curl → 必须 deny，且消息含「不在本任务授权范围」。
func TestForeignScopeDeniesAdoptedHost(t *testing.T) {
	g, cap := scopeGuard(scopeStub{foreign: []string{"10.0.0.9"}})
	blocked, msg, _ := g.Hooks().PreToolUse(taskCtx("100"), "Bash",
		json.RawMessage(`{"command":"curl http://10.0.0.9/x"}`))
	if !blocked {
		t.Fatal("外部任务资产必须被拦截")
	}
	if !strings.Contains(msg, "不在本任务授权范围") {
		t.Fatalf("拦截消息必须说明授权范围，got %q", msg)
	}
	if len(cap.logged) != 1 || cap.logged[0].RuleName != foreignScopeRuleName {
		t.Fatalf("必须按内置规则留痕，got %+v", cap.logged)
	}
}

// 分支 B：同一任务对自己的资产 127.0.0.1:9081 执行同样命令 → allow（不误伤）。
// 即使该 host 同时出现在外部清单里，本任务 assets 优先放行。
func TestForeignScopeAllowsOwnAsset(t *testing.T) {
	cases := []struct {
		name  string
		scope scopeStub
	}{
		{"外部清单不含本机", scopeStub{foreign: []string{"10.0.0.9"}, own: []string{"127.0.0.1"}}},
		{"外部清单也含本机（own 优先）", scopeStub{foreign: []string{"10.0.0.9", "127.0.0.1"}, own: []string{"127.0.0.1"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, _ := scopeGuard(c.scope)
			blocked, msg, _ := g.Hooks().PreToolUse(taskCtx("100"), "Bash",
				json.RawMessage(`{"command":"curl http://127.0.0.1:9081/x"}`))
			if blocked {
				t.Fatalf("本任务已有资产不得拦截: %s", msg)
			}
		})
	}
}

// 分支 C：任务未采纳任何任务 → 任意 host 不受影响（回归）。
func TestForeignScopeNoAdoptionAllowsAnyHost(t *testing.T) {
	g, _ := scopeGuard(scopeStub{})
	blocked, msg, _ := g.Hooks().PreToolUse(taskCtx("100"), "Bash",
		json.RawMessage(`{"command":"curl http://203.0.113.7/x"}`))
	if blocked {
		t.Fatalf("未采纳任务不应拦任何 host: %s", msg)
	}
}

// 登记资产是本规则的合法出口：add_task_scope 里的外部 host 不得被拦。
func TestForeignScopeAllowsAssetRegistration(t *testing.T) {
	g, _ := scopeGuard(scopeStub{foreign: []string{"10.0.0.9"}})
	blocked, msg, _ := g.Hooks().PreToolUse(taskCtx("100"), "add_task_scope",
		json.RawMessage(`{"scope":[{"kind":"ip","value":"10.0.0.9"}]}`))
	if blocked {
		t.Fatalf("登记资产必须先放行（否则无法走合法出口）: %s", msg)
	}
}

// 解析失败 / 查库失败 → 宁漏不误伤：放行。
func TestForeignScopeFailsOpen(t *testing.T) {
	g, _ := scopeGuard(scopeStub{foreign: []string{"10.0.0.9"}, err: errors.New("db down")})
	if blocked, msg, _ := g.Hooks().PreToolUse(taskCtx("100"), "Bash",
		json.RawMessage(`{"command":"curl http://10.0.0.9/x"}`)); blocked {
		t.Fatalf("查库失败应放行（宁漏不误伤）: %s", msg)
	}
	g2, _ := scopeGuard(scopeStub{foreign: []string{"10.0.0.9"}})
	if blocked, msg, _ := g2.Hooks().PreToolUse(taskCtx("100"), "Bash",
		json.RawMessage(`{"command":"ls -la /tmp"}`)); blocked {
		t.Fatalf("解析不出 host 应放行: %s", msg)
	}
	// 不在任务上下文（普通聊天）时不匹配任何任务的外部清单。
	if blocked, msg, _ := g2.Hooks().PreToolUse(context.Background(), "Bash",
		json.RawMessage(`{"command":"curl http://10.0.0.9/x"}`)); blocked {
		t.Fatalf("无任务上下文应放行: %s", msg)
	}
}

// Host 解析口径：URL、host:port、裸 IP、IPv6、端口省略。
func TestHostsInToolInput(t *testing.T) {
	cases := []struct {
		name  string
		tool  string
		input string
		want  []string
	}{
		{"URL", "Bash", `{"command":"curl http://10.0.0.9/x"}`, []string{"10.0.0.9"}},
		{"URL 带端口", "Bash", `{"command":"curl -sS http://10.0.0.9:8080/x -o /tmp/a"}`, []string{"10.0.0.9"}},
		{"host:port", "Bash", `{"command":"nc -vz 10.0.0.9:8080"}`, []string{"10.0.0.9"}},
		{"裸 IP", "Bash", `{"command":"ping -c1 10.0.0.9"}`, []string{"10.0.0.9"}},
		{"IPv6 URL", "Bash", `{"command":"curl http://[2001:db8::1]:8080/x"}`, []string{"2001:db8::1"}},
		{"IPv6 裸地址", "Bash", `{"command":"ping6 2001:db8::1"}`, []string{"2001:db8::1"}},
		{"域名 URL（端口省略）", "Bash", `{"command":"curl https://app.example.com/x"}`, []string{"app.example.com"}},
		{"域名 host:port", "Bash", `{"command":"curl app.example.com:8443/x"}`, []string{"app.example.com"}},
		{"HTTP 工具 url 字段", "WebFetch", `{"url":"http://10.0.0.9:8080/x"}`, []string{"10.0.0.9"}},
		{"MCP target 字段", "mcp__scan__run", `{"target":"10.0.0.9","port":80}`, []string{"10.0.0.9"}},
		{"MCP targets 数组", "mcp__scan__run", `{"targets":["10.0.0.9","app.example.com"]}`, []string{"10.0.0.9", "app.example.com"}},
		{"MCP host 字段裸域名", "mcp__scan__run", `{"host":"example.com"}`, []string{"example.com"}},
		{"MCP 嵌套 url", "mcp__scan__run", `{"request":{"url":"https://api.example.com/x"}}`, []string{"api.example.com"}},
		{"无 host", "Bash", `{"command":"ls -la /tmp/a.txt"}`, nil},
		{"空命令", "Bash", `{"command":""}`, nil},
		// 平台工具正文里引用地址不是「要发起请求」：不得误拦写意图/写 hint。
		{"add_intent 文本里的 URL", "add_intent", `{"summary":"验证 http://10.0.0.9/x 的越权"}`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hostsInToolInput(c.tool, json.RawMessage(c.input))
			if len(got) != len(c.want) {
				t.Fatalf("got %v want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("got %v want %v", got, c.want)
				}
			}
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"10.0.0.9":            "10.0.0.9",
		"10.0.0.9:8080":       "10.0.0.9",
		"APP.Example.COM":     "app.example.com",
		"app.example.com:443": "app.example.com",
		"[2001:db8::1]:8443":  "2001:db8::1",
		"2001:db8::1":         "2001:db8::1",
		"http://10.0.0.9/x":   "10.0.0.9",
		"/tmp/a.txt":          "",
		"":                    "",
	}
	for in, want := range cases {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q)=%q want %q", in, got, want)
		}
	}
}
