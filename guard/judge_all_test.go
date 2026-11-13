package guard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
)

// ============================================================================
// V5-B：白名单外工具（MCP / 自定义工具）不再直接放行，必须过判官。
//
// 路由本体接 enabled + judge 两个入参（见 judgeOutsideWhitelist），所以这组
// 用例不需要数据库：假判官在 Judge 这一层注入，等价于 SetReviewer 的假
// reviewer（后者要过 judgeConfig 的 DB 读，故在 intercept 侧测）。
// ============================================================================

// 总闸三分支：关掉 → 不判；工具名为空 → 不判；开启且有工具名 → 判。
func TestShouldJudgeBeyondWhitelistThreeBranches(t *testing.T) {
	cases := []struct {
		desc    string
		enabled bool
		tool    string
		want    bool
	}{
		{"开关关闭退回旧行为", false, "mcp__fs__read_file", false},
		{"开启但事件无工具名", true, "", false},
		{"开启且有工具名", true, "mcp__fs__read_file", true},
	}
	for _, c := range cases {
		if got := shouldJudgeBeyondWhitelist(c.enabled, c.tool); got != c.want {
			t.Fatalf("%s：want %t got %t", c.desc, c.want, got)
		}
	}
}

// 只缓存模型真实给出的 allow/deny；ask 与 fail_action 兜底结论不缓存
// （否则一次瞬时故障会在 TTL 内持续拦截/放行）。
func TestCacheableJudgeVerdict(t *testing.T) {
	cacheable := []intercept.Decision{{Action: "allow"}, {Action: "deny"}}
	uncacheable := []intercept.Decision{
		{Action: "ask"},
		{Action: "allow", ModelFallback: true},
		{Action: "deny", ModelFallback: true},
		{},
	}
	for _, d := range cacheable {
		if !cacheableJudgeVerdict(d) {
			t.Fatalf("%+v 应可缓存", d)
		}
	}
	for _, d := range uncacheable {
		if cacheableJudgeVerdict(d) {
			t.Fatalf("%+v 不应缓存", d)
		}
	}
}

// 缓存：命中 / 过期 / LRU 淘汰。时钟注入，不用 sleep。
func TestJudgeVerdictCacheHitExpiryAndLRU(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := newJudgeVerdictCache(func() time.Time { return now }, 5*time.Minute, 2)
	allow := intercept.Decision{Action: "allow", Message: "只读"}
	deny := intercept.Decision{Action: "deny", Message: "删生产文件"}

	c.put("a", allow)
	if got, ok := c.get("a"); !ok || got.Action != "allow" {
		t.Fatalf("刚写入应命中，得到 %+v ok=%v", got, ok)
	}
	now = now.Add(4*time.Minute + 59*time.Second)
	if _, ok := c.get("a"); !ok {
		t.Fatal("TTL 内应命中")
	}
	now = now.Add(2 * time.Second)
	if _, ok := c.get("a"); ok {
		t.Fatal("超过 TTL 应失效")
	}
	if c.len() != 0 {
		t.Fatalf("过期项应被清除，len=%d", c.len())
	}

	// LRU：容量 2，a 被 get 触达后写 c，最久未用的 b 应被淘汰。
	c.put("a", allow)
	c.put("b", deny)
	if _, ok := c.get("a"); !ok {
		t.Fatal("a 应命中")
	}
	c.put("c", allow)
	if c.len() != 2 {
		t.Fatalf("容量上限应为 2，len=%d", c.len())
	}
	if _, ok := c.get("b"); ok {
		t.Fatal("最久未用的 b 应被 LRU 淘汰")
	}
	if _, ok := c.get("a"); !ok {
		t.Fatal("刚被触达的 a 不应被淘汰")
	}
	if _, ok := c.get("c"); !ok {
		t.Fatal("新写入的 c 应命中")
	}
}

// 白名单外 + 判官 deny：判官被调用、调用被拦、消息带平台管控框架。
// 第二次相同调用命中缓存：不再调模型，但结论照旧生效。
func TestJudgeOutsideWhitelistDenyBlocksAndCaches(t *testing.T) {
	g := New() // 无 interceptor：本用例只验证路由与拦截结果
	calls := 0
	judge := func(context.Context, string, json.RawMessage) (intercept.Decision, bool) {
		calls++
		return intercept.Decision{Action: "deny", Message: "会外传凭据"}, true
	}
	ev := hook.Event{ToolName: "mcp__fs__read_file", Input: json.RawMessage(`{"path":"/etc/shadow"}`)}
	ctx := intercept.WithTaskContext(context.Background(), "judge-all-deny", "agent-a", nil)

	res := g.judgeOutsideWhitelist(ctx, ev, true, judge)
	if res.Decision != "block" {
		t.Fatalf("判官 deny 必须拦截，得到 %+v", res)
	}
	if !strings.Contains(res.Message, "【ARTEX 平台管控·非目标防御】") || !strings.Contains(res.Message, "会外传凭据") {
		t.Fatalf("拦截消息应带平台管控框架与模型理由，得到 %q", res.Message)
	}
	res = g.judgeOutsideWhitelist(ctx, ev, true, judge)
	if res.Decision != "block" {
		t.Fatalf("缓存命中也要拦截，得到 %+v", res)
	}
	if calls != 1 {
		t.Fatalf("同一会话相同调用应复用判官结论，判官被调用 %d 次", calls)
	}
}

// 白名单外 + 判官 allow：放行（不阻塞），判官确实被调用。
func TestJudgeOutsideWhitelistAllowPasses(t *testing.T) {
	g := New()
	called := false
	judge := func(context.Context, string, json.RawMessage) (intercept.Decision, bool) {
		called = true
		return intercept.Decision{Action: "allow", Message: "只读"}, true
	}
	ev := hook.Event{ToolName: "mcp__fs__list", Input: json.RawMessage(`{"path":"/tmp"}`)}
	res := g.judgeOutsideWhitelist(intercept.WithConvID(context.Background(), 42), ev, true, judge)
	if res.Decision != "" {
		t.Fatalf("allow 不应阻塞，得到 %+v", res)
	}
	if !called {
		t.Fatal("白名单外必须送判官")
	}
}

// intercept_judge_all_tools=false：退回旧行为——不送判官、直接放行。
func TestJudgeOutsideWhitelistSwitchOffAllows(t *testing.T) {
	g := New()
	called := false
	judge := func(context.Context, string, json.RawMessage) (intercept.Decision, bool) {
		called = true
		return intercept.Decision{Action: "deny", Message: "不该被调用"}, true
	}
	ev := hook.Event{ToolName: "mcp__fs__read_file", Input: json.RawMessage(`{"path":"/etc/shadow"}`)}
	if res := g.judgeOutsideWhitelist(context.Background(), ev, false, judge); res.Decision != "" {
		t.Fatalf("开关关闭时应放行，得到 %+v", res)
	}
	if called {
		t.Fatal("开关关闭时不得送判官")
	}
}

// 判官未开启/未接线（judged=false）：保持改动前的放行语义，且不写缓存。
func TestJudgeOutsideWhitelistJudgeUnavailableAllows(t *testing.T) {
	g := New()
	judge := func(context.Context, string, json.RawMessage) (intercept.Decision, bool) {
		return intercept.Decision{}, false
	}
	ev := hook.Event{ToolName: "mcp__x", Input: json.RawMessage(`{}`)}
	if res := g.judgeOutsideWhitelist(context.Background(), ev, true, judge); res.Decision != "" {
		t.Fatalf("判官不可用时保持放行，得到 %+v", res)
	}
	if g.judgeCache.len() != 0 {
		t.Fatal("判官未给结论时不得写缓存")
	}
}

// 会话隔离：不同会话的相同 (tool, input) 不共享缓存。
func TestJudgeOutsideWhitelistCacheIsSessionScoped(t *testing.T) {
	g := New()
	calls := 0
	judge := func(context.Context, string, json.RawMessage) (intercept.Decision, bool) {
		calls++
		return intercept.Decision{Action: "allow", Message: "只读"}, true
	}
	ev := hook.Event{ToolName: "mcp__fs__list", Input: json.RawMessage(`{"path":"/tmp"}`)}
	g.judgeOutsideWhitelist(intercept.WithConvID(context.Background(), 1), ev, true, judge)
	g.judgeOutsideWhitelist(intercept.WithConvID(context.Background(), 2), ev, true, judge)
	if calls != 2 {
		t.Fatalf("跨会话应各判一次，判官被调用 %d 次", calls)
	}
}

// ============================================================================
// DB 版（无库跳过）：真实 interceptor 接线下的生产路径 —— 白名单外送判官、
// 开关关闭不送、白名单内路径行为不变。judgeConfig 读设置需要库，故仅在库就绪
// 时执行；无库环境由上面的 enabled/judge 注入版覆盖。
// ============================================================================

func TestWiredJudgeOutsideWhitelist(t *testing.T) {
	d := openRouteTestDB(t)
	defer d.Close()
	ic := intercept.New(d)
	priorTools, err := ic.GetEnabledTools()
	if err != nil {
		t.Fatal(err)
	}
	priorCfg := ic.GetJudgeConfig()
	priorAll := ic.JudgeAllToolsEnabled()
	t.Cleanup(func() {
		_ = ic.SetEnabledTools(priorTools)
		_ = ic.SetJudgeConfig(priorCfg)
		_ = d.SetBool(intercept.SettingJudgeAllTools, priorAll)
	})
	if err := ic.SetEnabledTools([]string{"Bash"}); err != nil {
		t.Fatal(err)
	}
	if err := ic.SetJudgeConfig(intercept.JudgeConfig{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	ic.SetReviewer(func(context.Context, int64, string, intercept.ReviewInput) (intercept.Decision, error) {
		calls++
		return intercept.Decision{Action: "allow", Message: "只读"}, nil
	})
	g := NewWithInterceptor(ic)
	ev := hook.Event{ToolName: "mcp__probe__read", Input: json.RawMessage(`{"path":"/tmp/x"}`)}

	if err := d.SetBool(intercept.SettingJudgeAllTools, true); err != nil {
		t.Fatal(err)
	}
	if res := g.judgeOutsideWhitelist(context.Background(), ev, ic.JudgeAllToolsEnabled(), ic.Judge); res.Decision != "" {
		t.Fatalf("判官 allow 应放行，得到 %+v", res)
	}
	if calls != 1 {
		t.Fatalf("白名单外应送判官一次，实际 %d", calls)
	}

	// 白名单内路径不受影响：Bash 仍走规则匹配 → 无命中 → 判官。
	calls = 0
	bash := hook.Event{ToolName: "Bash", Input: json.RawMessage(`{"command":"ls"}`)}
	if blocked, _, _ := g.Hooks().PreToolUse(context.Background(), bash.ToolName, bash.Input); blocked {
		t.Fatal("白名单内判官 allow 不应阻塞")
	}
	if calls != 1 {
		t.Fatalf("白名单内无规则命中仍应送判官，实际 %d", calls)
	}

	// 关掉开关：白名单外不再送判官，白名单内照旧。
	if err := d.SetBool(intercept.SettingJudgeAllTools, false); err != nil {
		t.Fatal(err)
	}
	calls = 0
	if res := g.judgeOutsideWhitelist(context.Background(), ev, ic.JudgeAllToolsEnabled(), ic.Judge); res.Decision != "" {
		t.Fatalf("开关关闭应放行，得到 %+v", res)
	}
	if calls != 0 {
		t.Fatalf("开关关闭时不得送判官，实际 %d", calls)
	}
	if blocked, _, _ := g.Hooks().PreToolUse(context.Background(), bash.ToolName, bash.Input); blocked {
		t.Fatal("开关关闭不应影响白名单内路径")
	}
	if calls != 1 {
		t.Fatalf("白名单内仍应送判官一次，实际 %d", calls)
	}
}
