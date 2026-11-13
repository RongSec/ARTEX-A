package guard

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
)

// ============================================================================
// V5-B2：白名单外的判官面收敛 —— 只有「能执行代码 / 影响外部系统」的工具才
// 送判官，平台内置工具（record_fact / graph_overview / list_tasks …）不送。
//
// 分类器来自 intercept.IsToolExternal（查 tools 表 kind），这里用 externalProbe
// 注入假分类器，把路由矩阵在无库环境里钉死；真实分类语义见
// intercept/tool_external_test.go。
// ============================================================================

// builtinProbe 模仿线上 tools 表：这三个 key 是 kind=builtin，其余（含 mcp__
// 与未知名字、自定义 command 工具）都不是内置。
func builtinProbe(name string) bool {
	switch name {
	case "record_fact", "graph_overview", "list_tasks":
		return false
	}
	return true
}

// 内置平台工具一次都不许送判官 —— 这是本次修复的成本目标。
func TestBuiltinPlatformToolsNeverReachJudge(t *testing.T) {
	g := New()
	g.externalProbe = builtinProbe
	calls := 0
	judge := func(context.Context, string, json.RawMessage) (intercept.Decision, bool) {
		calls++
		return intercept.Decision{Action: "deny", Message: "不该被调用"}, true
	}
	for _, tool := range []string{"record_fact", "graph_overview", "list_tasks"} {
		ev := hook.Event{ToolName: tool, Input: json.RawMessage(`{"task_id":"t1"}`)}
		res := g.judgeOutsideWhitelist(context.Background(), ev, true, judge)
		if res.Decision != "" {
			t.Fatalf("内置工具 %s 不应被判官拦截，得到 %+v", tool, res)
		}
	}
	if calls != 0 {
		t.Fatalf("内置工具不得送判官，实际调用 %d 次", calls)
	}
	if g.judgeCache.len() != 0 {
		t.Fatalf("内置工具不应产生判官缓存，len=%d", g.judgeCache.len())
	}
}

// MCP / 未知工具名 / 自定义 command 工具：仍必须送判官（V5-B 的安全面不变）。
func TestExternalToolsStillReachJudge(t *testing.T) {
	cases := []struct {
		desc string
		tool string
	}{
		{"MCP 工具", "mcp__foo__bar"},
		{"未知工具名", "weird_tool"},
		{"自定义 command 工具", "my_custom_scan"},
	}
	for _, c := range cases {
		g := New()
		g.externalProbe = builtinProbe
		called := false
		judge := func(context.Context, string, json.RawMessage) (intercept.Decision, bool) {
			called = true
			return intercept.Decision{Action: "allow", Message: "只读"}, true
		}
		ev := hook.Event{ToolName: c.tool, Input: json.RawMessage(`{"x":1}`)}
		if res := g.judgeOutsideWhitelist(context.Background(), ev, true, judge); res.Decision != "" {
			t.Fatalf("%s：判官 allow 不应阻塞，得到 %+v", c.desc, res)
		}
		if !called {
			t.Fatalf("%s（%s）必须送判官", c.desc, c.tool)
		}
	}
}

// 开关 intercept_judge_all_tools=false：内置与外部工具全部不进判官（退回旧行为）。
func TestJudgeAllToolsSwitchOffSkipsEverything(t *testing.T) {
	g := New()
	g.externalProbe = builtinProbe
	calls := 0
	judge := func(context.Context, string, json.RawMessage) (intercept.Decision, bool) {
		calls++
		return intercept.Decision{Action: "deny", Message: "不该被调用"}, true
	}
	for _, tool := range []string{"mcp__foo__bar", "weird_tool", "my_custom_scan", "record_fact"} {
		ev := hook.Event{ToolName: tool, Input: json.RawMessage(`{}`)}
		if res := g.judgeOutsideWhitelist(context.Background(), ev, false, judge); res.Decision != "" {
			t.Fatalf("开关关闭时 %s 应放行，得到 %+v", tool, res)
		}
	}
	if calls != 0 {
		t.Fatalf("开关关闭时不得送判官，实际 %d 次", calls)
	}
}

// 无 interceptor 且未注入分类器：没有分类信息，fail-safe 送判（不能凭沉默放行）。
func TestToolIsExternalFailsSafeWithoutInterceptor(t *testing.T) {
	g := New()
	if !g.toolIsExternal("record_fact") {
		t.Fatal("无分类信息时应按外部工具处理（fail-safe 送判）")
	}
}

// 注入的分类器优先于 interceptor（测试缝本身的行为）。
func TestToolIsExternalPrefersProbe(t *testing.T) {
	g := New()
	g.externalProbe = func(string) bool { return false }
	if g.toolIsExternal("mcp__foo__bar") {
		t.Fatal("注入的分类器应生效")
	}
}
