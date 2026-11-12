package agent

import (
	"context"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// V4 安全面：tool_base='none' 的只读型 agent（observer/reader）在 ChatAgent
// 装配时剥离 SDK DefaultTools 执行底座（实网 reader conv#60 用继承的 Bash 21 次
// 直连 psql 越权侦查）。以下纯函数测无库可跑，守住两层不变式：
//  1. chatBaseTools 按 resolver 结果决定底座有无；
//  2. 剥离后 AugmentTools 仍保留绑定域工具（extras 直通），且列表里没有
//     Bash/Read/Write/Edit/LS/Glob/Grep；default 路径逐字节等价于旧行为。

// stubToolBase swaps the resolver for the test duration and restores it.
func stubToolBase(t *testing.T, m map[string]string) {
	t.Helper()
	old := ToolBaseResolver
	ToolBaseResolver = func(key string) string { return m[key] }
	t.Cleanup(func() { ToolBaseResolver = old })
}

func toolNamesList(ts []actool.CoreTool) []string {
	out := make([]string, 0, len(ts))
	for _, x := range ts {
		out = append(out, x.Name())
	}
	return out
}

// TestChatBaseToolsStripsDefaultBase：none → nil 底座；default/未知值/nil
// resolver → 完整 DefaultTools。
func TestChatBaseToolsStripsDefaultBase(t *testing.T) {
	stubToolBase(t, map[string]string{"observer": "none", "reader": "none", "worker": "default"})

	if got := chatBaseTools("observer"); got != nil {
		t.Errorf("observer(none) 底座应为 nil，实得 %v", toolNamesList(got))
	}
	if got := chatBaseTools("reader"); got != nil {
		t.Errorf("reader(none) 底座应为 nil，实得 %v", toolNamesList(got))
	}
	// worker 即使在 resolver 存在时也拿到完整底座（不误伤执行型 agent）。
	worker := chatBaseTools("worker")
	want := actool.DefaultTools()
	if len(worker) != len(want) {
		t.Fatalf("worker(default) 底座数量 = %d，期望 %d", len(worker), len(want))
	}
	for i, wt := range want {
		if worker[i].Name() != wt.Name() {
			t.Errorf("worker 底座第 %d 个 = %s，期望 %s（顺序/内容须与 DefaultTools 一致）", i, worker[i].Name(), wt.Name())
		}
	}
	// 未知 key / resolver 返回脏值 → default（fail-open，绝不误剥）。
	if got := chatBaseTools("pentest"); len(got) != len(want) {
		t.Errorf("未注册 agent 应拿到底座（fail-open），实得 %d 个", len(got))
	}
	stubToolBase(t, map[string]string{"x": "garbage"})
	if got := chatBaseTools("x"); len(got) != len(want) {
		t.Errorf("resolver 返回非法值应回落 default 底座，实得 %d 个", len(got))
	}
	old := ToolBaseResolver
	ToolBaseResolver = nil
	t.Cleanup(func() { ToolBaseResolver = old })
	if got := chatBaseTools("observer"); len(got) != len(want) {
		t.Errorf("nil resolver（未接线）应保持旧行为注入底座，实得 %d 个", len(got))
	}
}

// TestAugmentToolsNoneBaseKeepsBoundDomainTools：模拟 ChatAgent 对 none agent 的
// 完整装配链——base=nil、ToolAugment 提供绑定域工具（observer 六工具的宿主实例
// 经此路径进来）、ToolResolve 按 DB 绑定过滤——断言最终列表无执行底座工具、有绑
// 定域工具。ToolAugment/ToolResolve 用桩替换（server 层真实 wiring 由库测覆盖）。
func TestAugmentToolsNoneBaseKeepsBoundDomainTools(t *testing.T) {
	stubToolBase(t, map[string]string{"reader": "none"})
	oldAug, oldRes := ToolAugment, ToolResolve
	t.Cleanup(func() { ToolAugment, ToolResolve = oldAug, oldRes })
	ToolAugment = func(context.Context, string) ([]actool.CoreTool, DeferredInfo, func()) {
		return []actool.CoreTool{actool.NewRead()}, DeferredInfo{}, nil // 桩"绑定域工具"用 Read 实例占位
	}
	ToolResolve = func(_ context.Context, _ string, tools []actool.CoreTool) []actool.CoreTool {
		return tools
	}

	out, _, cleanup := AugmentTools(context.Background(), "reader", chatBaseTools("reader"))
	cleanup()
	names := map[string]bool{}
	for _, x := range out {
		names[x.Name()] = true
	}
	if !names["Read"] {
		t.Errorf("none agent 的绑定域工具丢失，最终列表 %v", toolNamesList(out))
	}
	for _, banned := range []string{"Bash", "Write", "Edit", "Glob", "Grep", "LS"} {
		if names[banned] {
			t.Errorf("none agent 混入执行底座工具 %s", banned)
		}
	}

	// 对照：default agent 同链路应拿到含 Bash 的完整底座。
	out2, _, cleanup2 := AugmentTools(context.Background(), "pentest", chatBaseTools("pentest"))
	cleanup2()
	names2 := map[string]bool{}
	for _, x := range out2 {
		names2[x.Name()] = true
	}
	if !names2["Bash"] {
		t.Errorf("default agent 丢失 Bash 底座（行为回归）")
	}
}
