package intercept

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// ============================================================================
// V5-B2：工具外部性分类（决定「白名单外的哪些工具要送判官」）。
// 纯函数部分无库可测；查表部分需要 PG，无库跳过。
// ============================================================================

// tools.kind → 是否送判官：builtin 不判，command/script/http 判，未知 kind 判。
func TestToolKindExternal(t *testing.T) {
	cases := []struct {
		kind string
		want bool
	}{
		{"builtin", false},
		{"", false}, // 老行/未写 kind：按内置处理
		{"command", true},
		{"script", true},
		{"http", true},
		{"weird", true}, // 未知 kind：fail-safe
	}
	for _, c := range cases {
		if got := toolKindExternal(c.kind); got != c.want {
			t.Fatalf("kind=%q：want %t got %t", c.kind, c.want, got)
		}
	}
}

// 没有库时一律按外部处理（fail-safe 送判）；空工具名交给总闸，不查库。
func TestIsToolExternalWithoutDB(t *testing.T) {
	ic := New(nil)
	if !ic.IsToolExternal("record_fact") {
		t.Fatal("无库时应 fail-safe 送判")
	}
	if !ic.IsToolExternal("mcp__foo__bar") {
		t.Fatal("无库时 MCP 工具应送判")
	}
	if ic.IsToolExternal("") {
		t.Fatal("空工具名不应被判为外部工具")
	}
	var nilIC *Interceptor
	if !nilIC.IsToolExternal("record_fact") {
		t.Fatal("nil Interceptor 应 fail-safe 送判")
	}
}

// 查表分类 + 60s 缓存 + Invalidate 清空（需要 PG，无库跳过）。
func TestIsToolExternalFromCatalogAndCache(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ic := New(d)

	const cmdTool, builtinTool, absentTool = "v5b2_probe_cmd", "v5b2_probe_builtin", "v5b2_probe_absent"
	mk := func(key, kind string) {
		t.Helper()
		if err := d.CreateCustomTool(&db.Tool{
			Key: key, Kind: kind, Enabled: true,
			Description: "v5b2 测试工具", Schema: json.RawMessage(`{}`),
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.DeleteCustomTool(key) })
	}
	_ = d.DeleteCustomTool(cmdTool)     // 上一轮残留
	_ = d.DeleteCustomTool(builtinTool) // 上一轮残留
	mk(cmdTool, "command")
	mk(builtinTool, "builtin")
	t.Cleanup(ic.Invalidate)

	if !ic.IsToolExternal(cmdTool) {
		t.Fatal("kind=command 的自定义工具必须送判官")
	}
	if ic.IsToolExternal(builtinTool) {
		t.Fatal("kind=builtin 的工具不应送判官")
	}
	if !ic.IsToolExternal(absentTool) {
		t.Fatal("tools 表里没有的工具名应 fail-safe 送判")
	}
	if !ic.IsToolExternal("mcp__foo__bar") {
		t.Fatal("mcp__ 前缀工具必须送判官")
	}

	// 缓存：改库后 60s 内仍用旧结论；Invalidate 后立刻生效。
	if err := d.UpdateCustomTool(&db.Tool{
		Key: cmdTool, Kind: "builtin", Enabled: true,
		Description: "v5b2 测试工具", Schema: json.RawMessage(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	if !ic.IsToolExternal(cmdTool) {
		t.Fatal("TTL 内应复用缓存结论")
	}
	ic.Invalidate()
	if ic.IsToolExternal(cmdTool) {
		t.Fatal("Invalidate 后应重新查表（已改为 builtin，不再送判）")
	}
}
