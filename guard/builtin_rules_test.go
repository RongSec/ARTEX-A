package guard

import "testing"

// V9-UI：管理页「内置规则」区块的数据源。守住三件事：
//  1. 要求的三条规则（控制面 / 平台凭据 / 外部任务资产范围）必须在目录里；
//  2. name 必须与真实判定用的 RuleName 常量一致（否则页面与审计链对不上）；
//  3. 全部为 deny —— 目录只展示无人工放行路径的硬拦项。
func TestBuiltinRulesCoverHardDenyRules(t *testing.T) {
	rules := BuiltinRules()
	if len(rules) == 0 {
		t.Fatal("内置规则目录不能为空")
	}
	byKey := map[string]BuiltinRule{}
	for _, r := range rules {
		if r.Key == "" || r.Name == "" || r.Description == "" {
			t.Fatalf("内置规则字段不完整: %+v", r)
		}
		if r.Action != "deny" {
			t.Fatalf("%s 的动作应为 deny，得到 %q", r.Key, r.Action)
		}
		if _, dup := byKey[r.Key]; dup {
			t.Fatalf("内置规则 key 重复: %s", r.Key)
		}
		byKey[r.Key] = r
	}

	want := map[string]string{
		"platform_control_plane": builtinControlPlaneRuleName,
		"platform_credentials":   builtinPlatformCredRuleName,
		"foreign_task_assets":    builtinForeignScopeRuleName,
	}
	for key, name := range want {
		r, ok := byKey[key]
		if !ok {
			t.Fatalf("内置规则目录缺少 %s", key)
		}
		if r.Name != name {
			t.Fatalf("%s 的名称 %q 与判定常量 %q 不一致", key, r.Name, name)
		}
	}
}

// 前缀约定：db.interceptSource 靠 "[代码常量]"/"[代码内置]" 识别来源。
func TestBuiltinRuleNamesKeepSourcePrefix(t *testing.T) {
	for _, r := range BuiltinRules() {
		if !hasBuiltinPrefix(r.Name) {
			t.Fatalf("%s 的 RuleName %q 缺少来源前缀", r.Key, r.Name)
		}
	}
}

func hasBuiltinPrefix(name string) bool {
	for _, p := range []string{"[代码常量]", "[代码内置]"} {
		if len(name) >= len(p) && name[:len(p)] == p {
			return true
		}
	}
	return false
}
