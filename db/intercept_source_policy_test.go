package db

import "testing"

// V6-AUTO：判官自己给不出结论时，按规则超时策略合成的终局 reason 以
// [自主] 开头。它和 [模型] 一样属于「模型参与后的判定」，decision_source
// 必须归 model；规则命中（无前缀）仍归 rule。这条前缀是跨包约定（见
// intercept.autonomousJudgeAskDecision），改了会让审计来源静默失真。
func TestInterceptSourceAutonomousIsModel(t *testing.T) {
	cases := []struct {
		desc   string
		ruleID int64
		reason string
		audits []*InterceptAudit
		want   string
	}{
		{"模型 allow/deny", 0, "[模型] ask 规则[x]交模型裁决：放行", nil, "model"},
		{"自主落定", 0, "[自主] 判官无法确定该操作，按规则的超时策略「拦截」直接执行", nil, "model"},
		{"规则命中（有 RuleID）", 7, "拦截规则 [x] 禁止执行此工具", nil, "rule"},
		{"规则命中（无前缀无 RuleID）", 0, "拦截规则 [x] 禁止执行此工具", nil, "unknown"},
		{"短路表", 0, "", []*InterceptAudit{{RuleName: "[代码常量] 平台低危工具放行"}}, "shortcircuit"},
		{"跨任务资产范围（内置）", 0, "该地址来自其它任务的经验参考，不在本任务授权范围；如确需测试，请先在本任务登记该资产并由人工确认。", []*InterceptAudit{{RuleName: "[代码内置] 外部任务资产范围"}}, "builtin_foreign_scope"},
	}
	for _, c := range cases {
		if got := interceptSource(c.ruleID, c.reason, c.audits); got != c.want {
			t.Fatalf("%s：want %q, got %q", c.desc, c.want, got)
		}
	}
}
