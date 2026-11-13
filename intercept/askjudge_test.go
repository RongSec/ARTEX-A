package intercept

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// ============================================================================
// V4-D 修复1：ask 规则命中且判官开启 → 先送模型判官，人工只兜底。
//
// 实网回归：此前 Judge() 仅在【无任何规则命中】时运行，用户显式配置
// action=ask 的规则命中后不送判官，直接进人工等待（实测 60s timeout deny）
// ——判官开着时这不是预期语义。下面钉住新路由的五个语义面。
// ============================================================================

// askRuleDecision 造一条 matchRule 风格的 ask 命中 Decision（不触库）。
func askRuleDecision() Decision {
	return matchRule(db.InterceptRule{
		ID: 7, Name: "高危命令审批", Action: "ask",
		TimeoutEnabled: true, TimeoutSeconds: 60, TimeoutAction: "deny",
	})
}

// fakeReviewer 返回一个产出固定 verdict 的判官（沿用仓库 agent 侧
// SetReviewer(fake) 的注入范式）。
func fakeReviewer(dec Decision, err error) Reviewer {
	return func(context.Context, int64, string, ReviewInput) (Decision, error) {
		if err != nil {
			return Decision{ProfileID: dec.ProfileID}, err
		}
		return dec, nil
	}
}

// 判官路由的唯一开关是 cfg.Enabled || reviewer==nil（judgeWithConfig 第一行），
// 所以无库注入 fake reviewer 即可完整测这条语义。
func newNoDBJudgeInterceptor(t *testing.T, rv Reviewer) *Interceptor {
	t.Helper()
	i := New(nil)
	i.SetReviewer(rv)
	return i
}

// 测例1：ask 命中 + 判官开启 + 模型 allow → 放行。
// 留痕要求：decision_source=model（reason [模型] 前缀 + RuleID 0，见
// db.interceptSource）、RuleName 带回命中的 ask 规则名、审计携带 ModelInput、
// 超时语义清空（已放行，不该再带 pending 超时）。
func TestJudgeAskVerdictModelAllowPasses(t *testing.T) {
	i := newNoDBJudgeInterceptor(t, fakeReviewer(Decision{Action: "allow", Message: "纯只读，放行"}, nil))
	d, ok := i.judgeWithConfig(context.Background(), JudgeConfig{Enabled: true}, "Bash", json.RawMessage(`{"command":"ls -la"}`))
	if !judgeAskOverridesHuman(d, ok) {
		t.Fatalf("模型 allow 应终结审批，得到 %+v ok=%v", d, ok)
	}
	if d.RuleID != 0 {
		t.Fatalf("模型 verdict 不应携带规则 RuleID（decision_source 靠它归为 model），得到 %d", d.RuleID)
	}
	if !strings.HasPrefix(d.Message, "[模型]") {
		t.Fatalf("留痕 reason 必须以 [模型] 前缀标识来源，得到 %q", d.Message)
	}
	if len(d.ModelInput) == 0 || d.ModelInputDigest == "" || d.ConfigDigest == "" {
		t.Fatalf("模型裁决必须带审计输入/摘要，得到 %+v", d)
	}
	if d.TimeoutEnabled {
		t.Fatalf("放行后不应保留规则超时语义，得到 %+v", d)
	}
}

// 测例2：ask 命中 + 判官开启 + 模型 deny → 拒绝，同样 decision_source=model。
func TestJudgeAskVerdictModelDenyBlocks(t *testing.T) {
	i := newNoDBJudgeInterceptor(t, fakeReviewer(Decision{Action: "deny", Message: "会外传凭据"}, nil))
	d, ok := i.judgeWithConfig(context.Background(), JudgeConfig{Enabled: true}, "Bash", json.RawMessage(`{"command":"ls -la"}`))
	if !judgeAskOverridesHuman(d, ok) {
		t.Fatalf("模型 deny 应终结审批，得到 %+v ok=%v", d, ok)
	}
	if d.Action != "deny" || d.RuleID != 0 || !strings.HasPrefix(d.Message, "[模型]") {
		t.Fatalf("模型 deny 留痕不完整： %+v", d)
	}
}

// 测例3：ask 命中 + 判官报错/超时/不可解析 → 回落人工审批（返回 false）。
// fail-closed 不变：回落由调用方走 HandleAsk（pending + 规则超时→deny）。
// 注意「判官自己给 ask」不在此列：那是判官的真实结论，V6-AUTO 起按策略
// 自主落定（见下方 TestJudgeAskVerdictAutoPolicy*）。
func TestJudgeAskVerdictFaultFallsBackToHuman(t *testing.T) {
	ctx := context.Background()
	ask := askRuleDecision()
	cases := []struct {
		desc string
		rv   Reviewer
	}{
		{"判官报错", fakeReviewer(Decision{}, errors.New("provider unavailable"))},
		{"输出不可解析", fakeReviewer(Decision{Action: "maybe"}, nil)},
	}
	for _, c := range cases {
		i := newNoDBJudgeInterceptor(t, c.rv)
		if d, ok := i.askVerdictWithConfig(ctx, JudgeConfig{Enabled: true, FailAction: "deny"}, ask, "Bash", json.RawMessage(`{"command":"ls"}`)); ok || d.Action != "" {
			t.Fatalf("%s：应回落人工（ok=false 且零值 Decision），得到 %+v ok=%v", c.desc, d, ok)
		}
	}
}

// FailAction 显式配成 allow 时也不得静默放行 ask 规则：判官故障一律交人工。
func TestJudgeAskVerdictFailActionAllowStillGoesToHuman(t *testing.T) {
	i := newNoDBJudgeInterceptor(t, fakeReviewer(Decision{}, errors.New("boom")))
	if d, ok := i.askVerdictWithConfig(context.Background(), JudgeConfig{Enabled: true, FailAction: "allow"}, askRuleDecision(), "Bash", json.RawMessage(`{"command":"ls"}`)); ok || d.Action != "" {
		t.Fatalf("FailAction=allow 也不应让判官故障静默放行，得到 %+v ok=%v", d, ok)
	}
}

// 判官未开启（或 reviewer 未接线）→ 一律回落人工，行为与改动前逐字节一致
// （基线不变，测例4 的 intercept 侧断言）。
func TestJudgeAskVerdictDisabledFallsBackToHuman(t *testing.T) {
	i := New(nil) // reviewer 未接线
	if d, ok := i.askVerdictWithConfig(context.Background(), JudgeConfig{Enabled: true}, askRuleDecision(), "Bash", json.RawMessage(`{"command":"ls"}`)); ok || d.Action != "" {
		t.Fatalf("判官未接线应回落人工，得到 %+v ok=%v", d, ok)
	}
	i.SetReviewer(fakeReviewer(Decision{Action: "allow"}, nil))
	if _, ok := i.judgeWithConfig(context.Background(), JudgeConfig{Enabled: false}, "Bash", json.RawMessage(`{"command":"ls"}`)); ok {
		t.Fatal("判官 enabled=false 时不得交裁")
	}
}

// 测例5（路由面）：deny 命中不送判官、allow 命中照旧 —— 这是 guard 层的
// 路由，不在此文件可达（guard 包），见 guard/askjudge_route_test.go。
// 此处钉住纯函数路由表 judgeAskOverridesHuman 的全语义：
// 只有【非 fallback 的 allow/deny】能终结审批，其余一律交人工。
func TestJudgeAskOverridesHumanRoutingTable(t *testing.T) {
	overrides := []Decision{{Action: "allow"}, {Action: "deny"}}
	fallsBack := []Decision{
		{Action: "ask"},
		{Action: "allow", ModelFallback: true}, // judge error→FailAction=allow：不许静默放行
		{Action: "deny", ModelFallback: true},  // judge error→FailAction=deny：也不替他拍板，人来看
		{Action: ""},
		{Action: "bogus"},
	}
	for _, d := range overrides {
		if !judgeAskOverridesHuman(d, true) {
			t.Fatalf("模型真实 verdict %q 应终结审批", d.Action)
		}
	}
	for _, d := range fallsBack {
		if judgeAskOverridesHuman(d, true) {
			t.Fatalf("verdict %+v 不应终结审批（应回落人工）", d)
		}
	}
	for _, d := range append(overrides, fallsBack...) {
		if judgeAskOverridesHuman(d, false) {
			t.Fatalf("judged=false（判官关闭/未接线）一律不终结，%+v 却为 true", d)
		}
	}
}

// 审计口径（跨包约定，见 db.interceptSource）：模型裁决的 RuleID 必须保持 0
// 且 reason 带 [模型] 前缀 —— 两个条件缺一，decision_source 就归不到 model。
func TestJudgeAskVerdictDecisionSourceContract(t *testing.T) {
	i := newNoDBJudgeInterceptor(t, fakeReviewer(Decision{Action: "allow", Message: "只读操作"}, nil))
	rule := askRuleDecision()
	d, ok := i.askVerdictWithConfig(context.Background(), JudgeConfig{Enabled: true}, rule, "Bash", json.RawMessage(`{"command":"ls -la"}`))
	if !ok {
		t.Fatal("allow 应终结审批")
	}
	if d.RuleID != 0 {
		t.Fatalf("模型裁决必须 RuleID=0（否则 decision_source 归为 rule），得到 %d", d.RuleID)
	}
	if !strings.HasPrefix(d.Message, "[模型] ask 规则[高危命令审批]交模型裁决") {
		t.Fatalf("reason 必须注明 ask 规则交模型裁决，得到 %q", d.Message)
	}
	if d.RuleName != rule.RuleName {
		t.Fatalf("规则归属必须留在 audit.RuleName（%q），得到 %q", rule.RuleName, d.RuleName)
	}
}

// ============================================================================
// V6-AUTO：判官自己给出 ask 时的自主落定（intercept_judge_ask_policy）。
//
// 背景：纯自主任务里人常常不在线。旧行为「判官 ask → 回落人工 → 60s 超时
// deny」等于「无人即拦掉成果」，与用户要的自主推进相反。默认策略改为
// 立即按规则自带的 timeout_action 落定终局，不进 pending。
// ============================================================================

// 判官 ask + policy=auto（缺省即 auto）+ rule.timeout_action=deny → 立即 deny。
func TestJudgeAskVerdictAutoPolicyDeny(t *testing.T) {
	i := newNoDBJudgeInterceptor(t, fakeReviewer(Decision{Action: "ask", Message: "拿不准是否影响业务"}, nil))
	rule := askRuleDecision() // TimeoutAction=deny
	d, ok := i.askVerdictWithConfig(context.Background(), JudgeConfig{Enabled: true}, rule, "Bash", json.RawMessage(`{"command":"rm -rf /tmp/x"}`))
	if !ok {
		t.Fatal("policy=auto 时判官 ask 必须立即落定（ok=true），不得回落人工")
	}
	if d.Action != "deny" {
		t.Fatalf("规则 timeout_action=deny → 应 deny，得到 %q", d.Action)
	}
	if d.RuleID != 0 {
		t.Fatalf("[自主] 终局必须 RuleID=0（decision_source 归 model），得到 %d", d.RuleID)
	}
	if !strings.HasPrefix(d.Message, "[自主]") {
		t.Fatalf("reason 必须以 [自主] 开头，得到 %q", d.Message)
	}
	if !strings.Contains(d.Message, "「拦截」") {
		t.Fatalf("reason 必须写明按超时策略拦截，得到 %q", d.Message)
	}
	if !strings.Contains(d.Message, "拿不准是否影响业务") {
		t.Fatalf("reason 必须保留原判官理由，得到 %q", d.Message)
	}
	wantRule := rule.RuleName + "·判官不确定"
	if d.RuleName != wantRule {
		t.Fatalf("RuleName 应为 %q，得到 %q", wantRule, d.RuleName)
	}
	if d.TimeoutEnabled {
		t.Fatalf("已落定的终局不应再带审批超时语义，得到 %+v", d)
	}
}

// 判官 ask + policy=auto + rule.timeout_action=allow → 立即 allow。
func TestJudgeAskVerdictAutoPolicyAllow(t *testing.T) {
	i := newNoDBJudgeInterceptor(t, fakeReviewer(Decision{Action: "ask", Message: "不确定"}, nil))
	rule := askRuleDecision()
	rule.TimeoutAction = "allow"
	d, ok := i.askVerdictWithConfig(context.Background(), JudgeConfig{Enabled: true, AskPolicy: judgeAskPolicyAuto}, rule, "Bash", json.RawMessage(`{"command":"ls"}`))
	if !ok || d.Action != "allow" {
		t.Fatalf("timeout_action=allow 应自主放行，得到 %+v ok=%v", d, ok)
	}
	if !strings.Contains(d.Message, "「放行」") {
		t.Fatalf("reason 必须写明按超时策略放行，得到 %q", d.Message)
	}
}

// timeout_action 为空/非法时按 deny 收敛（fail-closed，不放宽）。
func TestJudgeAskVerdictAutoPolicyEmptyTimeoutActionDenies(t *testing.T) {
	i := newNoDBJudgeInterceptor(t, fakeReviewer(Decision{Action: "ask", Message: "不确定"}, nil))
	rule := askRuleDecision()
	rule.TimeoutAction = ""
	d, ok := i.askVerdictWithConfig(context.Background(), JudgeConfig{Enabled: true}, rule, "Bash", json.RawMessage(`{"command":"ls"}`))
	if !ok || d.Action != "deny" {
		t.Fatalf("timeout_action 缺失应按 deny 收敛，得到 %+v ok=%v", d, ok)
	}
}

// 判官 ask + policy=human → 保持原行为：回落人工（ok=false）。
func TestJudgeAskVerdictHumanPolicyFallsBack(t *testing.T) {
	i := newNoDBJudgeInterceptor(t, fakeReviewer(Decision{Action: "ask", Message: "请人确认"}, nil))
	if d, ok := i.askVerdictWithConfig(context.Background(),
		JudgeConfig{Enabled: true, AskPolicy: judgeAskPolicyHuman}, askRuleDecision(), "Bash", json.RawMessage(`{"command":"ls"}`)); ok || d.Action != "" {
		t.Fatalf("policy=human 应回落人工，得到 %+v ok=%v", d, ok)
	}
}

// 判官故障（ModelFallback=true）不同于判官给 ask：即使 FailAction=ask 且
// policy=auto 也必须回落人工（fail-closed，不替人拍板）。
func TestJudgeAskVerdictModelFallbackStillHumanUnderAuto(t *testing.T) {
	i := newNoDBJudgeInterceptor(t, fakeReviewer(Decision{}, errors.New("timeout")))
	if d, ok := i.askVerdictWithConfig(context.Background(),
		JudgeConfig{Enabled: true, FailAction: "ask", AskPolicy: judgeAskPolicyAuto}, askRuleDecision(), "Bash", json.RawMessage(`{"command":"ls"}`)); ok || d.Action != "" {
		t.Fatalf("判官故障应回落人工（规则 ask → pending 15s），得到 %+v ok=%v", d, ok)
	}
}

// 策略值归一化：空与非法值都按 auto（fail-open 到自主）；human 原样保留。
func TestJudgeAskPolicyOf(t *testing.T) {
	cases := map[string]string{
		"":        judgeAskPolicyAuto,
		"auto":    judgeAskPolicyAuto,
		"human":   judgeAskPolicyHuman,
		" HUMAN ": judgeAskPolicyHuman,
		"bogus":   judgeAskPolicyAuto,
	}
	for in, want := range cases {
		if got := judgeAskPolicyOf(in); got != want {
			t.Fatalf("judgeAskPolicyOf(%q) = %q, want %q", in, got, want)
		}
	}
}
