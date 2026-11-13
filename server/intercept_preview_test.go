package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/intercept"
)

// fakeJudge 记录被调次数：试判的第一要求是"只算该算的层"——短路/规则给了
// 终局后再调模型就是白烧 token，也是行为偏离线上的证据。
type fakeJudge struct {
	calls int
	dec   intercept.Decision
	ok    bool
}

func (f *fakeJudge) judge(context.Context, string, json.RawMessage) (intercept.Decision, bool) {
	f.calls++
	return f.dec, f.ok
}

func mustRaw(t *testing.T, s string) json.RawMessage {
	t.Helper()
	if !json.Valid([]byte(s)) {
		t.Fatalf("非法 JSON: %s", s)
	}
	return json.RawMessage(s)
}

// 1. 短路表命中（裸读本机 /etc/shadow）：final 落在 shortcircuit，判官 0 次。
func TestJudgeTestShortCircuitHitSkipsJudge(t *testing.T) {
	fj := &fakeJudge{dec: intercept.Decision{Action: "allow"}, ok: true}
	deps := judgeTestDeps{
		shortCircuit: guard.PreviewShortCircuit,
		match: func(string, []byte) (intercept.Decision, bool) {
			t.Fatal("短路表命中后不应再跑 DB 规则（线上路径也是终局）")
			return intercept.Decision{}, false
		},
		judge: fj.judge,
	}
	resp := evaluateJudgeTest(context.Background(), judgeTestRequest{
		Tool:     "Bash",
		Input:    mustRaw(t, `{"command":"cat /etc/shadow"}`),
		UseJudge: ptrBool(true),
	}, deps)

	if !resp.ShortCircuit.Hit || resp.ShortCircuit.Action != "deny" {
		t.Fatalf("短路表应 deny，得到 %+v", resp.ShortCircuit)
	}
	if resp.ShortCircuit.RuleName == "" || resp.ShortCircuit.Message == "" {
		t.Fatalf("短路层须带规则名与消息：%+v", resp.ShortCircuit)
	}
	if resp.Final.Layer != "shortcircuit" || resp.Final.Action != "deny" {
		t.Fatalf("final 应为 shortcircuit/deny，得到 %+v", resp.Final)
	}
	if fj.calls != 0 || resp.Judge.Called {
		t.Fatalf("短路命中后判官不应被调用，calls=%d judge=%+v", fj.calls, resp.Judge)
	}
	if resp.JudgeCostHint != "" {
		t.Fatalf("未调判官不应给用量提示，得到 %q", resp.JudgeCostHint)
	}
}

// 2. DB 规则命中（crontab -r）：final 落在 rule，deny 不再下探判官。
func TestJudgeTestRuleHitStopsBeforeJudge(t *testing.T) {
	fj := &fakeJudge{dec: intercept.Decision{Action: "allow"}, ok: true}
	deps := judgeTestDeps{
		shortCircuit: guard.PreviewShortCircuit,
		match: func(tool string, _ []byte) (intercept.Decision, bool) {
			if tool != "Bash" {
				t.Fatalf("规则层收到的工具名不符：%q", tool)
			}
			return intercept.Decision{
				RuleID: 21, RuleName: "[内置] 定时任务删除", Action: "deny",
				Message: "禁止删除本机定时任务",
			}, true
		},
		judge: fj.judge,
	}
	resp := evaluateJudgeTest(context.Background(), judgeTestRequest{
		Tool:     "Bash",
		Input:    mustRaw(t, `{"command":"crontab -r"}`),
		UseJudge: ptrBool(true),
	}, deps)

	if resp.ShortCircuit.Hit {
		t.Fatal("crontab -r 不应命中短路表")
	}
	if !resp.Rule.Hit || resp.Rule.RuleID != 21 || resp.Rule.Action != "deny" {
		t.Fatalf("规则层应命中 21/deny，得到 %+v", resp.Rule)
	}
	if resp.Final.Layer != "rule" || resp.Final.Action != "deny" {
		t.Fatalf("final 应为 rule/deny，得到 %+v", resp.Final)
	}
	if fj.calls != 0 || resp.Judge.Called {
		t.Fatalf("规则 deny 后判官不应被调用，calls=%d", fj.calls)
	}
}

// 3. 两层都不命中 + use_judge=true + 假判官 allow → final 落在 judge。
func TestJudgeTestJudgeAllowsWhenNoLayerHit(t *testing.T) {
	fj := &fakeJudge{
		dec: intercept.Decision{Action: "allow", Message: "[模型] 只读列举，无副作用"},
		ok:  true,
	}
	deps := judgeTestDeps{
		shortCircuit: guard.PreviewShortCircuit,
		match:        func(string, []byte) (intercept.Decision, bool) { return intercept.Decision{}, false },
		judge:        fj.judge,
	}
	resp := evaluateJudgeTest(context.Background(), judgeTestRequest{
		Tool:     "Bash",
		Input:    mustRaw(t, `{"command":"ls -la"}`),
		UseJudge: ptrBool(true),
	}, deps)

	if resp.ShortCircuit.Hit || resp.Rule.Hit {
		t.Fatalf("两层都不应命中：%+v %+v", resp.ShortCircuit, resp.Rule)
	}
	if !resp.Judge.Called || resp.Judge.Action != "allow" || resp.Judge.ModelFallback {
		t.Fatalf("判官应被调用且 allow，得到 %+v", resp.Judge)
	}
	if resp.Final.Layer != "judge" || resp.Final.Action != "allow" {
		t.Fatalf("final 应为 judge/allow，得到 %+v", resp.Final)
	}
	if resp.JudgeCostHint == "" {
		t.Fatal("调到判官时应返回 token 用量提示")
	}
	if fj.calls != 1 {
		t.Fatalf("判官应恰好调用 1 次，得到 %d", fj.calls)
	}
}

// 4. use_judge=false：判官 0 次，final 落在 none（两层都没拦）。
func TestJudgeTestUseJudgeFalseSkipsJudge(t *testing.T) {
	fj := &fakeJudge{dec: intercept.Decision{Action: "deny"}, ok: true}
	deps := judgeTestDeps{
		shortCircuit: guard.PreviewShortCircuit,
		match:        func(string, []byte) (intercept.Decision, bool) { return intercept.Decision{}, false },
		judge:        fj.judge,
	}
	resp := evaluateJudgeTest(context.Background(), judgeTestRequest{
		Tool:     "Bash",
		Input:    mustRaw(t, `{"command":"ls -la"}`),
		UseJudge: ptrBool(false),
	}, deps)

	if resp.Judge.Called || fj.calls != 0 {
		t.Fatalf("use_judge=false 时不应调判官，calls=%d", fj.calls)
	}
	if resp.Judge.Reason != "未请求判官（use_judge=false）" {
		t.Fatalf("应说明未请求判官，得到 %q", resp.Judge.Reason)
	}
	if resp.Final.Layer != "none" || resp.Final.Action != "allow" {
		t.Fatalf("final 应为 none/allow，得到 %+v", resp.Final)
	}
}

// 判官未启用：called=false + reason=判官未启用，final 仍是 none。
func TestJudgeTestJudgeDisabled(t *testing.T) {
	deps := judgeTestDeps{
		shortCircuit: guard.PreviewShortCircuit,
		match:        func(string, []byte) (intercept.Decision, bool) { return intercept.Decision{}, false },
		judge: func(context.Context, string, json.RawMessage) (intercept.Decision, bool) {
			return intercept.Decision{}, false
		},
	}
	resp := evaluateJudgeTest(context.Background(), judgeTestRequest{
		Tool:  "Bash",
		Input: mustRaw(t, `{"command":"ls -la"}`),
	}, deps) // UseJudge 缺省=true

	if resp.Judge.Called {
		t.Fatalf("判官未启用时 called 应为 false：%+v", resp.Judge)
	}
	if resp.Judge.Reason != "判官未启用" {
		t.Fatalf("reason 应为判官未启用，得到 %q", resp.Judge.Reason)
	}
	if resp.Final.Layer != "none" || resp.Final.Action != "allow" {
		t.Fatalf("final 应为 none/allow，得到 %+v", resp.Final)
	}
}

// 5. 限流：同一 token 第 31 次 429；另一个 token 不受影响。
func TestJudgeTestRateLimit(t *testing.T) {
	s := &Server{} // 无库：只走短路表与放行面，够验证限流
	body := `{"tool":"Bash","input":{"command":"pwd"},"use_judge":false}`
	post := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/intercept/judge/test", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		s.interceptJudgeTest(rec, req)
		return rec
	}
	for i := 1; i <= judgeTestRateLimit; i++ {
		if rec := post("token-a"); rec.Code != http.StatusOK {
			t.Fatalf("第 %d 次应放行，得到 %d：%s", i, rec.Code, rec.Body.String())
		}
	}
	if rec := post("token-a"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("第 %d 次应 429，得到 %d：%s", judgeTestRateLimit+1, rec.Code, rec.Body.String())
	}
	if rec := post("token-b"); rec.Code != http.StatusOK {
		t.Fatalf("另一个 token 不应被连带限流，得到 %d", rec.Code)
	}
}

// 6. 副作用：试判前后 intercept_pending / audit_events 行数不变。
// 走真实 interceptor（含短路表 deny 这条线上一定会落库的路径），无库则 skip。
func TestJudgeTestWritesNoAuditRows(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	m := &Manager{pg: d, interceptor: intercept.New(d)}
	s := &Server{m: m, jwtKey: []byte("judge-test-signing-key")}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}

	counts := func() (pending, audit int) {
		t.Helper()
		if err := d.QueryRow(`SELECT COUNT(*) FROM intercept_pending`).Scan(&pending); err != nil {
			t.Fatal(err)
		}
		if err := d.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&audit); err != nil {
			t.Fatal(err)
		}
		return pending, audit
	}
	beforePending, beforeAudit := counts()

	post := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/intercept/judge/test", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		s.interceptJudgeTest(rec, req)
		return rec
	}

	// 短路表 deny：真实路径会 Log 一条 denied 并 append 审计链，试判不能。
	rec := post(`{"tool":"Bash","input":{"command":"cat /etc/shadow"},"use_judge":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("试判应 200，得到 %d：%s", rec.Code, rec.Body.String())
	}
	var resp judgeTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Final.Layer != "shortcircuit" {
		t.Fatalf("应命中短路表，得到 %+v", resp.Final)
	}
	// 非命中面也过一遍（落 none），确认整条路径都不写库。
	if rec := post(`{"tool":"Bash","input":{"command":"ls -la"},"use_judge":false}`); rec.Code != http.StatusOK {
		t.Fatalf("第二次试判应 200，得到 %d", rec.Code)
	}

	afterPending, afterAudit := counts()
	if afterPending != beforePending {
		t.Fatalf("intercept_pending 行数变化：%d → %d（试判不得写审批记录）", beforePending, afterPending)
	}
	if afterAudit != beforeAudit {
		t.Fatalf("audit_events 行数变化：%d → %d（试判不得污染审计链）", beforeAudit, afterAudit)
	}
}

// 返回体形状：hit/called/model_fallback 这些布尔字段必须显式出现（false 也要
// 序列化），下游用脚本读字段时不能靠"缺省即 false"猜。
func TestJudgeTestHTTPResponseShape(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/intercept/judge/test",
		strings.NewReader(`{"tool":"Bash","input":{"command":"cat /etc/shadow"}}`))
	req.Header.Set("Authorization", "Bearer shape-token")
	rec := httptest.NewRecorder()
	s.interceptJudgeTest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("应 200，得到 %d：%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		`"short_circuit":{"hit":true`,
		`"judge":{"called":false`,
		`"model_fallback":false`,
		`"final":{"action":"deny","layer":"shortcircuit"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("返回体缺少 %s：%s", want, body)
		}
	}
	// input 缺失/非法直接 400，不能拿一份空参数喂判官。
	bad := httptest.NewRequest(http.MethodPost, "/api/intercept/judge/test",
		strings.NewReader(`{"tool":"Bash"}`))
	bad.Header.Set("Authorization", "Bearer shape-token-2")
	brec := httptest.NewRecorder()
	s.interceptJudgeTest(brec, bad)
	if brec.Code != http.StatusBadRequest {
		t.Fatalf("缺 input 应 400，得到 %d", brec.Code)
	}
}

func ptrBool(v bool) *bool { return &v }
