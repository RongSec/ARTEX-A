package server

// V9-PURPOSE 接口用途模型补充的端到端用例：真实 PG + 假模型 provider。
// 覆盖：合法 JSON、非法 JSON 两次、超时、rebuild 幂等、无 LLM 配置。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"log"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

// fakeIntelPurposeProvider 是只实现 Complete 的假模型：calls 用于断言调用次数。
type fakeIntelPurposeProvider struct {
	calls int32
	fn    func(ctx context.Context, req llm.CompletionRequest) (string, error)
}

func (p *fakeIntelPurposeProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	atomic.AddInt32(&p.calls, 1)
	text, err := p.fn(ctx, req)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(text)}}, "end_turn", llm.Usage{}, nil
}

func (p *fakeIntelPurposeProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {}
}

func (p *fakeIntelPurposeProvider) count() int { return int(atomic.LoadInt32(&p.calls)) }

// intelPurposeAnswerFromPrompt 从提示词里的 JSON 接口清单回填每条 key 的用途，
// 模拟一个守约模型。
func intelPurposeAnswerFromPrompt(req llm.CompletionRequest) string {
	text := ""
	if len(req.Messages) > 0 {
		text = req.Messages[0].Text()
	}
	type input struct {
		Key string `json:"key"`
	}
	type item struct {
		Key     string `json:"key"`
		Purpose string `json:"purpose"`
	}
	var inputs []input
	if body, ok := extractIntelPurposeJSON(text); ok {
		_ = json.Unmarshal([]byte(body), &inputs)
	}
	var items []item
	for i, in := range inputs {
		items = append(items, item{Key: in.Key, Purpose: fmt.Sprintf("抽象用途%d", i+1)})
	}
	raw, _ := json.Marshal(items)
	return string(raw)
}

// intelPurposeFixture 建项目/任务/6 条接口的 finding，并返回可直接注入假模型的
// Server（llmOn/llmProv 是 globalProvider 的读取源）。
func intelPurposeFixture(t *testing.T) (*Server, *pgdb.DB, *pgdb.Task, *fakeIntelPurposeProvider) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	pg := m.PG()

	p, err := pg.CreateProject(pgdb.CreateProjectInput{Name: "intel-purpose-" + strconv.FormatInt(time.Now().UnixNano(), 10)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM projects WHERE id=$1`, p.ID) })
	task, err := pg.CreateTaskWithOptions("intel purpose task", "目标是验证 DVWA 命令注入", pgdb.TaskCreateOptions{ProjectID: &p.ID})
	if err != nil {
		t.Fatal(err)
	}

	evidence := strings.Join([]string{
		"GET /login HTTP/1.1\nHost: app.example.com",
		"GET /profile HTTP/1.1\nHost: app.example.com",
		"GET /admin/users HTTP/1.1\nHost: app.example.com",
		"POST /vulnerabilities/exec/ HTTP/1.1\nHost: app.example.com\nip=127.0.0.1",
		"GET /upload HTTP/1.1\nHost: app.example.com",
		"GET /logout HTTP/1.1\nHost: app.example.com",
	}, "\n\n")
	if _, err := pg.AddFinding(task.ID, 0, "cmdi", "DVWA Command Injection (exec.php ip 参数未过滤)", "high",
		"", evidence, "worker", nil); err != nil {
		t.Fatal(err)
	}

	fake := &fakeIntelPurposeProvider{
		fn: func(ctx context.Context, req llm.CompletionRequest) (string, error) {
			return intelPurposeAnswerFromPrompt(req), nil
		},
	}
	s := &Server{m: m}
	s.llmOn = true
	s.llmProv = fake
	return s, pg, task, fake
}

func intelEndpointRows(t *testing.T, pg *pgdb.DB, taskID int64) []pgdb.TaskIntel {
	t.Helper()
	rows, err := pg.TaskIntelForTask(context.Background(), taskID)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func intelEndpointDetail(t *testing.T, rows []pgdb.TaskIntel, key string) map[string]any {
	t.Helper()
	r := findIntel(rows, pgdb.IntelKindEndpoint, key)
	if r == nil {
		t.Fatalf("missing endpoint %q; have=%v", key, endpointKeys(rows))
	}
	return intelDetailMap(t, r)
}

const intelPurposeRuleTitle = "DVWA Command Injection (exec.php ip 参数未过滤)"

// TestIntelPurposeModelFillsAllEndpoints 假模型返回合法 JSON：6 条接口的
// purpose 全部为模型值、source=model，规则摘句保留在 purpose_rule。
func TestIntelPurposeModelFillsAllEndpoints(t *testing.T) {
	s, pg, task, fake := intelPurposeFixture(t)
	ctx := context.Background()
	if _, err := s.buildTaskIntel(ctx, task.ID); err != nil {
		t.Fatal(err)
	}
	rows := intelEndpointRows(t, pg, task.ID)
	eps := endpointKeys(rows)
	if len(eps) != 6 {
		t.Fatalf("endpoints=%d, want 6: %v", len(eps), eps)
	}
	for _, key := range eps {
		d := intelEndpointDetail(t, rows, key)
		if d["purpose_source"] != "model" {
			t.Errorf("%s purpose_source=%v, want model", key, d["purpose_source"])
		}
		p, _ := d["purpose"].(string)
		if !strings.HasPrefix(p, "抽象用途") {
			t.Errorf("%s purpose=%q, want model value", key, p)
		}
		if d["purpose_rule"] != intelPurposeRuleTitle {
			t.Errorf("%s purpose_rule=%v, want %q", key, d["purpose_rule"], intelPurposeRuleTitle)
		}
	}
	if got := fake.count(); got != 1 {
		t.Errorf("model calls=%d, want 1（一个任务只做一次批量调用）", got)
	}

	// API 投影：purpose 用模型值，并带 purpose_source。
	groups := buildIntelGroups(rows)
	if len(groups.Endpoint) != 6 {
		t.Fatalf("api endpoints=%d", len(groups.Endpoint))
	}
	for _, item := range groups.Endpoint {
		if item.PurposeSource != "model" || !strings.HasPrefix(item.Purpose, "抽象用途") {
			t.Errorf("api endpoint %s purpose=%q source=%q", item.Key, item.Purpose, item.PurposeSource)
		}
	}
}

// TestIntelPurposeInvalidJSONFallsBack 假模型两次都是非法 JSON：回退规则值，
// 任务不失败，日志含 WARN。
func TestIntelPurposeInvalidJSONFallsBack(t *testing.T) {
	s, pg, task, fake := intelPurposeFixture(t)
	fake.fn = func(ctx context.Context, req llm.CompletionRequest) (string, error) {
		return "这不是 JSON", nil
	}

	var buf bytes.Buffer
	prevWriter := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prevWriter)

	if _, err := s.buildTaskIntel(context.Background(), task.ID); err != nil {
		t.Fatalf("模型解析失败不应让情报表生成失败: %v", err)
	}
	rows := intelEndpointRows(t, pg, task.ID)
	for _, key := range endpointKeys(rows) {
		d := intelEndpointDetail(t, rows, key)
		if d["purpose_source"] != "rule" {
			t.Errorf("%s purpose_source=%v, want rule", key, d["purpose_source"])
		}
		if d["purpose"] != intelPurposeRuleTitle || d["purpose_rule"] != intelPurposeRuleTitle {
			t.Errorf("%s purpose=%v rule=%v", key, d["purpose"], d["purpose_rule"])
		}
	}
	if got := fake.count(); got != 2 {
		t.Errorf("model calls=%d, want 2（解析失败重试 1 次）", got)
	}
	if !strings.Contains(buf.String(), "WARN") {
		t.Errorf("日志缺少 WARN: %s", buf.String())
	}
}

// TestIntelPurposeTimeoutFallsBack 模型调用超时：回退规则值，不阻塞/不失败。
func TestIntelPurposeTimeoutFallsBack(t *testing.T) {
	s, pg, task, fake := intelPurposeFixture(t)
	fake.fn = func(ctx context.Context, req llm.CompletionRequest) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	prevTimeout := intelPurposeTimeout
	intelPurposeTimeout = 50 * time.Millisecond
	defer func() { intelPurposeTimeout = prevTimeout }()

	done := make(chan error, 1)
	go func() {
		_, err := s.buildTaskIntel(context.Background(), task.ID)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("超时不应让情报表生成失败: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("模型超时后 buildTaskIntel 未返回")
	}

	rows := intelEndpointRows(t, pg, task.ID)
	for _, key := range endpointKeys(rows) {
		d := intelEndpointDetail(t, rows, key)
		if d["purpose_source"] != "rule" || d["purpose"] != intelPurposeRuleTitle {
			t.Errorf("%s purpose=%v source=%v, want rule fallback", key, d["purpose"], d["purpose_source"])
		}
	}
	if got := fake.count(); got != 1 {
		t.Errorf("model calls=%d, want 1（超时不重试）", got)
	}
}

// TestIntelPurposeRebuildIdempotent rebuild 两次不再调用模型；显式 force 才重调。
func TestIntelPurposeRebuildIdempotent(t *testing.T) {
	s, pg, task, fake := intelPurposeFixture(t)
	ctx := context.Background()
	if _, err := s.buildTaskIntel(ctx, task.ID); err != nil {
		t.Fatal(err)
	}
	if got := fake.count(); got != 1 {
		t.Fatalf("首轮 model calls=%d, want 1", got)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.rebuildTaskIntel(ctx, task.ID); err != nil {
			t.Fatal(err)
		}
	}
	if got := fake.count(); got != 1 {
		t.Errorf("rebuild 两次后 model calls=%d, want 1（已模型化的行不重复请求）", got)
	}
	rows := intelEndpointRows(t, pg, task.ID)
	for _, key := range endpointKeys(rows) {
		d := intelEndpointDetail(t, rows, key)
		if d["purpose_source"] != "model" || !strings.HasPrefix(fmt.Sprint(d["purpose"]), "抽象用途") {
			t.Errorf("rebuild 后 %s purpose=%v source=%v", key, d["purpose"], d["purpose_source"])
		}
	}

	// 显式强制：允许重调，结果仍为模型值。
	if _, err := s.rebuildTaskIntelForcePurpose(ctx, task.ID); err != nil {
		t.Fatal(err)
	}
	if got := fake.count(); got != 2 {
		t.Errorf("force rebuild model calls=%d, want 2", got)
	}
}

// ---------------------------------------------------------------------------
// 纯函数层用例（不依赖 PG）：直接对内存行跑模型补充，覆盖解析/回退/幂等/30 条上限。
// 上面的 PG 用例负责落库与 rebuild 语义；本机无 PG 时这些纯函数用例仍可执行。
// ---------------------------------------------------------------------------

func pureIntelPurposeRows(n int) []pgdb.TaskIntel {
	rows := make([]pgdb.TaskIntel, 0, n)
	for i := 0; i < n; i++ {
		d := map[string]any{
			"count":         1,
			"methods":       []string{"get"},
			"hosts":         []string{"h:80"},
			"purpose":       intelPurposeRuleTitle,
			"finding_ids":   []int64{21},
			"auth_required": false,
		}
		raw, _ := json.Marshal(d)
		rows = append(rows, pgdb.TaskIntel{
			TaskID: 1, Kind: pgdb.IntelKindEndpoint,
			Key: fmt.Sprintf("get /ep%d", i+1), Detail: raw,
		})
	}
	return rows
}

func fakePurposeServer(fake *fakeIntelPurposeProvider) *Server {
	s := &Server{}
	s.llmOn = true
	s.llmProv = fake
	return s
}

func TestIntelPurposePureModelFill(t *testing.T) {
	rows := pureIntelPurposeRows(6)
	annotateIntelPurposeRules(rows)
	fake := &fakeIntelPurposeProvider{fn: func(ctx context.Context, req llm.CompletionRequest) (string, error) {
		return intelPurposeAnswerFromPrompt(req), nil
	}}
	s := fakePurposeServer(fake)
	s.fillIntelEndpointPurposes(context.Background(), nil,
		[]pgdb.IntelFinding{{ID: 21, Name: intelPurposeRuleTitle}}, nil, rows, false)

	for i := range rows {
		d := intelDetailMapOf(rows[i])
		if d["purpose_source"] != "model" {
			t.Errorf("%s source=%v, want model", rows[i].Key, d["purpose_source"])
		}
		if !strings.HasPrefix(fmt.Sprint(d["purpose"]), "抽象用途") {
			t.Errorf("%s purpose=%v", rows[i].Key, d["purpose"])
		}
		if d["purpose_rule"] != intelPurposeRuleTitle {
			t.Errorf("%s purpose_rule=%v", rows[i].Key, d["purpose_rule"])
		}
	}
	if fake.count() != 1 {
		t.Errorf("calls=%d, want 1", fake.count())
	}
}

func TestIntelPurposePureFallbackAndIdempotent(t *testing.T) {
	rows := pureIntelPurposeRows(6)
	annotateIntelPurposeRules(rows)
	// 非法 JSON 两次 → 规则回退。
	fake := &fakeIntelPurposeProvider{fn: func(ctx context.Context, req llm.CompletionRequest) (string, error) {
		return "nope", nil
	}}
	s := fakePurposeServer(fake)
	s.fillIntelEndpointPurposes(context.Background(), nil, nil, nil, rows, false)
	for i := range rows {
		d := intelDetailMapOf(rows[i])
		if d["purpose_source"] != "rule" || d["purpose"] != intelPurposeRuleTitle {
			t.Errorf("%s purpose=%v source=%v", rows[i].Key, d["purpose"], d["purpose_source"])
		}
	}
	if fake.count() != 2 {
		t.Errorf("calls=%d, want 2", fake.count())
	}

	// 成功一次后，拿旧行作 prev 再跑：不再调用模型（幂等）。
	rows2 := pureIntelPurposeRows(6)
	annotateIntelPurposeRules(rows2)
	fake2 := &fakeIntelPurposeProvider{fn: func(ctx context.Context, req llm.CompletionRequest) (string, error) {
		return intelPurposeAnswerFromPrompt(req), nil
	}}
	s2 := fakePurposeServer(fake2)
	s2.fillIntelEndpointPurposes(context.Background(), nil, nil, nil, rows2, false)
	before := fake2.count()
	prev := append([]pgdb.TaskIntel(nil), rows2...)

	rows3 := pureIntelPurposeRows(6)
	annotateIntelPurposeRules(rows3)
	s2.fillIntelEndpointPurposes(context.Background(), nil, nil, prev, rows3, false)
	if fake2.count() != before {
		t.Errorf("二次跑仍调用模型：calls=%d, want %d", fake2.count(), before)
	}
	for i := range rows3 {
		if d := intelDetailMapOf(rows3[i]); d["purpose_source"] != "model" {
			t.Errorf("%s 应沿用旧模型用途，source=%v", rows3[i].Key, d["purpose_source"])
		}
	}
}

func TestIntelPurposePureCap30(t *testing.T) {
	rows := pureIntelPurposeRows(35)
	annotateIntelPurposeRules(rows)
	fake := &fakeIntelPurposeProvider{fn: func(ctx context.Context, req llm.CompletionRequest) (string, error) {
		return intelPurposeAnswerFromPrompt(req), nil
	}}
	s := fakePurposeServer(fake)
	s.fillIntelEndpointPurposes(context.Background(), nil, nil, nil, rows, false)

	modelCount, ruleCount := 0, 0
	for i := range rows {
		d := intelDetailMapOf(rows[i])
		if d["purpose_source"] == "model" {
			modelCount++
		} else {
			ruleCount++
		}
	}
	if modelCount != 30 || ruleCount != 5 {
		t.Errorf("model=%d rule=%d, want 30/5", modelCount, ruleCount)
	}
	if fake.count() != 1 {
		t.Errorf("calls=%d, want 1（超出部分不额外调用）", fake.count())
	}
}

func TestIntelPurposeNoLLMConfigSkips(t *testing.T) {
	s, pg, task, fake := intelPurposeFixture(t)
	s.llmOn = false
	s.llmProv = nil

	if _, err := s.buildTaskIntel(context.Background(), task.ID); err != nil {
		t.Fatal(err)
	}
	rows := intelEndpointRows(t, pg, task.ID)
	if len(endpointKeys(rows)) != 6 {
		t.Fatalf("无 LLM 时情报表仍应生成: %v", endpointKeys(rows))
	}
	for _, key := range endpointKeys(rows) {
		d := intelEndpointDetail(t, rows, key)
		if d["purpose_source"] != "rule" || d["purpose"] != intelPurposeRuleTitle {
			t.Errorf("%s purpose=%v source=%v, want rule", key, d["purpose"], d["purpose_source"])
		}
	}
	if got := fake.count(); got != 0 {
		t.Errorf("无 LLM 配置时不得调用模型，calls=%d", got)
	}
}
