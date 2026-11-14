package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
)

// intelSample 构造抽取样本：1 个资产（1 条资产情报 + 1 个接口 + 2 个组件）、
// 1 条 finding（1 个接口 + 2 条凭据 + 1 条漏洞）、1 条 fact（1 个接口 + 1 条凭据）。
func intelSample() intelBuildInput {
	asset := &pgdb.Asset{
		ID: 7, Type: "service",
		URL:          "http://app.example.com:8080/login",
		Technologies: []string{"nginx/1.18.0", "PHP:7.4.33"},
	}
	evidence := strings.Join([]string{
		"POST /api/user/123/profile?id=1&debug=2 HTTP/1.1",
		"Host: app.example.com:8080",
		"Cookie: session=abc123def456",
		"X-Powered-By: PHP/7.4.33",
		"",
		"HTTP/1.1 200 OK",
		"Server: nginx/1.18.0",
		"password=Sup3rSecret! user=admin at 10.0.0.5",
	}, "\r\n")
	return intelBuildInput{
		TaskID: 42,
		Findings: []pgdb.IntelFinding{{
			ID: 21, Name: "SQL Injection on /api/user/123/profile", VulnClass: "sqli",
			Severity: "high", Evidence: evidence, AssetIDs: []int64{7},
			Summary: "union based injection via http://app.example.com:8080/api/export?token=tok123",
		}},
		Facts: []pgdb.IntelFact{{
			NodeID: 31, Summary: "订单接口与库凭据",
			Detail: "GET /api/order/42/detail?id=9 返回 200；mysql://root:RootPass123@10.0.0.9:3306 数据库凭据 root:RootPass123 可用",
		}},
		Assets: []*pgdb.Asset{asset},
	}
}

func findIntel(rows []pgdb.TaskIntel, kind, key string) *pgdb.TaskIntel {
	for i := range rows {
		if rows[i].Kind == kind && rows[i].Key == key {
			return &rows[i]
		}
	}
	return nil
}

// TestExtractTaskIntelSample 断言抽取行数、归一化 key、脱敏 value 与合并明细。
func TestExtractTaskIntelSample(t *testing.T) {
	rows := extractTaskIntel(intelSample())
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.Kind]++
		if r.TaskID != 42 {
			t.Fatalf("row task id=%d, want 42", r.TaskID)
		}
		if r.Key == "" || r.Value == "" || r.Source == "" {
			t.Fatalf("row missing fields: %+v", r)
		}
	}
	want := map[string]int{
		pgdb.IntelKindEndpoint: 4, pgdb.IntelKindCredential: 3,
		pgdb.IntelKindComponent: 2, pgdb.IntelKindAsset: 1, pgdb.IntelKindVuln: 1,
	}
	for k, n := range want {
		if counts[k] != n {
			t.Errorf("kind %s: rows=%d, want %d (all=%v)", k, counts[k], n, counts)
		}
	}

	// 数字段折叠 + query 去值。
	if r := findIntel(rows, pgdb.IntelKindEndpoint, "post /api/user/{id}/profile?debug&id"); r == nil {
		t.Errorf("missing folded endpoint key; endpoints=%v", endpointKeys(rows))
	}
	// UUID/数字折叠 fact 接口。
	if r := findIntel(rows, pgdb.IntelKindEndpoint, "get /api/order/{id}/detail?id"); r == nil {
		t.Errorf("missing fact endpoint key; endpoints=%v", endpointKeys(rows))
	}
	// 资产 URL 的接口（方法缺失记 GET）。
	if r := findIntel(rows, pgdb.IntelKindEndpoint, "get /login"); r == nil {
		t.Errorf("missing asset endpoint; endpoints=%v", endpointKeys(rows))
	}
	// 正文里的裸 URL：敏感 query 值必须脱敏（key 只留参数名，value 不能带明文）。
	if r := findIntel(rows, pgdb.IntelKindEndpoint, "get /api/export?token"); r == nil {
		t.Errorf("missing bare-URL endpoint; endpoints=%v", endpointKeys(rows))
	} else if strings.Contains(r.Value, "tok123") || !strings.Contains(r.Value, "REDACTED") {
		t.Errorf("endpoint value not redacted: %q", r.Value)
	}

	// 凭据：value 只写脱敏描述，密文只以 secret_masked（前 2 后 2）出现。
	cred := findIntel(rows, pgdb.IntelKindCredential, "password|admin|app.example.com:8080")
	if cred == nil {
		t.Fatalf("missing password credential; credentials=%v", credentialKeys(rows))
	}
	if cred.Value != "password for admin@app.example.com:8080" {
		t.Errorf("credential value=%q", cred.Value)
	}
	var detail map[string]any
	if err := json.Unmarshal(cred.Detail, &detail); err != nil {
		t.Fatal(err)
	}
	if detail["secret_masked"] != "Su****t!" {
		t.Errorf("secret_masked=%v, want Su****t!", detail["secret_masked"])
	}
	if c := findIntel(rows, pgdb.IntelKindCredential, "cookie|admin|app.example.com:8080"); c == nil {
		t.Errorf("missing cookie credential; credentials=%v", credentialKeys(rows))
	}
	if c := findIntel(rows, pgdb.IntelKindCredential, "password|root|10.0.0.9:3306"); c == nil {
		t.Errorf("missing fact user:pass credential; credentials=%v", credentialKeys(rows))
	}

	// 组件版本截断到 major.minor。
	for _, k := range []string{"nginx@1.18", "php@7.4"} {
		if r := findIntel(rows, pgdb.IntelKindComponent, k); r == nil {
			t.Errorf("missing component %q; components=%v", k, componentKeys(rows))
		}
	}

	// 资产 host:port。
	if findIntel(rows, pgdb.IntelKindAsset, "app.example.com:8080") == nil {
		t.Errorf("missing asset row; assets=%v", assetKeys(rows))
	}
	// 漏洞 key=title|asset（小写）。
	if r := findIntel(rows, pgdb.IntelKindVuln, "sql injection on /api/user/123/profile|app.example.com:8080"); r == nil {
		t.Errorf("missing vuln key; vulns=%v", vulnKeys(rows))
	}

	// 明文绝不出现在任何 value/detail 里。
	blob, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"Sup3rSecret", "RootPass123", "abc123def456", "tok123"} {
		if strings.Contains(string(blob), secret) {
			t.Errorf("plaintext %q leaked into task intel: %s", secret, blob)
		}
	}
}

// TestRedactURLForValue 断言 value 侧脱敏：userinfo 与敏感 query 值一律替换。
func TestRedactURLForValue(t *testing.T) {
	cases := map[string]string{
		"http://user:pass@h/a?token=abc&x=1": "http://REDACTED@h/a?token=REDACTED&x=1",
		"/a?password=p&y=2":                  "/a?password=REDACTED&y=2",
		"http://h/a?x=1":                     "http://h/a?x=1",
		"/login":                             "/login",
	}
	for in, want := range cases {
		if got := redactURLForValue(in); got != want {
			t.Errorf("redact(%q)=%q, want %q", in, got, want)
		}
	}
}

// TestExtractTaskIntelIdempotent 同一原料重复抽取，输出字节级一致（入库幂等的
// 前提：同 key 同 detail，不会每次跑出不同的 count/来源顺序）。
func TestExtractTaskIntelIdempotent(t *testing.T) {
	a, err := json.Marshal(extractTaskIntel(intelSample()))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(extractTaskIntel(intelSample()))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("extraction not deterministic:\n%s\n%s", a, b)
	}
}

// TestGroupTaskIntel 断言五组固定顺序、空组保留、组内计数。
func TestGroupTaskIntel(t *testing.T) {
	rows := []pgdb.TaskIntel{
		{Kind: pgdb.IntelKindEndpoint, Key: "get /a"},
		{Kind: pgdb.IntelKindEndpoint, Key: "get /b"},
		{Kind: pgdb.IntelKindVuln, Key: "x|y"},
	}
	groups := groupTaskIntel(rows)
	if len(groups) != len(intelGroupOrder) {
		t.Fatalf("groups=%d, want %d", len(groups), len(intelGroupOrder))
	}
	if groups[0].Kind != pgdb.IntelKindEndpoint || groups[0].Count != 2 {
		t.Fatalf("first group=%+v", groups[0])
	}
	if groups[len(groups)-1].Kind != pgdb.IntelKindVuln || groups[len(groups)-1].Count != 1 {
		t.Fatalf("last group=%+v", groups[len(groups)-1])
	}
	if groups[1].Count != 0 || groups[1].Items == nil {
		t.Fatalf("empty group must be present with empty items: %+v", groups[1])
	}
}

// TestTaskIntelGeneratedOnTaskDonePG 用真实 PG 跑一次终态流程：done → 情报表
// 生成 + project_graph_events 新增一行；再 rebuild 不重复发信号。
func TestTaskIntelGeneratedOnTaskDonePG(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	pg := m.PG()
	s := &Server{m: m}
	s.installTerminalHooks() // 与 server.New 的装配同一函数

	ctx := context.Background()
	p, err := pg.CreateProject(pgdb.CreateProjectInput{Name: "intel-hook-" + strconv.FormatInt(time.Now().UnixNano(), 10)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM projects WHERE id=$1`, p.ID) })
	task, err := pg.CreateTaskWithOptions("intel hook task", "goal", pgdb.TaskCreateOptions{ProjectID: &p.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pg.AddFinding(task.ID, 0, "sqli", "SQL Injection on /login", "high",
		"evidence", "POST /login HTTP/1.1\r\nHost: app.example.com\r\npassword=Sup3rSecret! user=admin at 10.0.0.5",
		"worker", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exploration(task.ExplorationID).AddNode(pgdb.KindFact, map[string]any{
		"summary": "指纹", "detail": "Server: nginx/1.18.0",
	}, 5, "confirmed", "worker", nil); err != nil {
		t.Fatal(err)
	}

	if err := m.SetTaskStatus(strconv.FormatInt(task.ID, 10), "done"); err != nil {
		t.Fatal(err)
	}

	// 钩子是异步的：轮询等情报表落库。
	deadline := time.Now().Add(10 * time.Second)
	var rows int
	for {
		if err := pg.QueryRowContext(ctx, `SELECT count(*) FROM task_intel WHERE task_id=$1`, task.ID).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if rows > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if rows == 0 {
		t.Fatal("终态后未生成 task_intel 行")
	}
	intel, err := pg.TaskIntelForTask(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if findIntel(intel, pgdb.IntelKindEndpoint, "post /login") == nil {
		t.Errorf("missing endpoint in DB rows: %v", endpointKeys(intel))
	}
	if findIntel(intel, pgdb.IntelKindCredential, "password|admin|app.example.com") == nil {
		t.Errorf("missing credential in DB rows: %v", credentialKeys(intel))
	}
	if findIntel(intel, pgdb.IntelKindComponent, "nginx@1.18") == nil {
		t.Errorf("missing component in DB rows: %v", componentKeys(intel))
	}
	blob, _ := json.Marshal(intel)
	if strings.Contains(string(blob), "Sup3rSecret") {
		t.Errorf("plaintext password leaked to DB: %s", blob)
	}

	var evCount int
	var summary string
	if err := pg.QueryRowContext(ctx, `SELECT count(*), COALESCE(max(delta_summary),'')
FROM project_graph_events WHERE project_id=$1 AND task_id=$2 AND kind='intel'`, p.ID, task.ID).
		Scan(&evCount, &summary); err != nil {
		t.Fatal(err)
	}
	if evCount != 1 {
		t.Fatalf("intel graph events=%d, want 1", evCount)
	}
	if !strings.Contains(summary, "task#"+strconv.FormatInt(task.ID, 10)) || !strings.Contains(summary, "接口情报") {
		t.Errorf("event summary=%q", summary)
	}

	// rebuild 幂等：行数不变、不重复发信号。
	st, err := s.buildTaskIntel(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st.Inserted != 0 {
		t.Errorf("rebuild inserted=%d, want 0", st.Inserted)
	}
	if err := pg.QueryRowContext(ctx, `SELECT count(*) FROM task_intel WHERE task_id=$1`, task.ID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if want := st.Rows; rows != want {
		t.Errorf("rebuild rows=%d, want %d", rows, want)
	}
	if err := pg.QueryRowContext(ctx, `SELECT count(*) FROM project_graph_events
WHERE project_id=$1 AND task_id=$2 AND kind='intel'`, p.ID, task.ID).Scan(&evCount); err != nil {
		t.Fatal(err)
	}
	if evCount != 1 {
		t.Errorf("rebuild must not emit duplicate signal: events=%d", evCount)
	}
}

// TestTaskIntelListAPIGrouped 断言 GET 接口按 kind 分组返回（含空组）。
func TestTaskIntelListAPIGrouped(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	pg := m.PG()
	ctx := context.Background()

	p, err := pg.CreateProject(pgdb.CreateProjectInput{Name: "intel-api-" + strconv.FormatInt(time.Now().UnixNano(), 10)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM projects WHERE id=$1`, p.ID) })
	task, err := pg.CreateTaskWithOptions("intel api task", "goal", pgdb.TaskCreateOptions{ProjectID: &p.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pg.UpsertTaskIntel(ctx, p.ID, task.ID, []pgdb.TaskIntel{
		{Kind: pgdb.IntelKindEndpoint, Key: "get /login", Value: "http://h/login", Source: "asset"},
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m, jwtKey: []byte("test-key")}
	req := httptest.NewRequest("GET", "/api/tasks/"+strconv.FormatInt(task.ID, 10)+"/intel", nil)
	req.SetPathValue("id", strconv.FormatInt(task.ID, 10))
	rec := httptest.NewRecorder()
	s.taskIntelList(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		TaskID int64        `json:"task_id"`
		Total  int          `json:"total"`
		Groups []IntelGroup `json:"groups"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.TaskID != task.ID || resp.Total != 1 || len(resp.Groups) != len(intelGroupOrder) {
		t.Fatalf("resp=%+v", resp)
	}
	if resp.Groups[0].Kind != pgdb.IntelKindEndpoint || resp.Groups[0].Count != 1 {
		t.Fatalf("endpoint group=%+v", resp.Groups[0])
	}
}

func endpointKeys(rows []pgdb.TaskIntel) []string   { return keysOf(rows, pgdb.IntelKindEndpoint) }
func credentialKeys(rows []pgdb.TaskIntel) []string { return keysOf(rows, pgdb.IntelKindCredential) }
func componentKeys(rows []pgdb.TaskIntel) []string  { return keysOf(rows, pgdb.IntelKindComponent) }
func assetKeys(rows []pgdb.TaskIntel) []string      { return keysOf(rows, pgdb.IntelKindAsset) }
func vulnKeys(rows []pgdb.TaskIntel) []string       { return keysOf(rows, pgdb.IntelKindVuln) }

func keysOf(rows []pgdb.TaskIntel, kind string) []string {
	var out []string
	for _, r := range rows {
		if r.Kind == kind {
			out = append(out, r.Key)
		}
	}
	return out
}
