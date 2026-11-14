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

// TestExtractTaskIntelNoiseSuppressed 覆盖线上实测的噪声样例行：修复后逐条不产出。
// 每行都是独立来源文本，断言对应 key 不存在，并对凭据做"用户名/服务"二次校验。
func TestExtractTaskIntelNoiseSuppressed(t *testing.T) {
	cases := []struct {
		name      string
		text      string
		kind      string
		forbidden string
	}{
		{
			name: "endpoint 整句被当 URL（中文逗号混进路径）",
			text: "GET //127.0.0.1:9081，Apache/2.4.25 HTTP/1.1\nServer: Apache/2.4.25 (Debian)",
			kind: pgdb.IntelKindEndpoint, forbidden: "get //127.0.0.1:9081，Apache/2.4.25",
		},
		{
			name: "component 把 MariaDB 版本套到 PHP 上",
			text: "PHP Version: 10.1.26\nMariaDB 10.1.26",
			kind: pgdb.IntelKindComponent, forbidden: "php@10.1",
		},
		{
			name: "component 状态码 200 当版本",
			text: "php 200",
			kind: pgdb.IntelKindComponent, forbidden: "php@200",
		},
		{
			name: "credential 页面词 surname 当用户名",
			text: "Surname: Smith\npassword=secret123\nHost: 127.0.0.1:9081",
			kind: pgdb.IntelKindCredential, forbidden: "password|surname|127.0.0.1:9081",
		},
		{
			name: "credential 页面词 name 当用户名",
			text: "name: John\npassword=secret123\nHost: 127.0.0.1:9081",
			kind: pgdb.IntelKindCredential, forbidden: "password|name|127.0.0.1:9081",
		},
		{
			name: "credential 页面词 currently 当用户名",
			text: "currently: active\npassword=secret123\nHost: 127.0.0.1:9081",
			kind: pgdb.IntelKindCredential, forbidden: "password|currently|127.0.0.1:9081",
		},
		{
			name: "credential 用户名 level + service 是路径",
			text: "Level: low\nhttp://127.0.0.1:9081/login.php\npassword=secret123",
			kind: pgdb.IntelKindCredential, forbidden: "password|level|login.php",
		},
		{
			name: "credential 用户名 phpids + service 是路径",
			text: "PHPIDS: enabled\nhttp://127.0.0.1:9081/login.php\npassword=secret123",
			kind: pgdb.IntelKindCredential, forbidden: "password|phpids|login.php",
		},
		{
			name: "credential cookie 的 service 是路径",
			text: "Cookie: PHPSESSID=abc123def456\nadmin\nhttp://127.0.0.1:9081/login.php",
			kind: pgdb.IntelKindCredential, forbidden: "cookie|admin|login.php",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rows := extractTaskIntel(intelBuildInput{TaskID: 1, Findings: []pgdb.IntelFinding{{
				ID: 1, Evidence: c.text,
			}}})
			if r := findIntel(rows, c.kind, c.forbidden); r != nil {
				t.Fatalf("噪声行未被抑制: %+v；同类现有=%v", *r, keysOf(rows, c.kind))
			}
			switch c.kind {
			case pgdb.IntelKindEndpoint:
				if got := endpointKeys(rows); len(got) != 0 {
					t.Fatalf("含中文标点的残句不得产出 endpoint，现有=%v", got)
				}
			case pgdb.IntelKindComponent:
				// 错配样例里 mariadb 应照常保留，但 php 的那条必须消失（已被上面断言覆盖）。
				if c.forbidden == "php@200" && len(componentKeys(rows)) != 0 {
					t.Fatalf("单段状态码不得产出任何 component，现有=%v", componentKeys(rows))
				}
			case pgdb.IntelKindCredential:
				for _, r := range rows {
					if r.Kind != pgdb.IntelKindCredential {
						continue
					}
					parts := strings.Split(r.Key, "|")
					if len(parts) == 3 && intelUsernameStopwords[parts[1]] {
						t.Fatalf("停用词 %q 不得作凭据用户名: %s", parts[1], r.Key)
					}
					if strings.HasSuffix(r.Key, "|login.php") {
						t.Fatalf("凭据 service 不得是路径: %s", r.Key)
					}
				}
			}
		})
	}
}

// TestExtractTaskIntelStrictPositive 是收紧口径后的正例：请求行 + 绝对 URL 各 1 条
// endpoint，三个紧邻组件（apache/php/mariadb），一条凭据（admin@127.0.0.1:9081）。
func TestExtractTaskIntelStrictPositive(t *testing.T) {
	text := strings.Join([]string{
		"POST /dvwa/vulnerabilities/exec/ HTTP/1.1",
		"http://127.0.0.1:9081/login.php?username=admin&password=password",
		"Server: Apache/2.4.25 (Debian)",
		"X-Powered-By: PHP/7.0.30",
		"MariaDB 10.1.26",
	}, "\n")
	rows := extractTaskIntel(intelBuildInput{TaskID: 7, Findings: []pgdb.IntelFinding{{
		ID: 3, Evidence: text,
	}}})

	eps := endpointKeys(rows)
	if len(eps) != 2 {
		t.Fatalf("endpoint rows=%d, want 2: %v", len(eps), eps)
	}
	if findIntel(rows, pgdb.IntelKindEndpoint, "post /dvwa/vulnerabilities/exec/") == nil {
		t.Errorf("missing request-line endpoint: %v", eps)
	}
	if findIntel(rows, pgdb.IntelKindEndpoint, "get /login.php?password&username") == nil {
		t.Errorf("missing absolute-URL endpoint: %v", eps)
	}

	comps := componentKeys(rows)
	if len(comps) != 3 {
		t.Fatalf("component rows=%d, want 3: %v", len(comps), comps)
	}
	for _, k := range []string{"apache@2.4", "php@7.0", "mariadb@10.1"} {
		if findIntel(rows, pgdb.IntelKindComponent, k) == nil {
			t.Errorf("missing component %q: %v", k, comps)
		}
	}
	if findIntel(rows, pgdb.IntelKindComponent, "php@10.1") != nil {
		t.Errorf("PHP 不得继承 MariaDB 的版本: %v", comps)
	}

	creds := credentialKeys(rows)
	if len(creds) != 1 || creds[0] != "password|admin|127.0.0.1:9081" {
		t.Fatalf("credentials=%v, want [password|admin|127.0.0.1:9081]", creds)
	}
	if c := findIntel(rows, pgdb.IntelKindCredential, creds[0]); c.Value != "password for admin@127.0.0.1:9081" {
		t.Errorf("credential value=%q", c.Value)
	}
}

// TestTaskIntelRebuildReplacesGeneratedPG 用真实 PG 验证 rebuild 语义：删除本任务
// 由抽取生成的旧行（噪声行消失）、source=manual 保留、链接表不动、两次 rebuild
// 行数与 key 集合一致。
func TestTaskIntelRebuildReplacesGeneratedPG(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	pg := m.PG()
	ctx := context.Background()

	p, err := pg.CreateProject(pgdb.CreateProjectInput{Name: "intel-rebuild-" + strconv.FormatInt(time.Now().UnixNano(), 10)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM projects WHERE id=$1`, p.ID) })
	task, err := pg.CreateTaskWithOptions("intel rebuild task", "goal", pgdb.TaskCreateOptions{ProjectID: &p.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pg.AddFinding(task.ID, 0, "sqli", "SQL Injection on /login", "high",
		"evidence", "POST /login HTTP/1.1\r\nHost: app.example.com\r\npassword=Sup3rSecret! user=admin at 10.0.0.5",
		"worker", nil); err != nil {
		t.Fatal(err)
	}

	const noiseKey = "get //127.0.0.1:9081，Apache/2.4.25"
	if _, err := pg.UpsertTaskIntel(ctx, p.ID, task.ID, []pgdb.TaskIntel{
		{Kind: pgdb.IntelKindEndpoint, Key: noiseKey, Value: "//127.0.0.1:9081，Apache/2.4.25", Source: "finding"},
		{Kind: pgdb.IntelKindEndpoint, Key: "get /manual", Value: "manual note", Source: "manual"},
	}); err != nil {
		t.Fatal(err)
	}
	linkID, err := pg.SaveTaskIntelLink(ctx, pgdb.TaskIntelLink{
		ProjectID: p.ID, TaskID: task.ID, RelatedTaskID: task.ID + 1, Decision: "candidate",
		Reason: "matched noise before rebuild", Matched: json.RawMessage(`[{"kind":"endpoint","key":"` + noiseKey + `"}]`),
	})
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	if _, err := s.rebuildTaskIntel(ctx, task.ID); err != nil {
		t.Fatal(err)
	}
	rows, err := pg.TaskIntelForTask(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if findIntel(rows, pgdb.IntelKindEndpoint, noiseKey) != nil {
		t.Fatalf("rebuild 后噪声行仍在: %v", endpointKeys(rows))
	}
	manual := findIntel(rows, pgdb.IntelKindEndpoint, "get /manual")
	if manual == nil || manual.Source != "manual" {
		t.Fatalf("source=manual 的行必须保留: %+v", manual)
	}
	if findIntel(rows, pgdb.IntelKindEndpoint, "post /login") == nil {
		t.Errorf("rebuild 未生成 endpoint: %v", endpointKeys(rows))
	}
	if findIntel(rows, pgdb.IntelKindCredential, "password|admin|app.example.com") == nil {
		t.Errorf("rebuild 未生成 credential: %v", credentialKeys(rows))
	}

	// 链接保留、matched 原样（不级联删、不改写历史决策）。
	links, err := pg.ListTaskIntelLinks(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].ID != linkID || !strings.Contains(string(links[0].Matched), noiseKey) {
		t.Fatalf("rebuild 不得改动 task_intel_links: %+v", links)
	}

	n1, keys1 := len(rows), allIntelKeys(rows)
	if _, err := s.rebuildTaskIntel(ctx, task.ID); err != nil {
		t.Fatal(err)
	}
	rows2, err := pg.TaskIntelForTask(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	n2, keys2 := len(rows2), allIntelKeys(rows2)
	if n1 != n2 {
		t.Fatalf("两次 rebuild 行数不一致: %d != %d", n1, n2)
	}
	if strings.Join(keys1, "\n") != strings.Join(keys2, "\n") {
		t.Fatalf("两次 rebuild key 集合不一致:\n%v\n%v", keys1, keys2)
	}
}

// allIntelKeys 返回 "kind key" 的稳定列表（rows 已按 kind,key 排序）。
func allIntelKeys(rows []pgdb.TaskIntel) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Kind+" "+r.Key)
	}
	return out
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
