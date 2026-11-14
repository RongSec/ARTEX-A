package server

// V8-INTEL3：任务小结接口与覆盖率审计的集成测试（真实 PG）。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
)

// newIntelTestTask 建一个挂项目的任务（PG 不可用则 skip）。
func newIntelTestTask(t *testing.T, prefix string) (*Manager, *pgdb.Project, *pgdb.Task, *Server) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	pg := m.PG()
	p, err := pg.CreateProject(pgdb.CreateProjectInput{Name: prefix + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM projects WHERE id=$1`, p.ID) })
	task, err := pg.CreateTaskWithOptions(prefix+" task", "验证命令注入", pgdb.TaskCreateOptions{ProjectID: &p.ID})
	if err != nil {
		t.Fatal(err)
	}
	return m, p, task, &Server{m: m, jwtKey: []byte("test-key")}
}

// TestTaskIntelSummaryAPI 断言任务小结返回 summary + 五组结构化字段（含空组 []）。
func TestTaskIntelSummaryAPI(t *testing.T) {
	_, p, task, s := newIntelTestTask(t, "intel-summary")
	ctx := context.Background()
	if _, err := s.m.pg.AddFinding(task.ID, 0, "cmdi", "DVWA 命令注入", "critical",
		"命令注入验证入口", "GET /login.php 返回 200\n\nPOST /vulnerabilities/exec/ HTTP/1.1\nHost: 127.0.0.1:9081\nip=127.0.0.1",
		"worker", nil); err != nil {
		t.Fatal(err)
	}
	detail, _ := json.Marshal(map[string]any{
		"count": 2, "methods": []string{"post"}, "hosts": []string{"127.0.0.1:9081"},
		"purpose": "命令注入验证入口", "params": []string{"ip"},
		"status_codes": []int{200}, "auth_required": true,
		"finding_ids": []int64{1}, "fact_node_ids": []int64{119},
	})
	credDetail, _ := json.Marshal(map[string]any{
		"count": 1, "secret_masked": "pa****rd", "where_used": []string{"/login.php"},
	})
	if _, err := s.m.pg.UpsertTaskIntel(ctx, p.ID, task.ID, []pgdb.TaskIntel{
		{Kind: pgdb.IntelKindEndpoint, Key: "post /vulnerabilities/exec/", Value: "/vulnerabilities/exec/", Detail: detail, Source: "fact"},
		{Kind: pgdb.IntelKindCredential, Key: "password|admin|127.0.0.1:9081", Value: "password for admin@127.0.0.1:9081", Detail: credDetail, Source: "fact"},
		{Kind: pgdb.IntelKindAsset, Key: "127.0.0.1:9081", Value: "127.0.0.1:9081", Source: "asset"},
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/tasks/"+strconv.FormatInt(task.ID, 10)+"/intel", nil)
	req.SetPathValue("id", strconv.FormatInt(task.ID, 10))
	rec := httptest.NewRecorder()
	s.taskIntelList(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		TaskID  int64             `json:"task_id"`
		Total   int               `json:"total"`
		Summary *taskIntelSummary `json:"summary"`
		Groups  struct {
			Endpoint   []intelEndpointItem   `json:"endpoint"`
			Credential []intelCredentialItem `json:"credential"`
			Component  []intelComponentItem  `json:"component"`
			Asset      []intelAssetItem      `json:"asset"`
			Vuln       []intelVulnItem       `json:"vuln"`
		} `json:"groups"`
		LegacyGroups []IntelGroup `json:"legacy_groups"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.TaskID != task.ID || resp.Total != 3 {
		t.Fatalf("task_id=%d total=%d", resp.TaskID, resp.Total)
	}
	if resp.Summary == nil {
		t.Fatal("summary 缺失")
	}
	if resp.Summary.Name != task.Name || resp.Summary.Goal != "验证命令注入" || resp.Summary.Status != task.Status {
		t.Errorf("summary 任务字段=%+v", resp.Summary)
	}
	if resp.Summary.ProjectID != p.ID || resp.Summary.ProjectName != p.Name {
		t.Errorf("summary 项目字段=%+v，want id=%d name=%q", resp.Summary, p.ID, p.Name)
	}
	if resp.Summary.StartedAt == nil {
		t.Error("started_at 不应为空")
	}
	if resp.Summary.Counts["finding"] != 1 || resp.Summary.Counts["endpoint"] != 1 ||
		resp.Summary.Counts["credential"] != 1 || resp.Summary.Counts["asset"] != 1 {
		t.Errorf("counts=%v", resp.Summary.Counts)
	}
	if _, ok := resp.Summary.Counts["intent"]; !ok {
		t.Errorf("counts 缺 intent: %v", resp.Summary.Counts)
	}

	// 空组必须是 []（不是 null）：前端固定渲染五张表。
	if resp.Groups.Component == nil || len(resp.Groups.Component) != 0 {
		t.Errorf("空组必须为 []: %+v", resp.Groups.Component)
	}
	if resp.Groups.Vuln == nil {
		t.Error("vuln 组不得为 null")
	}
	if len(resp.Groups.Endpoint) != 1 {
		t.Fatalf("endpoint 组=%+v", resp.Groups.Endpoint)
	}
	ep := resp.Groups.Endpoint[0]
	if ep.Method != "post" || ep.Path != "/vulnerabilities/exec/" {
		t.Errorf("endpoint method/path=%q %q", ep.Method, ep.Path)
	}
	if ep.Purpose != "命令注入验证入口" || ep.HitCount != 2 || !ep.AuthRequired {
		t.Errorf("endpoint 用途/次数/鉴权=%+v", ep)
	}
	if len(ep.Hosts) != 1 || ep.Hosts[0] != "127.0.0.1:9081" {
		t.Errorf("endpoint hosts=%v", ep.Hosts)
	}
	if len(ep.StatusCodes) != 1 || ep.StatusCodes[0] != 200 || len(ep.Params) != 1 || ep.Params[0] != "ip" {
		t.Errorf("endpoint 状态码/参数=%+v", ep)
	}
	if len(ep.Evidence) != 1 || ep.Evidence[0].FindingID == nil ||
		*ep.Evidence[0].FindingID != 1 || ep.Evidence[0].FactNodeID == nil || *ep.Evidence[0].FactNodeID != 119 {
		t.Errorf("endpoint evidence=%+v", ep.Evidence)
	}

	cred := resp.Groups.Credential[0]
	if cred.CredentialType != "password" || cred.Username != "admin" || cred.Service != "127.0.0.1:9081" {
		t.Errorf("credential=%+v", cred)
	}
	if cred.SecretMasked != "pa****rd" || len(cred.WhereUsed) != 1 || cred.WhereUsed[0] != "/login.php" {
		t.Errorf("credential 脱敏/使用位置=%+v", cred)
	}
	if strings.Contains(cred.Value, "password for") == false {
		t.Errorf("credential value=%q", cred.Value)
	}
	asset := resp.Groups.Asset[0]
	if asset.Host != "127.0.0.1" || asset.Port != 9081 {
		t.Errorf("asset=%+v", asset)
	}
	if len(resp.LegacyGroups) != len(intelGroupOrder) {
		t.Errorf("legacy_groups 应保留旧分组结构: %d", len(resp.LegacyGroups))
	}
}

// TestTaskIntelAPINotFound 任务不存在返回 404（两个接口一致）。
func TestTaskIntelAPINotFound(t *testing.T) {
	_, _, _, s := newIntelTestTask(t, "intel-404")
	const missing = "99999999"
	for name, h := range map[string]func(w *httptest.ResponseRecorder, r *http.Request){
		"list":     func(w *httptest.ResponseRecorder, r *http.Request) { s.taskIntelList(w, r) },
		"coverage": func(w *httptest.ResponseRecorder, r *http.Request) { s.taskIntelCoverage(w, r) },
	} {
		req := httptest.NewRequest("GET", "/api/tasks/"+missing+"/intel", nil)
		req.SetPathValue("id", missing)
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != 404 {
			t.Errorf("%s: status=%d, want 404 (body=%s)", name, rec.Code, rec.Body.String())
		}
	}
}

// TestTaskIntelCoverageAPI 断言覆盖率：正文 3 条、表里 2 条 → 67% + 1 条 missing。
func TestTaskIntelCoverageAPI(t *testing.T) {
	_, p, task, s := newIntelTestTask(t, "intel-coverage")
	ctx := context.Background()
	findingID, err := s.m.pg.AddFinding(task.ID, 0, "cmdi", "命令注入", "high", "注入验证",
		strings.Join([]string{
			"GET /a.php 返回 200",
			"",
			"POST /b.php HTTP/1.1",
			"Host: 127.0.0.1:9081",
			"",
			"GET /c.php 返回 403",
		}, "\n"), "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.UpsertTaskIntel(ctx, p.ID, task.ID, []pgdb.TaskIntel{
		{Kind: pgdb.IntelKindEndpoint, Key: "get /a.php", Value: "/a.php", Source: "finding"},
		{Kind: pgdb.IntelKindEndpoint, Key: "get /c.php", Value: "/c.php", Source: "finding"},
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/tasks/"+strconv.FormatInt(task.ID, 10)+"/intel/coverage", nil)
	req.SetPathValue("id", strconv.FormatInt(task.ID, 10))
	rec := httptest.NewRecorder()
	s.taskIntelCoverage(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp intelCoverageResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Seen != 3 || resp.Captured != 2 || resp.CoveragePct != 67 {
		t.Fatalf("seen/captured/pct=%d/%d/%d, want 3/2/67", resp.Seen, resp.Captured, resp.CoveragePct)
	}
	if len(resp.Missing) != 1 || resp.Missing[0].Path != "/b.php" || resp.Missing[0].Method != "post" {
		t.Fatalf("missing=%+v", resp.Missing)
	}
	if !strings.Contains(resp.Missing[0].Evidence, "finding#"+strconv.FormatInt(findingID, 10)) ||
		!strings.Contains(resp.Missing[0].Evidence, "/b.php") {
		t.Errorf("missing evidence=%q", resp.Missing[0].Evidence)
	}
	if len(resp.Notes) == 0 {
		t.Error("notes 不应为空")
	}
}

// TestTaskIntelCoverageEmptyTask 无 fact/finding：seen=0、pct=100 并说明。
func TestTaskIntelCoverageEmptyTask(t *testing.T) {
	_, _, task, s := newIntelTestTask(t, "intel-coverage-empty")
	req := httptest.NewRequest("GET", "/api/tasks/"+strconv.FormatInt(task.ID, 10)+"/intel/coverage", nil)
	req.SetPathValue("id", strconv.FormatInt(task.ID, 10))
	rec := httptest.NewRecorder()
	s.taskIntelCoverage(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp intelCoverageResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Seen != 0 || resp.Captured != 0 || resp.CoveragePct != 100 {
		t.Fatalf("seen/captured/pct=%d/%d/%d", resp.Seen, resp.Captured, resp.CoveragePct)
	}
	if len(resp.Notes) == 0 || !strings.Contains(strings.Join(resp.Notes, ";"), "无 fact/finding") {
		t.Errorf("notes=%v", resp.Notes)
	}
	if resp.Missing == nil {
		t.Error("missing 必须是 [] 不是 null")
	}
}

// TestTaskIntelRebuildAssetPortPG 断言 rebuild 用带端口的新资产行替换旧的无端口行，
// 且两次 rebuild 行数/键集合一致。
func TestTaskIntelRebuildAssetPortPG(t *testing.T) {
	_, p, task, s := newIntelTestTask(t, "intel-asset-port")
	ctx := context.Background()
	if _, err := s.m.pg.Assets().UpsertHTTPService(pgdb.UpsertHTTPServiceReq{
		URL: "http://127.0.0.1:9081/login.php", TaskID: task.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.UpsertTaskIntel(ctx, p.ID, task.ID, []pgdb.TaskIntel{
		{Kind: pgdb.IntelKindAsset, Key: "127.0.0.1", Value: "127.0.0.1", Source: "asset"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.rebuildTaskIntel(ctx, task.ID); err != nil {
		t.Fatal(err)
	}
	rows, err := s.m.pg.TaskIntelForTask(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if findIntel(rows, pgdb.IntelKindAsset, "127.0.0.1") != nil {
		t.Errorf("旧的无端口 asset 行未被替换: %v", assetKeys(rows))
	}
	if findIntel(rows, pgdb.IntelKindAsset, "127.0.0.1:9081") == nil {
		t.Errorf("新 asset 行应有端口: %v", assetKeys(rows))
	}

	n1, keys1 := len(rows), allIntelKeys(rows)
	if _, err := s.rebuildTaskIntel(ctx, task.ID); err != nil {
		t.Fatal(err)
	}
	rows2, err := s.m.pg.TaskIntelForTask(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows2) != n1 || strings.Join(allIntelKeys(rows2), "\n") != strings.Join(keys1, "\n") {
		t.Fatalf("两次 rebuild 不一致: %d/%v vs %d/%v", n1, keys1, len(rows2), allIntelKeys(rows2))
	}
}
