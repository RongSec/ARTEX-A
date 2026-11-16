package server

// V8-NAME / V9-UI 测试：任务视角的阅读者勾连审计接口。
// 四类用例：已决记录的双向分组、只有入向、全空不报错、candidate 不进审计面。
// 库集成照仓库 testDSN 范式：连不上 PG 时 skip。

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	pgdb "github.com/Autumn-27/artex/db"
)

// newReaderTraceTestTask 建一个带独立项目的任务，返回任务与清理函数。
func newReaderTraceTestTask(t *testing.T, pg *pgdb.DB, projectID *int64, name string) *pgdb.Task {
	t.Helper()
	task, err := pg.CreateTaskWithOptions(name, "goal", pgdb.TaskCreateOptions{ProjectID: projectID})
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func TestTaskReaderTracesGrouping(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	pg := m.PG()
	ctx := t.Context()

	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	pa, err := pg.CreateProject(pgdb.CreateProjectInput{Name: "rt-a-" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	pb, err := pg.CreateProject(pgdb.CreateProjectInput{Name: "rt-b-" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM projects WHERE id IN ($1,$2)`, pa.ID, pb.ID) })

	self := newReaderTraceTestTask(t, pg, &pa.ID, "rt-self-"+suffix)
	peerSame := newReaderTraceTestTask(t, pg, &pa.ID, "rt-peer-same-"+suffix)
	peerCross := newReaderTraceTestTask(t, pg, &pb.ID, "rt-peer-cross-"+suffix)
	peerPending := newReaderTraceTestTask(t, pg, &pb.ID, "rt-peer-pending-"+suffix)
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM task_intel_links WHERE task_id IN ($1,$2,$3,$4) OR related_task_id IN ($1,$2,$3,$4)`,
			self.ID, peerSame.ID, peerCross.ID, peerPending.ID)
		_, _ = pg.Exec(`DELETE FROM llm_records WHERE COALESCE(task_id,'')=$1`, i64s(self.ID))
	})

	// 本任务 → 同项目对端（out，adopted，有命中明细）
	if _, err := pg.SaveTaskIntelLink(ctx, db.TaskIntelLink{
		ProjectID: pa.ID, TaskID: self.ID, RelatedTaskID: peerSame.ID,
		Decision: "adopted", Reason: "同组件", DecidedBy: "reader",
		Matched: json.RawMessage(`[{"kind":"component","key":"canal@1.1","value":"Canal 1.1.5"}]`),
	}); err != nil {
		t.Fatal(err)
	}
	// V9-SCOPE：采纳带进来的外部资产 host，审计接口必须逐条展示。
	if _, err := pg.RecordTaskForeignAssets(ctx, self.ID, peerSame.ID, []string{"10.0.0.9"}); err != nil {
		t.Fatal(err)
	}
	// 本任务 → 跨项目对端（out，adopted）
	if _, err := pg.SaveTaskIntelLink(ctx, db.TaskIntelLink{
		ProjectID: pa.ID, TaskID: self.ID, RelatedTaskID: peerCross.ID,
		Decision: "adopted", Reason: "同接口", DecidedBy: "reader",
		Matched: json.RawMessage(`[{"kind":"endpoint","key":"get /login","value":"/login"}]`),
	}); err != nil {
		t.Fatal(err)
	}
	// 本任务 → 另一个跨项目对端（out，candidate）：中间态，接口层必须过滤掉
	if _, err := pg.SaveTaskIntelLink(ctx, db.TaskIntelLink{
		ProjectID: pa.ID, TaskID: self.ID, RelatedTaskID: peerPending.ID,
		Decision: "candidate", Reason: "待判",
		Matched: json.RawMessage(`[{"kind":"endpoint","key":"get /admin","value":"/admin"}]`),
	}); err != nil {
		t.Fatal(err)
	}
	// 同项目对端 → 本任务（in，dismissed）
	if _, err := pg.SaveTaskIntelLink(ctx, db.TaskIntelLink{
		ProjectID: pa.ID, TaskID: peerSame.ID, RelatedTaskID: self.ID,
		Decision: "dismissed", Reason: "误报",
		Matched: json.RawMessage(`[]`),
	}); err != nil {
		t.Fatal(err)
	}

	// 阅读者运行记录（有 text 时 summary 取首行）。
	if err := pg.InsertLLMRecord(&db.LLMRecord{
		TaskID: i64s(self.ID), Worker: "reader", SessionID: "conv-rt", Status: "ok",
		ResponseBody: `{"text":"跨项目串联完成\n细节略"}`,
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m, jwtKey: []byte("test-key")}
	req := httptest.NewRequest("GET", "/api/tasks/"+i64s(self.ID)+"/reader-traces", nil)
	req.SetPathValue("id", i64s(self.ID))
	rec := httptest.NewRecorder()
	s.taskReaderTraces(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		TaskID       int64             `json:"task_id"`
		CrossTask    []ReaderTraceItem `json:"cross_task"`
		CrossProject []ReaderTraceItem `json:"cross_project"`
		Runs         []db.ReaderLLMRun `json:"runs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.TaskID != self.ID {
		t.Fatalf("task_id=%d", resp.TaskID)
	}
	if len(resp.CrossTask) != 2 {
		t.Fatalf("cross_task=%d want 2: %+v", len(resp.CrossTask), resp.CrossTask)
	}
	if len(resp.CrossProject) != 1 {
		t.Fatalf("cross_project=%d want 1: %+v", len(resp.CrossProject), resp.CrossProject)
	}
	// 时间倒序：最后写入的 in 记录在最前。
	if resp.CrossTask[0].Direction != "in" || resp.CrossTask[0].RelatedTaskID != peerSame.ID {
		t.Fatalf("cross_task[0]=%+v want in/%d", resp.CrossTask[0], peerSame.ID)
	}
	if resp.CrossTask[1].Direction != "out" || resp.CrossTask[1].Decision != "adopted" {
		t.Fatalf("cross_task[1]=%+v", resp.CrossTask[1])
	}
	if resp.CrossTask[1].RelatedProjectName != pa.Name {
		t.Fatalf("related project name=%q want %q", resp.CrossTask[1].RelatedProjectName, pa.Name)
	}
	if resp.CrossTask[1].DecidedBy != "reader" {
		t.Fatalf("decided_by=%q want reader", resp.CrossTask[1].DecidedBy)
	}
	if len(resp.CrossTask[1].Matched) != 1 || resp.CrossTask[1].Matched[0].Kind != "component" {
		t.Fatalf("matched=%+v", resp.CrossTask[1].Matched)
	}
	// V9-SCOPE：采纳记录带 foreign_hosts；非采纳（in/dismissed）为空数组。
	if len(resp.CrossTask[1].ForeignHosts) != 1 || resp.CrossTask[1].ForeignHosts[0] != "10.0.0.9" {
		t.Fatalf("adopted foreign_hosts=%v want [10.0.0.9]", resp.CrossTask[1].ForeignHosts)
	}
	if resp.CrossTask[0].ForeignHosts == nil || len(resp.CrossTask[0].ForeignHosts) != 0 {
		t.Fatalf("dismissed foreign_hosts 应为空数组，got %v", resp.CrossTask[0].ForeignHosts)
	}
	if resp.CrossProject[0].RelatedTaskID != peerCross.ID || resp.CrossProject[0].RelatedProjectID != pb.ID {
		t.Fatalf("cross_project[0]=%+v", resp.CrossProject[0])
	}
	// V9-UI：candidate 是阅读者下钻的中间态，不能出现在审计面。
	for _, item := range append(append([]ReaderTraceItem{}, resp.CrossTask...), resp.CrossProject...) {
		if item.Decision == "candidate" {
			t.Fatalf("审计面不应包含 candidate: %+v", item)
		}
		if item.RelatedTaskID == peerPending.ID {
			t.Fatalf("candidate 对端任务不应出现: %+v", item)
		}
	}
	if len(resp.Runs) != 1 || resp.Runs[0].Worker != "reader" || resp.Runs[0].Summary != "跨项目串联完成" {
		t.Fatalf("runs=%+v", resp.Runs)
	}
}

// TestTaskReaderTracesInboundOnly 只有别人勾连本任务的记录（in），也必须出现在
// 对应分组里，且方向正确。
func TestTaskReaderTracesInboundOnly(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	pg := m.PG()
	ctx := t.Context()

	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	p, err := pg.CreateProject(pgdb.CreateProjectInput{Name: "rt-in-" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM projects WHERE id=$1`, p.ID) })
	self := newReaderTraceTestTask(t, pg, &p.ID, "rt-in-self-"+suffix)
	peer := newReaderTraceTestTask(t, pg, &p.ID, "rt-in-peer-"+suffix)
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM task_intel_links WHERE task_id IN ($1,$2) OR related_task_id IN ($1,$2)`, self.ID, peer.ID)
	})

	if _, err := pg.SaveTaskIntelLink(ctx, db.TaskIntelLink{
		ProjectID: p.ID, TaskID: peer.ID, RelatedTaskID: self.ID,
		Decision: "adopted", Reason: "复用组件", DecidedBy: "reader",
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m, jwtKey: []byte("test-key")}
	req := httptest.NewRequest("GET", "/api/tasks/"+i64s(self.ID)+"/reader-traces", nil)
	req.SetPathValue("id", i64s(self.ID))
	rec := httptest.NewRecorder()
	s.taskReaderTraces(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		CrossTask    []ReaderTraceItem `json:"cross_task"`
		CrossProject []ReaderTraceItem `json:"cross_project"`
		Runs         []db.ReaderLLMRun `json:"runs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.CrossTask) != 1 || resp.CrossTask[0].Direction != "in" {
		t.Fatalf("cross_task=%+v", resp.CrossTask)
	}
	if len(resp.CrossProject) != 0 {
		t.Fatalf("cross_project=%+v want empty", resp.CrossProject)
	}
	if len(resp.Runs) != 0 {
		t.Fatalf("runs=%+v want empty", resp.Runs)
	}
}

// TestTaskReaderTracesEmpty 全空：两组都是空数组、runs 空数组、HTTP 200。
func TestTaskReaderTracesEmpty(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	pg := m.PG()

	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	task, err := pg.CreateTaskWithOptions("rt-empty-"+suffix, "goal", pgdb.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID) })

	s := &Server{m: m, jwtKey: []byte("test-key")}
	req := httptest.NewRequest("GET", "/api/tasks/"+i64s(task.ID)+"/reader-traces", nil)
	req.SetPathValue("id", i64s(task.ID))
	rec := httptest.NewRecorder()
	s.taskReaderTraces(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		CrossTask    []ReaderTraceItem `json:"cross_task"`
		CrossProject []ReaderTraceItem `json:"cross_project"`
		Runs         []db.ReaderLLMRun `json:"runs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.CrossTask == nil || resp.CrossProject == nil || resp.Runs == nil {
		t.Fatalf("empty response must use arrays, got %+v", resp)
	}
	if len(resp.CrossTask)+len(resp.CrossProject)+len(resp.Runs) != 0 {
		t.Fatalf("want all empty: %+v", resp)
	}
}
