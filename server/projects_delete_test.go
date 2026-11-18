package server

// 项目删除（DELETE /api/projects/{id}）的两种语义：
//   - delete_tasks=false：任务保留、project_id 被 FK 置空（变为未分组）；
//   - delete_tasks=true ：旗下任务随项目一起删掉。
// PG 不可用时 skip（照既有集成测范式）。

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
)

func newProjectDeleteTestServer(t *testing.T, prefix string) (*Manager, *pgdb.Project, *pgdb.Task, *Server) {
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
	task, err := pg.CreateTaskWithOptions(prefix+" task", "项目删除语义", pgdb.TaskCreateOptions{ProjectID: &p.ID})
	if err != nil {
		t.Fatal(err)
	}
	return m, p, task, &Server{m: m, engine: NewEngine(m)}
}

func deleteProjectRequestForTest(s *Server, pid int64, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/api/projects/"+strconv.FormatInt(pid, 10), strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(pid, 10))
	rec := httptest.NewRecorder()
	s.projectsDelete(rec, req)
	return rec
}

// TestProjectDeleteKeepsTasksByDefault：不带 body 时任务保留，项目归属被置空。
func TestProjectDeleteKeepsTasksByDefault(t *testing.T) {
	m, p, task, s := newProjectDeleteTestServer(t, "proj-del-keep")
	rec := deleteProjectRequestForTest(s, p.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200 got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"tasks_kept":1`) {
		t.Fatalf("响应应报告保留 1 个任务: %s", rec.Body.String())
	}
	persisted, err := m.PG().GetTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted == nil {
		t.Fatal("任务不应被删除")
	}
	if persisted.ProjectID != nil {
		t.Fatalf("任务归属应被置空，实际 project_id=%d", *persisted.ProjectID)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(strconv.FormatInt(task.ID, 10), DeleteTaskOptions{}) })
}

// TestProjectDeleteWithDeleteTasks：delete_tasks=true 时任务随项目一起删。
func TestProjectDeleteWithDeleteTasks(t *testing.T) {
	m, p, task, s := newProjectDeleteTestServer(t, "proj-del-tasks")
	rec := deleteProjectRequestForTest(s, p.ID, `{"delete_tasks":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200 got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"tasks_deleted":1`) {
		t.Fatalf("响应应报告删除 1 个任务: %s", rec.Body.String())
	}
	persisted, err := m.PG().GetTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted != nil {
		t.Fatalf("任务应随项目删除，实际仍在: %+v", persisted)
	}
	if _, ok := m.Task(strconv.FormatInt(task.ID, 10)); ok {
		t.Fatal("内存任务注册表仍持有已删任务")
	}
}
