package db

// V9-UI 数据清理测试：
//   - 删任务时 task_intel_links 双向级联（发起方 / 被勾连方都清）
//   - 孤儿行清理幂等（第一次删掉，第二次 0 条）
//
// 库集成照仓库既有范式：连不上 PG 时 skip。

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

func newLinkTestProject(t *testing.T, d *DB, prefix string) (int64, func()) {
	t.Helper()
	name := prefix + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	p, err := d.CreateProject(CreateProjectInput{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return p.ID, func() { _, _ = d.Exec(`DELETE FROM projects WHERE id=$1`, p.ID) }
}

// TestDeleteTaskCascadeDropsIntelLinks 删任务必须带走它作为发起方和被勾连方
// 的全部勾连记录（表没有外键，此前会留下指向不存在任务的行）。
func TestDeleteTaskCascadeDropsIntelLinks(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	projectID, cleanupProject := newLinkTestProject(t, d, "link-cascade")
	defer cleanupProject()

	owner, err := d.CreateTaskWithOptions("link-owner-"+strconv.FormatInt(time.Now().UnixNano(), 10), "goal", TaskCreateOptions{ProjectID: &projectID})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := d.CreateTaskWithOptions("link-peer-"+strconv.FormatInt(time.Now().UnixNano(), 10), "goal", TaskCreateOptions{ProjectID: &projectID})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = d.Exec(`DELETE FROM task_intel_links WHERE task_id IN ($1,$2) OR related_task_id IN ($1,$2)`, owner.ID, peer.ID)
		_, _ = d.Exec(`DELETE FROM tasks WHERE id IN ($1,$2)`, owner.ID, peer.ID)
	}()

	// owner → peer（owner 是发起方）
	if _, err := d.SaveTaskIntelLink(ctx, TaskIntelLink{
		ProjectID: projectID, TaskID: owner.ID, RelatedTaskID: peer.ID,
		Decision: "adopted", Reason: "out", DecidedBy: "reader",
		Matched: json.RawMessage(`[]`),
	}); err != nil {
		t.Fatal(err)
	}
	// peer → owner（owner 是被勾连方）
	if _, err := d.SaveTaskIntelLink(ctx, TaskIntelLink{
		ProjectID: projectID, TaskID: peer.ID, RelatedTaskID: owner.ID,
		Decision: "dismissed", Reason: "in", DecidedBy: "reader",
		Matched: json.RawMessage(`[]`),
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := d.DeleteTaskCascade(owner.ID, false, false); err != nil {
		t.Fatal(err)
	}

	var left int
	if err := d.QueryRow(`SELECT COUNT(*) FROM task_intel_links WHERE task_id=$1 OR related_task_id=$1`, owner.ID).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("删任务后仍有 %d 条勾连记录指向它", left)
	}
}

// TestCleanupOrphanTaskIntelLinksIdempotent 孤儿行清理：第一次删掉本次造的
// 孤儿行，第二次执行返回 0（幂等）。
func TestCleanupOrphanTaskIntelLinksIdempotent(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	projectID, cleanupProject := newLinkTestProject(t, d, "link-orphan")
	defer cleanupProject()

	live, err := d.CreateTaskWithOptions("link-live-"+strconv.FormatInt(time.Now().UnixNano(), 10), "goal", TaskCreateOptions{ProjectID: &projectID})
	if err != nil {
		t.Fatal(err)
	}
	const ghost int64 = 990000001 // 不存在的任务 id
	defer func() {
		_, _ = d.Exec(`DELETE FROM task_intel_links WHERE task_id IN ($1,$2) OR related_task_id IN ($1,$2)`, live.ID, ghost)
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, live.ID)
	}()

	// 造两条孤儿：发起方不存在 / 被勾连方不存在。
	if _, err := d.Exec(`
INSERT INTO task_intel_links(project_id, task_id, related_task_id, decision)
VALUES ($1,$2,$3,'adopted'), ($1,$3,$2,'adopted')`, projectID, live.ID, ghost); err != nil {
		t.Fatal(err)
	}

	n, err := d.CleanupOrphanTaskIntelLinks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Fatalf("第一次清理应删除本次造的 2 条孤儿行，实际 %d", n)
	}
	var left int
	if err := d.QueryRow(`SELECT COUNT(*) FROM task_intel_links WHERE task_id=$1 OR related_task_id=$1`, ghost).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("清理后仍有 %d 条孤儿行", left)
	}

	again, err := d.CleanupOrphanTaskIntelLinks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again != 0 {
		t.Fatalf("第二次清理应幂等返回 0，实际 %d", again)
	}
}

// TestListTaskIntelLinkTracesSkipsCandidate 审计面只展示已决记录。
func TestListTaskIntelLinkTracesSkipsCandidate(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	projectID, cleanupProject := newLinkTestProject(t, d, "link-cand")
	defer cleanupProject()

	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	self, err := d.CreateTaskWithOptions("link-cand-self-"+suffix, "goal", TaskCreateOptions{ProjectID: &projectID})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := d.CreateTaskWithOptions("link-cand-peer-"+suffix, "goal", TaskCreateOptions{ProjectID: &projectID})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = d.Exec(`DELETE FROM task_intel_links WHERE task_id IN ($1,$2) OR related_task_id IN ($1,$2)`, self.ID, peer.ID)
		_, _ = d.Exec(`DELETE FROM tasks WHERE id IN ($1,$2)`, self.ID, peer.ID)
	}()

	if _, err := d.SaveTaskIntelLink(ctx, TaskIntelLink{
		ProjectID: projectID, TaskID: self.ID, RelatedTaskID: peer.ID,
		Decision: "candidate", Reason: "待判", DecidedBy: "reader",
		Matched: json.RawMessage(`[]`),
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := d.ListTaskIntelLinkTraces(ctx, self.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("candidate 不应出现在审计面，得到 %+v", rows)
	}
}
