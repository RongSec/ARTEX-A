package db

// 项目级约束回归：录入 → 复制进任务 → 去重 → 项目删除级联。
// 这是「项目/任务创建口径统一」的数据底座：项目约束必须每次下发都稳定复制，
// 且不能因为重复下发在同一个任务里堆两遍。

import (
	"testing"
)

func TestProjectConstraintsCopyToTaskAndCascade(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	var pid int64
	if err := d.QueryRow(`INSERT INTO projects(name) VALUES('项目约束回归') RETURNING id`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteProject(pid) })

	items := []ConstraintInput{
		{Kind: "allow", Text: "只允许测试 10.88.0.1 的 443"},
		{Kind: "deny", Text: "禁止爆破同一账号超过 3 次"},
		{Kind: "deny", Text: "不得删改生产数据"},
	}
	if _, err := d.ReplaceProjectConstraints(pid, items); err != nil {
		t.Fatal(err)
	}
	got, err := d.ListProjectConstraints(pid)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("项目约束应为 3 条，实际 %d", len(got))
	}
	if got[0].Kind != "allow" {
		t.Fatalf("allow 应排在前，实际首条=%+v", got[0])
	}

	tk, err := d.CreateTaskWithOptions("约束复制任务", "10.88.0.1", TaskCreateOptions{ProjectID: &pid})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.DeleteTaskCascadeOptions(tk.ID, TaskDeleteOptions{DeleteIntel: true, DeleteProjectGraph: true}) })

	n, err := d.CopyProjectConstraintsToTask(pid, tk.ExplorationID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("首次复制应写 3 条，实际 %d", n)
	}
	// 再复制一次：按 kind+text 去重，必须 0 新增。
	n, err = d.CopyProjectConstraintsToTask(pid, tk.ExplorationID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("重复复制应去重为 0，实际 %d", n)
	}
	// 任务内再手工塞同一条：也不应重复。
	n, err = d.InsertTaskConstraints(tk.ExplorationID, []ConstraintInput{{Kind: "deny", Text: "不得删改生产数据"}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("相同约束不应重复写入，实际新增 %d", n)
	}

	var total, fromProject int
	if err := d.QueryRow(`SELECT count(*), count(*) FILTER (WHERE origin='project')
FROM task_constraints WHERE exploration_id=$1`, tk.ExplorationID).Scan(&total, &fromProject); err != nil {
		t.Fatal(err)
	}
	if total != 3 || fromProject != 3 {
		t.Fatalf("任务约束应为 3 条且都来自项目，实际 total=%d project=%d", total, fromProject)
	}

	// 项目删除：project_constraints 必须随 FK 级联清掉（任务保留，任务约束不清）。
	if err := d.DeleteProject(pid); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := d.QueryRow(`SELECT count(*) FROM project_constraints WHERE project_id=$1`, pid).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("项目删除后项目约束仍残留 %d 条", left)
	}
	var taskCons int
	if err := d.QueryRow(`SELECT count(*) FROM task_constraints WHERE exploration_id=$1`, tk.ExplorationID).Scan(&taskCons); err != nil {
		t.Fatal(err)
	}
	if taskCons != 3 {
		t.Fatalf("项目删除不应连带删任务约束，实际 %d", taskCons)
	}
}
