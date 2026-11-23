package db

// 删除彻底性回归：任务/项目删掉后，所有没有外键的派生表都不能留下指向
// 已删任务的悬空 id。这个测试直接对着「线上手工清过一遍」的那几张表断言：
// task_intel / task_intel_links / reader_drills / project_index /
// project_graph_events / traffic_evidence_snapshots，以及 assets.task_ids 数组。

import (
	"fmt"
	"testing"
	"time"
)

func TestTaskDeletePurgesDerivedRowsAndDetachesAssetIDs(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	var pid int64
	if err := d.QueryRow(`INSERT INTO projects(name) VALUES('删除清理回归') RETURNING id`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteProject(pid) })

	// 上一轮失败可能留下同名资产（IP 有唯一约束），先清掉再建。
	if _, err := d.Exec(`DELETE FROM assets WHERE ip='10.99.99.99'`); err != nil {
		t.Fatal(err)
	}

	a, err := d.CreateTaskWithOptions("清理A", "目标A", TaskCreateOptions{ProjectID: &pid})
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.CreateTaskWithOptions("清理B", "目标B", TaskCreateOptions{ProjectID: &pid})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.DeleteTaskCascadeOptions(a.ID, TaskDeleteOptions{DeleteAssets: true, DeleteFindings: true}) })
	t.Cleanup(func() { _, _ = d.DeleteTaskCascadeOptions(b.ID, TaskDeleteOptions{DeleteAssets: true, DeleteFindings: true}) })

	// 资产同时挂两个任务：删 B 后数组里不能还留着 B 的 id。
	var aid int64
	if err := d.QueryRow(`INSERT INTO assets(type, ip, task_ids)
VALUES('ip','10.99.99.99', ARRAY[$1,$2]::bigint[]) RETURNING id`, a.ID, b.ID).Scan(&aid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, aid) })

	// A 的情报 / 下钻；A→B 的勾连；A 的图谱投影与事件。
	if _, err := d.Exec(`INSERT INTO task_intel(project_id,task_id,kind,key,match_key,value,source)
VALUES ($1,$2,'asset','10.99.99.99','10.99.99.99','10.99.99.99','manual')`, pid, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO task_intel_links(project_id,task_id,related_task_id,decision)
VALUES ($1,$2,$3,'adopted')`, pid, a.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO reader_drills(project_id,task_id,related_task_id,query)
VALUES ($1,$2,$3,'怎么打')`, pid, a.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO project_index(project_id,task_id,node_id,kind)
VALUES ($1,$2,990001,'fact')`, pid, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO project_graph_events(project_id,task_id,node_id,kind)
VALUES ($1,$2,990001,'fact')`, pid, a.ID); err != nil {
		t.Fatal(err)
	}

	// 漏洞 + 流量证据快照（快照没有 task_id，只能靠 binding 找到）。
	var fid int64
	if err := d.QueryRow(`INSERT INTO findings(task_id,name) VALUES($1,'测试漏洞') RETURNING id`, a.ID).Scan(&fid); err != nil {
		t.Fatal(err)
	}
	// 快照 id 带时间戳：测试库是共享的，旧的失败残留可能仍绑着同名快照。
	sid := fmt.Sprintf("snap-delete-test-%d", time.Now().UnixNano())
	if _, err := d.Exec(`INSERT INTO traffic_evidence_snapshots(id,source_traffic_id,captured_at,url,method,status,req_head,resp_head,req_hash,resp_hash,req_len,resp_len)
VALUES($1,'t-1',1,'http://x/','GET',200,'','','rh','sh',0,0)`, sid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM traffic_evidence_snapshots WHERE id=$1`, sid) })
	if _, err := d.Exec(`INSERT INTO finding_traffic_bindings(finding_id,snapshot_id,position)
VALUES($1,$2,0)`, fid, sid); err != nil {
		t.Fatal(err)
	}

	// 1) 删 B（默认开关）：勾连记录必须双向清掉——对端已不存在；资产数组摘 B；
	//    A 自己的情报/下钻保留（B 已被删时查询层会过滤掉悬空链接）。
	if _, err := d.DeleteTaskCascadeOptions(b.ID, TaskDeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, d, `SELECT count(*) FROM task_intel_links WHERE task_id=$1 OR related_task_id=$1`, b.ID); n != 0 {
		t.Fatalf("task_intel_links 仍有 %d 行指向已删任务 B", n)
	}
	var arrText string
	if err := d.QueryRow(`SELECT task_ids::text FROM assets WHERE id=$1`, aid).Scan(&arrText); err != nil {
		t.Fatal(err)
	}
	taskIDs := parsePGIntArray(arrText)
	for _, id := range taskIDs {
		if id == b.ID {
			t.Fatal("assets.task_ids 仍包含已删任务 B 的 id（悬空引用）")
		}
	}
	if n := countRows(t, d, `SELECT count(*) FROM task_intel WHERE task_id=$1`, a.ID); n != 1 {
		t.Fatalf("未勾删除情报时 A 的情报应保留，实际 %d 行", n)
	}
	if n := countRows(t, d, `SELECT count(*) FROM reader_drills WHERE task_id=$1`, a.ID); n != 1 {
		t.Fatalf("未勾删除情报时 A 的下钻应保留，实际 %d 行", n)
	}
	// 审计接口不能返回参考任务已删的记录（否则前端链接指向空页）。
	if drills, err := d.ListReaderDrills(t.Context(), a.ID); err != nil {
		t.Fatal(err)
	} else if len(drills) != 0 {
		t.Fatalf("ListReaderDrills 应过滤已删参考任务，实际返回 %d 行", len(drills))
	}

	// 2) 删 A 并勾全量清理：派生表、漏洞、快照必须全部归零。
	res, err := d.DeleteTaskCascadeOptions(a.ID, TaskDeleteOptions{
		DeleteAssets: true, DeleteFindings: true, DeleteIntel: true, DeleteProjectGraph: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IntelDeleted != 1 || res.DrillsDeleted != 1 || res.GraphIndexDeleted != 1 || res.GraphEventsDeleted != 1 {
		t.Fatalf("派生清理计数不符: %+v", res)
	}
	if res.FindingsDeleted != 1 || res.SnapshotsDeleted != 1 {
		t.Fatalf("漏洞/快照清理计数不符: %+v", res)
	}
	for _, q := range []string{
		`SELECT count(*) FROM task_intel WHERE task_id=$1`,
		`SELECT count(*) FROM reader_drills WHERE task_id=$1`,
		`SELECT count(*) FROM project_index WHERE task_id=$1`,
		`SELECT count(*) FROM project_graph_events WHERE task_id=$1`,
		`SELECT count(*) FROM findings WHERE task_id=$1`,
	} {
		if n := countRows(t, d, q, a.ID); n != 0 {
			t.Fatalf("删除后仍残留 %d 行: %s", n, q)
		}
	}
	if n := countRows(t, d, `SELECT count(*) FROM traffic_evidence_snapshots WHERE id=$1`, sid); n != 0 {
		t.Fatal("漏洞删掉后其流量证据快照仍残留")
	}
	if n := countRows(t, d, `SELECT count(*) FROM assets WHERE id=$1`, aid); n != 0 {
		t.Fatal("勾选删除资产后资产仍存在")
	}
}

func TestDeleteProjectPurgesProjectScopedDerivedRows(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	var pid int64
	if err := d.QueryRow(`INSERT INTO projects(name) VALUES('项目清理回归') RETURNING id`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	tk, err := d.CreateTaskWithOptions("项目内任务", "目标", TaskCreateOptions{ProjectID: &pid})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.DeleteTaskCascadeOptions(tk.ID, TaskDeleteOptions{}) })

	if _, err := d.Exec(`INSERT INTO task_intel(project_id,task_id,kind,key,match_key,value,source)
VALUES ($1,$2,'asset','x','x','x','manual')`, pid, tk.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO project_index(project_id,task_id,node_id,kind)
VALUES ($1,$2,990002,'fact')`, pid, tk.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO project_graph_events(project_id,task_id,node_id,kind)
VALUES ($1,$2,990002,'fact')`, pid, tk.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO reader_drills(project_id,task_id,related_task_id)
VALUES ($1,$2,$2)`, pid, tk.ID); err != nil {
		t.Fatal(err)
	}

	if err := d.DeleteProject(pid); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`SELECT count(*) FROM project_index WHERE project_id=$1`,
		`SELECT count(*) FROM project_graph_events WHERE project_id=$1`,
		`SELECT count(*) FROM task_intel WHERE project_id=$1`,
		`SELECT count(*) FROM task_intel_links WHERE project_id=$1`,
		`SELECT count(*) FROM reader_drills WHERE project_id=$1`,
	} {
		if n := countRows(t, d, q, pid); n != 0 {
			t.Fatalf("项目删除后仍残留 %d 行: %s", n, q)
		}
	}
	// 任务按 FK SET NULL 保留（这次没勾 delete_tasks）。
	kept, _ := d.GetTask(tk.ID)
	if kept == nil {
		t.Fatal("未勾删除任务时任务不应被删")
	}
	if kept.ProjectID != nil {
		t.Fatal("项目删除后任务 project_id 应被置空")
	}
}

func countRows(t *testing.T, d *DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := d.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("count query failed (%s): %v", q, err)
	}
	return n
}
