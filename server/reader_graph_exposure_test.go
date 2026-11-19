package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestAdoptedReaderLinkIsNotScopeInheritance 验证新的阅读者暴露口径：
//
//   - 采纳（task_intel_links.decision=adopted）**不**进入 DirectSourceStores：
//     对方整张图（含资产上下文）不会被当前任务继承；
//   - 但进入 ReaderRefs：给出概览 + 接口表（无 host）+ 可下钻 id；
//   - 下钻只对被采纳的任务开放，未采纳的任务取不到；
//   - 跨项目不暴露。
func TestAdoptedReaderLinkIsNotScopeInheritance(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	// Cleanup 在测试函数返回后才跑，defer m.Close() 会先关库导致清理全部失败
	// （实测：每跑一次就在库里多三条空任务）。注册成 Cleanup 让它最后执行。
	t.Cleanup(func() { _ = m.Close() })

	proj, err := m.pg.CreateProject(db.CreateProjectInput{Name: "_reader_exposure_probe", Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM projects WHERE id=$1`, proj.ID) })

	owner, err := m.CreateTaskWithOptions("owner", "owner goal", db.TaskCreateOptions{ProjectID: &proj.ID})
	if err != nil {
		t.Fatal(err)
	}
	source, err := m.CreateTaskWithOptions("source", "source goal", db.TaskCreateOptions{ProjectID: &proj.ID})
	if err != nil {
		t.Fatal(err)
	}
	other, err := m.CreateTaskWithOptions("other", "other goal", db.TaskCreateOptions{ProjectID: &proj.ID})
	if err != nil {
		t.Fatal(err)
	}
	// 用 SQL 清理：DeleteTask(空 options) 对 created 状态的任务不落删除，会在
	// 生产库里留下 owner/source/other 三条空任务（实测踩过）。
	t.Cleanup(func() { purgeTestProject(m, proj.ID) })

	ownerID := mustTaskID(t, owner.ID)
	sourceID := mustTaskID(t, source.ID)
	otherID := mustTaskID(t, other.ID)

	// 来源任务写一条含 host 的 finding + 一条接口情报，用来验证「脱敏可见」。
	findingID, err := source.Store.AddNode(db.KindFinding, map[string]any{
		"summary":  "OA 登录口 SQL 注入 @ oa.example-corp.com",
		"severity": "high",
		"evidence": "GET http://oa.example-corp.com:8080/api/login?user=admin 返回 200，password=Passw0rd!",
	}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.Exec(`INSERT INTO task_intel(project_id, task_id, kind, key, value, source)
VALUES ($1,$2,'endpoint','post /api/login','POST https://oa.example-corp.com/api/login','finding')`,
		proj.ID, sourceID); err != nil {
		t.Fatal(err)
	}

	if _, err := m.pg.SaveTaskIntelLink(t.Context(), db.TaskIntelLink{
		ProjectID: proj.ID, TaskID: ownerID, RelatedTaskID: sourceID,
		Decision: "adopted", Reason: "接口重合 1/1",
		Matched:   json.RawMessage(`[{"kind":"endpoint","key":"post /api/login","value":"POST https://oa.example-corp.com/api/login"}]`),
		DecidedBy: "reader",
	}); err != nil {
		t.Fatal(err)
	}

	// 1) 不再进入静态来源（不继承图/资产范围）。
	sources, err := owner.Store.DirectSourceStores()
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 0 {
		t.Fatalf("采纳不应升级为静态来源（否则等于继承对方整张图），got %d", len(sources))
	}

	// 2) ReaderRefs 给出概览 + 接口表（无 host）+ 可下钻 id。
	refs, err := owner.Store.ReaderRefs(4)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].TaskID != sourceID {
		t.Fatalf("adopt 后应出现在 reader_refs，got %+v", refs)
	}
	if len(refs[0].Endpoints) != 1 || refs[0].Endpoints[0].Path != "/api/login" {
		t.Fatalf("应暴露接口表的 path，got %+v", refs[0].Endpoints)
	}
	if len(refs[0].Overlap) != 1 || strings.Contains(refs[0].Overlap[0], "example-corp") {
		t.Fatalf("重合键只能是 METHOD /path，不能带 host：%+v", refs[0].Overlap)
	}
	found := false
	for _, n := range refs[0].Nodes {
		if n.ID == findingID {
			found = true
			if strings.Contains(n.Summary, "example-corp") {
				t.Fatalf("节点摘要也要脱敏（概览不能带 host）：%q", n.Summary)
			}
		}
	}
	if !found {
		t.Fatalf("finding 节点应可下钻，got %+v", refs[0].Nodes)
	}

	// 3) 下钻：被采纳的任务可读，未采纳的读不到。
	n, err := owner.Store.ReaderTaskNode(sourceID, findingID)
	if err != nil || n == nil {
		t.Fatalf("被采纳任务的节点应可下钻: n=%v err=%v", n, err)
	}
	if n, _ := owner.Store.ReaderTaskNode(otherID, 1); n != nil {
		t.Fatal("未采纳的任务不应被下钻（否则就是跨任务读取后门）")
	}

	// 4) 跨项目：不暴露。
	otherProj, err := m.pg.CreateProject(db.CreateProjectInput{Name: "_reader_exposure_other", Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { purgeTestProject(m, otherProj.ID) })
	if _, err := m.pg.Exec(`UPDATE tasks SET project_id=$1 WHERE id=$2`, otherProj.ID, sourceID); err != nil {
		t.Fatal(err)
	}
	refs, err = owner.Store.ReaderRefs(4)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Fatalf("跨项目采纳不应暴露，got %d", len(refs))
	}
}

// purgeTestProject 物理清掉一个测试项目及其任务/图/情报行（按 FK 依赖顺序）。
// 不用 Manager.DeleteTask：空 options 对 created 状态的任务不落删除，会在库里留脏。
func purgeTestProject(m *Manager, projectID int64) {
	var expIDs []int64
	rows, err := m.pg.Query(`SELECT exploration_id FROM tasks WHERE project_id=$1`, projectID)
	if err == nil {
		for rows.Next() {
			var id int64
			if rows.Scan(&id) == nil && id > 0 {
				expIDs = append(expIDs, id)
			}
		}
		rows.Close()
	}
	for _, expID := range expIDs {
		_, _ = m.pg.Exec(`DELETE FROM exploration_nodes WHERE exploration_id=$1`, expID)
	}
	_, _ = m.pg.Exec(`DELETE FROM task_relations WHERE task_id IN (SELECT id FROM tasks WHERE project_id=$1)
   OR source_task_id IN (SELECT id FROM tasks WHERE project_id=$1)`, projectID)
	// 引用 tasks 的子表都要先清，否则 DELETE FROM tasks 会被外键挡住（实测踩过：
	// 静默失败 → 每跑一次测试就在生产库多三条空任务）。
	for _, table := range []string{
		"task_scope", "task_asset_links", "task_foreign_assets", "task_intercept_rules",
		"task_llm_profiles", "task_intel_links", "task_intel", "findings",
		"side_question_sessions", "task_archives",
	} {
		_, _ = m.pg.Exec(`DELETE FROM `+table+` WHERE task_id IN (SELECT id FROM tasks WHERE project_id=$1)`, projectID)
	}
	_, _ = m.pg.Exec(`DELETE FROM tasks WHERE project_id=$1`, projectID)
	for _, expID := range expIDs {
		_, _ = m.pg.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	}
	_, _ = m.pg.Exec(`DELETE FROM projects WHERE id=$1`, projectID)
}
