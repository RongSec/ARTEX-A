package server

// T13(0) 纯逻辑单测（无库）：groupProjectIndexRows——投影行→按任务分组 DTO 的
// 顺序/组内保序/计数/合成占位。DB 查询侧（QueryProjectIndex 的 ORDER BY）在
// db 包已测，这里只锁映射逻辑本身。

import (
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func idxRow(taskID, nodeID int64, kind string, upd time.Time) db.ProjectIndexRow {
	return db.ProjectIndexRow{
		TaskID: taskID, NodeID: nodeID, Kind: kind, State: "confirmed",
		Summary: kind, AssetKeys: []string{"10.0.0.8:8080"},
		UpdatedAt: upd,
	}
}

func TestGroupProjectIndexRows(t *testing.T) {
	base := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	// 输入序（须按 updated_at DESC）：task7 最新→排首组；task9 次之；再回 task7
	// 一条老节点（同组内追加、不打乱组序）。
	rows := []db.ProjectIndexRow{
		idxRow(7, 1, "finding", base.Add(3*time.Minute)),
		idxRow(9, 5, "fact", base.Add(2*time.Minute)),
		idxRow(7, 2, "intent", base.Add(1*time.Minute)),
	}
	meta := func(taskID int64) (taskMeta, bool) {
		switch taskID {
		case 7:
			return taskMeta{name: "打 canal", desc: "目标A", status: "running"}, true
		case 9:
			return taskMeta{name: "打后台", desc: "目标B", status: "done"}, true
		}
		return taskMeta{}, false
	}
	groups := groupProjectIndexRows(rows, meta)
	if len(groups) != 2 {
		t.Fatalf("want 2 groups, got %d", len(groups))
	}
	// 组顺序=首现顺序：7 在前（其最新节点是 rows[0]），9 在后。
	if groups[0].TaskID != 7 || groups[1].TaskID != 9 {
		t.Errorf("group order wrong: %d then %d", groups[0].TaskID, groups[1].TaskID)
	}
	// 元信息透传。
	if groups[0].TaskName != "打 canal" || groups[0].Status != "running" || !groups[0].Projected {
		t.Errorf("task7 meta wrong: %+v", groups[0])
	}
	// task7 组内两节点，保持输入序（node1 finding 先于 node2 intent）。
	if len(groups[0].Nodes) != 2 || groups[0].Nodes[0].NodeID != 1 || groups[0].Nodes[1].NodeID != 2 {
		t.Errorf("task7 nodes wrong order/count: %+v", groups[0].Nodes)
	}
	// updated_at → unix 秒。
	if groups[0].Nodes[0].UpdatedAt != base.Add(3*time.Minute).Unix() {
		t.Errorf("updated_at not unix seconds: %d", groups[0].Nodes[0].UpdatedAt)
	}
	// 计数：task7 = {finding:1, intent:1}，task9 = {fact:1}。
	if groups[0].CountsByKind["finding"] != 1 || groups[0].CountsByKind["intent"] != 1 || len(groups[0].CountsByKind) != 2 {
		t.Errorf("task7 counts wrong: %+v", groups[0].CountsByKind)
	}
	if groups[1].CountsByKind["fact"] != 1 || len(groups[1].CountsByKind) != 1 {
		t.Errorf("task9 counts wrong: %+v", groups[1].CountsByKind)
	}
}

func TestGroupProjectIndexRowsSyntheticMeta(t *testing.T) {
	// meta 返回 ok=false（归档/硬删残留行）：组仍在（行该被看见），
	// Projected=false，名称合成 "任务#N"。
	base := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	rows := []db.ProjectIndexRow{idxRow(42, 1, "fact", base)}
	groups := groupProjectIndexRows(rows, func(int64) (taskMeta, bool) { return taskMeta{}, false })
	if len(groups) != 1 {
		t.Fatalf("orphan row must still form a group, got %d", len(groups))
	}
	if groups[0].Projected {
		t.Error("orphan group must be Projected=false")
	}
	if groups[0].TaskName != "任务#42" {
		t.Errorf("orphan name = %q want 任务#42", groups[0].TaskName)
	}
}

func TestGroupProjectIndexRowsEmpty(t *testing.T) {
	if g := groupProjectIndexRows(nil, func(int64) (taskMeta, bool) { return taskMeta{}, false }); len(g) != 0 {
		t.Errorf("nil rows must yield no groups, got %d", len(g))
	}
}
