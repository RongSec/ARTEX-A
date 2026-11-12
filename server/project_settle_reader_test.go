package server

import (
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// 去抖纯函数：无历史 / 超窗 才允许；窗口内一律跳过。
func TestReaderNudgeAllowed(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		desc string
		prev time.Time
		seen bool
		want bool
	}{
		{"从未触发", time.Time{}, false, true},
		{"刚触发过", now.Add(-10 * time.Second), true, false},
		{"窗口边界前一刻", now.Add(-readerNudgeDebounce + time.Second), true, false},
		{"恰好到窗口", now.Add(-readerNudgeDebounce), true, true},
		{"久以前", now.Add(-time.Hour), true, true},
	}
	for _, c := range cases {
		if got := readerNudgeAllowed(c.prev, c.seen, now); got != c.want {
			t.Fatalf("%s：readerNudgeAllowed=%v，期望 %v", c.desc, got, c.want)
		}
	}
}

// PG 集成测（无库 skip）：项目收官 + reader 触发器 enabled + 项目 reader_enabled
// 才唤起；未收官/未 opt-in 时零行为；同项目 60s 内只唤起一次。
func TestProjectSettleNudgesReader(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	// reader 触发器：环境里已有 enabled 行就直接用（不删不建，避免动用户配置）；
	// 没有则建一条临时的，用完删掉。
	trEnabled := false
	if trs, err := pg.ListEnabledTriggers(); err == nil {
		for _, tr := range trs {
			if tr.AgentKey == "reader" {
				trEnabled = true
			}
		}
	}
	var tempTriggerID int64
	if !trEnabled {
		tr, err := pg.CreateTrigger(&db.AgentTrigger{AgentKey: "reader", Enabled: true, IntervalSec: 1800})
		if err != nil {
			t.Fatalf("创建临时 reader 触发器失败: %v", err)
		}
		tempTriggerID = tr.ID
		defer func() { _ = pg.DeleteTrigger(tempTriggerID) }()
	}

	m := &Manager{pg: pg}
	s := &Server{m: m}

	// 1) 项目未 opt-in（reader_enabled=false）+ 任务收官 → 零行为。
	off, err := pg.CreateProject(db.CreateProjectInput{Name: "nudge-off"})
	if err != nil {
		t.Fatal(err)
	}
	offID := off.ID
	offTask, err := pg.CreateTaskWithOptions("nudge off", "goal", db.TaskCreateOptions{ProjectID: &offID})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pg.DeleteTaskCascade(offTask.ID, false, true)
		_ = pg.DeleteProject(offID)
	}()
	if err := pg.SetStatus(offTask.ID, "done"); err != nil {
		t.Fatal(err)
	}
	s.onTaskTerminalReaderNudge(offTask.ID, "done")
	if _, loaded := m.projectSettleNudgeAt.Load(offID); loaded {
		t.Fatalf("项目未开 reader_enabled 时不得唤起 reader（project %d）", offID)
	}

	// 2) 项目 opt-in + 有未终态任务 → 未收官，零行为。
	on, err := pg.CreateProject(db.CreateProjectInput{Name: "nudge-on", ReaderEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	onID := on.ID
	t1, err := pg.CreateTaskWithOptions("nudge on 1", "goal", db.TaskCreateOptions{ProjectID: &onID})
	if err != nil {
		t.Fatal(err)
	}
	t2, err := pg.CreateTaskWithOptions("nudge on 2", "goal", db.TaskCreateOptions{ProjectID: &onID})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pg.DeleteTaskCascade(t1.ID, false, true)
		_, _ = pg.DeleteTaskCascade(t2.ID, false, true)
		_ = pg.DeleteProject(onID)
	}()
	if err := pg.SetStatus(t1.ID, "done"); err != nil {
		t.Fatal(err)
	}
	s.onTaskTerminalReaderNudge(t1.ID, "done")
	if _, loaded := m.projectSettleNudgeAt.Load(onID); loaded {
		t.Fatalf("项目仍有未终态任务时不得唤起 reader（project %d）", onID)
	}

	// 3) 全部终态 → 唤起一次；立刻再来一次被去抖挡掉（时间戳不变）。
	if err := pg.SetStatus(t2.ID, "done"); err != nil {
		t.Fatal(err)
	}
	s.onTaskTerminalReaderNudge(t2.ID, "done")
	first, loaded := m.projectSettleNudgeAt.Load(onID)
	if !loaded {
		t.Fatalf("项目收官应唤起一轮 reader（project %d）", onID)
	}
	s.onTaskTerminalReaderNudge(t2.ID, "done")
	second, _ := m.projectSettleNudgeAt.Load(onID)
	if !first.(time.Time).Equal(second.(time.Time)) {
		t.Fatalf("同项目 60s 内重复唤起应被去抖（%v → %v）", first, second)
	}
}
