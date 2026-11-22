package server

// 小项 Y：原版零回归冒烟基线（集成测试，无 PG 时 skip）。
//
// 把「不建项目的任务 = 二开三条链路完全惰性」钉成可执行断言：
//  1. store.OnGraphChange==nil —— bindGraphHook 对 ProjectID=nil 不绑回调
//     （红线本体：原版图写路径逐字节=原版，连一次回调调用都不发生）；
//  2. record fact 后 project_graph_events / project_index 均无该任务行 ——
//     端到端结果（非空操作：先断言 indexer 确在运行，排除"两表无行只是没人
//     消费通道"的假阴性）；
//  3. （已移除）planner 洞察 resolver 断言随 project_insights 表删除而移除
//     （V12-CLEANUP），原版任务不再存在任何洞察注入路径。

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestVanillaTaskZeroRegressionBaseline(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("需要 PostgreSQL（环境未配置，跳过零回归基线）：%v", err)
	}
	t.Cleanup(func() { m.Close() })

	// indexer 必须在跑——否则"两表无行"可能只是没人消费通道的假阴性（断言 2 失效）。
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	if s.m.projectIndexer == nil {
		t.Fatal("前置破坏：indexer 未启动，零回归断言 2 将成空操作")
	}

	// 原版路径建任务：不建项目、不传 ProjectID（llmProfileID=nil 等全默认）。
	task, err := m.CreateTask("Y 零回归基线", "验证原版任务不进任何二开投影", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tid, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() {
		m.pg.Exec(`DELETE FROM task_archives WHERE task_id=$1`, tid)
		_ = m.pg.DeleteTask(tid)
	})

	if task.ProjectID != nil {
		t.Fatalf("前置破坏：原版任务不应有项目归属, got %d", *task.ProjectID)
	}
	// 断言 1：回调未绑定（bindGraphHook 的红线分支）。
	if task.Store.OnGraphChange != nil {
		t.Error("原版任务的 store 不应绑定 OnGraphChange 回调（零额外开销红线）")
	}

	// record fact：原版任务下这必须只是普通的 AddNode——无事件、无投影。
	if _, err := task.Store.AddNode(db.KindFact, map[string]any{"summary": "基线事实：无任何项目关联"}, 0, "confirmed", "worker", nil); err != nil {
		t.Fatal(err)
	}
	// 若误绑了回调，事件最迟一个攒批窗口（200ms）后落表；等 600ms 判无行。
	time.Sleep(600 * time.Millisecond)

	// 断言 2：两张二开表里都找不到这个任务的痕迹。
	var n int64
	if err := m.pg.QueryRow(`SELECT count(*) FROM project_graph_events WHERE task_id=$1`, tid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("原版任务不应产生 project_graph_events，实际 %d 行", n)
	}
	if err := m.pg.QueryRow(`SELECT count(*) FROM project_index WHERE task_id=$1`, tid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("原版任务不应进入 project_index，实际 %d 行", n)
	}

	// 断言 3（洞察注入）在 V12-CLEANUP 移除：project_insights 表与注入链已整体删除。
}
