package server

// V4-E / E3：项目收官 → 唤起一轮 reader（跨项目阅读者）。
//
// 背景：reader 原本只有 1800s 定时触发——项目刚收官的那批洞察（正是跨项目
// 串联最有料的时刻）要等最多半小时才被读到。这里在 T18 已有的「项目收官」
// 判定上加一段旁路：项目内全部任务落终态、且该项目 reader_enabled、reader
// 触发器 enabled 时，走 StartTriggeredRun 立刻点亮一轮（与 observer 的
// fireProjectGraph 同范式：一次 run、taskID=0 的项目级触发、mergeable=false
// 由 reader 的 serial+merge=all 策略自行合并）。定时 1800s 保留作兜底。
//
// 纪律（照 auto_report.go）：
//   - 任何失败只 log 一行，绝不回抛（任务终态早已提交，这里是"之后尽力"）；
//   - enabled=false（或没有 reader 触发器行）时零行为——连库查询都只到
//     「取任务→判项目」为止；
//   - 去抖 60s：同项目 60s 内只唤起一次（并发收官 / 收官后追问复活再收官
//     都可能让钩子重复进来）。

import (
	"fmt"
	"log"
	"time"

	"github.com/Autumn-27/artex/db"
)

// readerNudgeDebounce 是同项目两次唤起 reader 的最小间隔。
const readerNudgeDebounce = 60 * time.Second

// readerNudgeAllowed 是去抖纯函数：没有历史记录、或距上次触发已超过窗口才允许。
func readerNudgeAllowed(prev time.Time, seen bool, now time.Time) bool {
	return !seen || now.Sub(prev) >= readerNudgeDebounce
}

// readerTriggerEnabled 判定 reader 触发器是否处于 enabled（全局侧双闸之一）。
// 直接读 ListEnabledTriggers（调度器同一判据）：没有行 / 行 enabled=false
// 都是「关」，零行为。
func (s *Server) readerTriggerEnabled() bool {
	trs, err := s.m.pg.ListEnabledTriggers()
	if err != nil {
		log.Printf("[reader-nudge] 读取触发器失败: %v", err)
		return false
	}
	for _, tr := range trs {
		if tr.AgentKey == "reader" {
			return true
		}
	}
	return false
}

// onTaskTerminalReaderNudge 是任务终态钩子的第二段（第一段是自动报告）。
//
// 短路顺序按成本从低到高，且把【触发器 enabled】放在最前面：默认关时连
// 任务/项目都不查——「enabled=false → 零行为」是字面意义的零额外查询。
func (s *Server) onTaskTerminalReaderNudge(taskID int64, status string) {
	pg := s.m.pg
	if pg == nil {
		return
	}
	if !s.readerTriggerEnabled() {
		return // 触发器默认关：零行为
	}
	t, err := pg.GetTask(taskID)
	if err != nil {
		log.Printf("[reader-nudge] task %d 读取失败: %v", taskID, err)
		return
	}
	if t == nil || t.ProjectID == nil || *t.ProjectID <= 0 {
		return // 无项目=原版路径，零行为
	}
	pid := *t.ProjectID
	p, err := pg.GetProject(pid)
	if err != nil {
		log.Printf("[reader-nudge] project %d 读取失败: %v", pid, err)
		return
	}
	if p == nil || !p.ReaderEnabled {
		return // 项目未 opt-in 跨项目阅读：零行为
	}
	// 收官判定与自动报告共用 projectSettled（口径单源：项目内 0 任务不算收官，
	// 有任一未终态任务也不算）。
	tasks, err := pg.ProjectTasks(pid)
	if err != nil {
		log.Printf("[reader-nudge] project %d 任务列表失败: %v", pid, err)
		return
	}
	all := make(map[int64]bool, len(tasks))
	terminal := make(map[int64]bool, len(tasks))
	for _, x := range tasks {
		all[x.ID] = true
		if db.IsTerminal(x.Status) {
			terminal[x.ID] = true
		}
	}
	if settled, _ := projectSettled(all, terminal); !settled {
		return
	}
	// 去抖：LoadOrStore 一把原子完成「查+占位」，并发双终态不会双发。
	now := time.Now()
	for {
		prev, loaded := s.m.projectSettleNudgeAt.LoadOrStore(pid, now)
		if !loaded {
			break
		}
		if !readerNudgeAllowed(prev.(time.Time), true, now) {
			log.Printf("[reader-nudge] project %d 距上次唤起不足 %s，跳过", pid, readerNudgeDebounce)
			return
		}
		if s.m.projectSettleNudgeAt.CompareAndSwap(pid, prev, now) {
			break
		}
	}
	msg := fmt.Sprintf("\n\n【本次由项目收官触发】项目 #%d「%s」的全部 %d 个任务已落终态。请按资产优先口径做一轮跨项目串联：先看 cross_project_assets。",
		pid, p.Name, len(tasks))
	s.StartTriggeredRun("reader", fmt.Sprintf("项目收官触发 · project#%d", pid), msg, 0, false, "", "")
	log.Printf("[reader-nudge] project %d 已收官（%d 个任务），已唤起一轮 reader", pid, len(tasks))
}
