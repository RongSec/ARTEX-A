package server

// project_dispatcher.go —— 项目内批量任务的二道闸门调度（T07，artex-hs 二开）。
//
// 挂点：Scheduler.Run 每 5s tick，在原版 reconcileConcurrency 之后调
// Step(ctx)。Step 全程持 s.concMu——与 reconcile/admit 同一把锁，两个含义：
//  1. 串行互斥：Step 的「判项目额度 → 原子认领队首 → 准入启动」整段不与
//     reconcile 的补位循环交错。原版 reconcile 不认识项目闸，会把任何
//     queued=true 的行直接捞走；两道保险防截胡：①reconcile 的补位收集循环
//     显式跳过 queue_mode='project_batch' 的行（goals.go，本项目增量改动，
//     基线库恒无此值 → 原版行为零改动）；②Step 在 concMu 内认领（queued 翻
//     false），认领后的行 reconcile 无论如何也看不到。
//  2. 额度观测（runningTaskCount/项目占槽）与准入提交来自同一串行化时序，
//     不会拿过期快照多放行。
//
// 认领后以 bootstrap 走 startAdmittedTask（后台第 0 轮目标拆解 + engine.Run），
// 与原版 launchTask 的 admit 分支同语义，仅省 seed（批量 handler 建后已 seed）。
//
// 项目额度的分母为什么用内存口径而不是 DB 查询：批量任务准入后
// queue_mode 被 ApplyTaskAdmission 清成 ''、status 停在 'created' 直到第 0 轮
// 拆解完成，而 first_run_at 仅对设了超时的任务落戳
// （engine_timeout.go stampFirstRun 对 TimeoutSeconds<=0 直接跳过）——不限时
// 的批量任务在 DB 里与「原版已建未跑」行不可区分。故占槽判定与原版全局口径
// 完全同源（occupiesConcurrencySlot，内存 handle + engine 实况），另加一个
// 进程内认领集合 claimed 顶住「已认领、尚未开始占槽」的 tick 内窗口。
// 进程重启 claimed 清空：那个窗口里存在的行只有「已认领未准入」（queued=false
// ∧ queue_mode='bootstrap'），reconcile 不会碰它（非 queued），任务停在库里
// 等用户显式继续——continue 路径按 resumeAdmissionMode 认出 bootstrap 指纹，
// 照常做第 0 轮拆解，不谎跑、不双跑。
//
// 已文档化的让渡语义（都是用户显式意图优先）：批量行被用户暂停后继续
// （admitPausedTask）走原版通道、不吃项目闸；LLM 不可用被 reconcile 顶层
// 停车再入队时 mode 被改写为 resume/bootstrap，脱离批量轨道由原版 FIFO 接管。
// 项目删除（FK SET NULL）或归档后，其排队批量行对所有调度器不可见＝「不放
// 行」验收项；逃生口=PATCH /api/tasks/{id}/project 重新挂到 active 项目，
// dispatcher 下一 tick 继续按 FIFO 认领。

import (
	"context"
	"log"
	"strconv"
)

// ProjectDispatcher 的观测全部每 tick 现查；唯一进程内状态是 claimed——
// 「已认领但原版口径尚未计为占槽」的批量任务 taskID→projectID（读写都在
// concMu 临界区内，不需要独立锁）。
type ProjectDispatcher struct {
	s       *Server
	claimed map[int64]int64
}

// projectDispatchPlan 计算一个项目本 tick 可认领放行几个批量任务（纯函数，
// 无库单测）。参数均为调用方现查的观测值：
//
//	globalEnabled  全局并发上限是否启用（原版 settings）
//	globalLimit    全局上限（enabled=false 时无视）
//	globalRunning  当前占全局槽的任务数
//	projRunning    该项目当前占槽 + 已认领未计槽 的任务数
//	concurrency    项目额度（projects.concurrency，store 已归一 ≥1）
//	pending        该项目排队中的批量任务数
//
// 放行数 = min(concurrency-projRunning, globalLimit-globalRunning(若启用),
// pending)；任何一项 ≤0 → 0（不放行）。
func projectDispatchPlan(globalEnabled bool, globalLimit, globalRunning, projRunning, concurrency, pending int) int {
	if pending <= 0 {
		return 0
	}
	budget := concurrency - projRunning
	if budget <= 0 {
		return 0
	}
	if globalEnabled {
		free := globalLimit - globalRunning
		if free <= 0 {
			return 0
		}
		if free < budget {
			budget = free
		}
	}
	if budget > pending {
		budget = pending
	}
	return budget
}

// Step 执行一轮项目调度。pd==nil（未初始化）或 pd.s==nil 直接返回——
// nil-safe 兜底，让未接线的 Server（测试构造等）零副作用。
func (pd *ProjectDispatcher) Step(ctx context.Context) {
	if pd == nil || pd.s == nil {
		return
	}
	select {
	case <-ctx.Done():
		return
	default:
	}
	s := pd.s
	s.concMu.Lock()
	defer s.concMu.Unlock()

	pg := s.m.PG()
	if pd.claimed == nil {
		pd.claimed = map[int64]int64{}
	}
	// 修剪认领集合：handle 消失（删除）、进终态、或已被原版口径计为占槽
	// （occupiesConcurrencySlot 与本函数同一把锁下调用，口径严格同源）的
	// 任务从认领视图退休，改由原版计数，避免重复占额。
	for id := range pd.claimed {
		t, ok := s.m.Task(strconv.FormatInt(id, 10))
		if !ok || isTerminalStatus(t.lifecycleSnapshot().Status) || s.occupiesConcurrencySlot(t) {
			delete(pd.claimed, id)
		}
	}

	pendingProjects, err := pg.PendingBatchProjectIDs()
	if err != nil {
		log.Printf("[project-dispatch] 扫描待调度项目失败: %v", err)
		return
	}
	if len(pendingProjects) == 0 {
		return // 默认关路径：没有批量排队时本函数即一次 SELECT 的开销。
	}
	globalEnabled, globalLimit := s.m.ConcurrencyLimit()
	globalRunning := s.runningTaskCount("")

	// 项目占槽数（内存原版口径）：项目内所有真正占槽的任务 + 认领在途。
	projRunning := map[int64]int{}
	for _, t := range s.m.List() {
		if t.ProjectID != nil && s.occupiesConcurrencySlot(t) {
			projRunning[*t.ProjectID]++
		}
	}
	for _, pid := range pd.claimed {
		projRunning[pid]++
	}

	for _, pid := range pendingProjects {
		if ctx.Err() != nil {
			return
		}
		proj, err := pg.GetProject(pid)
		if err != nil || proj.Status != "active" {
			continue // 项目没了/被归档：排队行留在队列，等人工处置（不放行）。
		}
		queueLen, err := pg.ProjectBatchQueuedCount(pid)
		if err != nil {
			log.Printf("[project-dispatch] 项目 %d 排队数查询失败: %v", pid, err)
			continue // 宁可不放，不可乱放；下 tick 重试
		}
		n := projectDispatchPlan(globalEnabled, globalLimit, globalRunning, projRunning[pid], proj.Concurrency, queueLen)
		for i := 0; i < n; i++ {
			headID, err := pg.ProjectBatchHeadID(pid) // 条件 UPDATE 原子认领队首（FIFO: queued_at ASC NULLS LAST, id ASC）
			if err != nil {
				log.Printf("[project-dispatch] 认领队首失败(项目 %d): %v", pid, err)
				break
			}
			if headID == 0 {
				break // 队列空（或刚被人抢先处置）
			}
			tID := strconv.FormatInt(headID, 10)
			t, ok := s.m.Task(tID)
			if !ok {
				// 认领发生在库行上，而内存 handle 不在（任务恰被删除）。行已
				// queued=false+bootstrap：不谎报成功，也不回队列反复认领。
				log.Printf("[project-dispatch] task %s 已认领但无内存 handle（删除竞态），停在库中等人工处置", tID)
				continue
			}
			// 先记账再准入：准入半途早退（暂停/删除竞态）时下 tick retire 清掉；
			// 准入成功但尚未被原版口径计为占槽时它顶着额度，杜绝超发。
			pd.claimed[headID] = pid
			projRunning[pid]++
			globalRunning++ // 本 tick 内多项目共享全局余量的实时视图
			s.admitProjectTask(t)
		}
	}
}

// admitProjectTask 是 dispatcher 的准入原语：任务已被 Step 原子认领
// （queued=false、queue_mode='bootstrap'），这里只做「复查 + 落库 + 启动」，
// 不做「全局满→落回排队」的 shouldQueue 判定——落回排队等于把行重新喂给
// 不认识项目闸的其它通道。全局上限由 Step 在认领前挡。
//
// 调用方必须已持 s.concMu。
func (s *Server) admitProjectTask(t *Task) {
	if t == nil {
		return
	}
	current, exists := s.m.Task(t.ID)
	if !exists || current != t || s.engine.IsDeleting(t.ID) {
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		return
	}
	defer s.engine.decInflight(t.ID)
	lifecycle := t.lifecycleSnapshot()
	// 认领到准入之间被暂停/终结：放弃准入。它的持久态已是 queued=false，
	// 不再属于批量队列；paused 的用户恢复走原版 resume 通道。
	if lifecycle.Paused || isTerminalStatus(lifecycle.Status) || s.engine.IsPaused(t.ID) {
		return
	}
	if err := s.m.ApplyTaskAdmission(t.ID, lifecycle.Status, lifecycle.Status, false, "bootstrap", false); err != nil {
		log.Printf("[project-dispatch] task %s 准入落库失败: %v", t.ID, err)
		return
	}
	s.startAdmittedTask(t, "bootstrap")
}
