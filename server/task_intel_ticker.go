package server

// 情报表增量构建（V10-INTEL-LIVE）：让 endpoints 在任务跑的过程中就参与比对。
//
// 用户口径：任务执行过程中会逐渐产生自己的小结表（endpoints/组件/凭据…），
// SQL 比对才可能在中途发现「隔壁任务有可借鉴的接口」。原来只在 done/timeout
// 的终态钩子里构建，运行中任务的小结表始终是空的，阅读者没有比对面的输入。
//
// 做法：每分钟扫一次，挑「running 且距上次构建 ≥5 分钟」的任务重建（upsert，
// 不删行）。抽到新接口就发 project_graph_events —— 与终态同一套信号，阅读者
// 照常被唤醒。预算：每个任务最多每 5 分钟一次，单轮最多 2 个任务，避免抢
// planner/worker 的模型配额（接口用途补全只在出现新接口时才调模型）。

import (
	"context"
	"log"
	"time"
)

const (
	intelLiveInterval = 5 * time.Minute
	intelLiveScan     = time.Minute
	intelLivePerPass  = 2
)

// startTaskIntelTicker 跟随 server ctx 生命周期；ctx 取消即退出。
func (s *Server) startTaskIntelTicker(ctx context.Context) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	go func() {
		t := time.NewTicker(intelLiveScan)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.runIntelLivePass(ctx)
			}
		}
	}()
}

// runIntelLivePass 是一轮扫描：只挑运行中、有项目、水位过期的任务。
func (s *Server) runIntelLivePass(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[task-intel-live] panic: %v", r)
		}
	}()
	// 注意：tasks.status 只在终态写库（运行中一直是 created/queued），不能用
	// status='running' 当过滤条件——线上实测运行中的任务在库里就是 created。
	// 先用「非终态」粗筛，再问内存里的实时状态（Manager.TaskStatus）。
	rows, err := s.m.pg.Query(`
SELECT t.id FROM tasks t
WHERE t.status NOT IN ('done','failed','timeout') AND t.deleted_at IS NULL AND t.project_id IS NOT NULL
  -- 「在跑」的判据是最近 6 分钟有 activity：tasks.status 运行中不写库，
  -- 内存状态也停在 created，只有活动流能可靠区分「在跑」与「建了没跑」。
  AND EXISTS (SELECT 1 FROM activity a
              WHERE a.exploration_id=t.exploration_id
                AND a.created_at > now() - interval '6 minutes')
  AND (t.intel_built_at IS NULL OR t.intel_built_at < now() - ($1::int * interval '1 second'))
ORDER BY t.intel_built_at NULLS FIRST, t.id
LIMIT $2`, int(intelLiveInterval.Seconds()), intelLivePerPass*4)
	if err != nil {
		return
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	built := 0
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		if built >= intelLivePerPass {
			break
		}
		built++
		c, cancel := context.WithTimeout(ctx, taskIntelBuildTimeout)
		st, err := s.buildTaskIntel(c, id)
		cancel()
		if err != nil {
			log.Printf("[task-intel-live] task %d 增量构建失败: %v", id, err)
			continue
		}
		if st.Inserted > 0 {
			log.Printf("[task-intel-live] task %d 新增 %d 行情报（rows=%d）", id, st.Inserted, st.Rows)
		}
	}
}

// markIntelBuilt 推进水位。构建失败也推进：否则一个坏任务会被每分钟重试，
// 白烧配额；下一轮（5 分钟后）再试即可。
func (s *Server) markIntelBuilt(ctx context.Context, taskID int64) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	if _, err := s.m.pg.ExecContext(ctx, `UPDATE tasks SET intel_built_at=now() WHERE id=$1`, taskID); err != nil {
		log.Printf("[task-intel-live] 更新 task %d 水位失败: %v", taskID, err)
	}
}
