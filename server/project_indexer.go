package server

// ProjectIndexer（artex-hs T10/T12，架构 §2.1）：把图原语（AddNode /
// SetNodeState / Link / CompareAndSetIntentState / SoftDeleteIntent）经
// ExplorationStore.OnGraphChange 发来的图变更异步投影到 project_index，并
// 追加 project_graph_events 事实行（喂 T11 observer 的水位扫描）。热路径
// （planner/worker 写图）只付一次 select-default 入通道 + nil 判断的代价；
// 满则 drop（投影最终一致，漏的行由 RebuildProjectIndex 兜底重建），drop
// 计数限频告警。
//
// [已核实 T12 定稿] 投影常开：消费路径只按 exploration→project 归属过滤
// （pid<=0 丢弃=原版任务），**不过 observer_enabled**——project_index 是
// 大图 tab 的数据源，关闭跨任务阅读者的项目也要能看。observer_enabled 只管
// fireProjectGraph 触发与 insight 注入两处（各自侧过滤）。绑定侧的对应
// 红线见 bindGraphHook：原版（未挂项目）任务完全不回调、零额外查询。

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
)

const (
	indexChanCap   = 1024                   // 缓冲通道容量（满则 drop）
	indexBatchMax  = 50                     // 攒批上限：条数先到先刷
	indexBatchTick = 200 * time.Millisecond // 攒批时间窗：时间到即刷（投影延迟上界）
	indexWarnEvery = 30 * time.Second       // drop 告警限频
)

// indexedEvent 是一条待投影的图变更：T09 的 GraphChange + 注入闭包回填的
// taskID（store 侧只有 exploration_id，tasks↔explorations 1:1 UNIQUE，闭包
// 在绑定处已知 task——GraphChange 结构本身不改，任务书 T09 定稿）。
type indexedEvent struct {
	taskID int64
	ev     pgdb.GraphChange
}

// ProjectIndexer 消费通道并落投影。零值不可用，必须经 newProjectIndexer。
type ProjectIndexer struct {
	ch     chan indexedEvent
	pg     *pgdb.DB
	cancel context.CancelFunc // Stop 用（Start 里从父 ctx 派生）
	wg     sync.WaitGroup

	// taskPID 缓存 exploration_id → project_id(int64)。0=无归属（原版任务
	// 恒此值；也缓存，之后每事件零查询）。
	taskPID sync.Map

	drops    atomic.Int64 // 通道满被丢弃的事件累计数
	lastWarn atomic.Int64 // 上次 drop 告警时刻（unix nano，限频用）

	// now 仅为测试注入（nil=time.Now）；生产只多一次判空。
	now func() time.Time
}

func newProjectIndexer(pg *pgdb.DB) *ProjectIndexer {
	return &ProjectIndexer{ch: make(chan indexedEvent, indexChanCap), pg: pg}
}

// Enqueue 非阻塞入队：满则丢弃该事件并计数（投影最终一致设计——丢的是一行
// 摘要刷新，不是业务数据，重建接口补账）。ix==nil（链路未启用）直接返回，
// 调用点无须判空。由 store.OnGraphChange 闭包在图写事务提交后同步调用。
func (ix *ProjectIndexer) Enqueue(taskID int64, ev pgdb.GraphChange) {
	if ix == nil {
		return
	}
	select {
	case ix.ch <- indexedEvent{taskID: taskID, ev: ev}:
	default:
		n := ix.drops.Add(1)
		ix.maybeWarnDrop(n)
	}
}

// maybeWarnDrop 限频告警：每 indexWarnEvery 至多一条，带累计 drop 数。
// 返回是否真的打了这条日志（CAS 防多 worker 协程同刻刷屏；测试断言返回值，
// 不劫持全局 log 输出）。
func (ix *ProjectIndexer) maybeWarnDrop(total int64) bool {
	now := time.Now
	if ix.now != nil {
		now = ix.now
	}
	ts := now().UnixNano()
	last := ix.lastWarn.Load()
	if ts-last < int64(indexWarnEvery) {
		return false
	}
	if !ix.lastWarn.CompareAndSwap(last, ts) {
		return false
	}
	log.Printf("[project-indexer] 投影通道已满，事件被丢弃（累计 drop=%d；可由 RebuildProjectIndex 补账）", total)
	return true
}

// cachedResolve 是进程内缓存骨架（sync.Map + loader）：命中返回 (值, true,
// fromCache=true)；未命中调 loader——loader 的 ok=false 表示查询失败（不缓存，
// 下条事件重试），ok=true 的值（含零值 0/false）才写缓存。抽出来是为了能无库
// 单测「命中/miss/失败不缓存」三条路径（loader 注入 fake，绕开真实 PG）。
func cachedResolve[V any](cache *sync.Map, key int64, loader func() (V, bool)) (val V, ok bool, fromCache bool) {
	if v, hit := cache.Load(key); hit {
		cast, _ := v.(V)
		return cast, true, true
	}
	loaded, lok := loader()
	if !lok {
		var zero V
		return zero, false, false
	}
	cache.Store(key, loaded)
	return loaded, true, false
}

// projectOf 解析 exploration → 任务 → 项目归属（进程内缓存）。
// ok=false 仅表示查询失败（不缓存，下条事件重试）；pid=0/ok=true 表示
// 无归属（任务不存在/软删/未挂项目），消费端直接短路=原版任务天然零开销。
// tasks.exploration_id 1:1 UNIQUE（schema.sql:511），单行查询无需 JOIN。
func (ix *ProjectIndexer) projectOf(expID int64) (projectID int64, ok bool) {
	v, ok, _ := cachedResolve[int64](&ix.taskPID, expID, func() (int64, bool) {
		var pid sql.NullInt64
		err := ix.pg.QueryRow(`SELECT project_id FROM tasks WHERE exploration_id=$1`, expID).Scan(&pid)
		if err == sql.ErrNoRows { // 孤儿探索图：缓存 0 防每事件重查
			return 0, true
		}
		if err != nil {
			return 0, false
		}
		return pid.Int64, true // project_id IS NULL → 0（未挂项目）
	})
	return v, ok
}

// InvalidateTaskMapping 清一个探索图的项目归属缓存——tasks.project_id 被
// 改写（挂/摘项目）后必须调用，否则旧映射把事件投错项目。
// 消费方：Manager.AttachTaskProject（server/projects.go）。
func (ix *ProjectIndexer) InvalidateTaskMapping(expID int64) {
	if ix == nil {
		return
	}
	ix.taskPID.Delete(expID)
}

// filterAdmitted 纯函数（可注入解析器，单测直接断言）：一批事件逐条解析归属，
// 产出「通过投影」的条目与其 project_id（平行数组）。
// resolve 返回 ok=false=查询失败，本条丢弃（下条事件自愈）；pid<=0=无归属
// 丢弃（原版任务恒此路径）。
//
// [已核实 T12 定稿] 这里**不再过 observer_enabled**：project_index 是大图 tab
// 的数据源，关闭跨任务阅读者的项目也要能看大图——投影常开。observer_enabled 的语义
// 收窄为只管 ① fireProjectGraph 产不产触发（scheduler 侧 JOIN projects 过滤）
// ② T12 的 insight 注入。二者都不在本消费路径。
func filterAdmitted(batch []indexedEvent,
	resolve func(expID int64) (int64, bool)) ([]indexedEvent, []int64) {
	rows := make([]indexedEvent, 0, len(batch))
	pids := make([]int64, 0, len(batch))
	for _, ev := range batch {
		pid, ok := resolve(ev.ev.ExplorationID)
		if !ok || pid <= 0 {
			continue // 查询失败=下条自愈；无归属=原版任务天然短路（零回归）
		}
		rows = append(rows, ev)
		pids = append(pids, pid)
	}
	return rows, pids
}

// shouldFlushNow 纯函数：攒批是否达到条数阈值（时间窗到另由 ticker 驱动）。
func shouldFlushNow(batchLen, maxBatch int) bool {
	return batchLen >= maxBatch
}

// graphDeltaSummary 纯函数：组装喂 observer 的一行变更摘要
// （"task#7 finding[high]→confirmed: …"）。截断在 db 侧
// （InsertGraphEvent 500 rune 上限），这里只管拼法稳定可测。
func graphDeltaSummary(taskID int64, kind, state, severity, summary string) string {
	s := "task#" + strconv.FormatInt(taskID, 10) + " " + kind
	if severity != "" {
		s += "[" + severity + "]"
	}
	if state != "" {
		s += "→" + state
	}
	if summary != "" {
		s += ": " + summary
	}
	return s
}

// graphChangeDigest 纯函数：投影行 payload_digest 的载荷。节点身份与任务
// 回链（observer 从投影能跳回原探索图），不复制 payload 正文——大图要的是
// 摘要，原图永远可按 node_id 回查。json.Marshal 对 map[string]any 不会失败。
func graphChangeDigest(taskID int64, ev pgdb.GraphChange) json.RawMessage {
	raw, err := json.Marshal(map[string]any{
		"exploration_id": ev.ExplorationID,
		"source_task_id": taskID,
		"node_id":        ev.NodeID,
		"asset_ids":      ev.AssetIDs,
	})
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

// bindGraphHook 给任务专属的 ExplorationStore 挂上投影回调（T10 注入点，
// 架构 §2.1）。indexer 未启用（nil，无 PG/构造失败）时不挂——store 字段保持
// nil，原语逐字节走原版快路径（零回归）。
//
// [已核实 T12 裁决2] **仅当任务已挂项目（pt.ProjectID 非空）才绑定**：原版
// 高频路径（intent CAS 每轮都走）不得多 graphNodeSnapshot 的 2 条回查 SELECT
// ——零额外查询是红线。未绑定的任务事件根本不产生，消费侧 projectOf 的
// pid=0 短路保留为 defense-in-depth（事件可能来自已摘除归属的存量 handle）。
//
// 运行期挂/摘项目的投影语义（低频操作，拍板接受）：
//   - 挂载后：该任务存量图靠任务重启（LoadExisting 重新 bindGraphHook）或
//     T13 的 RebuildProjectIndex 按钮补齐；重启前的新节点不产事件。
//   - 摘除后：回调保持挂着（不运行期改写——与运行中协程的字段读竞争），
//     事件继续入通道但 AttachTaskProject 的 InvalidateTaskMapping 让消费侧
//     解析到新 pid=0 → 丢弃；旧投影行由下次 Rebuild 的 DELETE 谓词自然清掉
//     （大图上短暂残留旧任务行可接受）。
//
// 闭包只做两件事：回填 taskID + select-default 入通道。不查库、不加锁。
// 调用点：仅 taskFromPG（新建/LoadExisting，handle 发布前，写字段无竞争）。
func (m *Manager) bindGraphHook(store *pgdb.ExplorationStore, pt *pgdb.Task) {
	if store == nil || m.projectIndexer == nil || pt == nil {
		return
	}
	if pt.ProjectID == nil || *pt.ProjectID <= 0 {
		return // 原版任务：不绑定，零回调零开销（红线）
	}
	ix := m.projectIndexer
	taskID := pt.ID
	store.OnGraphChange = func(ev pgdb.GraphChange) {
		ix.Enqueue(taskID, ev)
	}
}

// Start 派生取消 ctx 并拉起单消费协程（幂等由调用方保证：server.New 一次）。
// 父 ctx 取消或 Stop 都会让 run flush 在途批次后退出（尽力而为；此时 DB
// 可能已关，flush 失败仅记日志——最终一致定位）。
func (ix *ProjectIndexer) Start(ctx context.Context) {
	if ix == nil {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	ix.cancel = cancel
	ix.wg.Add(1)
	go ix.run(ctx)
	log.Printf("[project-indexer] 已启动（通道 cap=%d，攒批 %dms/%d 条）", indexChanCap, indexBatchTick.Milliseconds(), indexBatchMax)
}

// Stop 取消消费协程并等在途批次 flush 完。未 Start 时立即返回。
// 调用方须保证 DB 仍开着（Manager.Close 把它排在 pg.Close 之前）。
func (ix *ProjectIndexer) Stop() {
	if ix == nil {
		return
	}
	if ix.cancel != nil {
		ix.cancel()
	}
	ix.wg.Wait()
}

func (ix *ProjectIndexer) run(ctx context.Context) {
	defer ix.wg.Done()
	t := time.NewTicker(indexBatchTick)
	defer t.Stop()
	batch := make([]indexedEvent, 0, indexBatchMax)
	flush := func(flushCtx context.Context) {
		if len(batch) == 0 {
			return
		}
		ix.handleBatch(flushCtx, batch)
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			// 关停收尾：在途批次最后刷一次。不能沿用已取消的 ctx——BeginTx
			// 会立刻 context canceled；给 2s 独立预算尽力而为（DB 已关则失败
			// 仅日志，最终一致定位：漏的行靠 RebuildProjectIndex 补账）。
			tCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			flush(tCtx)
			cancel()
			return
		case <-t.C:
			flush(ctx) // 时间窗到：不满一批也刷，投影延迟上界 ≈200ms
		case ev := <-ix.ch:
			batch = append(batch, ev)
			// 非阻塞把已到的一波全捞进来再判阈值：突发时一次事务刷满 50 条，
			// 低负载时不满足阈值则继续攒到时间窗。
		drain:
			for len(batch) < indexBatchMax {
				select {
				case more := <-ix.ch:
					batch = append(batch, more)
				default:
					break drain
				}
			}
			if shouldFlushNow(len(batch), indexBatchMax) {
				flush(ctx)
				t.Reset(indexBatchTick) // 刚刷过重新计时，避免空 tick 紧跟一发
			}
		}
	}
}

// handleBatch 单批消费：filterAdmitted 过闸（纯内存查表，miss 才一次单行
// 查询），通过的条目攒成一次事务落投影 + 事件行。批内同节点多条事件全保留
// （事件是事实流）；投影按 (project_id,node_id) 幂等 upsert，后写覆盖前写。
func (ix *ProjectIndexer) handleBatch(ctx context.Context, batch []indexedEvent) {
	rows, pids := filterAdmitted(batch, ix.projectOf)
	if len(rows) == 0 {
		return
	}
	tx, err := ix.pg.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("[project-indexer] begin: %v", err)
		return
	}
	defer tx.Rollback() //nolint:errcheck // 提交成功后是 no-op
	for i, ev := range rows {
		if err := ix.applyTx(ctx, tx, pids[i], ev); err != nil {
			// 单条失败弃整批回滚（投影可重建，绝不带半批状态提交）；
			// 一条日志收口，防坏数据刷屏。
			log.Printf("[project-indexer] batch apply 失败，弃批 %d 条: %v", len(rows)-i, err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		log.Printf("[project-indexer] commit: %v", err)
	}
}

// applyTx 落一条事件：intent 假删（state=deleted）删投影行；否则 upsert。
// 两种路径都追加一行事件（事实流完整：observer 要知道「发生过什么」）。
// asset_keys 解析走 ix.pg 主连接而非本事务：它是只读字典查询，锚定行在
// 事件产生前（AddNode 事务）已提交，跨连接读不到自己事务内写的东西——这里
// 本来也不写 assets。
func (ix *ProjectIndexer) applyTx(ctx context.Context, tx *sql.Tx, projectID int64, ev indexedEvent) error {
	if ev.ev.Kind == pgdb.KindIntent && ev.ev.State == pgdb.StateIntentDeleted {
		if err := pgdb.DeleteProjectIndexByNodeTx(ctx, tx, projectID, ev.ev.NodeID); err != nil {
			return err
		}
	} else {
		keys, err := ix.pg.AssetKeysForIDs(ev.ev.AssetIDs)
		if err != nil {
			return err
		}
		if err := pgdb.UpsertProjectIndexTx(ctx, tx, pgdb.ProjectIndexRow{
			ProjectID: projectID, TaskID: ev.taskID, NodeID: ev.ev.NodeID,
			Kind: ev.ev.Kind, State: ev.ev.State, Summary: ev.ev.Summary,
			AssetKeys: keys, Severity: ev.ev.Severity,
			PayloadJSON: graphChangeDigest(ev.taskID, ev.ev),
		}); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO project_graph_events(project_id, task_id, node_id, kind, delta_summary)
VALUES ($1, $2, $3, $4, $5)`,
		projectID, ev.taskID, nullIfZero(ev.ev.NodeID), ev.ev.Kind,
		graphDeltaSummary(ev.taskID, ev.ev.Kind, ev.ev.State, ev.ev.Severity, ev.ev.Summary))
	return err
}

func nullIfZero(v int64) any {
	if v <= 0 {
		return nil
	}
	return v
}

// RebuildProjectIndex 全量重建一个项目的投影：事务内 DELETE 该项目全部旧行 +
// 按任务逐图扫节点重新 upsert。供 T13 的 API 兜底（drop 补账/挂项目后补齐
// 存量图投影）。投影常开（[已核实 T12 定稿]，大图 tab 的数据源），不看
// observer_enabled——只要项目存在就重建。返回重建的投影行数。
//
// 摘除归属的旧投影行清理也由此天然完成：DELETE 以 project_id 为谓词，
// 重建后只剩「当前挂在项目上的任务」的节点。
func (s *Server) RebuildProjectIndex(ctx context.Context, projectID int64) (int, error) {
	var exists bool
	if err := s.m.pg.QueryRow(`SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1)`, projectID).Scan(&exists); err != nil {
		return 0, err
	}
	if !exists {
		return 0, pgdb.ErrProjectNotFound
	}
	type taskExp struct {
		id    int64
		expID int64
	}
	var tasks []taskExp
	rows, err := s.m.pg.QueryContext(ctx, `SELECT id, exploration_id FROM tasks
WHERE project_id=$1 AND deleted_at IS NULL ORDER BY id`, projectID)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var t taskExp
		if err := rows.Scan(&t.id, &t.expID); err != nil {
			rows.Close()
			return 0, err
		}
		tasks = append(tasks, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	// 节点先全量收集再进事务：事务只做 DELETE+INSERT，持锁时间 = 写入时间，
	// 不被逐图 SELECT（另一条连接）拖长；单任务图上限沿用 Nodes 的 20000。
	var all []pgdb.ProjectIndexRow
	for _, t := range tasks {
		nodes, err := s.m.pg.Exploration(t.expID).NodesWithAnchors(ctx, 0)
		if err != nil {
			return 0, err
		}
		for _, n := range nodes {
			if n.Kind == pgdb.KindIntent && n.State == pgdb.StateIntentDeleted {
				continue // 假删节点不进投影（与事件路径同口径）
			}
			digest, err := json.Marshal(map[string]any{
				"exploration_id": t.expID, "source_task_id": t.id,
				"node_id": n.ID, "asset_ids": n.Anchors,
			})
			if err != nil {
				digest = []byte(`{}`)
			}
			// 资产键解析失败按空键继续：投影是尽力而为的旁路（同事件路径）。
			keys, err := s.m.pg.AssetKeysForIDs(n.Anchors)
			if err != nil {
				keys = nil
			}
			all = append(all, pgdb.ProjectIndexRow{
				ProjectID: projectID, TaskID: t.id, NodeID: n.ID,
				Kind: n.Kind, State: n.State,
				Summary:     pgdb.PayloadSummary(n.Payload),
				AssetKeys:   keys,
				Severity:    pgdb.PayloadSeverity(n.Payload, n.Kind),
				PayloadJSON: digest,
			})
		}
	}
	tx, err := s.m.pg.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // 提交成功后是 no-op
	if _, err := tx.ExecContext(ctx, `DELETE FROM project_index WHERE project_id=$1`, projectID); err != nil {
		return 0, err
	}
	for i := range all {
		if err := pgdb.UpsertProjectIndexTx(ctx, tx, all[i]); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(all), nil
}
