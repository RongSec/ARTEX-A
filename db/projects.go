package db

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Project 是 projects 表的一行：artex-hs 二开的「项目-任务两级模型」上层。
// 任务经 tasks.project_id 可选归属；NULL=无项目（完全等价原版行为）。
type Project struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Status          string    `json:"status"` // active | archived
	Owner           string    `json:"owner"`
	Concurrency     int       `json:"concurrency"`       // 项目内批量任务并发数（1=串行）
	ObserverEnabled bool      `json:"observer_enabled"`  // B3 观察者总开关（默认关）
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// ProjectStats 是项目列表/详情的聚合统计（任务数/排队数/finding 分档数）。
type ProjectStats struct {
	TaskCount  int            `json:"task_count"`
	QueuedTask int            `json:"queued_tasks"`
	Findings   map[string]int `json:"findings"` // severity(critical|high|medium|low|其他) → 计数
}

// ProjectWithStats 组合一行项目与其统计（列表页直接下发）。
type ProjectWithStats struct {
	Project
	Stats ProjectStats `json:"stats"`
}

// ErrProjectNotFound 表示项目不存在（或已软删——本期不做项目软删，仅状态归档）。
var ErrProjectNotFound = errors.New("project not found")

// normalizeProjectConcurrency 把并发数归一到 [1,8]；<=0 回落到默认 2。
// 上限 8 防手滑把项目内并发调超机器/LLM 承载（全局上限另有 reconcile 兜底）。
func normalizeProjectConcurrency(n int) int {
	if n <= 0 {
		return 2
	}
	if n > 8 {
		return 8
	}
	return n
}

const projectCols = `id, name, description, status, owner, concurrency, observer_enabled, created_at, updated_at`

func scanProject(sc interface{ Scan(...any) error }) (*Project, error) {
	var p Project
	if err := sc.Scan(&p.ID, &p.Name, &p.Description, &p.Status, &p.Owner, &p.Concurrency, &p.ObserverEnabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

// CreateProject 插入一个项目（status 固定 active 起步；owner 可空）。
func (d *DB) CreateProject(name, description, owner string, concurrency int) (*Project, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("project name is required")
	}
	if concurrency <= 0 {
		concurrency = 2
	}
	return scanProject(d.QueryRow(`
INSERT INTO projects(name, description, owner, concurrency)
VALUES ($1, $2, $3, $4)
RETURNING `+projectCols, name, strings.TrimSpace(description), strings.TrimSpace(owner), normalizeProjectConcurrency(concurrency)))
}

// GetProject 返回单个项目；不存在时返回 ErrProjectNotFound。
func (d *DB) GetProject(id int64) (*Project, error) {
	p, err := scanProject(d.QueryRow(`SELECT `+projectCols+` FROM projects WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrProjectNotFound
	}
	return p, err
}

// ListProjects 返回全部项目（active 在前、新在前）+ 每项统计。列表量小（项目
// 是人建的分组单位），统计用两条 GROUP BY 批量算，避免 N+1。
func (d *DB) ListProjects(status string) ([]*ProjectWithStats, error) {
	q := `SELECT ` + projectCols + ` FROM projects`
	var args []any
	if status != "" {
		q += ` WHERE status=$1`
		args = append(args, status)
	}
	q += ` ORDER BY (status='active') DESC, created_at DESC`
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	var out []*ProjectWithStats
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, &ProjectWithStats{Project: *p, Stats: ProjectStats{Findings: map[string]int{}}})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	byID := map[int64]*ProjectWithStats{}
	for _, p := range out {
		byID[p.ID] = p
	}
	// 任务统计：总数 + 排队数
	trows, err := d.Query(`SELECT project_id, count(*), count(*) FILTER (WHERE queued) FROM tasks
WHERE deleted_at IS NULL AND project_id = ANY($1) GROUP BY project_id`, projectIDsOf(out))
	if err != nil {
		return nil, err
	}
	for trows.Next() {
		var pid int64
		var total, queued int
		if err := trows.Scan(&pid, &total, &queued); err != nil {
			trows.Close()
			return nil, err
		}
		if p := byID[pid]; p != nil {
			p.Stats.TaskCount = total
			p.Stats.QueuedTask = queued
		}
	}
	trows.Close()
	if err := trows.Err(); err != nil {
		return nil, err
	}
	// finding 统计：按 (project_id, severity) 聚合（findings 经 task_id 关联；
	// 任务删除后 findings.task_id 置 NULL 的行自然脱离项目统计，与任务列表一致）。
	frows, err := d.Query(`SELECT t.project_id, COALESCE(NULLIF(f.severity,''),'其他'), count(*)
FROM findings f JOIN tasks t ON t.id = f.task_id
WHERE t.deleted_at IS NULL AND t.project_id = ANY($1)
GROUP BY 1, 2`, projectIDsOf(out))
	if err != nil {
		return nil, err
	}
	for frows.Next() {
		var pid int64
		var sev string
		var n int
		if err := frows.Scan(&pid, &sev, &n); err != nil {
			frows.Close()
			return nil, err
		}
		if p := byID[pid]; p != nil {
			p.Stats.Findings[sev] += n
		}
	}
	frows.Close()
	if err := frows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func projectIDsOf(ps []*ProjectWithStats) []int64 {
	ids := make([]int64, 0, len(ps))
	for _, p := range ps {
		ids = append(ids, p.ID)
	}
	return ids
}

// UpdateProjectPatch 是 PATCH 的局部字段集；nil=不动该项。
type UpdateProjectPatch struct {
	Name            *string
	Description     *string
	Owner           *string
	Status          *string // active|archived
	Concurrency     *int
	ObserverEnabled *bool
}

// UpdateProject 应用局部更新并返回新行。status 非法值返回错误（DDL 有 CHECK，
// 提前在 server 侧挡掉好过让 PG 抛 23514）。
func (d *DB) UpdateProject(id int64, patch UpdateProjectPatch) (*Project, error) {
	if patch.Status != nil {
		switch *patch.Status {
		case "active", "archived":
		default:
			return nil, errors.New(`invalid status (want active|archived)`)
		}
	}
	p, err := scanProject(d.QueryRow(`UPDATE projects SET
	name          = CASE WHEN $2::boolean THEN $3 ELSE name END,
	description   = CASE WHEN $4::boolean THEN $5 ELSE description END,
	owner         = CASE WHEN $6::boolean THEN $7 ELSE owner END,
	status        = CASE WHEN $8::boolean THEN $9 ELSE status END,
	concurrency   = CASE WHEN $10::boolean THEN $11 ELSE concurrency END,
	observer_enabled = CASE WHEN $12::boolean THEN $13 ELSE observer_enabled END
WHERE id=$1
RETURNING `+projectCols,
		id,
		patch.Name != nil, derefStr(patch.Name),
		patch.Description != nil, derefStr(patch.Description),
		patch.Owner != nil, derefStr(patch.Owner),
		patch.Status != nil, derefStr(patch.Status),
		patch.Concurrency != nil, normalizeProjectConcurrency(derefInt(patch.Concurrency)),
		patch.ObserverEnabled != nil, derefBool(patch.ObserverEnabled)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrProjectNotFound
	}
	return p, err
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}
func derefInt(n *int) int {
	if n == nil {
		return 0
	}
	return *n
}
func derefBool(b *bool) bool { return b != nil && *b }

// DeleteProject 删项目行。tasks.project_id 的 FK 是 ON DELETE SET NULL：任务
// 保留、归属自动摘除（任务数据比分组贵重）。其 queued 的 project_batch 任务
// 由此变为 project_id IS NULL，dispatcher 不再认领（见 server/project_dispatcher.go），
// 等待用户显式继续（继续时按原版 resumeAdmissionMode 推断 bootstrap）。
func (d *DB) DeleteProject(id int64) error {
	res, err := d.Exec(`DELETE FROM projects WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrProjectNotFound
	}
	return nil
}

// ProjectTasks 返回某项目下的全部存活任务行（新在前），供详情聚合 API。
func (d *DB) ProjectTasks(projectID int64) ([]*Task, error) {
	rows, err := d.Query(`SELECT `+taskCols+` FROM tasks
WHERE deleted_at IS NULL AND project_id=$1
ORDER BY id DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > 0 {
		if err := d.hydrateTasksContext(out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ProjectBatchQueuedIDs 返回某项目批量下发、仍在排队等待项目调度的存活任务
// PG id（queue_mode='project_batch' ∧ queued ∧ 未暂停 ∧ 非终态）。
// dispatcher 每 tick 对每个项目跑一次（pending 集），claim 后行自动脱离。
func (d *DB) ProjectBatchQueuedIDs(projectID int64) ([]int64, error) {
	rows, err := d.Query(`SELECT id FROM tasks
WHERE project_id=$1 AND deleted_at IS NULL AND queued=true AND paused=false
  AND queue_mode='project_batch' AND status NOT IN ('done','failed','timeout')`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ProjectBatchHeadID 用一条条件 UPDATE 原子认领该项目批量队列的队首
// （queued_at ASC，NULLS LAST 兜旧行；同秒并列按 id 稳定）：把 queued 翻成
// false、queue_mode 改写为 bootstrap、清 queued_at，RETURNING id。
//
// 为什么是「认领」而不是「读队首再放行」：原版 reconcileConcurrency 每 5s
// 会盲补所有 queued 行（不认识 project 闸），批量任务若保持 queued=true 等着
// 被 dispatcher「放行」，会在下一 tick 被 reconcile 先捞走——二道闸门形同虚设。
// 唯一能抢先的窗口就是 reconcile 的串行锁 concMu：dispatcher 的 Step 全程
// 持 concMu（同 tick 顺序执行、互斥），在锁内做这次原子 UPDATE，就把
// 「检查项目额度 + 认领队首」压进一个不 interleaving 的动作；认领成功后该行
// queued=false，reconcile 的后续补位循环再也看不到它，只能经标准 resume 通道
// （LLM 不可用 parking 等），不会绕过项目并发额。
// 返回 0 表示该项目无可认领任务。
func (d *DB) ProjectBatchHeadID(projectID int64) (int64, error) {
	var id int64
	err := d.QueryRow(`UPDATE tasks SET queued=false, queue_mode='bootstrap', queued_at=NULL
WHERE id = (
	SELECT id FROM tasks
	WHERE project_id=$1 AND deleted_at IS NULL AND queued=true AND paused=false
	  AND queue_mode='project_batch' AND status NOT IN ('done','failed','timeout')
	ORDER BY queued_at ASC NULLS LAST, id ASC
	LIMIT 1
)
RETURNING id`, projectID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// ProjectRunningCount 统计某项目当前占用运行槽的**批量任务**数（项目并发额度
// 的分母）。只数经批量通道下发过的任务：queue_mode='resume' ∧ 不在排队 ∧
// 未暂停 ∧ 非终态 ∧ 未删除 ∧ 首次运行过（first_run_at 非 NULL）。
//
// 三条排除各治一种误算：
//   - queue_mode='project_batch'（还在等队）：未被认领的排队行绝不计数；
//   - first_run_at IS NULL（认领后从未跑过）：dispatcher 认领→admit 落回排队
//     的瞬时窗口里该条件是 true，但它从未消耗过槽，若算入会出现
//     「项目 0 在跑却判满额死锁」，直到下一次用户手工继续才被解套；
//   - 手工建的在跑任务（queue_mode 空且没跑完过/一直 running）：不属于批量
//     通道，用户显式建的在跑任务与批量任务的资源竞争交给全局上限兜，不计入
//     项目额度（否则新建一个手工任务就能把项目批量队列饿死）。
func (d *DB) ProjectRunningCount(projectID int64) (int, error) {
	var n int
	err := d.QueryRow(`SELECT count(*) FROM tasks
WHERE project_id=$1 AND deleted_at IS NULL AND queued=false AND paused=false
  AND queue_mode='resume' AND first_run_at IS NOT NULL
  AND status NOT IN ('done','failed','timeout')`, projectID).Scan(&n)
	return n, err
}
