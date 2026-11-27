package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Project 是 projects 表的一行：artex-hs 二开的「项目-任务两级模型」上层。
// 任务经 tasks.project_id 可选归属；NULL=无项目（完全等价原版行为）。
type Project struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	Status          string `json:"status"` // active | archived
	Owner           string `json:"owner"`
	Concurrency     int    `json:"concurrency"`      // 项目内批量任务并发数（1=串行）
	ObserverEnabled bool   `json:"observer_enabled"` // 跨任务/项目内阅读开关（scope='project'；默认关）
	// T18 项目设置扩展三列。ReportTemplateID=nil → 走默认模板链；指针区分
	// 「未设置」与「显式 0」，PATCH 语义与其余两列一致。
	ReportTemplateID *int64 `json:"report_template_id"`
	// V9-RPT2：两个独立勾选，可同时为 true。
	//   AutoReport      = 只出一个项目汇总报告（全部任务收官后）
	//   AutoReportTasks = 子任务都出报告（每个任务终态各一份）
	AutoReport      bool      `json:"auto_report"`
	AutoReportTasks bool      `json:"auto_report_tasks"`
	ReaderEnabled   bool      `json:"reader_enabled"` // 跨项目阅读开关（scope='cross' 聚合/来源校验/注入；默认关）
	// TaskTemplateID 是项目默认任务模板（task_templates.id）；nil=未预设。
	// 批量下发时作为默认带出，用户仍可在下发弹窗里改。
	TaskTemplateID *int64 `json:"task_template_id"`
	// Targets/Credentials 是项目默认测试资产（一行一个的原始文本）与凭据行。
	// 批量下发时作为默认值带出；项目详情页可编辑。
	Targets     string           `json:"targets"`
	Credentials []map[string]any `json:"credentials"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
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

const projectCols = `id, name, description, status, owner, concurrency, observer_enabled, report_template_id, auto_report, auto_report_tasks, reader_enabled, task_template_id, targets, credentials, created_at, updated_at`

func scanProject(sc interface{ Scan(...any) error }) (*Project, error) {
	var p Project
	var credJSON []byte
	if err := sc.Scan(&p.ID, &p.Name, &p.Description, &p.Status, &p.Owner, &p.Concurrency, &p.ObserverEnabled, &p.ReportTemplateID, &p.AutoReport, &p.AutoReportTasks, &p.ReaderEnabled, &p.TaskTemplateID, &p.Targets, &credJSON, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	if len(credJSON) > 0 {
		_ = json.Unmarshal(credJSON, &p.Credentials)
	}
	return &p, nil
}

// CreateProjectInput 是建项目的入参集（T18：新增三字段，nil/false = 列默认值，
// 与三列的「默认关=基线」语义一致）。ObserverEnabled 后补（T19 方案 A 对齐
// PATCH 字段集），同默认关=基线。
type CreateProjectInput struct {
	Name             string
	Description      string
	Owner            string
	Concurrency      int
	ObserverEnabled  bool
	ReportTemplateID *int64 // nil=不绑定，走默认模板链
	AutoReport       bool   // 只出一个项目汇总报告
	AutoReportTasks  bool   // 子任务都出报告（可与 AutoReport 同真=叠加）
	ReaderEnabled    bool
	TaskTemplateID   *int64 // 项目默认任务模板；nil=未预设
	Targets          string // 项目默认测试资产文本
	Credentials      []map[string]any
}

// CreateProject 插入一个项目（status 固定 active 起步；owner 可空）。
func (d *DB) CreateProject(in CreateProjectInput) (*Project, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, errors.New("project name is required")
	}
	concurrency := in.Concurrency
	if concurrency <= 0 {
		concurrency = 2
	}
	var tmpl any
	if in.ReportTemplateID != nil && *in.ReportTemplateID > 0 {
		tmpl = *in.ReportTemplateID
	}
	// V6-DUAL：两个尺度各自独立开关，各写各的列，互不镜像——
	//   observer_enabled = 跨任务/项目内（scope='project' 洞察的写/触发/注入）
	//   reader_enabled   = 跨项目（scope='cross' 的聚合/来源校验/注入）
	var taskTmpl any
	if in.TaskTemplateID != nil && *in.TaskTemplateID > 0 {
		taskTmpl = *in.TaskTemplateID
	}
	credJSON, err := json.Marshal(nonNilCredentials(in.Credentials))
	if err != nil {
		return nil, err
	}
	return scanProject(d.QueryRow(`
INSERT INTO projects(name, description, owner, concurrency, observer_enabled, report_template_id, auto_report, auto_report_tasks, reader_enabled, task_template_id, targets, credentials)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb)
RETURNING `+projectCols, name, strings.TrimSpace(in.Description), strings.TrimSpace(in.Owner),
		normalizeProjectConcurrency(concurrency), in.ObserverEnabled, tmpl, in.AutoReport, in.AutoReportTasks, in.ReaderEnabled, taskTmpl,
		strings.TrimSpace(in.Targets), string(credJSON)))
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
	// T18：三列的 PATCH 指针字段。report_template_id 可空，*int64 的 nil 无法
	// 区分「键缺席」与「显式 null=清除」，故加 Set 标志（server 判键后置位，
	// 值指针 nil=清除回默认模板链）。
	ReportTemplateID    *int64
	ReportTemplateIDSet bool
	AutoReport          *bool
	AutoReportTasks     *bool
	ReaderEnabled       *bool
	// TaskTemplateIDSet/TaskTemplateID 与 ReportTemplateID 同款：nil 无法区分
	// 「键缺席」与「显式清除」，由 server 判键后置 Set。
	TaskTemplateID    *int64
	TaskTemplateIDSet bool
	// Targets/Credentials：nil=键缺席（不改），非 nil=整段替换。
	Targets     *string
	Credentials *[]map[string]any
}

// UpdateProject 应用局部更新并返回新行。status 非法值返回错误（DDL 有 CHECK，
// 提前在 server 侧挡掉好过让 PG 抛 23514）。
func (d *DB) UpdateProject(id int64, patch UpdateProjectPatch) (*Project, error) {
	// V6-DUAL：两层开关各自独立——只动了哪个字段就只写哪列，绝不把另一列
	// 一并覆盖（V6-U4 的镜像写已撤销）。API 侧同样按「键出现才置指针」。
	if patch.Status != nil {
		switch *patch.Status {
		case "active", "archived":
		default:
			return nil, errors.New(`invalid status (want active|archived)`)
		}
	}
	// report_template_id 可空：$15 直接传 any——显式清除时是 nil→SQL NULL，
	// 绑定时是 int64。CASE 谓词 $14 用 Set 标志判「键是否出现」。
	var templateAny any
	if patch.ReportTemplateIDSet && patch.ReportTemplateID != nil && *patch.ReportTemplateID > 0 {
		templateAny = *patch.ReportTemplateID
	}
	p, err := scanProject(d.QueryRow(`UPDATE projects SET
	name          = CASE WHEN $2::boolean THEN $3 ELSE name END,
	description   = CASE WHEN $4::boolean THEN $5 ELSE description END,
	owner         = CASE WHEN $6::boolean THEN $7 ELSE owner END,
	status        = CASE WHEN $8::boolean THEN $9 ELSE status END,
	concurrency   = CASE WHEN $10::boolean THEN $11 ELSE concurrency END,
	observer_enabled = CASE WHEN $12::boolean THEN $13 ELSE observer_enabled END,
	report_template_id = CASE WHEN $14::boolean THEN $15::bigint ELSE report_template_id END,
	auto_report   = CASE WHEN $16::boolean THEN $17 ELSE auto_report END,
	auto_report_tasks = CASE WHEN $18::boolean THEN $19 ELSE auto_report_tasks END,
	reader_enabled = CASE WHEN $20::boolean THEN $21 ELSE reader_enabled END,
	task_template_id = CASE WHEN $22::boolean THEN $23::bigint ELSE task_template_id END,
	targets       = CASE WHEN $24::boolean THEN $25 ELSE targets END,
	credentials   = CASE WHEN $26::boolean THEN $27::jsonb ELSE credentials END
WHERE id=$1
RETURNING `+projectCols,
		id,
		patch.Name != nil, derefStr(patch.Name),
		patch.Description != nil, derefStr(patch.Description),
		patch.Owner != nil, derefStr(patch.Owner),
		patch.Status != nil, derefStr(patch.Status),
		patch.Concurrency != nil, normalizeProjectConcurrency(derefInt(patch.Concurrency)),
		patch.ObserverEnabled != nil, derefBool(patch.ObserverEnabled),
		patch.ReportTemplateIDSet, templateAny,
		patch.AutoReport != nil, derefBool(patch.AutoReport),
		patch.AutoReportTasks != nil, derefBool(patch.AutoReportTasks),
		patch.ReaderEnabled != nil, derefBool(patch.ReaderEnabled),
		patch.TaskTemplateIDSet, taskTmplAny(patch),
		patch.Targets != nil, derefStr(patch.Targets),
		patch.Credentials != nil, credentialsJSON(patch.Credentials)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrProjectNotFound
	}
	return p, err
}

// credentialsJSON 把凭据行序列化成 JSON 文本；nil 视为空数组（不是 SQL NULL，
// 列上有 NOT NULL 默认 '[]'）。
func credentialsJSON(creds *[]map[string]any) string {
	if creds == nil {
		return "[]"
	}
	raw, err := json.Marshal(nonNilCredentials(*creds))
	if err != nil {
		return "[]"
	}
	return string(raw)
}

// nonNilCredentials 保证序列化结果是 [] 而不是 null。
func nonNilCredentials(creds []map[string]any) []map[string]any {
	if creds == nil {
		return []map[string]any{}
	}
	return creds
}

// taskTmplAny 把 PATCH 里的模板 id 转成可绑定值：显式清除 → nil（SQL NULL）。
func taskTmplAny(patch UpdateProjectPatch) any {
	if patch.TaskTemplateID != nil && *patch.TaskTemplateID > 0 {
		return *patch.TaskTemplateID
	}
	return nil
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

// DeleteProject 删项目行，并在同一事务里清掉所有以 project_id 归属的派生数据：
//   - project_index / project_graph_events：项目图谱投影与事件流（无外键，不删
//     就永久残留，指向已不存在的项目与任务）
//   - task_intel / task_intel_links / reader_drills：跨任务比对与阅读者审计
//     （项目没了就没有比对语境；行里的 task_id 还会变成悬空 id）
//
// 这些数据是「项目视图的派生结果」，不是任务自身的探索图：即使调用方选择
// delete_tasks=false 保留任务，项目级派生数据也必然失效——重新挂到别的项目
// 后投影会按新项目重建，情报表也会在新任务收官时重抽。
//
// tasks.project_id 的 FK 是 ON DELETE SET NULL：默认任务保留、归属自动摘除。
// 其 queued 的 project_batch 任务由此变为 project_id IS NULL，dispatcher 与
// reconcile（跳过 project_batch）都认不到它，停在队列里等待人工处置。
func (d *DB) DeleteProject(id int64) error {
	_, err := d.DeleteProjectWithReports(id, false)
	return err
}

// DeleteProjectWithReports 删项目行及其派生数据；deleteReports 时同事务删掉
// scope='project' 的报告行，并回传产物路径供调用方在提交后清磁盘。报告与项目
// 之间没有外键，不显式删就是永久孤儿行。
func (d *DB) DeleteProjectWithReports(id int64, deleteReports bool) ([]string, error) {
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM project_index WHERE project_id=$1`,
		`DELETE FROM project_graph_events WHERE project_id=$1`,
		`DELETE FROM task_intel_links WHERE project_id=$1`,
		`DELETE FROM task_intel WHERE project_id=$1`,
		`DELETE FROM reader_drills WHERE project_id=$1`,
	} {
		if _, err := tx.Exec(q, id); err != nil {
			return nil, err
		}
	}
	var paths []string
	if deleteReports {
		rows, err := tx.Query(`DELETE FROM reports WHERE scope='project' AND project_id=$1 RETURNING file_path`, id)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var p string
			if err := rows.Scan(&p); err != nil {
				rows.Close()
				return nil, err
			}
			if p != "" {
				paths = append(paths, p)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	res, err := tx.Exec(`DELETE FROM projects WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrProjectNotFound
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return paths, nil
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

// ProjectBatchQueuedCount 返回某项目当前排队等待项目调度的批量任务数
// （dispatcher 计算本 tick 放行量的分子；条件与 PendingBatchProjectIDs/
// ProjectBatchHeadID 一致，三者对「什么算批量排队行」的口径必须同步改）。
func (d *DB) ProjectBatchQueuedCount(projectID int64) (int, error) {
	var n int
	err := d.QueryRow(`SELECT count(*) FROM tasks
WHERE project_id=$1 AND deleted_at IS NULL AND queued=true AND paused=false
  AND queue_mode='project_batch' AND status NOT IN ('done','failed','timeout')`, projectID).Scan(&n)
	return n, err
}

// PendingBatchProjectIDs 返回「有排队中的批量任务、且项目 active」的项目 id
// 集（dispatcher 每 tick 的遍历入口；量小——项目是人工建的分组单位）。
// 归档项目不出现在这里：其排队任务停在队列等人工处置，dispatcher 不认领。
func (d *DB) PendingBatchProjectIDs() ([]int64, error) {
	rows, err := d.Query(`SELECT DISTINCT t.project_id FROM tasks t
JOIN projects p ON p.id = t.project_id
WHERE t.deleted_at IS NULL AND t.queued=true AND t.paused=false
  AND t.queue_mode='project_batch'
  AND t.status NOT IN ('done','failed','timeout')
  AND p.status='active'
ORDER BY t.project_id`)
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
// 认领条件里带项目 active 谓词：pending 扫描与实际认领之间项目可能被人
// 归档，条件 UPDATE 把 TOCTOU 窗口压没。
//
// 为什么要「认领」而不是「读队首再放行」：等待态若保持 queued=true，原版
// reconcileConcurrency 的盲补循环会在下个 tick 把它按普通排队行捞走（绕过
// 项目闸）。两道保险：①reconcile 收集循环显式跳过 queue_mode='project_batch'
// （server/goals.go）；②Step 在 concMu 内做本条原子 UPDATE——「检查项目额度
// + 认领队首」压进一个不交错的动作，认领后 queued=false，谁都当它是普通
// bootstrap 行。返回 0 表示该项目无可认领任务。
func (d *DB) ProjectBatchHeadID(projectID int64) (int64, error) {
	var id int64
	err := d.QueryRow(`UPDATE tasks SET queued=false, queue_mode='bootstrap', queued_at=NULL
WHERE id = (
	SELECT id FROM tasks
	WHERE project_id=$1 AND deleted_at IS NULL AND queued=true AND paused=false
	  AND queue_mode='project_batch' AND status NOT IN ('done','failed','timeout')
	  AND EXISTS (SELECT 1 FROM projects p WHERE p.id=$1 AND p.status='active')
	ORDER BY queued_at ASC NULLS LAST, id ASC
	LIMIT 1
)
RETURNING id`, projectID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// ---------- 未分类项目（创建任务必须归属项目） ----------

// UncategorizedProjectName 是「创建任务时没选项目」的兜底归属项目名。
// 用户口径：任务必须挂在项目下，不选就进未分类，而不是留成 project_id=NULL 的
// 孤儿行——孤儿行在项目视图里既看不见也管不到。
const UncategorizedProjectName = "未分类"

// uncategorizedProjectKey 记住兜底项目的 id。记 id 而不是每次按名字找：
// 用户把「未分类」改名后，下次建任务仍然要落回同一个项目，不能又建一个新的。
const uncategorizedProjectKey = "project.uncategorized_id"

// EnsureUncategorizedProject 返回「未分类」项目，缺失时创建。
//
// 并发安全靠事务级 advisory lock：建任务是多入口（页面、编排 spawn_task、
// 批量下发）都会走的路，两个请求同时发现「没有未分类项目」就会各建一个。
// 锁内重查 settings 与同名项目，把「查-建-记」压成一个不交错的动作。
func (d *DB) EnsureUncategorizedProject() (*Project, error) {
	if v, ok, err := d.GetSetting(uncategorizedProjectKey); err == nil && ok {
		if id, cerr := strconv.ParseInt(strings.TrimSpace(v), 10, 64); cerr == nil && id > 0 {
			if p, perr := d.GetProject(id); perr == nil && p.Status == "active" {
				return p, nil
			}
		}
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext('artex.uncategorized_project'))`); err != nil {
		return nil, err
	}
	// 锁内重查：等锁期间别的请求可能已经建好并写库。
	var stored string
	if err := tx.QueryRow(`SELECT value FROM settings WHERE key=$1`, uncategorizedProjectKey).Scan(&stored); err == nil {
		if id, cerr := strconv.ParseInt(strings.TrimSpace(stored), 10, 64); cerr == nil && id > 0 {
			if p, perr := scanProject(tx.QueryRow(`SELECT `+projectCols+` FROM projects WHERE id=$1 AND status='active'`, id)); perr == nil {
				return p, tx.Commit()
			}
		}
	}
	p, err := scanProject(tx.QueryRow(`SELECT `+projectCols+` FROM projects
WHERE name=$1 AND status='active' ORDER BY id LIMIT 1`, UncategorizedProjectName))
	if errors.Is(err, sql.ErrNoRows) {
		p, err = scanProject(tx.QueryRow(`
INSERT INTO projects(name, description, owner, concurrency)
VALUES ($1, $2, '', 2)
RETURNING `+projectCols, UncategorizedProjectName, "创建任务时未选择项目的默认归属"))
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`
INSERT INTO settings(key, value) VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		uncategorizedProjectKey, strconv.FormatInt(p.ID, 10)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}
