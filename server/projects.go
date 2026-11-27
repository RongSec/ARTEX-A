package server

// projects.go —— artex-hs 二开「项目-任务两级模型」的服务端（T05）。
//
// 设计约束（对照架构文档 §1.1/§1.2/§6.2）：
//   - 项目是纯分组层：不建任务、不碰引擎；任务经 tasks.project_id 可选归属，
//     NULL=无项目，原版路径（createTask/编排 spawn/归档……）零改动。
//   - 响应沿用 writeJSON/writeErr 裸格式，不造 {code,data} 信封。
//   - 详情聚合复用 listTasks 的 taskDTO + TaskListMetricsAll 口径（token/目标/
//     finding 与任务列表页完全同源），不另写一套统计 SQL。

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// AttachTaskProject 把已存在的（未启动的）任务挂到项目或摘除归属（T05 挂/摘、
// T06 建后归位共用）。只动 project_id 一列 + 内存 handle，不做队列/状态迁移。
// projectID=nil 表示摘除。
//
// 返回值 changed=本次归属变动涉及的项目 id 集（去重，最多两个）：挂载时含新
// 项目（补该任务存量图投影）、摘除/换挂时含旧项目（清该任务残留行）。调用方
// （tasksAttachProject handler）据此后台异步 RebuildProjectIndex——见小项 X。
// 归属写入本身成功即返回，重建异步进行、失败不回传给本函数。
// DetachProjectTasks 项目被删除后同步内存视图：DB 侧 tasks.project_id 由 FK
// SET NULL 置空，但常驻内存的 Task 对象仍持有旧 project_id，接口会继续返回
// 已不存在的项目（实测踩过）。这里只清内存，不再写库。
func (m *Manager) DetachProjectTasks(projectID int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tasks {
		if t.ProjectID != nil && *t.ProjectID == projectID {
			t.ProjectID = nil
		}
	}
}

func (m *Manager) AttachTaskProject(id string, projectID *int64) (changed []int64, err error) {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}
	// 旧归属先读（UPDATE 后拿不到）：摘除/换挂时旧项目也要重建清残留行。
	var oldPID int64
	{
		var op sql.NullInt64
		if err := m.pg.QueryRow(`SELECT project_id FROM tasks WHERE id=$1 AND deleted_at IS NULL`, n).Scan(&op); err != nil {
			return nil, err
		}
		oldPID = op.Int64
	}
	var rows int64
	if err := m.pg.QueryRow(`SELECT count(*) FROM tasks WHERE id=$1 AND deleted_at IS NULL`, n).Scan(&rows); err != nil {
		return nil, err
	}
	if rows == 0 {
		return nil, errors.New("task not found")
	}
	if projectID != nil {
		var exists bool
		if err := m.pg.QueryRow(`SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1)`, *projectID).Scan(&exists); err != nil {
			return nil, err
		}
		if !exists {
			return nil, errors.New("project not found")
		}
	}
	if _, err := m.pg.Exec(`UPDATE tasks SET project_id=$2 WHERE id=$1`, n, projectID); err != nil {
		return nil, err
	}
	m.mu.Lock()
	var expID int64
	if t := m.tasks[id]; t != nil {
		t.ProjectID = cloneInt64Ptr(projectID)
		expID = t.ExpID
	}
	m.mu.Unlock()
	// 归属变了，消费侧 exploration→project 缓存必须作废，否则在途事件按旧
	// project_id 投影。回调绑定只在 taskFromPG（handle 发布前）做一次且永不
	// 改写（运行期改字段与运行中协程的读构成数据竞争）。[已核实 T12 裁决2]
	// 运行期挂/摘项目的投影语义：挂载后该任务的回调并未新增（事件暂不产生）；
	// 小项 X 起由调用方后台异步 RebuildProjectIndex 立即补齐（不再等任务重启）。
	// 摘除后存量回调的事件因缓存失效解析到新 pid=0 被丢弃，旧投影行由旧项目
	// 这次重建清掉。
	if expID > 0 {
		m.projectIndexer.InvalidateTaskMapping(expID)
	}
	// 汇总受影响项目：旧（>0 且与新不同）+ 新（>0）。dedup 防换挂同项目时空转。
	newPID := int64(0)
	if projectID != nil {
		newPID = *projectID
	}
	if oldPID > 0 && oldPID != newPID {
		changed = append(changed, oldPID)
	}
	if newPID > 0 {
		changed = append(changed, newPID)
	}
	return changed, nil
}

// EnqueueTaskProjectBatch 是批量下发专用入队（T06）：持久层写
// queued=true + queue_mode='project_batch'，并同步内存 handle 的 FIFO 排序键。
// queue_mode 列无 CHECK（schema.sql:517 实测），自定义值直接可用；原版
// EnqueueTask/ApplyTaskAdmission 只认 bootstrap/resume（传别的会报错或被
// CASE 吞成 resume），故独立小函数、不复用不改它们（零回归）。
// 消费方是 projectDispatcher.Step（T07）；原版 reconcileConcurrency 把这行
// 当普通排队行看待，但 dispatcher 在同 tick 的 concMu 临界区内抢先「认领+
// 准入」，认领后 queued=false，reconcile 再也看不到它——项目闸由此成立。
func (m *Manager) EnqueueTaskProjectBatch(id string) error {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}
	res, err := m.pg.Exec(`UPDATE tasks
		SET queued=true, queued_at=now(), queue_mode='project_batch'
		WHERE id=$1 AND deleted_at IS NULL`, n)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return errors.New("task is unavailable for enqueue")
	}
	m.mu.Lock()
	if t := m.tasks[id]; t != nil {
		// queued_at 语义是「刚写 now()」——内存排序键直接取当前时刻 unix nano，
		// 与 DB 值误差微秒级；同批任务的 FIFO 先后由写入顺序保证，稳定可用。
		t.updateLifecycle(func(state *taskLifecycleState) {
			state.Queued = true
			state.QueueMode = "project_batch"
			state.QueuedAt = time.Now().UnixNano()
		})
	}
	m.mu.Unlock()
	return nil
}

// --- HTTP handlers ---

// projectsCreate 建项目。body {name, description?, owner?, concurrency?,
// observer_enabled?, report_template_id?, auto_report?, auto_report_tasks?,
// reader_enabled?}（auto_report=只出项目汇总；auto_report_tasks=子任务都出，
// 两者可同勾=叠加）。
// V6-DUAL：observer_enabled（跨任务/项目内）与 reader_enabled（跨项目）各自
// 独立生效、各自回显，互不镜像。
func (s *Server) projectsCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name             string `json:"name"`
		Description      string `json:"description"`
		Owner            string `json:"owner"`
		Concurrency      int    `json:"concurrency"`
		ObserverEnabled  bool   `json:"observer_enabled"`
		ReportTemplateID *int64 `json:"report_template_id"`
		AutoReport       bool   `json:"auto_report"`
		AutoReportTasks  bool   `json:"auto_report_tasks"`
		ReaderEnabled    bool   `json:"reader_enabled"`
		// TaskTemplateID 项目默认任务模板；0/null=不预设。校验存在性后落库。
		TaskTemplateID *int64 `json:"task_template_id"`
		// Targets/Credentials 项目默认测试资产（原始文本）与凭据行；批量下发
		// 时作为默认值带出，项目详情页可编辑。
		Targets     string              `json:"targets"`
		Credentials []map[string]any    `json:"credentials"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, 400, "项目名不能为空")
		return
	}
	// 模板存在性校验（仿 reportgen.go:331-340）：传了 >0 就必须是真的模板行；
	// 0/null 视为不绑定。
	if req.ReportTemplateID != nil && *req.ReportTemplateID > 0 {
		t, err := s.m.PG().GetReportTemplate(*req.ReportTemplateID)
		if err != nil {
			writeErr(w, 500, "读取模板失败: "+err.Error())
			return
		}
		if t == nil {
			writeErr(w, 400, "模板不存在")
			return
		}
	}
	// 项目默认任务模板：传了 >0 就必须是真的模板行（同报告模板校验范式）。
	if req.TaskTemplateID != nil && *req.TaskTemplateID > 0 {
		if t, err := s.m.PG().GetTaskTemplate(*req.TaskTemplateID); err != nil {
			writeErr(w, 500, "读取任务模板失败: "+err.Error())
			return
		} else if t == nil {
			writeErr(w, 400, "任务模板不存在")
			return
		}
	}
	p, err := s.m.PG().CreateProject(db.CreateProjectInput{
		Name:             req.Name,
		Description:      req.Description,
		Owner:            req.Owner,
		Concurrency:      req.Concurrency,
		ObserverEnabled:  req.ObserverEnabled,
		ReportTemplateID: req.ReportTemplateID,
		AutoReport:       req.AutoReport,
		AutoReportTasks:  req.AutoReportTasks,
		ReaderEnabled:    req.ReaderEnabled,
		TaskTemplateID:   req.TaskTemplateID,
		Targets:          req.Targets,
		Credentials:      req.Credentials,
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, p)
}

// projectsPause 暂停项目：状态置 paused（dispatcher 不再放行排队任务），并把
// 项目内正在跑/等待中的单个任务一并暂停，打 paused_by_project 标记。
// 排队中的批量任务保持 queued：项目非 active，dispatcher 自然不会认领；
// 若把它们也 pause，任务就脱离了批量队列，恢复时只能逐个手动继续。
func (s *Server) projectsPause(w http.ResponseWriter, r *http.Request) {
	pid, ok := projectIDParam(w, r)
	if !ok {
		return
	}
	p, err := s.m.PG().GetProject(pid)
	if errors.Is(err, db.ErrProjectNotFound) {
		writeErr(w, 404, "项目不存在")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if p.Status == "paused" {
		writeJSON(w, 200, map[string]any{"ok": true, "status": "paused", "paused": 0})
		return
	}
	if p.Status != "active" {
		writeErr(w, 400, "只有进行中的项目可以暂停（已归档项目请先恢复）")
		return
	}
	st := "paused"
	if _, err := s.m.PG().UpdateProject(pid, db.UpdateProjectPatch{Status: &st}); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	rows, err := s.m.PG().ProjectTasks(pid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	paused := 0
	for _, row := range rows {
		if row.Queued || row.Paused || isTerminalStatus(row.Status) {
			continue
		}
		t, ok := s.m.Task(strconv.FormatInt(row.ID, 10))
		if !ok {
			continue
		}
		if _, err := s.applyTaskControlWithCause(t, "pause", agent.AbortPausedByProject); err != nil {
			log.Printf("[project-pause] task %d 暂停失败: %v", row.ID, err)
			continue
		}
		if err := s.m.PG().MarkTaskPausedByProject(row.ID); err != nil {
			log.Printf("[project-pause] task %d 标记失败: %v", row.ID, err)
		}
		paused++
	}
	log.Printf("[project-pause] project %d 已暂停，连带暂停 %d 个任务", pid, paused)
	writeJSON(w, 200, map[string]any{"ok": true, "status": "paused", "paused": paused})
}

// projectsResume 继续项目：状态置 active，只恢复「因项目暂停而暂停」的任务；
// 用户此前手动暂停的任务保持暂停。排队中的批量任务留在队列，dispatcher 下一
// tick 按项目额度继续放行。
func (s *Server) projectsResume(w http.ResponseWriter, r *http.Request) {
	pid, ok := projectIDParam(w, r)
	if !ok {
		return
	}
	p, err := s.m.PG().GetProject(pid)
	if errors.Is(err, db.ErrProjectNotFound) {
		writeErr(w, 404, "项目不存在")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if p.Status == "active" {
		writeJSON(w, 200, map[string]any{"ok": true, "status": "active", "resumed": 0})
		return
	}
	if p.Status != "paused" {
		writeErr(w, 400, "只有已暂停的项目可以继续（已归档项目请先恢复）")
		return
	}
	st := "active"
	if _, err := s.m.PG().UpdateProject(pid, db.UpdateProjectPatch{Status: &st}); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ids, err := s.m.PG().ProjectPausedTaskIDs(pid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	resumed := 0
	for _, id := range ids {
		t, ok := s.m.Task(strconv.FormatInt(id, 10))
		if !ok {
			_ = s.m.PG().ClearTaskPausedByProject(id)
			continue
		}
		if _, err := s.applyTaskControl(t, "resume"); err != nil {
			log.Printf("[project-resume] task %d 恢复失败: %v", id, err)
			continue
		}
		_ = s.m.PG().ClearTaskPausedByProject(id)
		resumed++
	}
	log.Printf("[project-resume] project %d 已继续，恢复 %d 个任务", pid, resumed)
	writeJSON(w, 200, map[string]any{"ok": true, "status": "active", "resumed": resumed})
}

// projectsList 返回项目列表（?status=active|archived|paused 过滤；默认全部）。
func (s *Server) projectsList(w http.ResponseWriter, r *http.Request) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" && status != "active" && status != "archived" && status != "paused" {
		writeErr(w, 400, "status 仅支持 active|archived|paused")
		return
	}
	list, err := s.m.PG().ListProjects(status)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if list == nil {
		list = []*db.ProjectWithStats{}
	}
	writeJSON(w, 200, map[string]any{"projects": list})
}

// projectIDParam 解析 {id} 路径参数。
func projectIDParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "项目 id 无效")
		return 0, false
	}
	return id, true
}

// projectsGet 详情：项目行 + 该项目任务聚合（taskDTO 口径与任务列表一致，
// 带 token/目标进度/finding 分档）+ finding 汇总。
func (s *Server) projectsGet(w http.ResponseWriter, r *http.Request) {
	pid, ok := projectIDParam(w, r)
	if !ok {
		return
	}
	p, err := s.m.PG().GetProject(pid)
	if errors.Is(err, db.ErrProjectNotFound) {
		writeErr(w, 404, "项目不存在")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	metrics, _ := s.m.PG().TaskListMetricsAll()
	archiveBlockers, _ := s.m.PG().TaskArchiveBlockers()
	dtos := make([]TaskDTO, 0, 16)
	agg := db.ProjectStats{TaskCount: 0, QueuedTask: 0, Findings: map[string]int{}}
	pStr := strconv.FormatInt(pid, 10)
	for _, t := range s.m.List() {
		if t.ProjectID == nil || strconv.FormatInt(*t.ProjectID, 10) != pStr {
			continue
		}
		dto := taskDTO(t, s.resolvedTaskStatus(t))
		applyTaskArchiveBlocker(&dto, archiveBlockers)
		m := metrics[t.ExpID]
		dto.Tokens = tokenTotalDTO(m.Tokens)
		if live := s.engine.LastActivity(t.ID); live > dto.LastActivity {
			dto.LastActivity = live
		}
		dto.GoalsTotal = m.Goals.Total
		dto.GoalsMet = m.Goals.Met
		dto.InFlight = m.RunningIntents
		dto.Findings = FindingSeverityDTO{Critical: m.Findings.Critical, High: m.Findings.High, Medium: m.Findings.Medium, Low: m.Findings.Low}
		agg.TaskCount++
		if dto.Queued {
			agg.QueuedTask++
		}
		agg.Findings["critical"] += dto.Findings.Critical
		agg.Findings["high"] += dto.Findings.High
		agg.Findings["medium"] += dto.Findings.Medium
		agg.Findings["low"] += dto.Findings.Low
		dtos = append(dtos, dto)
	}
	writeJSON(w, 200, map[string]any{"project": p, "tasks": dtos, "stats": agg})
}

// projectsUpdate PATCH 项目。body 全部可选：只动传了键的字段。
// name 传了但为空白 = 拒绝（改空项目名没意义）；description/owner 可清空。
func (s *Server) projectsUpdate(w http.ResponseWriter, r *http.Request) {
	pid, ok := projectIDParam(w, r)
	if !ok {
		return
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	var patch db.UpdateProjectPatch
	if v, has := raw["name"]; has {
		var sVal string
		if err := json.Unmarshal(v, &sVal); err != nil {
			writeErr(w, 400, "name 须为字符串")
			return
		}
		if strings.TrimSpace(sVal) == "" {
			writeErr(w, 400, "项目名不能为空")
			return
		}
		patch.Name = &sVal
	}
	if v, has := raw["description"]; has {
		var sVal string
		if err := json.Unmarshal(v, &sVal); err != nil {
			writeErr(w, 400, "description 须为字符串")
			return
		}
		patch.Description = &sVal
	}
	if v, has := raw["owner"]; has {
		var sVal string
		if err := json.Unmarshal(v, &sVal); err != nil {
			writeErr(w, 400, "owner 须为字符串")
			return
		}
		patch.Owner = &sVal
	}
	if v, has := raw["status"]; has {
		var sVal string
		if err := json.Unmarshal(v, &sVal); err != nil {
			writeErr(w, 400, "status 须为字符串")
			return
		}
		patch.Status = &sVal
	}
	if v, has := raw["concurrency"]; has {
		var n int
		if err := json.Unmarshal(v, &n); err != nil {
			writeErr(w, 400, "concurrency 须为整数")
			return
		}
		patch.Concurrency = &n
	}
	if v, has := raw["observer_enabled"]; has {
		var b bool
		if err := json.Unmarshal(v, &b); err != nil {
			writeErr(w, 400, "observer_enabled 须为布尔")
			return
		}
		patch.ObserverEnabled = &b
	}
	// T18 三字段。report_template_id 显式 null=清除绑定（回退默认模板链），
	// 数字>0=绑定（校验存在性，仿 reportgen.go:331-340）；0 同 null。
	if v, has := raw["report_template_id"]; has {
		patch.ReportTemplateIDSet = true
		if string(v) != "null" {
			var n int64
			if err := json.Unmarshal(v, &n); err != nil {
				writeErr(w, 400, "report_template_id 须为整数或 null")
				return
			}
			if n > 0 {
				t, err := s.m.PG().GetReportTemplate(n)
				if err != nil {
					writeErr(w, 500, "读取模板失败: "+err.Error())
					return
				}
				if t == nil {
					writeErr(w, 400, "模板不存在")
					return
				}
				patch.ReportTemplateID = &n
			}
		}
	}
	if v, has := raw["auto_report"]; has {
		var b bool
		if err := json.Unmarshal(v, &b); err != nil {
			writeErr(w, 400, "auto_report 须为布尔")
			return
		}
		patch.AutoReport = &b
	}
	if v, has := raw["auto_report_tasks"]; has {
		var b bool
		if err := json.Unmarshal(v, &b); err != nil {
			writeErr(w, 400, "auto_report_tasks 须为布尔")
			return
		}
		patch.AutoReportTasks = &b
	}
	if v, has := raw["reader_enabled"]; has {
		var b bool
		if err := json.Unmarshal(v, &b); err != nil {
			writeErr(w, 400, "reader_enabled 须为布尔")
			return
		}
		patch.ReaderEnabled = &b
	}
	// 项目默认任务模板：null/0=清除，>0=绑定（校验存在性，与创建同款）。
	if v, has := raw["task_template_id"]; has {
		patch.TaskTemplateIDSet = true
		if string(v) != "null" {
			var n int64
			if err := json.Unmarshal(v, &n); err != nil {
				writeErr(w, 400, "task_template_id 须为整数或 null")
				return
			}
			if n > 0 {
				if t, err := s.m.PG().GetTaskTemplate(n); err != nil {
					writeErr(w, 500, "读取任务模板失败: "+err.Error())
					return
				} else if t == nil {
					writeErr(w, 400, "任务模板不存在")
					return
				}
				patch.TaskTemplateID = &n
			}
		}
	}
	// 项目默认测试资产：整段替换（空串=清空）；凭据是数组，整段替换。
	if v, has := raw["targets"]; has {
		var sVal string
		if err := json.Unmarshal(v, &sVal); err != nil {
			writeErr(w, 400, "targets 须为字符串")
			return
		}
		patch.Targets = &sVal
	}
	if v, has := raw["credentials"]; has {
		var rows []map[string]any
		if err := json.Unmarshal(v, &rows); err != nil {
			writeErr(w, 400, "credentials 须为数组")
			return
		}
		patch.Credentials = &rows
	}
	p, err := s.m.PG().UpdateProject(pid, patch)
	if errors.Is(err, db.ErrProjectNotFound) {
		writeErr(w, 404, "项目不存在")
		return
	}
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// 勾选「跨项目阅读」时顺手打开 reader 的全局触发器：项目开关只表示
	// 「允许读」，真正跑不跑还取决于 agent_triggers.enabled（默认关）。否则
	// 用户勾了开关却发现阅读者从不运行，审计页面永远是空的。
	if patch.ReaderEnabled != nil && *patch.ReaderEnabled {
		if n, err := s.m.PG().EnsureAgentTriggerEnabled("reader"); err != nil {
			log.Printf("[project] 打开 reader 触发器失败: %v", err)
		} else if n > 0 {
			log.Printf("[project] 已随项目 %d 的跨项目阅读开关启用 reader 触发器", pid)
		}
	}
	// 投影常开（T12 定稿）：observer_enabled 翻转不影响 project_index，无需
	// 失效任何投影侧缓存。该开关只管 fireProjectGraph 触发（scheduler 每 tick
	// 直查 JOIN projects，无缓存）与 insight 注入（planner resolver 每次直查，
	// 无缓存），两处都即时生效。
	writeJSON(w, 200, p)
}

// deleteProjectRequest 是 DELETE /api/projects/{id} 的可选 body。五个清理开关
// 与任务删除（DeleteTaskOptions）同名同义；delete_tasks=true 表示连同旗下任务
// 一起删。
type deleteProjectRequest struct {
	DeleteTaskOptions
	DeleteTasks bool `json:"delete_tasks"`
}

// projectsDelete 删项目。tasks.project_id FK=ON DELETE SET NULL：默认（不带 body
// 或 delete_tasks=false）任务保留、归属自动摘除。其排队中的批量任务由此脱离
// 项目调度（dispatcher 只认 project_id 命中 ∧ active 项目），停在队列里等用户
// 显式继续——不会偷偷跑，也不会被删。
//
// delete_tasks=true 时先逐任务走与 DELETE /api/tasks/{id} 完全相同的拆除流程
// （排空 agent → 级联删除），单个任务失败不中断整体：错误记入 task_errors，
// 最后再删项目行；失败的任务因 FK SET NULL 保留为未分组。
func (s *Server) projectsDelete(w http.ResponseWriter, r *http.Request) {
	pid, ok := projectIDParam(w, r)
	if !ok {
		return
	}
	var req deleteProjectRequest
	if err := decode(r, &req); err != nil && err != io.EOF {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	tasks, err := s.m.PG().ProjectTasks(pid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	tasksDeleted := 0
	taskErrors := []string{}
	if req.DeleteTasks {
		for _, t := range tasks {
			id := strconv.FormatInt(t.ID, 10)
			if _, err := s.deleteTaskCore(r.Context(), id, req.DeleteTaskOptions); err != nil {
				var committed *taskDeleteCommittedError
				if errors.As(err, &committed) {
					// PostgreSQL 行已删：算删除成功，只是外部清理不完整。
					tasksDeleted++
				}
				taskErrors = append(taskErrors, fmt.Sprintf("task %d: %s", t.ID, err))
				continue
			}
			tasksDeleted++
		}
	}
	reportPaths, err := s.m.PG().DeleteProjectWithReports(pid, req.DeleteReports)
	if errors.Is(err, db.ErrProjectNotFound) {
		writeErr(w, 404, "项目不存在")
		return
	} else if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	for _, p := range reportPaths {
		_ = removeReportArtifacts(s.m.dir, p)
	}
	// 保留分支：FK 已把库里的 project_id 置空，内存对象要同步，否则任务列表
	// 还会显示一个不存在的项目。
	s.m.DetachProjectTasks(pid)
	writeJSON(w, 200, map[string]any{
		"deleted":         pid,
		"tasks_deleted":   tasksDeleted,
		"tasks_kept":      len(tasks) - tasksDeleted,
		"task_errors":     taskErrors,
		"reports_deleted": len(reportPaths),
	})
}

// tasksAttachProject 给任务挂/摘项目：PATCH /api/tasks/{id}/project
// body {"project_id": 3 | null}。挂项目对运行状态不做任何迁移——归属是标签，
// 生命周期归生命周期（拍板：项目层松耦合）。
func (s *Server) tasksAttachProject(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if _, err := strconv.ParseInt(id, 10, 64); err != nil {
		writeErr(w, 400, "任务 id 无效")
		return
	}
	var req struct {
		ProjectID *int64 `json:"project_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if req.ProjectID != nil && *req.ProjectID <= 0 {
		writeErr(w, 400, "project_id 无效")
		return
	}
	changed, err := s.m.AttachTaskProject(id, req.ProjectID)
	if err != nil {
		if err.Error() == "task not found" {
			writeErr(w, 404, "任务不存在")
			return
		}
		if err.Error() == "project not found" {
			writeErr(w, 400, "项目不存在")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	// 小项 X：归属变动→后台异步重建受影响项目投影（含被摘除的旧项目，清残留行）。
	s.scheduleProjectRebuild(changed)
	t, _ := s.m.Task(id)
	if t == nil {
		writeJSON(w, 200, map[string]any{"task_id": id, "project_id": req.ProjectID})
		return
	}
	writeJSON(w, 200, taskDTO(t, s.resolvedTaskStatus(t)))
}
