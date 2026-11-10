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
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// AttachTaskProject 把已存在的（未启动的）任务挂到项目或摘除归属（T05 挂/摘、
// T06 建后归位共用）。只动 project_id 一列 + 内存 handle，不做队列/状态迁移。
// projectID=nil 表示摘除。
func (m *Manager) AttachTaskProject(id string, projectID *int64) error {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}
	var rows int64
	if err := m.pg.QueryRow(`SELECT count(*) FROM tasks WHERE id=$1 AND deleted_at IS NULL`, n).Scan(&rows); err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("task not found")
	}
	if projectID != nil {
		var exists bool
		if err := m.pg.QueryRow(`SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1)`, *projectID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return errors.New("project not found")
		}
	}
	if _, err := m.pg.Exec(`UPDATE tasks SET project_id=$2 WHERE id=$1`, n, projectID); err != nil {
		return err
	}
	m.mu.Lock()
	var expID int64
	if t := m.tasks[id]; t != nil {
		t.ProjectID = cloneInt64Ptr(projectID)
		expID = t.ExpID
	}
	m.mu.Unlock()
	// 归属变了，消费侧 exploration→project 缓存必须作废，否则在途事件按旧
	// project_id 投影。回调本身（store.OnGraphChange）在 taskFromPG 处一经绑定
	// 就不再改写（避免与运行中 planner/worker 对该函数字段的读构成数据竞争）：
	// 挂项目的任务靠 projectOf 缓存失效后下一事件自动解析到新 pid 恢复投影，
	// 摘项目的任务解析到 pid=0 自动短路，都无需重启。
	if expID > 0 {
		m.projectIndexer.InvalidateTaskMapping(expID)
	}
	return nil
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

// projectsCreate 建项目。body {name, description?, owner?, concurrency?}。
func (s *Server) projectsCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Owner       string `json:"owner"`
		Concurrency int    `json:"concurrency"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, 400, "项目名不能为空")
		return
	}
	p, err := s.m.PG().CreateProject(req.Name, req.Description, req.Owner, req.Concurrency)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, p)
}

// projectsList 返回项目列表（?status=active|archived 过滤；默认全部）。
func (s *Server) projectsList(w http.ResponseWriter, r *http.Request) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" && status != "active" && status != "archived" {
		writeErr(w, 400, "status 仅支持 active|archived")
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
	p, err := s.m.PG().UpdateProject(pid, patch)
	if errors.Is(err, db.ErrProjectNotFound) {
		writeErr(w, 404, "项目不存在")
		return
	}
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// 开关翻转：作废消费侧 projGate 缓存，让下一事件立刻按新开关判定
	// （命中关=丢弃，命中开=恢复投影）。
	if patch.ObserverEnabled != nil {
		s.m.projectIndexer.InvalidateProjectGate(pid)
	}
	writeJSON(w, 200, p)
}

// projectsDelete 删项目。tasks.project_id FK=ON DELETE SET NULL：任务保留、
// 归属自动摘除。其排队中的批量任务由此脱离项目调度（dispatcher 只认
// project_id 命中 ∧ active 项目），停在队列里等用户显式继续——不会偷偷跑，
// 也不会被删。
func (s *Server) projectsDelete(w http.ResponseWriter, r *http.Request) {
	pid, ok := projectIDParam(w, r)
	if !ok {
		return
	}
	if err := s.m.PG().DeleteProject(pid); errors.Is(err, db.ErrProjectNotFound) {
		writeErr(w, 404, "项目不存在")
		return
	} else if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": pid})
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
	if err := s.m.AttachTaskProject(id, req.ProjectID); err != nil {
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
	t, _ := s.m.Task(id)
	if t == nil {
		writeJSON(w, 200, map[string]any{"task_id": id, "project_id": req.ProjectID})
		return
	}
	writeJSON(w, 200, taskDTO(t, s.resolvedTaskStatus(t)))
}
