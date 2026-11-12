package server

// 事实台账 API（V4-A）。fact = exploration_nodes kind='fact'。两端点：
//   GET   /api/facts?project_id=&task_id=&q=   三层聚合（项目→任务→事实）
//   PATCH /api/facts/{nodeId}                  人工编辑 summary/description/category，
//        首编把机器原文固化进 payload.machine_original（db.MergeFactEdit 纯函数）。
// 解析/分组/合并全在 db 层纯函数，本文件只做参数、DTO 序列化与路由。
// 新路由注册在 Handler() 主 requireAuth 段（api := cors(s.requireAuth(mux))）。

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// ---- DTO（id 一律字符串，与站内 FindingDTO 口径一致） ----

type factAnchorDTO struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

type factTextsDTO struct {
	Summary     string `json:"summary"`
	Description string `json:"description"`
}

type factNodeDTO struct {
	ID              string          `json:"id"`
	TaskID          string          `json:"task_id"`
	Summary         string          `json:"summary"`
	Description     string          `json:"description"`
	Evidence        string          `json:"evidence,omitempty"`
	Confidence      string          `json:"confidence,omitempty"`
	Category        string          `json:"category,omitempty"`
	Source          string          `json:"source"`
	Edited          bool            `json:"edited"`
	MachineOriginal *factTextsDTO   `json:"machine_original,omitempty"`
	Anchors         []factAnchorDTO `json:"anchors"`
	CreatedAt       string          `json:"created_at"`
	UpdatedAt       string          `json:"updated_at"`
}

type factTaskDTO struct {
	ID     string        `json:"id"`
	Name   string        `json:"name"`
	Status string        `json:"status"`
	Facts  []factNodeDTO `json:"facts"`
}

type factProjectDTO struct {
	Project *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"project"` // null=未挂项目组
	Tasks []factTaskDTO `json:"tasks"`
}

func factNodeToDTO(n db.FactNode, taskID int64) factNodeDTO {
	d := factNodeDTO{
		ID:          i64s(n.ID),
		TaskID:      i64s(taskID),
		Summary:     n.Summary,
		Description: n.Description,
		Evidence:    n.Evidence,
		Confidence:  n.Confidence,
		Category:    n.Category,
		Source:      n.Source,
		Edited:      n.Edited,
		CreatedAt:   rfc3339(n.CreatedAt),
		UpdatedAt:   rfc3339(n.UpdatedAt),
		Anchors:     []factAnchorDTO{},
	}
	for _, a := range n.Anchors {
		d.Anchors = append(d.Anchors, factAnchorDTO{ID: i64s(a.ID), Type: a.Type, Label: a.Label})
	}
	if n.MachineOriginal != nil {
		d.MachineOriginal = &factTextsDTO{Summary: n.MachineOriginal.Summary, Description: n.MachineOriginal.Description}
	}
	return d
}

// factsQuery GET /api/facts：一次聚合查询 + 一次锚点批量查询 → 三层 DTO。
func (s *Server) factsQuery(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	q := r.URL.Query()
	var fq db.FactQuery
	if v := strings.TrimSpace(q.Get("project_id")); v != "" {
		if v == "none" {
			// 未挂项目组（前端"未挂项目"筛选）。
			fq.Unassigned = true
		} else {
			id, err := strconv.ParseInt(v, 10, 64)
			if err != nil || id <= 0 {
				writeErr(w, 400, "project_id 无效")
				return
			}
			fq.ProjectID = id
		}
	}
	if v := strings.TrimSpace(q.Get("task_id")); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id <= 0 {
			writeErr(w, 400, "task_id 无效")
			return
		}
		fq.TaskID = id
	}
	fq.Q = q.Get("q")

	rows, err := s.m.PG().ListFactRows(r.Context(), fq)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ids := make([]int64, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.NodeID)
	}
	anchors, err := s.m.PG().FactAnchorsByNode(r.Context(), ids)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	groups := db.GroupFactRows(rows, anchors)
	out := make([]factProjectDTO, 0, len(groups))
	for _, g := range groups {
		pd := factProjectDTO{Tasks: []factTaskDTO{}}
		if g.ProjectID != nil {
			pd.Project = &struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}{ID: i64s(*g.ProjectID), Name: g.ProjectName}
		}
		for _, t := range g.Tasks {
			fd := factTaskDTO{ID: i64s(t.TaskID), Name: t.TaskName, Status: t.TaskStatus, Facts: []factNodeDTO{}}
			for _, n := range t.Facts {
				fd.Facts = append(fd.Facts, factNodeToDTO(n, t.TaskID))
			}
			pd.Tasks = append(pd.Tasks, fd)
		}
		out = append(out, pd)
	}
	writeJSON(w, 200, out)
}

// factEdit PATCH /api/facts/{nodeId}：人工编辑一条事实（仅 kind='fact'）。
// body {summary?,description?,category?}，字段白名单、首编固化机器原文均在
// db.MergeFactEdit。成功返回更新后的 fact DTO。
func (s *Server) factEdit(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("nodeId")), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "fact node id 无效")
		return
	}
	var body struct {
		Summary     *string `json:"summary"`
		Description *string `json:"description"`
		Category    *string `json:"category"`
	}
	if decErr := json.NewDecoder(r.Body).Decode(&body); decErr != nil {
		writeErr(w, 400, "bad json: "+decErr.Error())
		return
	}
	if body.Summary == nil && body.Description == nil && body.Category == nil {
		writeErr(w, 400, "nothing to update: provide summary/description/category")
		return
	}
	if body.Summary != nil && strings.TrimSpace(*body.Summary) == "" {
		writeErr(w, 400, "summary 不能为空")
		return
	}
	if body.Category != nil && !db.ValidFactCategory(*body.Category) {
		writeErr(w, 400, "bad category: "+*body.Category)
		return
	}
	payload, origin, found, err := s.m.PG().GetFactNodePayload(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !found {
		writeErr(w, 404, "fact 不存在")
		return
	}
	merged, err := db.MergeFactEdit(payload, db.KindFact, db.FactEditPatch{
		Summary: body.Summary, Description: body.Description, Category: body.Category})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	updated, err := s.m.PG().SaveFactNodePayload(r.Context(), id, merged)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !updated {
		writeErr(w, 404, "fact 不存在")
		return
	}
	// 回读组装 DTO（updated_at 由触发器刷新）。
	var raw []byte
	var createdAt, updatedAt time.Time
	if err := s.m.PG().QueryRowContext(r.Context(),
		`SELECT payload, created_at, updated_at FROM exploration_nodes WHERE id=$1 AND kind='fact'`, id).
		Scan(&raw, &createdAt, &updatedAt); err != nil {
		writeErr(w, 500, "读取更新结果失败: "+err.Error())
		return
	}
	n := db.ParseFactRow(db.FactRow{NodeID: id, Payload: json.RawMessage(raw), Origin: origin,
		CreatedAt: createdAt, UpdatedAt: updatedAt})
	anchors, _ := s.m.PG().FactAnchorsByNode(r.Context(), []int64{id})
	n.Anchors = anchors[id]
	// PATCH 响应不含任务归属（前端从当前列表行合并正文/类别/编辑字段），task_id 占位。
	writeJSON(w, 200, factNodeToDTO(n, 0))
}
