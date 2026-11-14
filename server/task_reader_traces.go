package server

// 任务视角的「阅读者勾连审计」接口（V8-NAME）：
//
//	GET /api/tasks/{id}/reader-traces
//
// 返回两组记录，供任务详情会话区直接审计「这个任务被谁勾连过、勾连了谁」：
//   - cross_task：与本任务同项目的勾连记录（项目内视角 = 跨任务阅读者）
//   - cross_project：对端任务属于其它项目的勾连记录（跨项目视角 = 跨项目阅读者）
//
// 两组都按时间倒序；direction 表示本任务是发起方（out）还是被勾连方（in）。
// 若该任务还命中了阅读者 LLM 运行（llm_records.worker IN reader/observer），
// 一并返回 runs；没有就是空数组，不报错。

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/db"
)

// ReaderTraceMatch 是一条命中明细（task_intel_links.matched 的元素子集）。
type ReaderTraceMatch struct {
	Kind  string `json:"kind"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ReaderTraceItem 是一条勾连记录。对端项目可能为空（任务未挂项目）。
type ReaderTraceItem struct {
	RelatedTaskID      int64              `json:"related_task_id"`
	RelatedTaskName    string             `json:"related_task_name"`
	RelatedProjectID   int64              `json:"related_project_id"`
	RelatedProjectName string             `json:"related_project_name"`
	Decision           string             `json:"decision"`
	Reason             string             `json:"reason"`
	Matched            []ReaderTraceMatch `json:"matched"`
	CreatedAt          time.Time          `json:"created_at"`
	Direction          string             `json:"direction"` // out=本任务勾连别人，in=别人勾连本任务
}

// taskReaderTraces GET /api/tasks/{id}/reader-traces。
func (s *Server) taskReaderTraces(w http.ResponseWriter, r *http.Request) {
	taskID, ok := pathInt(r, "id")
	if !ok || taskID <= 0 {
		writeErr(w, 400, "任务 id 无效")
		return
	}
	t, err := s.m.pg.GetTask(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if t == nil {
		writeErr(w, 404, "任务不存在")
		return
	}
	rows, err := s.m.pg.ListTaskIntelLinkTraces(r.Context(), taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	var projectID int64
	if t.ProjectID != nil {
		projectID = *t.ProjectID
	}

	crossTask := []ReaderTraceItem{}
	crossProject := []ReaderTraceItem{}
	for _, row := range rows {
		item := ReaderTraceItem{
			RelatedTaskID:      row.RelatedTaskID,
			RelatedTaskName:    row.RelatedTaskName,
			RelatedProjectID:   row.RelatedProjectID.Int64,
			RelatedProjectName: row.RelatedProjectName.String,
			Decision:           row.Decision,
			Reason:             row.Reason,
			Matched:            decodeReaderTraceMatches(row.Matched),
			CreatedAt:          row.CreatedAt,
			Direction:          row.Direction,
		}
		// 同项目才有「跨任务」视角；本任务未挂项目时，任何勾连都只能算跨项目。
		if projectID > 0 && row.RelatedProjectID.Valid && row.RelatedProjectID.Int64 == projectID {
			crossTask = append(crossTask, item)
		} else {
			crossProject = append(crossProject, item)
		}
	}

	runs, err := s.m.pg.ListReaderRunsForTask(r.Context(), i64s(taskID), 50)
	if err != nil {
		// 运行记录是附加信息：查不到不能让整个审计面失败。
		runs = []db.ReaderLLMRun{}
	}
	writeJSON(w, 200, map[string]any{
		"task_id":       taskID,
		"cross_task":    crossTask,
		"cross_project": crossProject,
		"runs":          runs,
	})
}

// decodeReaderTraceMatches 把 matched JSONB 收敛成 {kind,key,value} 数组。
// 坏行/空行都归一为空数组，保证前端拿到的永远是数组。
func decodeReaderTraceMatches(raw json.RawMessage) []ReaderTraceMatch {
	out := []ReaderTraceMatch{}
	if len(raw) == 0 {
		return out
	}
	var items []ReaderTraceMatch
	if err := json.Unmarshal(raw, &items); err != nil {
		return out
	}
	if items == nil {
		return out
	}
	return items
}
