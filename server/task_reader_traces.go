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
	// 两级评分：match_* 是 SQL 命中分（进候选的依据），relevance_* 是阅读者
	// 读完整图后的相关性分（暴露的依据）。审计要把两个都亮出来，否则看不出
	// 「为什么进了候选却没采纳」。
	MatchStrength     string          `json:"match_strength"`
	MatchScore        float64         `json:"match_score"`
	MatchHits         int             `json:"match_hits"`
	RelevanceScore    int             `json:"relevance_score"`
	RelevanceStrength string          `json:"relevance_strength"`
	Chains            []db.ReaderChain `json:"chains"`
	// ForeignHosts 是本条采纳带进发起方任务的外部资产 host（V9-SCOPE）。
	// 只有 decision=adopted 才有；dismissed/候选恒为空数组。
	ForeignHosts []string  `json:"foreign_hosts"`
	DecidedBy    string    `json:"decided_by"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Direction    string    `json:"direction"` // out=本任务勾连别人，in=别人勾连本任务
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
			MatchStrength:      row.MatchStrength,
			MatchScore:         row.MatchScore,
			MatchHits:          row.MatchHits,
			RelevanceScore:     row.RelevanceScore,
			RelevanceStrength:  row.RelevanceStrength,
			Chains:             decodeReaderChains(row.Chains),
			ForeignHosts:       []string{},
			DecidedBy:          row.DecidedBy,
			CreatedAt:          row.CreatedAt,
			UpdatedAt:          row.UpdatedAt,
			Direction:          row.Direction,
		}
		if row.Decision == "adopted" {
			// out：本任务是发起方，外部资产记在 (本任务 ← 对端)；
			// in ：对端是发起方，外部资产记在 (对端任务 ← 本任务)，也一并展示，
			//      让被勾连方能看到「我的哪些资产被带进了对方的任务」。
			adoptTask, sourceTask := taskID, row.RelatedTaskID
			if row.Direction == "in" {
				adoptTask, sourceTask = row.TaskID, taskID
			}
			if hosts, err := s.m.pg.ForeignHostsForTaskSource(r.Context(), adoptTask, sourceTask); err == nil && len(hosts) > 0 {
				item.ForeignHosts = hosts
			}
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
	// 下钻明细：审计的第二块——「采纳了谁」之外，还要看到「用了对方的哪几个点」。
	// 查询失败同样降级为空数组，审计面不因附加信息缺失而整体 500。
	drills, err := s.m.pg.ListReaderDrills(r.Context(), taskID)
	if err != nil {
		drills = []db.ReaderDrill{}
	}
	writeJSON(w, 200, map[string]any{
		"task_id":       taskID,
		"cross_task":    crossTask,
		"cross_project": crossProject,
		"runs":          runs,
		"drills":        drills,
	})
}

// decodeReaderChains 把 chains JSONB 收敛成结构化链摘要。坏行归一为空。
func decodeReaderChains(raw json.RawMessage) []db.ReaderChain {
	if len(raw) == 0 {
		return []db.ReaderChain{}
	}
	var chains []db.ReaderChain
	if err := json.Unmarshal(raw, &chains); err != nil {
		return []db.ReaderChain{}
	}
	if chains == nil {
		return []db.ReaderChain{}
	}
	return chains
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
