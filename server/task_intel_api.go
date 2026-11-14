package server

// 任务情报表 API（V7-INTEL 第一层）。两个端点：
//   GET  /api/tasks/{id}/intel          该任务的情报表，按 kind 分组
//   POST /api/tasks/{id}/intel/rebuild  立即重建（同步；管理员=登录态，见 auth.go
//        单管理员模型：/api/* 全部过 JWT，没有更细的角色维度）
//
// GET 只读不生成：情报表的生成时机是任务终态（或显式 rebuild），避免打开面板
// 就触发写库+发信号。

import (
	"net/http"

	"github.com/Autumn-27/artex/db"
)

// IntelGroup 是情报表的一个 kind 分组（顺序固定：endpoint/credential/
// component/asset/vuln，前端不用自己排序）。
type IntelGroup struct {
	Kind  string         `json:"kind"`
	Label string         `json:"label"`
	Count int            `json:"count"`
	Items []db.TaskIntel `json:"items"`
}

// intelGroupOrder 是分组展示顺序（与事件摘要同序）。
var intelGroupOrder = []string{
	db.IntelKindEndpoint, db.IntelKindCredential, db.IntelKindComponent,
	db.IntelKindAsset, db.IntelKindVuln,
}

// groupTaskIntel 纯函数：平铺行 → 按 kind 分组（空 kind 也保留分组，前端
// 渲染五张固定表头更稳；组内保持输入序=DB 的 kind,key 序）。
func groupTaskIntel(rows []db.TaskIntel) []IntelGroup {
	byKind := map[string][]db.TaskIntel{}
	for _, r := range rows {
		byKind[r.Kind] = append(byKind[r.Kind], r)
	}
	out := make([]IntelGroup, 0, len(intelGroupOrder))
	for _, k := range intelGroupOrder {
		items := byKind[k]
		if items == nil {
			items = []db.TaskIntel{}
		}
		out = append(out, IntelGroup{Kind: k, Label: db.IntelKindLabel(k), Count: len(items), Items: items})
	}
	return out
}

// taskIntelList GET /api/tasks/{id}/intel。
func (s *Server) taskIntelList(w http.ResponseWriter, r *http.Request) {
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
	rows, err := s.m.pg.TaskIntelForTask(r.Context(), taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	groups := groupTaskIntel(rows)
	resp := map[string]any{
		"task_id": taskID,
		"total":   len(rows),
		"groups":  groups,
	}
	if t.ProjectID == nil || *t.ProjectID <= 0 {
		resp["hint"] = "该任务未挂项目：情报表只在项目内生成（跨任务比对需要项目范围）。"
	} else if len(rows) == 0 {
		resp["hint"] = "暂无情报：任务收官时自动生成，也可点「重建」立即抽取。"
	}
	writeJSON(w, 200, resp)
}

// taskIntelRebuild POST /api/tasks/{id}/intel/rebuild —— 同步重建。终态钩子
// 是异步尽力而为，这里是可重试的确定性入口（幂等：重复调用行数不变，只有
// 真新增才发图变更信号）。
func (s *Server) taskIntelRebuild(w http.ResponseWriter, r *http.Request) {
	taskID, ok := pathInt(r, "id")
	if !ok || taskID <= 0 {
		writeErr(w, 400, "任务 id 无效")
		return
	}
	st, err := s.buildTaskIntel(r.Context(), taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, st)
}
