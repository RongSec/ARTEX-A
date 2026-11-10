package server

// 项目大图 / 洞察面板 API（artex-hs T13，架构 §2.1 投影 / §2.4 注入 / §6 文件清单）。
//
// 数据源是 project_index 投影（[已核实 T12 定稿] 投影常开：observer_enabled
// 只 gate 触发与 insight 注入，**不 gate 这里**——关着观察者的项目照样能看
// 大图）。四个端点：
//   GET  /api/projects/{id}/graph           按任务分组的投影节点
//   POST /api/projects/{id}/graph/rebuild   全量重建投影（RebuildProjectIndex，
//        T12(0) 定稿的「挂/摘项目后补投影」入口，低频同步调用可接受）
//   GET  /api/projects/{id}/insights        观察者洞察列表
//   DELETE /api/projects/{id}/insights/{iid} 删一条（项目作用域 SQL，防越权）
//
// 分组逻辑抽成纯函数 groupProjectIndexRows（DB 行 → DTO 分组），单测直接
// 断言，无需库。

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/db"
)

// GraphNode 是大图里一个投影节点的线格式。
type GraphNode struct {
	NodeID    int64    `json:"node_id"`
	Kind      string   `json:"kind"`
	State     string   `json:"state"`
	Summary   string   `json:"summary"`
	Severity  string   `json:"severity"`
	AssetKeys []string `json:"asset_keys"`
	UpdatedAt int64    `json:"updated_at"` // unix 秒（与站内时间字段口径一致）
}

// GraphTaskGroup 大图按任务分组的一卡：任务元信息 + 节点（新在前）+ kind 计数。
type GraphTaskGroup struct {
	TaskID       int64          `json:"task_id"`
	TaskName     string         `json:"task_name"`
	TaskDesc     string         `json:"task_desc"`
	Status       string         `json:"status"`
	Projected    bool           `json:"projected"` // false=内存里已无此任务handle（归档/硬删残留行），节点仍可展示
	Nodes        []GraphNode    `json:"nodes"`
	CountsByKind map[string]int `json:"counts_by_kind"`
}

// taskMeta 分组时补的任务元信息（内存 handle 缺失时 ok=false，调用方合成占位，
// 防归档任务的残留投影行把整页带崩）。
type taskMeta struct {
	name, desc, status string
}

// groupProjectIndexRows 纯函数：投影行（须按 updated_at DESC, id DESC 查出，
// 函数忠实保持输入序）→ 按任务分组的 DTO。组顺序=各任务最新节点的出现顺序
// （=任务按最近变更新在前）；组内节点保持输入序；CountsByKind 组内统计。
// meta 返回 ok=false 时该组 Projected=false、名称回退 "任务#N"（不丢组——
// 行还在表里就该被看见，点进去是死链由前端按 Projected 禁跳）。
func groupProjectIndexRows(rows []db.ProjectIndexRow, meta func(taskID int64) (taskMeta, bool)) []GraphTaskGroup {
	byTask := map[int64]*GraphTaskGroup{}
	var order []int64
	for _, r := range rows {
		g := byTask[r.TaskID]
		if g == nil {
			tm, live := meta(r.TaskID)
			if !live {
				tm = taskMeta{name: "任务#" + strconv.FormatInt(r.TaskID, 10)}
			}
			g = &GraphTaskGroup{
				TaskID: r.TaskID, TaskName: tm.name, TaskDesc: tm.desc,
				Status: tm.status, Projected: live,
				CountsByKind: map[string]int{},
			}
			byTask[r.TaskID] = g
			order = append(order, r.TaskID)
		}
		g.Nodes = append(g.Nodes, GraphNode{
			NodeID: r.NodeID, Kind: r.Kind, State: r.State, Summary: r.Summary,
			Severity: r.Severity, AssetKeys: r.AssetKeys,
			UpdatedAt: r.UpdatedAt.Unix(),
		})
		g.CountsByKind[r.Kind]++
	}
	out := make([]GraphTaskGroup, 0, len(order))
	for _, id := range order {
		out = append(out, *byTask[id])
	}
	return out
}

// projectGraph GET /api/projects/{id}/graph。
func (s *Server) projectGraph(w http.ResponseWriter, r *http.Request) {
	pid, ok := projectIDParam(w, r)
	if !ok {
		return
	}
	if _, err := s.m.PG().GetProject(pid); errors.Is(err, db.ErrProjectNotFound) {
		writeErr(w, 404, "项目不存在")
		return
	} else if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 一次全量拉取（大图 tab 的定位=项目内全部任务的投影总览；量级=任务数×
	// 节点数摘要行，5000 上限对几百任务的项目仍宽余，超出截断由重建按钮补序，
	// 分页留待真实痛点出现再加——YAGNI）。
	rows, err := s.m.PG().QueryProjectIndex(r.Context(), pid, db.ProjectIndexFilter{Limit: 5000})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	meta := func(taskID int64) (taskMeta, bool) {
		t, ok := s.m.Task(strconv.FormatInt(taskID, 10))
		if !ok {
			return taskMeta{}, false
		}
		return taskMeta{name: t.Name, desc: t.Description, status: s.resolvedTaskStatus(t)}, true
	}
	groups := groupProjectIndexRows(rows, meta)
	resp := map[string]any{"groups": groups}
	if len(rows) == 0 {
		// 空态提示文案由后端给（前后端单一出处；前端空态区展示）。
		resp["hint"] = "暂无投影：任务运行中会实时出现；批量下发/挂项目后未更新的，点「重建投影」补齐。"
	}
	writeJSON(w, 200, resp)
}

// scheduleProjectRebuild 后台异步重建受影响项目的投影（小项 X，消除 B3 遗留
// 风险#1：挂/摘项目后投影不再等任务重启/手动重建）。fire-and-forget：
//   - ctx=s.ctx 派生 30s 预算——进程关停随之取消；单项目重建是几百行级事务，
//     30s 足够且防毒循环占死连接；
//   - recover 兜底——这里 panic 绝不能带崩进程（归属写入已成功，重建只是补账）；
//   - 失败仅 log：下次任意事件流/手动重建自愈（投影最终一致定位）。
//
// 去重由调用方保证（AttachTaskProject 的 changed 集已去重）。
func (s *Server) scheduleProjectRebuild(pids []int64) {
	for _, pid := range pids {
		pid := pid
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[project-indexer] 异步重建 panic project#%d（已恢复）: %v", pid, r)
				}
			}()
			ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
			defer cancel()
			if n, err := s.RebuildProjectIndex(ctx, pid); err != nil {
				log.Printf("[project-indexer] 异步重建失败 project#%d: %v", pid, err)
			} else {
				log.Printf("[project-indexer] 挂/摘触发异步重建完成 project#%d（%d 节点）", pid, n)
			}
		}()
	}
}

// projectGraphRebuild POST /api/projects/{id}/graph/rebuild —— 同步全量重建
// （RebuildProjectIndex 一个事务内清旧灌新；低频手动/程序触发，不进轮询）。
func (s *Server) projectGraphRebuild(w http.ResponseWriter, r *http.Request) {
	pid, ok := projectIDParam(w, r)
	if !ok {
		return
	}
	n, err := s.RebuildProjectIndex(r.Context(), pid)
	if errors.Is(err, db.ErrProjectNotFound) {
		writeErr(w, 404, "项目不存在")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"rebuilt": n})
}

// projectInsightsList GET /api/projects/{id}/insights —— 观察者经验面板。
// 不做关键词命中排序（那是 planner 注入侧的事），恒 created_at 新在前。
func (s *Server) projectInsightsList(w http.ResponseWriter, r *http.Request) {
	pid, ok := projectIDParam(w, r)
	if !ok {
		return
	}
	if _, err := s.m.PG().GetProject(pid); errors.Is(err, db.ErrProjectNotFound) {
		writeErr(w, 404, "项目不存在")
		return
	} else if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	list, err := s.m.PG().ListInsights(r.Context(), pid, nil, 200)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"insights": list})
}

// projectInsightDelete DELETE /api/projects/{id}/insights/{iid}。
// iid 与项目作用域同 WHERE 删除（db.DeleteProjectInsight）：不存在或不属于
// 本项目都回 404，错误信息不区分两态（防探测他项目洞察是否存在）。
func (s *Server) projectInsightDelete(w http.ResponseWriter, r *http.Request) {
	pid, ok := projectIDParam(w, r)
	if !ok {
		return
	}
	iid, ok := pathInt(r, "iid")
	if !ok || iid <= 0 {
		writeErr(w, 400, "洞察 id 无效")
		return
	}
	if err := s.m.PG().DeleteProjectInsight(r.Context(), pid, iid); errors.Is(err, db.ErrInsightNotFound) {
		writeErr(w, 404, "洞察不存在")
		return
	} else if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": iid})
}
