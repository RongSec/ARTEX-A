package server

import (
	"net/http"

	"github.com/Autumn-27/artex/db"
)

// ---------- P3 agent triggers (仅自定义 agent) ----------

func (s *Server) pgListTriggers(w http.ResponseWriter, r *http.Request) {
	pg, a, ok := s.agentByKey(w, r)
	if !ok {
		return
	}
	trs, err := pg.ListTriggersFor(a.Key)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"triggers": trs})
}

type triggerReq struct {
	Enabled       bool `json:"enabled"`
	IntervalSec   int  `json:"interval_sec"`
	OnFinding     bool `json:"on_finding"`
	OnGoalMet     bool `json:"on_goal_met"`
	OnTaskTimeout bool `json:"on_task_timeout"`
	OnToolCall    bool `json:"on_tool_call"`
	OnTaskCreate  bool `json:"on_task_create"`
	// T11 on_project_graph：指针 + PUT 缺省回填原值。observer 触发器行由 seed
	// 自动创建，而 web 触发器表单还不认识该字段——若按普通 bool 无条件写回，
	// 用户在页面上编辑任何其他触发器都会把 observer 的图变更开关静默拆掉。
	OnProjectGraph      *bool    `json:"on_project_graph"`
	IntervalMessage     string   `json:"interval_message"`
	FindingMessage      string   `json:"finding_message"`
	GoalMessage         string   `json:"goal_message"`
	TaskTimeoutMessage  string   `json:"task_timeout_message"`
	ToolCallMessage     string   `json:"tool_call_message"`
	TaskCreateMessage   string   `json:"task_create_message"`
	ProjectGraphMessage string   `json:"project_graph_message"`
	ToolNames           []string `json:"tool_names"`
}

// validateTrigger enforces the shared trigger rules for create/update:
// at least one condition, and on_tool_call requires a non-empty tool set.
func validateTrigger(req *triggerReq) string {
	if req.IntervalSec == 0 && !req.OnFinding && !req.OnGoalMet && !req.OnTaskTimeout && !req.OnToolCall && !req.OnTaskCreate && !derefBoolPtr(req.OnProjectGraph) {
		return "至少选择一种触发条件(定时/发现finding/目标达成/任务超时/工具调用/任务创建/项目图变更)"
	}
	if req.OnToolCall && len(req.ToolNames) == 0 {
		return "工具调用触发至少选择一个工具"
	}
	return ""
}

func derefBoolPtr(b *bool) bool { return b != nil && *b }

func (s *Server) pgCreateTrigger(w http.ResponseWriter, r *http.Request) {
	pg, a, ok := s.agentByKey(w, r)
	if !ok {
		return
	}
	if a.Builtin {
		writeErr(w, 400, "触发器仅支持自定义 agent")
		return
	}
	var req triggerReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.IntervalSec < 0 {
		req.IntervalSec = 0
	}
	if msg := validateTrigger(&req); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	tr, err := pg.CreateTrigger(&db.AgentTrigger{
		AgentKey: a.Key, Enabled: req.Enabled, IntervalSec: req.IntervalSec,
		OnFinding: req.OnFinding, OnGoalMet: req.OnGoalMet, OnTaskTimeout: req.OnTaskTimeout, OnToolCall: req.OnToolCall, OnTaskCreate: req.OnTaskCreate,
		OnProjectGraph:  derefBoolPtr(req.OnProjectGraph),
		IntervalMessage: req.IntervalMessage, FindingMessage: req.FindingMessage,
		GoalMessage: req.GoalMessage, TaskTimeoutMessage: req.TaskTimeoutMessage,
		ToolCallMessage: req.ToolCallMessage, TaskCreateMessage: req.TaskCreateMessage,
		ProjectGraphMessage: req.ProjectGraphMessage, ToolNames: req.ToolNames,
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, tr)
}

func (s *Server) pgUpdateTrigger(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad trigger id")
		return
	}
	var req triggerReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.IntervalSec < 0 {
		req.IntervalSec = 0
	}
	// PUT 缺省 on_project_graph：先读原行回填（缺键与显式 false 在 JSON 层
	// 无法区分语义上的"表单不知道这个字段"与"用户显式关闭"——统一保守：
	// 未提供=保持原值；用户在页面显式切换该字段属于前端后续批次（T13）的
	// 工作，届时带上键即可正常覆盖）。读失败按"未提供"处理（保守不拆）。
	if req.OnProjectGraph == nil {
		if cur, err := pg.GetTriggerByID(id); err == nil && cur != nil {
			req.OnProjectGraph = &cur.OnProjectGraph
			if req.ProjectGraphMessage == "" {
				req.ProjectGraphMessage = cur.ProjectGraphMessage
			}
		}
	}
	if msg := validateTrigger(&req); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if err := pg.UpdateTrigger(&db.AgentTrigger{
		ID: id, Enabled: req.Enabled, IntervalSec: req.IntervalSec,
		OnFinding: req.OnFinding, OnGoalMet: req.OnGoalMet, OnTaskTimeout: req.OnTaskTimeout, OnToolCall: req.OnToolCall, OnTaskCreate: req.OnTaskCreate,
		OnProjectGraph:  derefBoolPtr(req.OnProjectGraph),
		IntervalMessage: req.IntervalMessage, FindingMessage: req.FindingMessage,
		GoalMessage: req.GoalMessage, TaskTimeoutMessage: req.TaskTimeoutMessage,
		ToolCallMessage: req.ToolCallMessage, TaskCreateMessage: req.TaskCreateMessage,
		ProjectGraphMessage: req.ProjectGraphMessage, ToolNames: req.ToolNames,
	}); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) pgDeleteTrigger(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad trigger id")
		return
	}
	if err := pg.DeleteTrigger(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}
