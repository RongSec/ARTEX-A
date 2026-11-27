package db

import (
	"database/sql"
	"encoding/json"
	"time"
)

// AgentTrigger is one P3 trigger attached to a custom agent. Six trigger
// conditions can be on at once: interval / on_finding / on_goal_met /
// on_task_timeout / on_tool_call / on_task_create. ToolNames scopes the tool-call
// trigger to a non-empty set of tool keys (empty is rejected at the API layer for
// on_tool_call).
type AgentTrigger struct {
	ID                  int64      `json:"id"`
	AgentKey            string     `json:"agent_key"`
	Enabled             bool       `json:"enabled"`
	IntervalSec         int        `json:"interval_sec"`
	OnFinding           bool       `json:"on_finding"`
	OnGoalMet           bool       `json:"on_goal_met"`
	OnTaskTimeout       bool       `json:"on_task_timeout"`
	OnToolCall          bool       `json:"on_tool_call"`
	OnTaskCreate        bool       `json:"on_task_create"`
	OnProjectGraph      bool       `json:"on_project_graph"` // artex-hs T11：项目图变更触发（observer）
	IntervalMessage     string     `json:"interval_message"` // 各触发条件的独立用户消息
	FindingMessage      string     `json:"finding_message"`
	GoalMessage         string     `json:"goal_message"`
	TaskTimeoutMessage  string     `json:"task_timeout_message"`
	ToolCallMessage     string     `json:"tool_call_message"`
	TaskCreateMessage   string     `json:"task_create_message"`
	ProjectGraphMessage string     `json:"project_graph_message"` // on_project_graph 的用户消息模板
	ToolNames           []string   `json:"tool_names"`            // 选中的工具 key 列表(DB 存 JSON 文本)
	LastFire            *time.Time `json:"last_fire,omitempty"`
}

const triggerCols = `id, agent_key, enabled, interval_sec, on_finding, on_goal_met, on_task_timeout, on_tool_call, on_task_create, on_project_graph, interval_message, finding_message, goal_message, task_timeout_message, tool_call_message, task_create_message, project_graph_message, tool_names, last_fire`

// marshalToolNames encodes the tool-key list as JSON text for the tool_names column.
// A nil/empty list stores "" (not "null"/"[]") so the column default stays clean.
func marshalToolNames(names []string) string {
	if len(names) == 0 {
		return ""
	}
	b, err := json.Marshal(names)
	if err != nil {
		return ""
	}
	return string(b)
}

func scanTrigger(sc interface{ Scan(...any) error }) (*AgentTrigger, error) {
	var t AgentTrigger
	var lf sql.NullTime
	var toolNames string
	if err := sc.Scan(&t.ID, &t.AgentKey, &t.Enabled, &t.IntervalSec, &t.OnFinding, &t.OnGoalMet, &t.OnTaskTimeout, &t.OnToolCall, &t.OnTaskCreate, &t.OnProjectGraph,
		&t.IntervalMessage, &t.FindingMessage, &t.GoalMessage, &t.TaskTimeoutMessage, &t.ToolCallMessage, &t.TaskCreateMessage, &t.ProjectGraphMessage, &toolNames, &lf); err != nil {
		return nil, err
	}
	t.ToolNames = []string{}
	if toolNames != "" {
		_ = json.Unmarshal([]byte(toolNames), &t.ToolNames)
	}
	if lf.Valid {
		t.LastFire = &lf.Time
	}
	return &t, nil
}

// CreateTrigger inserts a trigger for agentKey and returns it.
func (d *DB) CreateTrigger(t *AgentTrigger) (*AgentTrigger, error) {
	row := d.QueryRow(`
INSERT INTO agent_triggers(agent_key, enabled, interval_sec, on_finding, on_goal_met, on_task_timeout, on_tool_call, on_task_create, on_project_graph, interval_message, finding_message, goal_message, task_timeout_message, tool_call_message, task_create_message, project_graph_message, tool_names)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING `+triggerCols,
		t.AgentKey, t.Enabled, t.IntervalSec, t.OnFinding, t.OnGoalMet, t.OnTaskTimeout, t.OnToolCall, t.OnTaskCreate, t.OnProjectGraph,
		t.IntervalMessage, t.FindingMessage, t.GoalMessage, t.TaskTimeoutMessage, t.ToolCallMessage, t.TaskCreateMessage, t.ProjectGraphMessage, marshalToolNames(t.ToolNames))
	return scanTrigger(row)
}

// UpdateTrigger updates a trigger's fields (not last_fire).
func (d *DB) UpdateTrigger(t *AgentTrigger) error {
	_, err := d.Exec(`UPDATE agent_triggers SET enabled=$2, interval_sec=$3, on_finding=$4, on_goal_met=$5, on_task_timeout=$6, on_tool_call=$7, on_task_create=$8, on_project_graph=$9, interval_message=$10, finding_message=$11, goal_message=$12, task_timeout_message=$13, tool_call_message=$14, task_create_message=$15, project_graph_message=$16, tool_names=$17 WHERE id=$1`,
		t.ID, t.Enabled, t.IntervalSec, t.OnFinding, t.OnGoalMet, t.OnTaskTimeout, t.OnToolCall, t.OnTaskCreate, t.OnProjectGraph,
		t.IntervalMessage, t.FindingMessage, t.GoalMessage, t.TaskTimeoutMessage, t.ToolCallMessage, t.TaskCreateMessage, t.ProjectGraphMessage, marshalToolNames(t.ToolNames))
	return err
}

// DeleteTrigger removes a trigger.
func (d *DB) DeleteTrigger(id int64) error {
	_, err := d.Exec(`DELETE FROM agent_triggers WHERE id=$1`, id)
	return err
}

// ListTriggersFor returns an agent's triggers.
func (d *DB) ListTriggersFor(agentKey string) ([]*AgentTrigger, error) {
	return d.queryTriggers(`SELECT `+triggerCols+` FROM agent_triggers WHERE agent_key=$1 ORDER BY id`, agentKey)
}

// GetTriggerByID returns one trigger by id, or (nil, nil) when absent.
// PATCH-style update handlers use it to preserve columns that the web form
// doesn't know about yet（如 T11 的 on_project_graph：老前端 PUT 不带该字段，
// 若无条件写 false 会把 seed 的 observer 触发器静默拆掉）。
func (d *DB) GetTriggerByID(id int64) (*AgentTrigger, error) {
	list, err := d.queryTriggers(`SELECT `+triggerCols+` FROM agent_triggers WHERE id=$1`, id)
	if err != nil || len(list) == 0 {
		return nil, err
	}
	return list[0], nil
}

// ListEnabledTriggers returns all enabled triggers (for the scheduler).
func (d *DB) ListEnabledTriggers() ([]*AgentTrigger, error) {
	return d.queryTriggers(`SELECT ` + triggerCols + ` FROM agent_triggers WHERE enabled ORDER BY id`)
}

// EnsureAgentTriggerEnabled 打开指定内置 agent 的触发器。项目级开关
// reader_enabled 只是「允许读取」，真正的运行还受 agent_triggers.enabled
// 这道全局闸控制；用户勾了项目开关却发现阅读者从不运行，就是这里默认关。
// 幂等：已经开着时影响 0 行。
func (d *DB) EnsureAgentTriggerEnabled(agentKey string) (int, error) {
	res, err := d.Exec(`UPDATE agent_triggers SET enabled=true WHERE agent_key=$1 AND enabled=false`, agentKey)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (d *DB) queryTriggers(q string, args ...any) ([]*AgentTrigger, error) {
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AgentTrigger{}
	for rows.Next() {
		t, err := scanTrigger(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TouchTriggerFire records an interval trigger's fire time (now).
func (d *DB) TouchTriggerFire(id int64) error {
	_, err := d.Exec(`UPDATE agent_triggers SET last_fire=now() WHERE id=$1`, id)
	return err
}

// DeleteTriggersForAgent removes all triggers of an agent (custom agent delete).
func (d *DB) DeleteTriggersForAgent(agentKey string) error {
	_, err := d.Exec(`DELETE FROM agent_triggers WHERE agent_key=$1`, agentKey)
	return err
}

// ---------- scheduler_state (kv watermarks) ----------

func (d *DB) GetSchedState(key string) (string, error) {
	var v string
	err := d.QueryRow(`SELECT value FROM scheduler_state WHERE key=$1`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (d *DB) SetSchedState(key, value string) error {
	_, err := d.Exec(`INSERT INTO scheduler_state(key,value) VALUES ($1,$2)
ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`, key, value)
	return err
}

// ---------- event queries (cross-exploration, for the scheduler) ----------

// TaskEvent is a finding/goal event carrying the owning task's info, used to
// compose the trigger message context.
type TaskEvent struct {
	NodeID     int64  `json:"node_id"`
	TaskID     int64  `json:"task_id"`
	TaskDesc   string `json:"task_description"`
	TaskGoal   string `json:"task_goal"`
	Summary    string `json:"summary"`     // finding summary / goal text
	VulnClass  string `json:"vulnclass"`   // finding only
	Severity   string `json:"severity"`    // finding only
	Tool       string `json:"tool"`        // tool-call only: tool name
	ToolInput  string `json:"tool_input"`  // tool-call only: 入参(JSON 文本)
	ToolOutput string `json:"tool_output"` // tool-call only: 返回内容
	ToolIsErr  bool   `json:"tool_is_err"` // tool-call only: 工具返回是否为错误
}

// NewFindingsSince returns findings with node id > lastID across all live tasks,
// ordered by id (monotonic watermark → no double-fire).
func (d *DB) NewFindingsSince(lastID int64) ([]TaskEvent, error) {
	rows, err := d.Query(`
SELECT n.id, t.id, t.description, t.goal, n.payload
FROM exploration_nodes n JOIN tasks t ON t.exploration_id = n.exploration_id
WHERE n.kind='finding' AND n.id > $1 AND t.deleted_at IS NULL
ORDER BY n.id`, lastID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskEvent{}
	for rows.Next() {
		var e TaskEvent
		var payload []byte
		if err := rows.Scan(&e.NodeID, &e.TaskID, &e.TaskDesc, &e.TaskGoal, &payload); err != nil {
			return nil, err
		}
		var p struct{ Summary, Vulnclass, Severity string }
		_ = json.Unmarshal(payload, &p)
		e.Summary, e.VulnClass, e.Severity = p.Summary, p.Vulnclass, p.Severity
		out = append(out, e)
	}
	return out, rows.Err()
}

// TimedOutTasksSince returns tasks that reached status='timeout' with id > lastID,
// ordered by id (monotonic watermark → no double-fire across restarts).
func (d *DB) TimedOutTasksSince(lastID int64) ([]TaskEvent, error) {
	rows, err := d.Query(`
SELECT id, description, goal FROM tasks
WHERE status='timeout' AND deleted_at IS NULL AND id > $1
ORDER BY id`, lastID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskEvent{}
	for rows.Next() {
		var e TaskEvent
		if err := rows.Scan(&e.NodeID, &e.TaskDesc, &e.TaskGoal); err != nil {
			return nil, err
		}
		e.TaskID = e.NodeID // task id doubles as NodeID for the watermark
		e.Summary = e.TaskGoal
		out = append(out, e)
	}
	return out, rows.Err()
}

// NewTasksSince returns tasks created with id > lastID (excluding deleted),
// ordered by id (monotonic watermark → no double-fire across restarts). Triggered
// agent runs are conversations, not tasks, so this never fires on its own output.
func (d *DB) NewTasksSince(lastID int64) ([]TaskEvent, error) {
	rows, err := d.Query(`
SELECT id, description, goal FROM tasks
WHERE deleted_at IS NULL AND id > $1
ORDER BY id`, lastID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskEvent{}
	for rows.Next() {
		var e TaskEvent
		if err := rows.Scan(&e.NodeID, &e.TaskDesc, &e.TaskGoal); err != nil {
			return nil, err
		}
		e.TaskID = e.NodeID // task id doubles as NodeID for the watermark
		e.Summary = e.TaskGoal
		out = append(out, e)
	}
	return out, rows.Err()
}

// NewToolCallsSince returns completed tool calls (a tool_result row) with activity
// id > lastID across all live tasks, ordered by id (monotonic watermark → no
// double-fire). It is driven by tool_result rows (the tool finished, so both input
// and output are available) and joins back to the paired tool_use row for the input.
// Only task-execution activity is scanned — triggered agent runs are conversations
// (conversation_activities), so a tool-call trigger never fires on its own output.
func (d *DB) NewToolCallsSince(lastID int64) ([]TaskEvent, error) {
	rows, err := d.Query(`
SELECT r.id, t.id, t.description, t.goal, r.tool, COALESCE(u.detail,''), COALESCE(r.detail,''), r.is_error
FROM activity r
JOIN tasks t ON t.exploration_id = r.exploration_id
LEFT JOIN activity u ON u.exploration_id = r.exploration_id AND u.tool_use_id = r.tool_use_id AND u.kind='tool_use'
WHERE r.kind='tool_result' AND r.id > $1 AND r.tool <> '' AND t.deleted_at IS NULL
ORDER BY r.id`, lastID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskEvent{}
	for rows.Next() {
		var e TaskEvent
		if err := rows.Scan(&e.NodeID, &e.TaskID, &e.TaskDesc, &e.TaskGoal, &e.Tool, &e.ToolInput, &e.ToolOutput, &e.ToolIsErr); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// MetGoals returns all met goals across live tasks (the scheduler filters out the
// ones it already fired for via the persisted fired-set).
func (d *DB) MetGoals() ([]TaskEvent, error) {
	rows, err := d.Query(`
SELECT n.id, t.id, t.description, t.goal, n.payload
FROM exploration_nodes n JOIN tasks t ON t.exploration_id = n.exploration_id
WHERE n.kind='goal' AND n.state='met' AND t.deleted_at IS NULL
ORDER BY n.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskEvent{}
	for rows.Next() {
		var e TaskEvent
		var payload []byte
		if err := rows.Scan(&e.NodeID, &e.TaskID, &e.TaskDesc, &e.TaskGoal, &payload); err != nil {
			return nil, err
		}
		var p struct{ Text, Summary string }
		_ = json.Unmarshal(payload, &p)
		if p.Text != "" {
			e.Summary = p.Text
		} else {
			e.Summary = p.Summary
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
