package db

// 事实台账（V4-A）：fact = exploration_nodes 中 kind='fact' 的节点。任务经
// tasks.exploration_id 关联探索图，项目经 tasks.project_id 可选归属。
// 本文件放查询（跨任务/跨项目全量，一次 join + 一次锚点批量查询）与两个
// 无库纯函数：GroupFactRows（行→三层聚合）、MergeFactEdit（人工编辑合并，
// 首编保留机器原文），供 server handler 与单测复用。
//
// fact payload 实际字段（写入方 agent/tools.go recordOneFact 与
// db/tasks.go origin fact）：
//   worker/main fact: {summary, detail?, evidence?, confidence?}
//   origin fact:      {summary, description, goal}
// 台账对外统一 summary + description：description 优先取 payload 的
// description，缺省回退 detail（两种写入方字段名不一致，UI 只呈现一个正文字段）。
// category 为二开新增的人工可选维度，直接存进 payload["category"]（不加表列）。

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// FactCategoryOptions 是类别枚举（编辑可选填；留空=其他）。值即落库/展示文案，
// 前端 select 与后端校验共用这份定义（server 直接引这里导出）。
var FactCategoryOptions = []string{"技术栈指纹", "凭据", "入口点", "漏洞面", "网络环境", "防护行为", "其他"}

// ValidFactCategory 空串合法（payload 不落键，前端展示为"其他"）。
func ValidFactCategory(c string) bool {
	if c == "" {
		return true
	}
	for _, o := range FactCategoryOptions {
		if o == c {
			return true
		}
	}
	return false
}

// FactAnchor 是 fact 锚定的一个资产（展示用预标签）。
type FactAnchor struct {
	ID    int64  `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

// FactRow 是台账查询的一行：fact 节点 + 所属任务/项目。
type FactRow struct {
	NodeID      int64
	Payload     json.RawMessage
	Origin      string
	State       string // confirmed | dismissed | origin（origin=任务起点种子）
	CreatedAt   time.Time
	UpdatedAt   time.Time
	TaskID      int64
	TaskName    string
	TaskStatus  string
	ProjectID   *int64
	ProjectName string
}

// FactQuery 是台账列表的过滤参数（零值=不过滤）。
type FactQuery struct {
	ProjectID  int64  // >0 时按项目过滤
	Unassigned bool   // true=只看未挂项目（与 ProjectID 互斥）
	TaskID     int64  // >0 时按任务过滤
	Q          string // 对 summary/description/detail 的 ILIKE 子串
}

// ListFactRows 跨任务查询 fact 节点（join tasks/projects，新在前）。
func (d *DB) ListFactRows(ctx context.Context, q FactQuery) ([]FactRow, error) {
	conds := []string{"en.kind='fact'", "t.deleted_at IS NULL"}
	args := []any{}
	add := func(format string, v any) {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf(format, len(args)))
	}
	if q.ProjectID > 0 {
		add("t.project_id=$%d", q.ProjectID)
	}
	if q.Unassigned {
		conds = append(conds, "t.project_id IS NULL")
	}
	if q.TaskID > 0 {
		add("t.id=$%d", q.TaskID)
	}
	if s := strings.TrimSpace(q.Q); s != "" {
		args = append(args, "%"+s+"%")
		m := "$" + fmt.Sprint(len(args))
		conds = append(conds, fmt.Sprintf(
			"(en.payload->>'summary' ILIKE %[1]s OR en.payload->>'description' ILIKE %[1]s OR en.payload->>'detail' ILIKE %[1]s)", m))
	}
	sqlText := `SELECT en.id, en.payload, COALESCE(en.origin,''), en.state, en.created_at, en.updated_at,
       t.id, t.name, t.status, t.project_id, COALESCE(p.name,'')
FROM exploration_nodes en
JOIN tasks t ON t.exploration_id = en.exploration_id
LEFT JOIN projects p ON p.id = t.project_id
WHERE ` + strings.Join(conds, " AND ") + `
ORDER BY en.id DESC`
	rows, err := d.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FactRow
	for rows.Next() {
		var r FactRow
		var payload []byte
		var projectID sql.NullInt64
		if err := rows.Scan(&r.NodeID, &payload, &r.Origin, &r.State, &r.CreatedAt, &r.UpdatedAt,
			&r.TaskID, &r.TaskName, &r.TaskStatus, &projectID, &r.ProjectName); err != nil {
			return nil, err
		}
		r.Payload = json.RawMessage(payload)
		if projectID.Valid {
			pid := projectID.Int64
			r.ProjectID = &pid
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// FactAnchorsByNode 批量取一批 fact 节点的锚定资产（node_id → 锚点，按资产 id 稳定序）。
// 标签口径对齐 db/task_scope.go covTargetCTE / server assetLabel 的兜底链
// （url>domain>ip>app>bundle>service>root_domain；端口拼接由 server 层不做——
// 台账锚点 chip 用类型+主键值已足够辨识）。
func (d *DB) FactAnchorsByNode(ctx context.Context, nodeIDs []int64) (map[int64][]FactAnchor, error) {
	out := map[int64][]FactAnchor{}
	if len(nodeIDs) == 0 {
		return out, nil
	}
	rows, err := d.QueryContext(ctx, `SELECT ea.node_id, a.id, a.type,
       COALESCE(NULLIF(a.url,''), NULLIF(a.domain,''), NULLIF(a.ip,''), NULLIF(a.app_name,''), NULLIF(a.bundle_id,''), NULLIF(a.service_name,''), NULLIF(a.root_domain,''), '')
FROM exploration_anchors ea
JOIN assets a ON a.id = ea.asset_id
WHERE ea.node_id = ANY($1)
ORDER BY ea.node_id, a.id`, nodeIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var nodeID int64
		var a FactAnchor
		if err := rows.Scan(&nodeID, &a.ID, &a.Type, &a.Label); err != nil {
			return nil, err
		}
		if a.Label == "" {
			a.Label = fmt.Sprintf("#%d", a.ID)
		}
		out[nodeID] = append(out[nodeID], a)
	}
	return out, rows.Err()
}

// GetFactNodePayload 读取单个 fact 节点的 payload（编辑端点用）。
// 返回 found=false 表示节点不存在或 kind≠fact。
func (d *DB) GetFactNodePayload(ctx context.Context, nodeID int64) (payload json.RawMessage, origin, state string, found bool, err error) {
	var raw []byte
	switch err := d.QueryRowContext(ctx,
		`SELECT payload, COALESCE(origin,''), state FROM exploration_nodes WHERE id=$1 AND kind='fact'`, nodeID).
		Scan(&raw, &origin, &state); {
	case err == nil:
		return json.RawMessage(raw), origin, state, true, nil
	case err == sql.ErrNoRows:
		return nil, "", "", false, nil
	default:
		return nil, "", "", false, err
	}
}

// SaveFactNodePayload 写回单个 fact 节点 payload（kind='fact' 作用域，防误改
// 其他类型节点）。updated 返回 false=节点不存在或非 fact。
func (d *DB) SaveFactNodePayload(ctx context.Context, nodeID int64, payload json.RawMessage) (updated bool, err error) {
	res, err := d.ExecContext(ctx,
		`UPDATE exploration_nodes SET payload=$1 WHERE id=$2 AND kind='fact'`, string(payload), nodeID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// FactTexts 是一条事实的正文（summary + 统一后的 description）。
type FactTexts struct {
	Summary     string `json:"summary"`
	Description string `json:"description"`
}

// FactNode 是台账三层结构里的叶子 DTO 输入（纯函数解析产物，id 保持 int64，
// 序列化转 string 由 server 层负责）。
type FactNode struct {
	ID          int64
	Summary     string
	Description string
	Evidence    string
	Confidence  string
	Category    string
	// Source ∈ worker | observer | human（origin 列 + 编辑标记判定；见 factSource）。
	Source string
	// OriginFact=true 是任务起点种子（state='origin'，建任务时写入），前端渲染
	// 「任务起点」灰徽章；可编辑（人工修订起点描述是合理需求）。
	OriginFact bool
	// Edited=payload.edited_by=="human"，即被人工改过。
	Edited bool
	// MachineOriginal 首编时固化的机器原文；未编辑过=nil。
	MachineOriginal *FactTexts
	Anchors         []FactAnchor
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// factPayloadShape 是 fact payload 的解析视图（两类写入方字段并集 + 编辑元数据）。
type factPayloadShape struct {
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Detail      string `json:"detail"`
	Evidence    string `json:"evidence"`
	Confidence  string `json:"confidence"`
	Category    string `json:"category"`
	EditedBy    string `json:"edited_by"`
}

// ParseFactRow 解析一行 fact（payload → 正文/来源/编辑维度）。
// 来源三分法：human（origin=human 或人工编辑过）> observer > worker（其余
// 机器值 system/planner/work#N…）。description 统一视图=payload.description
// 优先（origin fact），回退 detail（worker fact）。
func ParseFactRow(r FactRow) FactNode {
	var p factPayloadShape
	_ = json.Unmarshal(r.Payload, &p)
	n := FactNode{
		ID:          r.NodeID,
		Summary:     p.Summary,
		Description: p.Description,
		Evidence:    p.Evidence,
		Confidence:  p.Confidence,
		Category:    p.Category,
		Edited:      p.EditedBy == "human",
		OriginFact:  r.State == StateOrigin,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
	if n.Description == "" {
		n.Description = p.Detail
	}
	n.Source = factSource(r.Origin, n.Edited)
	if p.EditedBy == "human" {
		var mo struct {
			MachineOriginal *FactTexts `json:"machine_original"`
		}
		_ = json.Unmarshal(r.Payload, &mo)
		n.MachineOriginal = mo.MachineOriginal
	}
	return n
}

// factSource 是来源三分法。当前写入方没有 observer 直写 fact（见调研），
// 但保留该分支：origin=='observer' 即归类 observer。
func factSource(origin string, edited bool) string {
	if edited || origin == "human" {
		return "human"
	}
	if origin == "observer" {
		return "observer"
	}
	return "worker"
}

// FactTaskGroup 台账中间层：一个任务 + 其 facts（保持输入序=新在前）。
type FactTaskGroup struct {
	TaskID     int64
	TaskName   string
	TaskStatus string
	Facts      []FactNode
}

// FactProjectGroup 台账顶层：一个项目（nil=未挂项目组）+ 其任务分组。
type FactProjectGroup struct {
	ProjectID   *int64
	ProjectName string
	Tasks       []FactTaskGroup
}

// GroupFactRows 纯函数：按 fact id DESC 排好的行 + 锚点表 → 项目/任务/事实三层。
// 项目顺序=组内最新事实的首次出现顺序（新在前），「未挂项目」组恒最后；
// 任务顺序=任务内最新事实的首次出现顺序；事实保持输入序（时间倒序）。
// 空输入返回 nil（server 层负责转 []）。
func GroupFactRows(rows []FactRow, anchors map[int64][]FactAnchor) []*FactProjectGroup {
	if len(rows) == 0 {
		return nil
	}
	type pkey struct {
		pid   int64
		nulls bool
	}
	// 第一遍：按任务聚合。rows 已新在前 → 任务/项目首见序即"按最新事实出现在前"。
	tasks := map[int64]*FactTaskGroup{}
	projects := map[pkey]*FactProjectGroup{}
	var projOrder []pkey
	attachTask := map[pkey][]int64{} // 项目组 → 任务 id（首见序，二遍统一挂指针快照）
	for _, r := range rows {
		tg := tasks[r.TaskID]
		if tg == nil {
			tg = &FactTaskGroup{TaskID: r.TaskID, TaskName: r.TaskName, TaskStatus: r.TaskStatus}
			tasks[r.TaskID] = tg
		}
		n := ParseFactRow(r)
		n.Anchors = anchors[r.NodeID]
		tg.Facts = append(tg.Facts, n)

		var k pkey
		if r.ProjectID != nil {
			k = pkey{pid: *r.ProjectID}
		} else {
			k = pkey{nulls: true}
		}
		if projects[k] == nil {
			pg := &FactProjectGroup{}
			if !k.nulls {
				pid := k.pid
				pg.ProjectID = &pid
				pg.ProjectName = r.ProjectName
			}
			projects[k] = pg
			projOrder = append(projOrder, k)
		}
		seen := false
		for _, id := range attachTask[k] {
			if id == r.TaskID {
				seen = true
				break
			}
		}
		if !seen {
			attachTask[k] = append(attachTask[k], r.TaskID)
		}
	}
	// 「未挂项目」组恒排最后。
	ranked := make([]pkey, 0, len(projOrder))
	for _, k := range projOrder {
		if !k.nulls {
			ranked = append(ranked, k)
		}
	}
	for _, k := range projOrder {
		if k.nulls {
			ranked = append(ranked, k)
		}
	}
	// 二遍：任务聚合完成后再挂到项目组（一次快照最终值，无值拷贝同步问题）。
	// 任务只属一个项目（tasks.project_id 单值），跨组防重是零成本保险。
	out := make([]*FactProjectGroup, 0, len(ranked))
	attached := map[int64]bool{}
	for _, k := range ranked {
		pg := projects[k]
		for _, tid := range attachTask[k] {
			if attached[tid] {
				continue
			}
			attached[tid] = true
			pg.Tasks = append(pg.Tasks, *tasks[tid])
		}
		out = append(out, pg)
	}
	return out
}

// FactEditPatch 是人工编辑的字段白名单（nil=不改该字段）。
type FactEditPatch struct {
	Summary     *string
	Description *string
	Category    *string
}

// MergeFactEdit 纯函数：把人工编辑补丁合并进 fact payload 并维护编辑元数据。
// 语义（与 server PATCH 一体）：
//   - 仅 kind=="fact" 的节点可编辑（调用方已用 SQL 作用域兜底，这里再防一手）；
//   - 字段白名单：只允许覆盖 summary/description/category，其余键不动；
//   - category 空串=删除该键（展示回"其他"），非法枚举值报错；
//   - 首次人工编辑：把当时的 {summary,description}（机器原文）存入
//     payload["machine_original"]，并置 payload["edited_by"]="human"；
//     之后再编辑不覆盖 machine_original；
//   - summary/description 只有非 nil 才写（缺省保持原值）；description 一律
//     写 payload["description"] 键（读取侧 description??detail 的统一视图）。
//
// 返回新 payload JSON；现有 payload 非法 JSON 时报错（不静默清空）。
func MergeFactEdit(existing json.RawMessage, kind string, patch FactEditPatch) (json.RawMessage, error) {
	if kind != KindFact {
		return nil, fmt.Errorf("仅事实（fact）节点可在此编辑，当前 kind=%q", kind)
	}
	obj := map[string]any{}
	if len(existing) > 0 {
		if err := json.Unmarshal(existing, &obj); err != nil {
			return nil, fmt.Errorf("fact payload 非法 JSON: %w", err)
		}
	}
	if obj == nil {
		obj = map[string]any{}
	}
	if patch.Category != nil && !ValidFactCategory(*patch.Category) {
		return nil, fmt.Errorf("bad category: %q", *patch.Category)
	}
	// 首次人工编辑固化机器原文（在覆盖之前取值）。
	if obj["edited_by"] != "human" {
		mo := map[string]any{}
		if s, ok := obj["summary"].(string); ok && s != "" {
			mo["summary"] = s
		}
		d, _ := obj["description"].(string)
		if d == "" {
			d, _ = obj["detail"].(string)
		}
		if d != "" {
			mo["description"] = d
		}
		obj["machine_original"] = mo
		obj["edited_by"] = "human"
	}
	if patch.Summary != nil {
		obj["summary"] = *patch.Summary
	}
	if patch.Description != nil {
		obj["description"] = *patch.Description
	}
	if patch.Category != nil {
		if *patch.Category == "" {
			delete(obj, "category")
		} else {
			obj["category"] = *patch.Category
		}
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return raw, nil
}
