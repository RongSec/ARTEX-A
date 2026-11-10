package db

// 项目级节点投影（project_index）与图变更事件（project_graph_events）的读写。
// 架构 §1.3/§1.4、§2.1：三图原语（AddNode/SetNodeState/Link）经 OnGraphChange
// 把变更交给 server 侧 ProjectIndexer，后者异步落到这里；observer 只读投影、
// 不回写。全部方法挂在 *DB 上（跨探索图/按项目查），与 ExplorationStore 无耦合。

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ProjectIndexRow 是 project_index 表的一行（一个任务图节点在项目里的摘要投影）。
type ProjectIndexRow struct {
	ID          int64           `json:"id"`
	ProjectID   int64           `json:"project_id"`
	TaskID      int64           `json:"task_id"`
	NodeID      int64           `json:"node_id"`
	Kind        string          `json:"kind"`
	State       string          `json:"state"`
	Summary     string          `json:"summary"`
	AssetKeys   []string        `json:"asset_keys"`
	Severity    string          `json:"severity"`
	PayloadJSON json.RawMessage `json:"payload_digest"`
	UpdatedAt   time.Time       `json:"updated_at"` // 行最后刷新时刻（大图节点排序/新鲜度展示）
}

// marshalInt64Array 把 []int64 编成 PG int[] 字面量（'{}' 表示空数组）。
// 照 db/assets.go marshalStringArray 的既有惯例：database/sql 下传数组统一走
// 文本字面量 + SQL 侧 ::bigint[]/::text[] 转型，不引 pgx 特有类型。
// 元素是数字，无需转义，空串直接丢弃（防脏输入拼出非法字面量）。
func marshalInt64Array(items []int64) string {
	if len(items) == 0 {
		return "{}"
	}
	parts := make([]string, 0, len(items))
	seen := make(map[int64]bool, len(items))
	for _, n := range items {
		if seen[n] {
			continue
		}
		seen[n] = true
		parts = append(parts, fmt.Sprintf("%d", n))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// marshalTextArray 把 []string 编成 PG text[] 字面量（'{}' 表示空数组）。
// 双引号包裹每个元素并转义 \ 与 "，与 db/assets.go marshalStringArray 同构
// （多一条反斜杠转义：数组字面量里 \ 同样是转义符）。
func marshalTextArray(items []string) string {
	if len(items) == 0 {
		return "{}"
	}
	parts := make([]string, 0, len(items))
	seen := make(map[string]bool, len(items))
	for _, s := range items {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		parts = append(parts, `"`+s+`"`)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// assetKeyFor 把一行 assets 的四个主机/地址字段收敛成一个归一化资产键：
// URL 优先（最具体），其次域名，再次 IP；全空返回 ""（调用方丢弃）。
// 域名走 DomainKey 归一化（小写/去尾点），与写入侧一致，保证跨任务同资产
// 产出的键逐字节相同——这是 asset_keys 能做交集命中的前提。
// 纯函数，单测覆盖。
func assetKeyFor(domain, rootDomain, ip, url string) string {
	if u := strings.TrimSpace(url); u != "" {
		return u
	}
	if d := DomainKey(domain); d != "" {
		return d
	}
	if h := DomainKey(rootDomain); h != "" {
		return h
	}
	return IPKey(ip)
}

// AssetKeysForIDs 把资产 id 解析成归一化资产键列表（project_index.asset_keys
// 的写入原料）。不存在的 id 静默跳过（投影是尽力而为的旁路，不该因单个脏
// 锚定失败）。返回顺序与入参无关（SQL 聚合），调用方不依赖顺序。
func (d *DB) AssetKeysForIDs(ids []int64) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := d.Query(`SELECT COALESCE(domain,''), COALESCE(root_domain,''), COALESCE(ip,''), COALESCE(url,'')
FROM assets WHERE id = ANY($1::bigint[])`, marshalInt64Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var domain, root, ip, u string
		if err := rows.Scan(&domain, &root, &ip, &u); err != nil {
			return nil, err
		}
		if k := assetKeyFor(domain, root, ip, u); k != "" {
			out = append(out, k)
		}
	}
	return out, rows.Err()
}

// UpsertProjectIndex 写入/刷新一个节点的投影行（ON CONFLICT (project_id,
// node_id) DO UPDATE，幂等）。updated_at 由触发器 trg_pidx_upd 维护。
// payload_digest 传 nil/空按 '{}' 落库；utf8 清洗照站内惯例（工具输出可能
// 带非法字节，PG text/jsonb 会拒）。
func (d *DB) UpsertProjectIndex(ctx context.Context, row ProjectIndexRow) error {
	digest := row.PayloadJSON
	if len(digest) == 0 {
		digest = []byte("{}")
	}
	_, err := d.ExecContext(ctx, `
INSERT INTO project_index(project_id, task_id, node_id, kind, state, summary, asset_keys, severity, payload_digest)
VALUES ($1, $2, $3, $4, $5, $6, $7::text[], $8, $9::jsonb)
ON CONFLICT (project_id, node_id) DO UPDATE SET
    task_id        = EXCLUDED.task_id,
    kind           = EXCLUDED.kind,
    state          = EXCLUDED.state,
    summary        = EXCLUDED.summary,
    asset_keys     = EXCLUDED.asset_keys,
    severity       = EXCLUDED.severity,
    payload_digest = EXCLUDED.payload_digest`,
		row.ProjectID, row.TaskID, row.NodeID, utf8Clean(row.Kind), utf8Clean(row.State),
		utf8Clean(row.Summary), marshalTextArray(row.AssetKeys), utf8Clean(row.Severity),
		string(jsonbClean(digest)))
	return err
}

// DeleteProjectIndexByNode 删除某节点在项目里的投影行（节点被硬删/假删时清理）。
// 幂等：行不存在不报错。
func (d *DB) DeleteProjectIndexByNode(projectID, nodeID int64) error {
	_, err := d.Exec(`DELETE FROM project_index WHERE project_id=$1 AND node_id=$2`, projectID, nodeID)
	return err
}

// DeleteProjectIndexByNodeTx 是 DeleteProjectIndexByNode 的事务内版本，供
// ProjectIndexer 把「删投影 + 插事件」压进一个事务。语义一致、幂等。
func DeleteProjectIndexByNodeTx(ctx context.Context, tx *sql.Tx, projectID, nodeID int64) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM project_index WHERE project_id=$1 AND node_id=$2`, projectID, nodeID)
	return err
}

// ProjectIndexFilter 是 QueryProjectIndex 的可选过滤条件；零值=不过滤。
type ProjectIndexFilter struct {
	Kinds      []string // kind IN (...)
	Severities []string // severity IN (...)（一般只圈 finding 的 critical/high…）
	AssetKeys  []string // asset_keys && (...)：与任一资产键重叠即命中（GIN）
	Query      string   // summary ILIKE 关键词（大小写不敏感子串）
	Limit      int      // <=0 用默认 200（observer 一次总览的量级）
}

// buildProjectIndexWhere 纯函数：把过滤条件拼成 WHERE 子句与实参（不含 LIMIT）。
// 参数占位符从 $1 起连续编号；project_id 恒为第一个条件。单测直接断言返回值，
// 无需数据库。AssetKeys 走 `asset_keys && $n::text[]`（GIN 索引可命中）。
func buildProjectIndexWhere(projectID int64, f ProjectIndexFilter) (where string, args []any) {
	args = []any{projectID}
	conds := []string{"project_id = $1"}
	addIn := func(column string, values []string) {
		if len(values) == 0 {
			return
		}
		marks := make([]string, 0, len(values))
		for _, v := range values {
			args = append(args, v)
			marks = append(marks, "$"+fmt.Sprint(len(args)))
		}
		conds = append(conds, column+" IN ("+strings.Join(marks, ",")+")")
	}
	addIn("kind", f.Kinds)
	addIn("severity", f.Severities)
	if len(f.AssetKeys) > 0 {
		args = append(args, marshalTextArray(f.AssetKeys))
		conds = append(conds, "asset_keys && $"+fmt.Sprint(len(args))+"::text[]")
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		args = append(args, "%"+escapeLikePattern(q)+"%")
		conds = append(conds, "summary ILIKE $"+fmt.Sprint(len(args))+" ESCAPE '\\'")
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// escapeLikePattern 转义 LIKE/ILIKE 模式里的三个特殊字符（\ % _），使关键词
// 按字面匹配——照站内既有做法（server 搜索侧同款转义 + ESCAPE '\'）。
// 纯函数，单测覆盖。
func escapeLikePattern(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

const projectIndexCols = `id, project_id, task_id, node_id, kind, state, summary, array_to_json(asset_keys)::text, severity, payload_digest, updated_at`

// scanProjectIndexRow 扫一行投影（asset_keys 走 array_to_json 文本再反序列化，
// 照 db/assets.go 扫数组列的既有惯例：database/sql 不能直接 Scan 进 []string）。
func scanProjectIndexRow(sc interface{ Scan(...any) error }) (ProjectIndexRow, error) {
	var r ProjectIndexRow
	var keysJSON string
	var digest []byte
	if err := sc.Scan(&r.ID, &r.ProjectID, &r.TaskID, &r.NodeID, &r.Kind, &r.State, &r.Summary, &keysJSON, &r.Severity, &digest, &r.UpdatedAt); err != nil {
		return r, err
	}
	r.PayloadJSON = json.RawMessage(digest)
	_ = json.Unmarshal([]byte(keysJSON), &r.AssetKeys) // 数组恒合法；失败留 nil 即可
	return r, nil
}

// QueryProjectIndex 按过滤条件查某项目的投影行（updated_at 最新在前）。
// observer 的 query_project_index 工具与项目大图 API 共用此入口。
func (d *DB) QueryProjectIndex(ctx context.Context, projectID int64, f ProjectIndexFilter) ([]ProjectIndexRow, error) {
	where, args := buildProjectIndexWhere(projectID, f)
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	rows, err := d.QueryContext(ctx, `SELECT `+projectIndexCols+` FROM project_index`+where+
		` ORDER BY updated_at DESC, id DESC LIMIT $`+fmt.Sprint(len(args)+1), append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProjectIndexRow
	for rows.Next() {
		r, err := scanProjectIndexRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertProjectIndexTx 在调用方事务内写入/刷新投影行（语义同
// UpsertProjectIndex）。RebuildProjectIndex 用它把「清旧行+灌新行」压进一个
// 事务：重建中途失败不会留下半套投影。tx 由 server 侧提供并负责提交。
func UpsertProjectIndexTx(ctx context.Context, tx *sql.Tx, row ProjectIndexRow) error {
	digest := row.PayloadJSON
	if len(digest) == 0 {
		digest = []byte("{}")
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO project_index(project_id, task_id, node_id, kind, state, summary, asset_keys, severity, payload_digest)
VALUES ($1, $2, $3, $4, $5, $6, $7::text[], $8, $9::jsonb)
ON CONFLICT (project_id, node_id) DO UPDATE SET
    task_id        = EXCLUDED.task_id,
    kind           = EXCLUDED.kind,
    state          = EXCLUDED.state,
    summary        = EXCLUDED.summary,
    asset_keys     = EXCLUDED.asset_keys,
    severity       = EXCLUDED.severity,
    payload_digest = EXCLUDED.payload_digest`,
		row.ProjectID, row.TaskID, row.NodeID, utf8Clean(row.Kind), utf8Clean(row.State),
		utf8Clean(row.Summary), marshalTextArray(row.AssetKeys), utf8Clean(row.Severity),
		string(jsonbClean(digest)))
	return err
}

// ProjectIndexNode 是重建投影要扫的一个探索图节点（含锚定资产）。
type ProjectIndexNode struct {
	ID      int64
	Kind    string
	State   string
	Payload json.RawMessage
	Anchors []int64
}

// NodesWithAnchors 一次查出一个探索图的全部节点及其锚定资产（重建投影用；
// 与 Nodes() 分开是避免给图可视化热路径带上 join 成本）。
func (s *ExplorationStore) NodesWithAnchors(ctx context.Context, limit int) ([]ProjectIndexNode, error) {
	if limit <= 0 {
		limit = 20000
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT n.id, n.kind, n.state, n.payload,
       COALESCE(array_to_json(array_agg(a.asset_id) FILTER (WHERE a.asset_id IS NOT NULL))::text, '[]')
FROM exploration_nodes n
LEFT JOIN exploration_anchors a ON a.node_id = n.id
WHERE n.exploration_id = $1
GROUP BY n.id, n.kind, n.state, n.payload
ORDER BY n.id LIMIT $2`, s.expID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProjectIndexNode
	for rows.Next() {
		var nd ProjectIndexNode
		var payload []byte
		var anchorsJSON string
		if err := rows.Scan(&nd.ID, &nd.Kind, &nd.State, &payload, &anchorsJSON); err != nil {
			return nil, err
		}
		nd.Payload = json.RawMessage(payload)
		_ = json.Unmarshal([]byte(anchorsJSON), &nd.Anchors)
		out = append(out, nd)
	}
	return out, rows.Err()
}

// PayloadSummary 取 payload（jsonb 原文）里的一行摘要，口径同 nodeSummaryOf
// （summary 优先、text 兜底）。重建/查询侧拿到的是 JSON 文本，非 map。
func PayloadSummary(payload json.RawMessage) string {
	var m map[string]any
	if json.Unmarshal(payload, &m) != nil {
		return ""
	}
	return nodeSummaryOf(m)
}

// PayloadSeverity 取 finding payload 里的 severity（非 finding 恒空）。
func PayloadSeverity(payload json.RawMessage, kind string) string {
	if kind != KindFinding {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(payload, &m) != nil {
		return ""
	}
	s, _ := m["severity"].(string)
	return s
}

// ProjectIndexGroup 是「全项目大图」按任务分组的计数行（task 维度汇总 +
// 分 kind 计数，前端 project-graph.tsx 的分组骨架）。
type ProjectIndexGroup struct {
	TaskID int64          `json:"task_id"`
	Total  int            `json:"total"`
	ByKind map[string]int `json:"by_kind"`
}

// ProjectIndexGroups 按 task_id 分组统计某项目的投影节点数（含分 kind 计数），
// 任务新在前（max(updated_at) DESC）。一条 GROUP BY + 一条 kind 细分聚合，
// 避免 N+1；供项目详情页/大图 tab 直接下发。
func (d *DB) ProjectIndexGroups(ctx context.Context, projectID int64) ([]ProjectIndexGroup, error) {
	rows, err := d.QueryContext(ctx, `SELECT task_id, count(*), COALESCE(array_to_json(array_agg(DISTINCT kind))::text,'[]')
FROM project_index WHERE project_id=$1 GROUP BY task_id ORDER BY max(updated_at) DESC, task_id DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProjectIndexGroup
	for rows.Next() {
		var g ProjectIndexGroup
		var kindsJSON string
		if err := rows.Scan(&g.TaskID, &g.Total, &kindsJSON); err != nil {
			return nil, err
		}
		var kinds []string
		_ = json.Unmarshal([]byte(kindsJSON), &kinds)
		g.ByKind = make(map[string]int, len(kinds))
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	// kind 细分：一次 (task_id, kind) 聚合回填，量 = 任务数×kind 数，恒小。
	krows, err := d.QueryContext(ctx, `SELECT task_id, kind, count(*) FROM project_index
WHERE project_id=$1 GROUP BY task_id, kind`, projectID)
	if err != nil {
		return nil, err
	}
	defer krows.Close()
	byTask := make(map[int64]*ProjectIndexGroup, len(out))
	for i := range out {
		byTask[out[i].TaskID] = &out[i]
	}
	for krows.Next() {
		var taskID int64
		var kind string
		var n int
		if err := krows.Scan(&taskID, &kind, &n); err != nil {
			return nil, err
		}
		if g := byTask[taskID]; g != nil {
			g.ByKind[kind] = n
		}
	}
	return out, krows.Err()
}

// InsertGraphEvent 追加一行图变更事件（observer 水位扫描的事实源）。只追加、
// 永不 UPDATE/DELETE（消费进度存 scheduler_settings 水位，与 notification_events
// 同构）。delta_summary 由 server 侧组装（"task#7 新增 finding[high] …"）。
func (d *DB) InsertGraphEvent(ctx context.Context, projectID, taskID int64, nodeID int64, kind, deltaSummary string) error {
	var nodeArg any
	if nodeID > 0 {
		nodeArg = nodeID
	}
	_, err := d.ExecContext(ctx, `
INSERT INTO project_graph_events(project_id, task_id, node_id, kind, delta_summary)
VALUES ($1, $2, $3, $4, $5)`,
		projectID, taskID, nodeArg, utf8Clean(kind), utf8Clean(truncateRunes(deltaSummary, 500)))
	return err
}

// GraphEvent 是 project_graph_events 的一行（observer 水位扫描的事件载荷）。
type GraphEvent struct {
	ID           int64         `json:"id"`
	ProjectID    int64         `json:"project_id"` // 跨项目扫描（fireProjectGraph）时带；单项目查询不填
	TaskID       int64         `json:"task_id"`
	NodeID       sql.NullInt64 `json:"node_id,omitempty"`
	Kind         string        `json:"kind"`
	DeltaSummary string        `json:"delta_summary"`
}

// MaxGraphEventID 返回某项目当前最大事件 id（init 播种水位用；无事件返回 0）。
func (d *DB) MaxGraphEventID(ctx context.Context, projectID int64) (int64, error) {
	var id int64
	err := d.QueryRowContext(ctx, `SELECT COALESCE(max(id),0) FROM project_graph_events WHERE project_id=$1`, projectID).Scan(&id)
	return id, err
}

// NewGraphEventsSince 跨项目按**全局事件 id 水位**取新事件（scheduler
// fireProjectGraph 专用，T11）。返回 (matched, watermark, err)：
//   - matched 只含「归属项目 observer_enabled=true」的行（JOIN projects，含
//     task_id/kind/摘要，喂 observer 触发清单）；
//   - watermark 是本次扫描窗口内的**绝对最大 id**（无论 enabled 与否），供
//     调用方无条件推进水位——关键是关闭项目的行也必须被水位跨过，否则水位
//     卡在这批 disabled 行上，每 tick 重复扫同一批空结果（活锁式自旋）。
//
// observer 事后开启不回放到历史事件（水位已推过去），与 finding 水位"启用
// 后才计"语义一致。按 id 升序 → 单调不双发。limit<=0 默认 200。
func (d *DB) NewGraphEventsSince(lastID int64, limit int) (matched []GraphEvent, watermark int64, err error) {
	if limit <= 0 {
		limit = 200
	}
	watermark = lastID
	rows, err := d.Query(`SELECT e.id, e.project_id, e.task_id, e.node_id, e.kind, e.delta_summary, p.observer_enabled
FROM project_graph_events e JOIN projects p ON p.id = e.project_id
WHERE e.id > $1
ORDER BY e.id LIMIT $2`, lastID, limit)
	if err != nil {
		return nil, lastID, err
	}
	defer rows.Close()
	for rows.Next() {
		var e GraphEvent
		var on bool
		if err := rows.Scan(&e.ID, &e.ProjectID, &e.TaskID, &e.NodeID, &e.Kind, &e.DeltaSummary, &on); err != nil {
			return nil, lastID, err
		}
		if e.ID > watermark {
			watermark = e.ID // 无条件推进（含 disabled 行，防空转自旋）
		}
		if on {
			matched = append(matched, e)
		}
	}
	return matched, watermark, rows.Err()
}

// ListGraphEvents 按水位增量取某项目的新事件（id 单调，ORDER BY id）。
func (d *DB) ListGraphEvents(ctx context.Context, projectID, afterID int64, limit int) ([]GraphEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.QueryContext(ctx, `SELECT id, task_id, node_id, kind, delta_summary
FROM project_graph_events WHERE project_id=$1 AND id > $2 ORDER BY id LIMIT $3`, projectID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GraphEvent
	for rows.Next() {
		var e GraphEvent
		if err := rows.Scan(&e.ID, &e.TaskID, &e.NodeID, &e.Kind, &e.DeltaSummary); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// OpenIntentAnchorAssetIDs 返回某探索图里所有 open 意图锚定的资产 id（去重）。
// T12 insight 注入的命中原料：这些资产的归一化键与 project_insights.keywords
// 求交集，命中的洞察排前（ListInsights 的 matchKeywords 排序）。
func (d *DB) OpenIntentAnchorAssetIDs(ctx context.Context, expID int64) ([]int64, error) {
	rows, err := d.QueryContext(ctx, `
SELECT DISTINCT ea.asset_id
FROM exploration_anchors ea
JOIN exploration_nodes en ON en.id = ea.node_id
WHERE en.exploration_id=$1 AND en.kind='intent' AND en.state='open' AND ea.asset_id IS NOT NULL`, expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// TaskInsightContext 一次查回 insight 注入决策所需的全部字段：任务的
// exploration 归属 + 项目观察者开关（LEFT JOIN——未挂项目时 enabled=false）。
// 单行查询、每 planner 轮一次，无缓存=挂/摘与开关翻转即时生效。
type TaskInsightContext struct {
	ExplorationID int64
	ProjectID     int64 // 0=未挂项目
	ObserverOn    bool  // projects.observer_enabled（项目不存在/未挂=false）
}

func (d *DB) TaskInsightContext(ctx context.Context, taskID int64) (*TaskInsightContext, error) {
	var c TaskInsightContext
	var pid sql.NullInt64
	var on sql.NullBool
	err := d.QueryRowContext(ctx, `
SELECT t.exploration_id, t.project_id, p.observer_enabled
FROM tasks t LEFT JOIN projects p ON p.id = t.project_id
WHERE t.id=$1 AND t.deleted_at IS NULL`, taskID).Scan(&c.ExplorationID, &pid, &on)
	if err != nil {
		return nil, err // ErrNoRows=任务不存在/已删，调用方按空处理
	}
	c.ProjectID = pid.Int64
	c.ObserverOn = on.Bool
	return &c, nil
}

// truncateRunes 按 rune 截断（PG 存 UTF-8 没问题，但事件摘要喂 LLM 不必超长；
// 500 rune 上限防一条异常长文本占满 observer 上下文）。
func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
