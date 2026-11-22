package db

// 统一阅读者洞察（V6-U2）：observer（项目内=跨任务阅读者）与 reader（跨项目=跨项目阅读者）两条链合成
// 一套表 project_insights，用 scope 列区分：scope='project' 项目洞察
// （project_id 指向所属项目）、scope='cross' 跨项目洞察（project_id=NULL）。
// planner 侧按「open 意图锚定 asset_keys ∩ keywords/asset_keys 交集命中优先、
// 不足按 created_at DESC 补至 ≤limit」限量注入。
//
// 兼容：GlobalInsight 结构与 WriteGlobalInsight/ListGlobalInsights/
// ListCrossProjectInsights/RejectInsight 的函数签名全部保留（工具 kind 枚举
// project/global 不变），内部 SQL 一律指向 project_insights 且带 scope='cross'。
// 旧 global_insights 表在 V6-U1 迁移里改名归档，Go 层不再读写它。
//
// V5-A（跨项目勾连回流）：cross 行带 asset_keys 后也能注入 planner——同一套
// 归一化资产键求交集，命中才注入，且渲染时显式标注「来自其他项目、仅作假设」。
// 同资产写新洞察会把旧行置 superseded（生命周期），planner 还可用
// reject_insight 把某条置 rejected。两条只影响「是否还参与注入」，不物理删行。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Insight 是 project_insights 里 scope='project' 的项目洞察一行。
type Insight struct {
	ID             int64     `json:"id"`
	ProjectID      int64     `json:"project_id"`
	Content        string    `json:"content"`
	SourceTaskID   int64     `json:"source_task_id,omitempty"` // 0=未知/无来源任务（DB 存 NULL）
	Keywords       []string  `json:"keywords"`
	Status         string    `json:"status"`                    // active|rejected|superseded
	RejectedReason string    `json:"rejected_reason,omitempty"` // status='rejected' 时的原因
	CreatedAt      time.Time `json:"created_at"`
}

// GlobalInsight 是 project_insights 里 scope='cross' 的跨项目洞察（reader 产出）
// 的视图结构。表名虽已合并，结构/字段名保持不变——工具与渲染层无需改动。
type GlobalInsight struct {
	ID             int64     `json:"id"`
	Content        string    `json:"content"`
	SourceProjects []int64   `json:"source_projects"`
	AssetKeys      []string  `json:"asset_keys"` // 归一化资产键；空=永不注入 planner
	Status         string    `json:"status"`     // active|rejected|superseded
	SupersededBy   int64     `json:"superseded_by,omitempty"`
	RejectedReason string    `json:"rejected_reason,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// ErrInsightNotFound 按 id 删除/更新时目标不存在。
var ErrInsightNotFound = errors.New("insight not found")

// ErrInsightKindInvalid 是 RejectInsight 收到非 project/global 的 kind。
var ErrInsightKindInvalid = errors.New("insight kind must be project or global")

// 洞察生命周期状态（与 schema 的 CHECK 同值域）。
const (
	InsightStatusActive     = "active"
	InsightStatusRejected   = "rejected"
	InsightStatusSuperseded = "superseded"
)

// WriteInsight 追加一条项目洞察。content 必填（空白拒写，防 observer 空转
// 产生垃圾行——与 projects.go CreateProject 的名称校验同风格）。
// sourceTaskID<=0 落 NULL。keywords 走 text[] 字面量 + ::text[] 转型惯例。
func (d *DB) WriteInsight(ctx context.Context, projectID int64, content string, sourceTaskID int64, keywords []string) (*Insight, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, errors.New("insight content is required")
	}
	var srcArg any
	if sourceTaskID > 0 {
		srcArg = sourceTaskID
	}
	in := &Insight{ProjectID: projectID, Content: content, SourceTaskID: sourceTaskID, Keywords: keywords, Status: InsightStatusActive}
	var src sql.NullInt64
	var kwJSON string
	err := d.QueryRowContext(ctx, `
INSERT INTO project_insights(project_id, content, source_task_id, keywords, scope)
VALUES ($1, $2, $3, $4::text[], 'project')
RETURNING id, project_id, content, source_task_id, array_to_json(keywords)::text, status, rejected_reason, created_at`,
		projectID, utf8Clean(content), srcArg, marshalTextArray(keywords)).
		Scan(&in.ID, &in.ProjectID, &in.Content, &src, &kwJSON, &in.Status, &in.RejectedReason, &in.CreatedAt)
	if err != nil {
		return nil, err
	}
	if src.Valid {
		in.SourceTaskID = src.Int64
	}
	_ = json.Unmarshal([]byte(kwJSON), &in.Keywords)
	return in, nil
}

// ListInsights 返回某项目【active】的洞察（新在前）。matchKeywords 非空时，
// 交集命中的行排在前（命中数降序），其余按 created_at DESC 补位——与 §2.4 的
// 注入限量算法同口径，调用方取前 limit 条即得「命中优先」序列。limit<=0 默认 50。
//
// V5-A：rejected/superseded 行不参与注入（WHERE status='active'），但仍留在
// 表里供人工复核；管理面需要全量时请直接查表。
func (d *DB) ListInsights(ctx context.Context, projectID int64, matchKeywords []string, limit int) ([]Insight, error) {
	if limit <= 0 {
		limit = 50
	}
	args := []any{projectID}
	order := "created_at DESC, id DESC"
	if len(matchKeywords) > 0 {
		args = append(args, marshalTextArray(matchKeywords))
		// 命中数降序=命中多者优先；0（不相交）行靠后、按时间补位。
		//
		// 注意：这里原本用数组交集运算符 `keywords & $N::text[]`，但 `&` 在
		// PostgreSQL 里只由 intarray 扩展提供 int[] 版本，text[] 从来不可用
		// （PG16 实测 42883: operator does not exist: text[] & text[]）——只要
		// 有关键词就整条查询报错，resolver 静默退化到零注入。改成 unnest+ANY
		// 的等价计数，语义相同（交集的基数）且不依赖扩展。
		order = "(SELECT count(*) FROM unnest(keywords) kw WHERE kw = ANY($" + fmt.Sprint(len(args)) + "::text[])) DESC, " + order
	}
	args = append(args, limit)
	rows, err := d.QueryContext(ctx, `SELECT id, project_id, content, source_task_id, array_to_json(keywords)::text, status, rejected_reason, created_at
FROM project_insights WHERE project_id=$1 AND scope='project' AND status='active'
ORDER BY `+order+` LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Insight
	for rows.Next() {
		var in Insight
		var src sql.NullInt64
		var kwJSON string
		if err := rows.Scan(&in.ID, &in.ProjectID, &in.Content, &src, &kwJSON, &in.Status, &in.RejectedReason, &in.CreatedAt); err != nil {
			return nil, err
		}
		if src.Valid {
			in.SourceTaskID = src.Int64
		}
		_ = json.Unmarshal([]byte(kwJSON), &in.Keywords)
		out = append(out, in)
	}
	return out, rows.Err()
}

// ListInsightsMatch 返回某项目【active 且 keywords 与 matchKeys 有交集】的洞察
// （命中数降序，同分新在前）。与 ListInsights 的唯一差别是**不做时间补位**：
// 一条都不交集时返回空，不是「拿最近的 3 条顶上」。
//
// 为什么要这个变体（V11-INSIGHT9）：planner 侧注入原来走 ListInsights，关键词
// 全不命中时按 created_at DESC 补满 limit。项目 ≠ 相关域——一个项目里可能挂
// 着 N 个互不相关的目标系统，补位等于把「A 任务的 canal 经验」无差别广播给
// 正在打 B 系统的任务：每轮 3×200 字噪声，还稀释真正命中的信号。
// 只注入真交集，「跨任务复用」才回到「同资产/同组件」的原意。
//
// matchKeys 为空直接返回 nil（不发 SQL）：没有任何锚定键时，任何洞察都不该
// 被视为「与本任务相关」。
func (d *DB) ListInsightsMatch(ctx context.Context, projectID int64, matchKeys []string, limit int) ([]Insight, error) {
	if projectID <= 0 || len(matchKeys) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}
	// 命中计数写两遍（ORDER BY / WHERE 各一次）：PG 不会把同一条子查询在
	// ORDER BY 与 WHERE 间复用，拆成 CTE 反而多一次物化——行数少（单项目
	// 洞察通常几十条），重复算更省。
	const hits = `(SELECT count(*) FROM unnest(keywords) kw WHERE kw = ANY($2::text[]))`
	rows, err := d.QueryContext(ctx, `SELECT id, project_id, content, source_task_id,
       array_to_json(keywords)::text, status, rejected_reason, created_at
FROM project_insights
WHERE project_id=$1 AND scope='project' AND status='active' AND `+hits+` > 0
ORDER BY `+hits+` DESC, created_at DESC, id DESC
LIMIT $3`, projectID, marshalTextArray(matchKeys), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Insight
	for rows.Next() {
		var in Insight
		var src sql.NullInt64
		var kwJSON string
		if err := rows.Scan(&in.ID, &in.ProjectID, &in.Content, &src, &kwJSON, &in.Status, &in.RejectedReason, &in.CreatedAt); err != nil {
			return nil, err
		}
		if src.Valid {
			in.SourceTaskID = src.Int64
		}
		_ = json.Unmarshal([]byte(kwJSON), &in.Keywords)
		out = append(out, in)
	}
	return out, rows.Err()
}

// DeleteInsight 按 id 删一条项目洞察；不存在返回 ErrInsightNotFound
// （observer 管理面/测试清理用，调用方按项目归属自行校验前先查行）。
func (d *DB) DeleteInsight(ctx context.Context, id int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM project_insights WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrInsightNotFound
	}
	return nil
}

// DeleteProjectInsight 是项目作用域的删除（API 面专用）：WHERE 带 project_id，
// 单条 SQL 即防越权删他项目行——不靠"调用方先查行再删"的自觉（那有 TOCTOU 窗，
// 且每删一条多一次往返）。ErrInsightNotFound 同时覆盖"不存在"与"不属于该项目"
// 两态（对调用方语义一致：这条你删不了）。
func (d *DB) DeleteProjectInsight(ctx context.Context, projectID, id int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM project_insights WHERE id=$1 AND project_id=$2 AND scope='project'`, id, projectID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrInsightNotFound
	}
	return nil
}

// WriteGlobalInsight 追加一条跨项目洞察（reader 产出）。content 必填；
// sourceProjects 记录串联涉及的项目 id 集（不校验存在性：只读旁路，
// 项目随后被删也不该让洞察写入失败——source 列无 FK 正是此意）。
//
// V5-A：assetKeys 是注入命中键（归一化资产键，见 AssetKeysForProjects /
// DeriveAssetKeys），空=永不注入。写入是【同资产覆盖】的原子操作——插入新行后
// 同一事务把「status='active' 且 asset_keys 与新键相交」的旧行置 superseded、
// superseded_by=新 id，保证同一资产只留最新一条可注入洞察（旧行留档可查，
// 不物理删）。
func (d *DB) WriteGlobalInsight(ctx context.Context, content string, sourceProjects []int64, assetKeys []string) (*GlobalInsight, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, errors.New("global insight content is required")
	}
	g := &GlobalInsight{Content: content, SourceProjects: sourceProjects, AssetKeys: assetKeys, Status: InsightStatusActive}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }() // 已 Commit 后 Rollback 是 no-op
	var spJSON, akJSON string
	err = tx.QueryRowContext(ctx, `
INSERT INTO project_insights(content, source_projects, asset_keys, scope, project_id)
VALUES ($1, $2::bigint[], $3::text[], 'cross', NULL)
RETURNING id, content, array_to_json(source_projects)::text, array_to_json(asset_keys)::text,
          status, COALESCE(superseded_by,0), rejected_reason, created_at`,
		utf8Clean(content), marshalInt64Array(sourceProjects), marshalTextArray(assetKeys)).
		Scan(&g.ID, &g.Content, &spJSON, &akJSON, &g.Status, &g.SupersededBy, &g.RejectedReason, &g.CreatedAt)
	if err != nil {
		return nil, err
	}
	if len(assetKeys) > 0 {
		// 同资产覆盖：只动 active 行（rejected 是人/planner 的明确判断，不该被
		// 新写悄悄复活成 superseded；superseded 已是历史，无需再改）。
		if _, err := tx.ExecContext(ctx, `
UPDATE project_insights SET status='superseded', superseded_by=$1
WHERE scope='cross' AND status='active' AND id<>$1 AND asset_keys && $2::text[]`,
			g.ID, marshalTextArray(assetKeys)); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(spJSON), &g.SourceProjects)
	_ = json.Unmarshal([]byte(akJSON), &g.AssetKeys)
	return g, nil
}

// ListGlobalInsights 返回全局洞察（新在前，含已否决/被覆盖行——这是查看面，
// 不是注入面）。limit<=0 默认 50。
func (d *DB) ListGlobalInsights(ctx context.Context, limit int) ([]GlobalInsight, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.QueryContext(ctx, `SELECT id, content, array_to_json(source_projects)::text,
       array_to_json(asset_keys)::text, status, COALESCE(superseded_by,0), rejected_reason, created_at
FROM project_insights WHERE scope='cross' ORDER BY created_at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GlobalInsight
	for rows.Next() {
		var g GlobalInsight
		var spJSON, akJSON string
		if err := rows.Scan(&g.ID, &g.Content, &spJSON, &akJSON, &g.Status, &g.SupersededBy, &g.RejectedReason, &g.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(spJSON), &g.SourceProjects)
		_ = json.Unmarshal([]byte(akJSON), &g.AssetKeys)
		out = append(out, g)
	}
	return out, rows.Err()
}

// ListCrossProjectInsights 返回【可注入】的跨项目洞察：status='active' 且
// asset_keys 与 matchKeys 相交（GIN 索引 idx_pins_asset），新在前。matchKeys
// 为空直接返回空——没有任何本任务锚定键时，「跨项目经验」只可能误导，宁可不注入。
func (d *DB) ListCrossProjectInsights(ctx context.Context, matchKeys []string, limit int) ([]GlobalInsight, error) {
	if len(matchKeys) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.QueryContext(ctx, `SELECT id, content, array_to_json(source_projects)::text,
       array_to_json(asset_keys)::text, status, COALESCE(superseded_by,0), rejected_reason, created_at
FROM project_insights
WHERE scope='cross' AND status='active' AND asset_keys && $1::text[]
ORDER BY created_at DESC, id DESC LIMIT $2`, marshalTextArray(matchKeys), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GlobalInsight
	for rows.Next() {
		var g GlobalInsight
		var spJSON, akJSON string
		if err := rows.Scan(&g.ID, &g.Content, &spJSON, &akJSON, &g.Status, &g.SupersededBy, &g.RejectedReason, &g.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(spJSON), &g.SourceProjects)
		_ = json.Unmarshal([]byte(akJSON), &g.AssetKeys)
		out = append(out, g)
	}
	return out, rows.Err()
}

// ListRecentCrossProjectInsights 返回最近 limit 条【active】的跨项目洞察（新在
// 前）。V6-XPROJ：本任务没有任何锚定资产键时的退化注入来源——跨任务阅读者经验在
// 「本任务尚未锚定资产」时仍有全局参照价值，故不再因交集为空整段不注入；
// 调用方（server/project_insight.go）只取 insightCrossMax 条并要求 reader 闸门
// 打开。limit<=0 默认 50。
func (d *DB) ListRecentCrossProjectInsights(ctx context.Context, limit int) ([]GlobalInsight, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.QueryContext(ctx, `SELECT id, content, array_to_json(source_projects)::text,
       array_to_json(asset_keys)::text, status, COALESCE(superseded_by,0), rejected_reason, created_at
FROM project_insights
WHERE scope='cross' AND status='active'
ORDER BY created_at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GlobalInsight
	for rows.Next() {
		var g GlobalInsight
		var spJSON, akJSON string
		if err := rows.Scan(&g.ID, &g.Content, &spJSON, &akJSON, &g.Status, &g.SupersededBy, &g.RejectedReason, &g.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(spJSON), &g.SourceProjects)
		_ = json.Unmarshal([]byte(akJSON), &g.AssetKeys)
		out = append(out, g)
	}
	return out, rows.Err()
}

// RejectInsight 把一条洞察置为 rejected 并记原因（planner 的 reject_insight
// 工具）。kind 只接受 project/global，并作为【scope 断言】（V6-U2 单表后）：
// global→'cross'、project→'project'，防跨 scope 误否决——拿 global kind 去否决
// 一条项目洞察会被「该 scope 下不存在」挡回。幂等：已 rejected 再拒 →
// changed=false 且不报错（重复调用无副作用）；id 不存在/不属于该 scope →
// ErrInsightNotFound。reason 为空时保留原 rejected_reason（不抹掉已有留痕）。
func (d *DB) RejectInsight(ctx context.Context, kind string, id int64, reason string) (changed bool, err error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind != "project" && kind != "global" {
		return false, ErrInsightKindInvalid
	}
	if id <= 0 {
		return false, ErrInsightNotFound
	}
	reason = strings.TrimSpace(reason)
	var got int64
	err = d.QueryRowContext(ctx, `UPDATE project_insights
SET status='rejected', rejected_reason=CASE WHEN $2<>'' THEN $2 ELSE rejected_reason END
WHERE id=$1 AND scope=CASE WHEN $3='global' THEN 'cross' ELSE 'project' END
  AND status<>'rejected' RETURNING id`, id, utf8Clean(reason), kind).Scan(&got)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	// 没有行被更新：要么不存在/不属于该 scope，要么本来就是 rejected（幂等路径）。
	var exists int64
	if err2 := d.QueryRowContext(ctx, `SELECT id FROM project_insights
WHERE id=$1 AND scope=CASE WHEN $2='global' THEN 'cross' ELSE 'project' END`, id, kind).Scan(&exists); err2 != nil {
		if errors.Is(err2, sql.ErrNoRows) {
			return false, ErrInsightNotFound
		}
		return false, err2
	}
	return false, nil
}

// AssetKeysForProjects 返回这些项目下【出现过的资产】的归一化键集合
// （V5-C 起为父子两级：host、host:port、host:port/path，见 assetKeyLevels；
// 另含历史完整 URL/域名/IP 键保兼容）。关联链以真实 schema 为准：
// assets.task_ids（BIGINT[]）∩ 项目下未删任务的 id。
//
// 用途：reader 写 global_insight 时没给 asset_keys，就从正文里匹配这些已知键
// （DeriveAssetKeys）——写入侧与注入侧（AssetKeysForIDs）用同一套归一化规则，
// 交集才可能命中。
func (d *DB) AssetKeysForProjects(ctx context.Context, projectIDs []int64) ([]string, error) {
	if len(projectIDs) == 0 {
		return nil, nil
	}
	rows, err := d.QueryContext(ctx, `
SELECT DISTINCT COALESCE(a.type,''), COALESCE(a.domain,''), COALESCE(a.root_domain,''), COALESCE(a.ip,''),
       COALESCE(a.port,0), COALESCE(a.url,'')
FROM assets a
WHERE a.task_ids && ARRAY(
    SELECT t.id FROM tasks t
    WHERE t.project_id = ANY($1::bigint[]) AND t.deleted_at IS NULL
)`, marshalInt64Array(projectIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var typ, domain, root, ip, u string
		var port int
		if err := rows.Scan(&typ, &domain, &root, &ip, &port, &u); err != nil {
			return nil, err
		}
		out = appendAssetKeys(out, seen, assetKeyLevels(typ, domain, root, ip, port, u))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(out) // 确定性（调用方/测试不依赖 SQL 返回序）
	return out, nil
}

// DeriveAssetKeys 是纯函数：从洞察正文里挑出命中的已知资产键（子串、大小写
// 不敏感），去重后按字典序返回。
//
// 召回边界（有意为之）：只做「已知键 ⊂ 正文」的单向子串命中，不做模糊/拼音/
// 端口补齐；短于 deriveAssetKeyMinLen 的键不参与（避免 "a.io" 之类的极短域名
// 在长正文里误命中）。正文若只写了组件名（canal/nginx）而没有资产键，则一条
// 也匹配不到——这种洞察 asset_keys 落空=不注入，只能人工看（宁缺勿滥）。
func DeriveAssetKeys(content string, candidates []string) []string {
	body := strings.ToLower(content)
	if body == "" || len(candidates) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range candidates {
		k := strings.ToLower(strings.TrimSpace(c))
		if len(k) < deriveAssetKeyMinLen || seen[k] {
			continue
		}
		if strings.Contains(body, k) {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// deriveAssetKeyMinLen 是 DeriveAssetKeys 参与匹配的最短键长度（字节）。
// 归一化键是主机名/IP/URL，全部 ASCII，字节长度≈字符长度。
const deriveAssetKeyMinLen = 4
