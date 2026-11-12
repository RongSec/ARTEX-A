package db

// 项目洞察（project_insights，observer 产出）与全局洞察（global_insights，
// reader 产出）的读写。架构 §1.5/§1.6、§2.4：observer 把跨任务可借鉴处写成
// 洞察行，planner 侧按「open 意图锚定 asset_keys ∩ keywords 交集命中优先、
// 不足按 created_at DESC 补至 ≤limit」限量注入；global_insights 默认不注入。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Insight 是 project_insights 表的一行。
type Insight struct {
	ID           int64     `json:"id"`
	ProjectID    int64     `json:"project_id"`
	Content      string    `json:"content"`
	SourceTaskID int64     `json:"source_task_id,omitempty"` // 0=未知/无来源任务（DB 存 NULL）
	Keywords     []string  `json:"keywords"`
	CreatedAt    time.Time `json:"created_at"`
}

// GlobalInsight 是 global_insights 表的一行（reader 跨项目产出）。
type GlobalInsight struct {
	ID             int64     `json:"id"`
	Content        string    `json:"content"`
	SourceProjects []int64   `json:"source_projects"`
	CreatedAt      time.Time `json:"created_at"`
}

// ErrInsightNotFound 按 id 删除/更新时目标不存在。
var ErrInsightNotFound = errors.New("insight not found")

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
	in := &Insight{ProjectID: projectID, Content: content, SourceTaskID: sourceTaskID, Keywords: keywords}
	var src sql.NullInt64
	var kwJSON string
	err := d.QueryRowContext(ctx, `
INSERT INTO project_insights(project_id, content, source_task_id, keywords)
VALUES ($1, $2, $3, $4::text[])
RETURNING id, project_id, content, source_task_id, array_to_json(keywords)::text, created_at`,
		projectID, utf8Clean(content), srcArg, marshalTextArray(keywords)).
		Scan(&in.ID, &in.ProjectID, &in.Content, &src, &kwJSON, &in.CreatedAt)
	if err != nil {
		return nil, err
	}
	if src.Valid {
		in.SourceTaskID = src.Int64
	}
	_ = json.Unmarshal([]byte(kwJSON), &in.Keywords)
	return in, nil
}

// ListInsights 返回某项目的洞察（新在前）。matchKeywords 非空时，交集命中的
// 行排在前（命中数降序），其余按 created_at DESC 补位——与 §2.4 的注入限量
// 算法同口径，调用方取前 limit 条即得「命中优先」序列。limit<=0 默认 50。
func (d *DB) ListInsights(ctx context.Context, projectID int64, matchKeywords []string, limit int) ([]Insight, error) {
	if limit <= 0 {
		limit = 50
	}
	args := []any{projectID}
	order := "created_at DESC, id DESC"
	if len(matchKeywords) > 0 {
		args = append(args, marshalTextArray(matchKeywords))
		// cardinality(交集) 降序=命中多者优先；0（不相交）行靠后、按时间补位。
		order = "cardinality(keywords & $" + fmt.Sprint(len(args)) + "::text[]) DESC, " + order
	}
	args = append(args, limit)
	rows, err := d.QueryContext(ctx, `SELECT id, project_id, content, source_task_id, array_to_json(keywords)::text, created_at
FROM project_insights WHERE project_id=$1
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
		if err := rows.Scan(&in.ID, &in.ProjectID, &in.Content, &src, &kwJSON, &in.CreatedAt); err != nil {
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
	res, err := d.ExecContext(ctx, `DELETE FROM project_insights WHERE id=$1 AND project_id=$2`, id, projectID)
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
func (d *DB) WriteGlobalInsight(ctx context.Context, content string, sourceProjects []int64) (*GlobalInsight, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, errors.New("global insight content is required")
	}
	g := &GlobalInsight{Content: content, SourceProjects: sourceProjects}
	var spJSON string
	err := d.QueryRowContext(ctx, `
INSERT INTO global_insights(content, source_projects)
VALUES ($1, $2::bigint[])
RETURNING id, content, array_to_json(source_projects)::text, created_at`,
		utf8Clean(content), marshalInt64Array(sourceProjects)).
		Scan(&g.ID, &g.Content, &spJSON, &g.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(spJSON), &g.SourceProjects)
	return g, nil
}

// ListGlobalInsights 返回全局洞察（新在前）。limit<=0 默认 50。
func (d *DB) ListGlobalInsights(ctx context.Context, limit int) ([]GlobalInsight, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.QueryContext(ctx, `SELECT id, content, array_to_json(source_projects)::text, created_at
FROM global_insights ORDER BY created_at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GlobalInsight
	for rows.Next() {
		var g GlobalInsight
		var spJSON string
		if err := rows.Scan(&g.ID, &g.Content, &spJSON, &g.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(spJSON), &g.SourceProjects)
		out = append(out, g)
	}
	return out, rows.Err()
}
