package db

// 任务情报勾连的查询面：V9-READER 起由阅读者按攻击面/增量 (kind,key) 反查
// 情报表里命中的任务，link_tasks 仍可写候选关联。
//
// 与 db/task_intel.go 的落库读写分开，避免那个文件继续膨胀；本文件只做
// 「按 (kind,key) 命中 + 任务价值统计」和「candidate 写保护」两件事。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// IntelKeyRef 是一次攻击面抽出的候选键（kind 已在抽取侧归一化）。
type IntelKeyRef struct {
	Kind string `json:"kind"`
	Key  string `json:"key"`
}

// IntelTaskMatch 是命中行 + 任务侧价值统计（阅读者判断候选值不值得下钻）。
type IntelTaskMatch struct {
	TaskIntel
	TaskName     string `json:"task_name"`
	FindingCount int    `json:"finding_count"`
	IntentCount  int    `json:"intent_count"`
}

// MatchTaskIntel 按【匹配键】命中 task_intel，排除当前任务。
//
// 比对用 match_key（IntelMatchKey 粗化后的键），不是精确 key：用户要的是
// "接口/凭据/组件层面可比"，同一个路径换了方法、少了 query、组件差个小版本
// 都不该断链。返回行仍带精确 key/value，供阅读者下钻。
//
// scope 语义：
//   - cross=false（项目内）：只查 projectID 这一个项目；
//   - cross=true（跨项目）：只查【其他项目】，且目标项目必须
//     reader_enabled=true 且 status='active'（跨项目尺度开关，与
//     observer_enabled 无关）。
//
// (kind, match_key) 去重后按对传入 unnest：既精确到 kind（避免 endpoint 路径
// 与 asset 主机同名误撞），又能走 idx_tintel_matchkey。已删档任务不参与
// （情报表仍留档，但阅读者无法 adopt 一个不存在的任务）。返回按
// task_id/kind/key 稳定排序，聚合排序在 server 层做。
func (d *DB) MatchTaskIntel(ctx context.Context, projectID int64, keys []IntelKeyRef, excludeTaskID int64, cross bool) ([]IntelTaskMatch, error) {
	if projectID <= 0 || len(keys) == 0 {
		return nil, nil
	}
	kinds := make([]string, 0, len(keys))
	matchKeys := make([]string, 0, len(keys))
	seen := map[string]bool{}
	for _, k := range keys {
		kind := strings.ToLower(strings.TrimSpace(k.Kind))
		mk := IntelMatchKey(kind, k.Key)
		if kind == "" || mk == "" {
			continue
		}
		id := kind + "\x00" + mk
		if seen[id] {
			continue
		}
		seen[id] = true
		kinds = append(kinds, kind)
		matchKeys = append(matchKeys, mk)
	}
	if len(kinds) == 0 {
		return nil, nil
	}
	args := []any{kinds, matchKeys, excludeTaskID, projectID}
	var scope string
	if cross {
		scope = `ti.project_id <> $4 AND ti.project_id IN (
SELECT id FROM projects WHERE reader_enabled = TRUE AND status = 'active')`
	} else {
		scope = "ti.project_id = $4"
	}

	q := `SELECT ti.id, ti.project_id, ti.task_id, ti.kind, ti.key, ti.match_key, ti.value, ti.detail,
       ti.source, ti.source_id, ti.created_at, ti.updated_at,
       COALESCE(t.name, ''),
       (SELECT COUNT(*) FROM findings f WHERE f.task_id = ti.task_id),
       (SELECT COUNT(*) FROM exploration_nodes en
          WHERE en.exploration_id = t.exploration_id AND en.kind = 'intent')
FROM task_intel ti
JOIN tasks t ON t.id = ti.task_id AND t.deleted_at IS NULL
JOIN unnest($1::text[], $2::text[]) AS q(kind, match_key)
  ON ti.kind = q.kind AND ti.match_key = q.match_key
WHERE ti.task_id <> $3 AND ` + scope + `
ORDER BY ti.task_id, ti.kind, ti.key`

	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IntelTaskMatch
	for rows.Next() {
		var m IntelTaskMatch
		var detail []byte
		var sourceID sql.NullInt64
		if err := rows.Scan(&m.ID, &m.ProjectID, &m.TaskID, &m.Kind, &m.Key, &m.MatchKey, &m.Value, &detail,
			&m.Source, &sourceID, &m.CreatedAt, &m.UpdatedAt,
			&m.TaskName, &m.FindingCount, &m.IntentCount); err != nil {
			return nil, err
		}
		if len(detail) == 0 {
			detail = []byte(`{}`)
		}
		m.Detail = json.RawMessage(detail)
		if sourceID.Valid {
			v := sourceID.Int64
			m.SourceID = &v
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// TaskIntelLinkFor 读一条 (task_id, related_task_id) 的现有决策；无行返回
// (nil, nil)（重复 adopt 的幂等判定用）。
func (d *DB) TaskIntelLinkFor(ctx context.Context, taskID, relatedTaskID int64) (*TaskIntelLink, error) {
	if taskID <= 0 || relatedTaskID <= 0 {
		return nil, nil
	}
	var l TaskIntelLink
	var matched []byte
	err := d.QueryRowContext(ctx, `
SELECT id, project_id, task_id, related_task_id, decision, reason, matched, decided_by, created_at
FROM task_intel_links WHERE task_id=$1 AND related_task_id=$2`, taskID, relatedTaskID).
		Scan(&l.ID, &l.ProjectID, &l.TaskID, &l.RelatedTaskID, &l.Decision, &l.Reason, &matched, &l.DecidedBy, &l.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(matched) == 0 {
		matched = []byte(`[]`)
	}
	l.Matched = json.RawMessage(matched)
	return &l, nil
}

// TaskIntelLinkTrace 是一条「任务视角」的勾连记录：既覆盖本任务勾连别人
// （direction=out），也覆盖别人勾连本任务（direction=in）。Related* 是对端
// 任务与它所属项目；相关项目可能为空（任务未挂项目）。
type TaskIntelLinkTrace struct {
	ID                 int64
	ProjectID          int64
	TaskID             int64
	RelatedTaskID      int64
	Decision           string
	Reason             string
	Matched            json.RawMessage
	DecidedBy          string
	CreatedAt          time.Time
	Direction          string // out=本任务发起，in=对端勾连本任务
	RelatedTaskName    string
	RelatedProjectID   sql.NullInt64
	RelatedProjectName sql.NullString
}

// ListTaskIntelLinkTraces 返回与本任务相关的全部勾连记录（双向），按时间倒序。
// 只连未删除的对端任务（已删档任务仍留在 links 表，但审计面展示无意义）。
func (d *DB) ListTaskIntelLinkTraces(ctx context.Context, taskID int64) ([]TaskIntelLinkTrace, error) {
	if taskID <= 0 {
		return nil, nil
	}
	rows, err := d.QueryContext(ctx, `
SELECT l.id, l.project_id, l.task_id,
       CASE WHEN l.task_id = $1 THEN l.related_task_id ELSE l.task_id END,
       l.decision, l.reason, l.matched, l.decided_by, l.created_at,
       CASE WHEN l.task_id = $1 THEN 'out' ELSE 'in' END,
       COALESCE(rt.name, ''),
       rt.project_id,
       rp.name
FROM task_intel_links l
JOIN tasks rt ON rt.id = CASE WHEN l.task_id = $1 THEN l.related_task_id ELSE l.task_id END
             AND rt.deleted_at IS NULL
LEFT JOIN projects rp ON rp.id = rt.project_id
WHERE l.task_id = $1 OR l.related_task_id = $1
ORDER BY l.created_at DESC, l.id DESC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskIntelLinkTrace
	for rows.Next() {
		var t TaskIntelLinkTrace
		var matched []byte
		if err := rows.Scan(&t.ID, &t.ProjectID, &t.TaskID, &t.RelatedTaskID, &t.Decision, &t.Reason, &matched,
			&t.DecidedBy, &t.CreatedAt, &t.Direction, &t.RelatedTaskName, &t.RelatedProjectID, &t.RelatedProjectName); err != nil {
			return nil, err
		}
		if len(matched) == 0 {
			matched = []byte(`[]`)
		}
		t.Matched = json.RawMessage(matched)
		out = append(out, t)
	}
	return out, rows.Err()
}

// SaveCandidateIntelLink 写 reader 的候选关联：幂等 upsert，但【不覆盖】已有
// adopted/dismissed —— candidate 不能覆盖已做过的正式决策。
// 返回行 id 与是否真的写入（被保护时 applied=false，返回 existing id）。
func (d *DB) SaveCandidateIntelLink(ctx context.Context, l TaskIntelLink) (id int64, applied bool, err error) {
	if l.ProjectID <= 0 || l.TaskID <= 0 || l.RelatedTaskID <= 0 {
		return 0, false, fmt.Errorf("intel link: project/task/related task id required")
	}
	matched := l.Matched
	if len(matched) == 0 || !json.Valid(matched) {
		matched = json.RawMessage(`[]`)
	}
	err = d.QueryRowContext(ctx, `
INSERT INTO task_intel_links(project_id, task_id, related_task_id, decision, reason, matched, decided_by)
VALUES ($1,$2,$3,'candidate',$4,$5,'reader')
ON CONFLICT (task_id, related_task_id) DO UPDATE
SET decision = 'candidate',
    reason = EXCLUDED.reason,
    matched = EXCLUDED.matched,
    decided_by = EXCLUDED.decided_by
WHERE task_intel_links.decision NOT IN ('adopted','dismissed')
RETURNING id`,
		l.ProjectID, l.TaskID, l.RelatedTaskID,
		truncateRunes(utf8Clean(l.Reason), 1000), string(matched)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		// 已有 adopted/dismissed：保护生效，回读现有行 id 供调用方回报。
		cur, qerr := d.TaskIntelLinkFor(ctx, l.TaskID, l.RelatedTaskID)
		if qerr != nil {
			return 0, false, qerr
		}
		if cur != nil {
			return cur.ID, false, nil
		}
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}
