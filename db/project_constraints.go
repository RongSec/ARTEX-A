package db

// 项目级操作约束：建项目时录入（或经 LLM 从自然语言解析）的 allow/deny 条目。
// 批量下发任务时逐条复制进 task_constraints，作为任务启动时的初始边界；任务
// 之后仍可在总览「操作约束」里单独增删，不回写项目。

import (
	"fmt"
	"strings"
)

// ConstraintInput 是项目约束的写入形状（与 task_constraints 的 kind/text 同构）。
type ConstraintInput struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

// ListProjectConstraints 返回项目约束（allow 在前、同组按 id）。
func (d *DB) ListProjectConstraints(projectID int64) ([]Constraint, error) {
	rows, err := d.Query(`
SELECT id, kind, text, COALESCE(origin,''), created_at
FROM project_constraints WHERE project_id=$1
ORDER BY (kind='deny'), id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Constraint{}
	for rows.Next() {
		var c Constraint
		if err := rows.Scan(&c.ID, &c.Kind, &c.Text, &c.Origin, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ReplaceProjectConstraints 全量替换项目约束（事务内先删后插）。
// 空列表 = 清空。kind 非 allow/deny 或 text 为空 → 400 语义错误。
func (d *DB) ReplaceProjectConstraints(projectID int64, items []ConstraintInput) error {
	clean := make([]ConstraintInput, 0, len(items))
	for _, it := range items {
		kind := strings.TrimSpace(strings.ToLower(it.Kind))
		text := strings.TrimSpace(it.Text)
		if kind != "allow" && kind != "deny" {
			return fmt.Errorf("约束类型必须是 allow 或 deny")
		}
		if text == "" {
			return fmt.Errorf("约束内容不能为空")
		}
		clean = append(clean, ConstraintInput{Kind: kind, Text: text})
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM project_constraints WHERE project_id=$1`, projectID); err != nil {
		return err
	}
	for _, it := range clean {
		if _, err := tx.Exec(`INSERT INTO project_constraints(project_id, kind, text, origin)
VALUES ($1,$2,$3,'human')`, projectID, it.Kind, it.Text); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CopyProjectConstraintsToTask 把项目约束复制进任务的 task_constraints
// （origin=project）。批量下发每个任务调一次；去重按 (kind,text)，避免重复下发
// 同一批目标时同一任务出现两遍（任务本身是新建的，实际不会重复，防御性保留）。
func (d *DB) CopyProjectConstraintsToTask(projectID, explorationID int64) (int, error) {
	res, err := d.Exec(`
INSERT INTO task_constraints(exploration_id, kind, text, origin)
SELECT $2, kind, text, 'project'
FROM project_constraints p
WHERE p.project_id=$1
  AND NOT EXISTS (
    SELECT 1 FROM task_constraints c
    WHERE c.exploration_id=$2 AND c.kind=p.kind AND c.text=p.text
  )
ORDER BY (kind='deny'), id`, projectID, explorationID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// InsertTaskConstraints 写入任务创建时手工/LLM 解析的约束（origin=human）。
// 与 goals 拆解器随后抽取的约束并存（去重同 CopyProjectConstraintsToTask）。
func (d *DB) InsertTaskConstraints(explorationID int64, items []ConstraintInput) (int, error) {
	n := 0
	for _, it := range items {
		kind := strings.TrimSpace(strings.ToLower(it.Kind))
		text := strings.TrimSpace(it.Text)
		if kind != "allow" && kind != "deny" {
			return n, fmt.Errorf("约束类型必须是 allow 或 deny")
		}
		if text == "" {
			continue
		}
		res, err := d.Exec(`
INSERT INTO task_constraints(exploration_id, kind, text, origin)
SELECT $1,$2,$3,'human'
WHERE NOT EXISTS (
  SELECT 1 FROM task_constraints WHERE exploration_id=$1 AND kind=$2 AND text=$3
)`, explorationID, kind, text)
		if err != nil {
			return n, err
		}
		if rows, _ := res.RowsAffected(); rows > 0 {
			n++
		}
	}
	return n, nil
}
