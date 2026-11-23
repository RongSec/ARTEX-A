package db

// 阅读者下钻审计（V11-READER3）。
//
// 背景：任务页原本的「阅读者审计」只记「采纳了谁」（task_intel_links），
// 看不到「哪些点被下钻过、被哪条意图用了」。下钻是规划者/执行者拿细节的
// 唯一通道，没有记录就无法回答「这条意图的经验到底从哪来」。
//
// 每次 ask_reader 落一行；纯检索（没给 node_ids）也记，node_ids 为空表示
// 只做了关键词检索。写入失败不影响下钻本身——审计是旁路，不能反过来卡执行。

import (
	"context"
	"strings"
	"time"
)

// ReaderDrill 是一次下钻记录。
type ReaderDrill struct {
	ID            int64     `json:"id"`
	ProjectID     int64     `json:"project_id"`
	TaskID        int64     `json:"task_id"`
	RelatedTaskID int64     `json:"related_task_id"`
	IntentID      int64     `json:"intent_id"` // 0 = 规划者发起（不在意图内）
	NodeIDs       []int64   `json:"node_ids"`
	Query         string    `json:"query"`
	Mode          string    `json:"mode"` // planner=要方法论 / detail=要执行细节
	ItemCount     int       `json:"item_count"`
	CreatedAt     time.Time `json:"created_at"`
}

// int64ArrayLiteral 把 id 列表拼成 Postgres 数组字面量。走字面量而不是驱动
// 的 slice 编码：pgx stdlib 对 []int64 的映射在不同版本上行为不一致，字面量
// 是确定性的。
func int64ArrayLiteral(ids []int64) string {
	if len(ids) == 0 {
		return "{}"
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, id := range ids {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(itoa64(id))
	}
	b.WriteByte('}')
	return b.String()
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [24]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// RecordReaderDrill 落一条下钻记录。project_id 从 tasks 表现取（调用方不必
// 关心任务挂在哪个项目）；任务不存在时静默不写。
func (s *ExplorationStore) RecordReaderDrill(ctx context.Context, r ReaderDrill) error {
	if s == nil || s.db == nil || r.TaskID <= 0 || r.RelatedTaskID <= 0 {
		return nil
	}
	mode := strings.TrimSpace(r.Mode)
	if mode == "" {
		mode = "planner"
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO reader_drills(project_id, task_id, related_task_id, intent_id, node_ids, query, mode, item_count)
SELECT COALESCE(project_id, 0), id, $2, $3, $4::bigint[], $5, $6, $7
FROM tasks WHERE id = $1`,
		r.TaskID, r.RelatedTaskID, r.IntentID, int64ArrayLiteral(r.NodeIDs),
		truncateRunes(utf8Clean(r.Query), 500), truncateRunes(mode, 20), r.ItemCount)
	return err
}

// ListReaderDrills 返回某任务发起过的下钻审计（新在前）。审计接口按
// related_task_id 分组展示。JOIN tasks 过滤掉参考任务已删档的行：清理开关
// 没勾时记录还在，但审计面不能给出指向已删任务的链接（前端会渲染成
// 「参考任务 #N」→ 打开是空页）。
func (d *DB) ListReaderDrills(ctx context.Context, taskID int64) ([]ReaderDrill, error) {
	if taskID <= 0 {
		return nil, nil
	}
	rows, err := d.QueryContext(ctx, `
SELECT d.id, d.project_id, d.task_id, d.related_task_id, d.intent_id, d.node_ids::text, d.query, d.mode, d.item_count, d.created_at
FROM reader_drills d
JOIN tasks rt ON rt.id = d.related_task_id AND rt.deleted_at IS NULL
WHERE d.task_id=$1 ORDER BY d.id DESC LIMIT 500`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReaderDrill{}
	for rows.Next() {
		var r ReaderDrill
		var ids string
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.TaskID, &r.RelatedTaskID, &r.IntentID,
			&ids, &r.Query, &r.Mode, &r.ItemCount, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.NodeIDs = parsePGIntArray(ids)
		out = append(out, r)
	}
	return out, rows.Err()
}
