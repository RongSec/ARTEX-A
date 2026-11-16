package db

import (
	"context"
	"sort"
	"strings"
)

// V9-SCOPE：task_foreign_assets 是「阅读者采纳任务时带进来的外部资产 host」。
//
// 语义是【负向清单】：hint 里的经验可以复用，但这些 host 属于被勾连任务，
// 不在发起方任务的授权范围。guard 的内置规则在工具调用命中这些 host 且未在
// 本任务 assets 里时直接 deny（见 guard/foreign_scope.go）。本文件只负责读写
// 与幂等；host 归一化由调用方（server/guard 共用的 NormalizeHost）完成。

// RecordTaskForeignAssets 幂等写入被勾连任务的资产 host。
// 同一 (task_id, host) 重复采纳只更新 source_task_id，不会膨胀；空 host 忽略。
// 返回受影响的 host 数（新增 + 已存在的更新）。
func (d *DB) RecordTaskForeignAssets(ctx context.Context, taskID, sourceTaskID int64, hosts []string) (int, error) {
	if taskID <= 0 || sourceTaskID <= 0 || len(hosts) == 0 {
		return 0, nil
	}
	seen := make(map[string]struct{}, len(hosts))
	clean := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		clean = append(clean, h)
	}
	if len(clean) == 0 {
		return 0, nil
	}
	res, err := d.ExecContext(ctx, `
INSERT INTO task_foreign_assets(task_id, host, source_task_id)
SELECT $1, h, $3 FROM unnest($2::text[]) AS h
ON CONFLICT (task_id, host) DO UPDATE SET source_task_id=EXCLUDED.source_task_id`,
		taskID, clean, sourceTaskID)
	if err != nil {
		return 0, err
	}
	if n, err := res.RowsAffected(); err == nil {
		return int(n), nil
	}
	return len(clean), nil
}

// ForeignHostsForTask 返回某任务名下记录的全部外部资产 host（升序）。
func (d *DB) ForeignHostsForTask(ctx context.Context, taskID int64) ([]string, error) {
	if taskID <= 0 {
		return nil, nil
	}
	return d.queryForeignHosts(ctx, `
SELECT host FROM task_foreign_assets WHERE task_id=$1 ORDER BY host`, taskID)
}

// ForeignHostsForTaskSource 返回某任务从指定被勾连任务带进来的外部资产 host。
// 供 reader-traces 的每条采纳记录展示 foreign_hosts。
func (d *DB) ForeignHostsForTaskSource(ctx context.Context, taskID, sourceTaskID int64) ([]string, error) {
	if taskID <= 0 || sourceTaskID <= 0 {
		return nil, nil
	}
	return d.queryForeignHosts(ctx, `
SELECT host FROM task_foreign_assets
WHERE task_id=$1 AND source_task_id=$2 ORDER BY host`, taskID, sourceTaskID)
}

// CountTaskForeignAssets 返回某任务记录的外部资产 host 数（测试/可观测用）。
func (d *DB) CountTaskForeignAssets(ctx context.Context, taskID int64) (int, error) {
	if taskID <= 0 {
		return 0, nil
	}
	var n int
	err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM task_foreign_assets WHERE task_id=$1`, taskID).Scan(&n)
	return n, err
}

func (d *DB) queryForeignHosts(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := d.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}
