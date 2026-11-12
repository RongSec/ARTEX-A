package db

// 跨项目资产聚合（V4-E / reader「资产优先」输入面）。
//
// 背景：跨项目最强的信号是「同一资产/同一组件出现在多个项目里」，这本质是
// 一次 join，不该让模型从各项目洞察的散文里自己猜。本文件把它做成一条 SQL，
// 结果直接进 read_all_project_insights 的 cross_project_assets 字段。
//
// 【资产关联链（以真实 schema 为准）】
//   findings.asset_ids (JSONB 数组，元素=assets.id)
//     → findings.task_id → tasks.project_id → projects
//     → assets（取 label/kind）
//
// 仓库里【没有】finding_assets 表：findings.asset_ids 就是发现↔资产的关联列
// （db/findings.go AddFinding 写入、db/finding_assets.go BuildFindingAssetTree
// 按同一列反查），所以用这条链，而不是任务书里假设的 finding_assets。
//
// 口径：只统计挂在【有项目归属】（tasks.project_id NOT NULL）且未软删任务上的
// 发现；同一资产在 ≥2 个不同项目里出现过才返回。排序=项目数 desc → 最近出现
// desc → 资产 id（稳定），limit 默认 20。

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// crossProjectAssetDefaultLimit 是聚合行数上限的默认值。跨项目信号是「少而
// 精」的输入（reader 要围绕它写全局洞察），不是全量报表。
const crossProjectAssetDefaultLimit = 20

// CrossProjectAssetProject 是跨项目资产行里的一个项目引用（id + 名称，供
// reader 在洞察正文里点名）。
type CrossProjectAssetProject struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// CrossProjectAssetRow 是「同一资产出现在多个项目」的一行聚合。
type CrossProjectAssetRow struct {
	AssetID      int64                      `json:"asset_id"`
	Label        string                     `json:"label"` // assets 表的展示标签（URL > domain > ip > app_name > root_domain，服务补端口）
	Kind         string                     `json:"kind"`  // assets.type
	ProjectCount int                        `json:"project_count"`
	Projects     []CrossProjectAssetProject `json:"projects"`
	FindingCount int                        `json:"finding_count"`
	LastFoundAt  time.Time                  `json:"last_found_at"`
}

// crossProjectAssetRaw 是 SQL 原样行（标签/项目名尚未组装）。
type crossProjectAssetRaw struct {
	asset        assetRow
	projectIDs   []int64
	findingCount int
	lastFoundAt  time.Time
}

// CrossProjectAssetRows 返回跨项目资产聚合行（项目数 ≥2，最多 limit 行）。
// limit<=0 用默认 20。
func (d *DB) CrossProjectAssetRows(ctx context.Context, limit int) ([]CrossProjectAssetRow, error) {
	if limit <= 0 {
		limit = crossProjectAssetDefaultLimit
	}
	rows, err := d.QueryContext(ctx, `
WITH fa AS (
    SELECT f.id AS finding_id, f.created_at, t.project_id,
           (elem.value)::bigint AS asset_id
    FROM findings f
    JOIN tasks t ON t.id = f.task_id AND t.deleted_at IS NULL
    CROSS JOIN LATERAL jsonb_array_elements_text(
        CASE WHEN jsonb_typeof(f.asset_ids) = 'array' THEN f.asset_ids ELSE '[]'::jsonb END
    ) AS elem(value)
    WHERE f.task_id IS NOT NULL
      AND t.project_id IS NOT NULL
      AND elem.value ~ '^[0-9]+$'
), agg AS (
    SELECT fa.asset_id,
           count(DISTINCT fa.project_id)  AS project_count,
           count(DISTINCT fa.finding_id)  AS finding_count,
           max(fa.created_at)             AS last_found_at,
           array_agg(DISTINCT fa.project_id) AS project_ids
    FROM fa
    GROUP BY fa.asset_id
    HAVING count(DISTINCT fa.project_id) >= 2
)
SELECT a.id, a.type, COALESCE(a.company_id,0),
       COALESCE(a.domain,''), COALESCE(a.root_domain,''), COALESCE(a.ip,''),
       COALESCE(a.url,''), COALESCE(a.port,0), COALESCE(a.service_type,''),
       COALESCE(a.app_name,''),
       agg.finding_count, agg.last_found_at, array_to_json(agg.project_ids)::text
FROM agg JOIN assets a ON a.id = agg.asset_id
ORDER BY agg.project_count DESC, agg.last_found_at DESC, a.id
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var raws []crossProjectAssetRaw
	for rows.Next() {
		var r crossProjectAssetRaw
		var idsJSON string
		if err := rows.Scan(&r.asset.id, &r.asset.kind, &r.asset.companyID,
			&r.asset.domain, &r.asset.rootDomain, &r.asset.ip,
			&r.asset.url, &r.asset.port, &r.asset.serviceType, &r.asset.appName,
			&r.findingCount, &r.lastFoundAt, &idsJSON); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(idsJSON), &r.projectIDs); err != nil {
			return nil, fmt.Errorf("decode project ids: %w", err)
		}
		raws = append(raws, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	names, err := d.projectNamesByIDs(ctx, raws)
	if err != nil {
		return nil, err
	}
	return assembleCrossProjectAssets(raws, names, limit), nil
}

// projectNamesByIDs 批量取 id→name（一条 SQL，避免 N+1）。
func (d *DB) projectNamesByIDs(ctx context.Context, raws []crossProjectAssetRaw) (map[int64]string, error) {
	seen := map[int64]bool{}
	var ids []int64
	for _, r := range raws {
		for _, id := range r.projectIDs {
			if id > 0 && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	out := make(map[int64]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := d.QueryContext(ctx, `SELECT id, name FROM projects WHERE id = ANY($1::bigint[])`,
		marshalInt64Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = name
	}
	return out, rows.Err()
}

// assembleCrossProjectAssets 是纯函数（无库可单测）：组装标签与项目名、
// 过滤项目数 <2 的行、排序、截断。
//
// 排序：项目数 desc → 最近出现 desc → 资产 id asc（末位键保证确定性）。
// 项目列表按 id 升序；项目行被删/取名失败时回落到 "project#<id>"，不静默丢行
// （reader 仍能看到「某资产确实跨了 N 个项目」这一事实）。
func assembleCrossProjectAssets(raw []crossProjectAssetRaw, names map[int64]string, limit int) []CrossProjectAssetRow {
	if limit <= 0 {
		limit = crossProjectAssetDefaultLimit
	}
	out := make([]CrossProjectAssetRow, 0, len(raw))
	for _, r := range raw {
		ids := make([]int64, 0, len(r.projectIDs))
		seen := map[int64]bool{}
		for _, id := range r.projectIDs {
			if id <= 0 || seen[id] {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
		if len(ids) < 2 {
			continue
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		projects := make([]CrossProjectAssetProject, 0, len(ids))
		for _, id := range ids {
			name := names[id]
			if name == "" {
				name = fmt.Sprintf("project#%d", id)
			}
			projects = append(projects, CrossProjectAssetProject{ID: id, Name: name})
		}
		a := r.asset
		out = append(out, CrossProjectAssetRow{
			AssetID:      a.id,
			Label:        a.label(),
			Kind:         a.kind,
			ProjectCount: len(projects),
			Projects:     projects,
			FindingCount: r.findingCount,
			LastFoundAt:  r.lastFoundAt,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProjectCount != out[j].ProjectCount {
			return out[i].ProjectCount > out[j].ProjectCount
		}
		if !out[i].LastFoundAt.Equal(out[j].LastFoundAt) {
			return out[i].LastFoundAt.After(out[j].LastFoundAt)
		}
		return out[i].AssetID < out[j].AssetID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// FilterCrossProjectAssetsByProjects 按 reader 可见项目集裁剪聚合行（纯函数）。
//
// T18 的 reader_enabled 项目级闸必须作用到这份输入上：否则 A 项目开了闸、
// B 没开，行里仍会带出 B 的项目名——等于绕过 opt-in 把 B 的情报读给 reader。
// 裁剪后不足 2 个项目的行直接丢弃（单项目资产不是跨项目信号）。
func FilterCrossProjectAssetsByProjects(rows []CrossProjectAssetRow, visible map[int64]bool) []CrossProjectAssetRow {
	if len(rows) == 0 {
		return rows
	}
	out := make([]CrossProjectAssetRow, 0, len(rows))
	for _, r := range rows {
		kept := make([]CrossProjectAssetProject, 0, len(r.Projects))
		for _, p := range r.Projects {
			if visible[p.ID] {
				kept = append(kept, p)
			}
		}
		if len(kept) < 2 {
			continue
		}
		r.Projects = kept
		r.ProjectCount = len(kept)
		out = append(out, r)
	}
	return out
}
