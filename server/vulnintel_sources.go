package server

// 库配置：vuln_sources 表的读写，以及「配置 + 运行时状态」的合并视图。
//
// 现在只有 5 个内置源（NVD / KEV / GHSA / GitHub PoC / nuclei 模板），不加新源；
// 但这张表是骨架：以后加源 = 插一行 + 在 vulnintel 包里注册一个 adapter，
// 页面不用改一行代码。
//
// 设计取舍：**不把端点写死在代码里**。NVD 换镜像、GitHub 走内网代理、模板树
// 换私有 fork，都只需要改这一行的 endpoint，不用重新编译。

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/vulnintel"
)

// vulnSource 是库配置的一行（含运行时状态）。
type vulnSource struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Kind  string `json:"kind"` // api_json / json_feed / github_api / git_repo
	Enabled bool `json:"enabled"`
	Endpoint string `json:"endpoint"`
	// CredentialSetting 是凭据在 settings 表里的键名；CredentialHint 说明
	// 没凭据会怎样（限速、不可用），页面直接展示。
	CredentialSetting string `json:"credential_setting"`
	CredentialHint    string `json:"credential_hint"`
	CredentialSet     bool   `json:"credential_set"`
	Priority          int    `json:"priority"`
	SyncMode          string `json:"sync_mode"`
	IntervalMinutes   int    `json:"interval_minutes"`
	BackfillDays      int    `json:"backfill_days"`
	Note              string `json:"note"`

	// 运行时（来自 vuln_sync_state + 计数）
	LastSyncAt  *time.Time `json:"last_sync_at,omitempty"`
	Cursor      string     `json:"cursor,omitempty"`
	TotalSynced int64      `json:"total_synced"`
	LastError   string     `json:"last_error,omitempty"`
	ErrorHint   string     `json:"error_hint,omitempty"`
	Count       int64      `json:"count"`
	Status      string     `json:"status"` // ok / error / never
}

// listVulnSources 读全部库配置并合并运行时状态。
func (s *Server) listVulnSources(ctx context.Context) ([]vulnSource, error) {
	if s.m == nil || s.m.pg == nil {
		return nil, fmt.Errorf("数据库未就绪")
	}
	rows, err := s.m.pg.QueryContext(ctx, `
SELECT s.id, s.name, s.kind, s.enabled, s.endpoint, s.credential_setting, s.credential_hint,
       s.priority, s.sync_mode, s.interval_minutes, s.backfill_days, s.note,
       st.last_sync_at, COALESCE(st.cursor,''), COALESCE(st.total_synced,0), COALESCE(st.last_error,'')
FROM vuln_sources s
LEFT JOIN vuln_sync_state st ON st.source = s.id
ORDER BY s.sort_order, s.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []vulnSource{}
	for rows.Next() {
		var v vulnSource
		var last sql.NullTime
		var credKey string
		if err := rows.Scan(&v.ID, &v.Name, &v.Kind, &v.Enabled, &v.Endpoint, &credKey, &v.CredentialHint,
			&v.Priority, &v.SyncMode, &v.IntervalMinutes, &v.BackfillDays, &v.Note,
			&last, &v.Cursor, &v.TotalSynced, &v.LastError); err != nil {
			return nil, err
		}
		v.CredentialSetting = credKey
		if last.Valid {
			t := last.Time
			v.LastSyncAt = &t
		}
		if credKey != "" {
			v.CredentialSet = settingString(s.m.pg, credKey) != ""
		}
		switch {
		case v.LastError != "":
			v.Status = "error"
			v.ErrorHint = vulnIntelErrorHint(v.LastError)
		case v.LastSyncAt != nil:
			v.Status = "ok"
		default:
			v.Status = "never"
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 每个库贡献的条数：口径不同，分开查比一条 UNION 更好读。
	for i := range out {
		out[i].Count = s.vulnSourceCount(ctx, out[i].ID)
	}
	return out, nil
}

// vulnSourceCount 返回该库在库内的条数。
//
// 口径说明：
//   - nvd / ghsa 按 source 列（一条 CVE 的记录来源）；
//   - kev 按 kev 标记（KEV 是给别的源打的标，不是独立的记录集合）；
//   - github_poc 按 PoC 条目数；
//   - nuclei_templates 按本地 yaml 文件数（不是数据库行）。
func (s *Server) vulnSourceCount(ctx context.Context, id string) int64 {
	var n int64
	switch id {
	case "nvd":
		_ = s.m.pg.QueryRowContext(ctx, `SELECT count(*) FROM vuln_cves WHERE source='nvd'`).Scan(&n)
	case "kev":
		_ = s.m.pg.QueryRowContext(ctx, `SELECT count(*) FROM vuln_cves WHERE kev`).Scan(&n)
	case "ghsa":
		_ = s.m.pg.QueryRowContext(ctx, `SELECT count(*) FROM vuln_cves WHERE source='ghsa'`).Scan(&n)
	case "github_poc":
		_ = s.m.pg.QueryRowContext(ctx, `SELECT count(*) FROM vuln_poc_entries`).Scan(&n)
	case "nuclei_templates":
		if s.vuln != nil && s.vuln.nucleiDir != "" {
			n = int64(vulnintel.CountTemplates(s.vuln.nucleiDir))
		}
	}
	return n
}

// vulnSourceEnabled 读某一行的启用开关。读不到按 def 处理（新库、旧库升级）。
func (s *Server) vulnSourceEnabled(id string, def bool) bool {
	if s == nil || s.m == nil || s.m.pg == nil {
		return def
	}
	var v bool
	err := s.m.pg.QueryRowContext(context.Background(),
		`SELECT enabled FROM vuln_sources WHERE id=$1`, id).Scan(&v)
	if err != nil {
		return def
	}
	return v
}

// patchVulnSource 改一行的可编辑字段。只接受白名单字段，避免把表当 KV 用。
type patchVulnSource struct {
	Enabled         *bool   `json:"enabled"`
	Endpoint        *string `json:"endpoint"`
	Priority        *int    `json:"priority"`
	SyncMode        *string `json:"sync_mode"`
	IntervalMinutes *int    `json:"interval_minutes"`
	BackfillDays    *int    `json:"backfill_days"`
}

func (s *Server) updateVulnSource(ctx context.Context, id string, p patchVulnSource) error {
	sets := []string{}
	args := []any{}
	add := func(expr string, v any) {
		args = append(args, v)
		sets = append(sets, strings.Replace(expr, "?", fmt.Sprintf("$%d", len(args)), 1))
	}
	if p.Enabled != nil {
		add("enabled = ?", *p.Enabled)
	}
	if p.Endpoint != nil {
		add("endpoint = ?", strings.TrimSpace(*p.Endpoint))
	}
	if p.Priority != nil {
		add("priority = ?", *p.Priority)
	}
	if p.SyncMode != nil {
		m := strings.TrimSpace(*p.SyncMode)
		switch m {
		case "full", "incremental", "manual":
			add("sync_mode = ?", m)
		default:
			return fmt.Errorf("sync_mode 只能是 full / incremental / manual")
		}
	}
	if p.IntervalMinutes != nil {
		m := *p.IntervalMinutes
		if m < 0 {
			m = 0
		}
		add("interval_minutes = ?", m)
	}
	if p.BackfillDays != nil {
		d := *p.BackfillDays
		if d < 0 {
			d = 0
		}
		add("backfill_days = ?", d)
	}
	if len(sets) == 0 {
		return nil
	}
	sets = append(sets, "updated_at = now()")
	args = append(args, id)
	res, err := s.m.pg.ExecContext(ctx,
		`UPDATE vuln_sources SET `+strings.Join(sets, ", ")+` WHERE id = $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("未知的库: %s", id)
	}
	return nil
}
