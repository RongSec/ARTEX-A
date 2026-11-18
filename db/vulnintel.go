package db

// 漏洞情报的存储层：NVD / CISA KEV 拉下来的条目入库与检索。
//
// 数据边界：这里只存公开源（NVD API 2.0、CISA KEV JSON）的条目。PoC 链接只保留
// NVD 自己给出的参考 URL——平台不抓取、不托管任何私有 PoC 仓库。情报只是「候选」，
// 能不能利用必须由 agent 在授权目标上实测确认。

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// VulnIntelEntry 是一行情报。CPE 存归一后的 "vendor:product" 片段，
// 用于把资产的技术指纹（assets.technologies）反查到候选 CVE。
type VulnIntelEntry struct {
	CVEID       string    `json:"cve_id"`
	Source      string    `json:"source"` // nvd | kev
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CVSS        float64   `json:"cvss"`
	PublishedAt time.Time `json:"published_at,omitempty"`
	ModifiedAt  time.Time `json:"modified_at,omitempty"`
	KEV         bool      `json:"kev"`
	KEVDue      string    `json:"kev_due,omitempty"`
	Ransomware  bool      `json:"ransomware,omitempty"`
	CPE         []string  `json:"cpe,omitempty"`
	Refs        []string  `json:"refs,omitempty"`
	// PocCount 是 GitHub 公开仓库线索数（V10-POC）。0 有两种含义：没查过、查过没结果；
	// 需要区分时看 poc_checked_at（只在库里，不下发）。
	PocCount int `json:"poc_count"`
}

// VulnIntelSearch 是检索条件。全部字段可选，零值=不过滤。
type VulnIntelSearch struct {
	Query    string  // 标题/描述/编号模糊匹配
	KEVOnly  bool    // 只看在野利用
	MinCVSS  float64 // CVSS 下限
	Severity string  // CRITICAL/HIGH/...
	Since    string  // 发布时间下限（YYYY-MM-DD）
	Limit    int
	Offset   int
}

// textArrayLiteral 把 []string 编成 PG 数组字面量（`{"a","b"}`），配合
// `$n::text[]` 使用。驱动是 pgx stdlib，直接传 []string 不会被当成 text[]，
// 又不想为这一处引入 lib/pq，所以自己转义。
func textArrayLiteral(items []string) string {
	if len(items) == 0 {
		return "{}"
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, item := range items {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('"')
		for _, r := range item {
			if r == '"' || r == '\\' {
				sb.WriteByte('\\')
			}
			sb.WriteRune(r)
		}
		sb.WriteByte('"')
	}
	sb.WriteByte('}')
	return sb.String()
}

// UpsertVulnIntel 批量写入（cve_id 冲突则更新可变字段），返回写入条数。
// 每 120 行拼一条多值 INSERT：逐行往返在「120 天回填」这个量级上太慢。
func (d *DB) UpsertVulnIntel(ctx context.Context, entries []VulnIntelEntry) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}
	const batch = 120
	const ncol = 13
	written := 0
	for start := 0; start < len(entries); start += batch {
		end := start + batch
		if end > len(entries) {
			end = len(entries)
		}
		chunk := entries[start:end]
		var sb strings.Builder
		sb.WriteString(`INSERT INTO vuln_intel
(cve_id, source, title, description, severity, cvss, published_at, modified_at, kev, kev_due, ransomware, cpe, refs)
VALUES `)
		args := make([]any, 0, len(chunk)*ncol)
		for i, e := range chunk {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteByte('(')
			for j := 1; j <= ncol; j++ {
				if j > 1 {
					sb.WriteByte(',')
				}
				sb.WriteByte('$')
				sb.WriteString(itoa(int64(i*ncol + j)))
				if j == 12 || j == 13 {
					sb.WriteString("::text[]")
				}
			}
			sb.WriteByte(')')
			var published, modified, due any
			if !e.PublishedAt.IsZero() {
				published = e.PublishedAt
			}
			if !e.ModifiedAt.IsZero() {
				modified = e.ModifiedAt
			}
			if e.KEVDue != "" {
				due = e.KEVDue
			}
			args = append(args,
				e.CVEID, e.Source, e.Title, e.Description, e.Severity, e.CVSS,
				published, modified, e.KEV, due, e.Ransomware,
				textArrayLiteral(e.CPE), textArrayLiteral(e.Refs))
		}
		sb.WriteString(` ON CONFLICT (cve_id) DO UPDATE SET
source=EXCLUDED.source,
title=CASE WHEN EXCLUDED.title<>'' THEN EXCLUDED.title ELSE vuln_intel.title END,
description=CASE WHEN EXCLUDED.description<>'' THEN EXCLUDED.description ELSE vuln_intel.description END,
severity=CASE WHEN EXCLUDED.severity<>'' THEN EXCLUDED.severity ELSE vuln_intel.severity END,
cvss=GREATEST(vuln_intel.cvss, EXCLUDED.cvss),
published_at=COALESCE(EXCLUDED.published_at, vuln_intel.published_at),
modified_at=COALESCE(EXCLUDED.modified_at, vuln_intel.modified_at),
kev=vuln_intel.kev OR EXCLUDED.kev,
kev_due=COALESCE(EXCLUDED.kev_due, vuln_intel.kev_due),
ransomware=vuln_intel.ransomware OR EXCLUDED.ransomware,
cpe=CASE WHEN cardinality(EXCLUDED.cpe)>0 THEN EXCLUDED.cpe ELSE vuln_intel.cpe END,
refs=CASE WHEN cardinality(EXCLUDED.refs)>0 THEN EXCLUDED.refs ELSE vuln_intel.refs END,
updated_at=now()`)
		if _, err := d.ExecContext(ctx, sb.String(), args...); err != nil {
			return written, err
		}
		written += len(chunk)
	}
	return written, nil
}

// vulnIntelCols 与 scanVulnIntel 一一对应。数组列用 array_to_json 转成 JSON 文本，
// 避免依赖驱动的 text[] 扫描行为。
const vulnIntelCols = `cve_id, source, title, description, severity, cvss,
COALESCE(published_at, 'epoch'::timestamptz), COALESCE(modified_at, 'epoch'::timestamptz),
kev, COALESCE(to_char(kev_due,'YYYY-MM-DD'), ''), ransomware,
array_to_json(cpe)::text, array_to_json(refs)::text, poc_count`

func scanVulnIntel(sc interface{ Scan(...any) error }) (*VulnIntelEntry, error) {
	var e VulnIntelEntry
	var cpeJSON, refsJSON string
	if err := sc.Scan(&e.CVEID, &e.Source, &e.Title, &e.Description, &e.Severity, &e.CVSS,
		&e.PublishedAt, &e.ModifiedAt, &e.KEV, &e.KEVDue, &e.Ransomware, &cpeJSON, &refsJSON, &e.PocCount); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(cpeJSON), &e.CPE)
	_ = json.Unmarshal([]byte(refsJSON), &e.Refs)
	return &e, nil
}

// SearchVulnIntel 返回一页条目与总数（总数用于前端分页）。
func (d *DB) SearchVulnIntel(ctx context.Context, q VulnIntelSearch) ([]*VulnIntelEntry, int, error) {
	var where []string
	var args []any
	add := func(cond string, val any) {
		args = append(args, val)
		where = append(where, strings.Replace(cond, "?", "$"+itoa(int64(len(args))), 1))
	}
	if s := strings.TrimSpace(q.Query); s != "" {
		args = append(args, "%"+s+"%")
		idx := "$" + itoa(int64(len(args)))
		where = append(where, "(cve_id ILIKE "+idx+" OR title ILIKE "+idx+" OR description ILIKE "+idx+")")
	}
	if q.KEVOnly {
		where = append(where, "kev")
	}
	if q.MinCVSS > 0 {
		add("cvss >= ?", q.MinCVSS)
	}
	if s := strings.TrimSpace(q.Severity); s != "" {
		add("upper(severity) = ?", strings.ToUpper(s))
	}
	if s := strings.TrimSpace(q.Since); s != "" {
		add("published_at >= ?::date", s)
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM vuln_intel`+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	pageArgs := append(append([]any{}, args...), limit, q.Offset)
	rows, err := d.QueryContext(ctx, `SELECT `+vulnIntelCols+` FROM vuln_intel`+cond+
		` ORDER BY kev DESC, cvss DESC, published_at DESC NULLS LAST LIMIT $`+itoa(int64(len(args)+1))+
		` OFFSET $`+itoa(int64(len(args)+2)), pageArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]*VulnIntelEntry, 0, limit)
	for rows.Next() {
		e, err := scanVulnIntel(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// VulnIntelStats 是状态卡用的聚合。
type VulnIntelStats struct {
	Total     int64 `json:"total"`
	KEV       int64 `json:"kev"`
	Critical  int64 `json:"critical"`
	Last7Days int64 `json:"last_7_days"`
}

func (d *DB) VulnIntelStats(ctx context.Context) (VulnIntelStats, error) {
	var s VulnIntelStats
	err := d.QueryRowContext(ctx, `SELECT count(*),
count(*) FILTER (WHERE kev),
count(*) FILTER (WHERE cvss >= 9),
count(*) FILTER (WHERE published_at >= now() - interval '7 days')
FROM vuln_intel`).Scan(&s.Total, &s.KEV, &s.Critical, &s.Last7Days)
	return s, err
}

// AssetVulnHit 是「资产技术指纹命中的候选 CVE」。version_in_range 三态：
// yes=版本明确落在受影响区间；no=明确不在；unknown=缺少版本信息（我们只采到
// 组件名时一律 unknown，禁止据此直接判定可利用）。
type AssetVulnHit struct {
	CVEID          string    `json:"cve_id"`
	Title          string    `json:"title"`
	Severity       string    `json:"severity"`
	CVSS           float64   `json:"cvss"`
	KEV            bool      `json:"kev"`
	PublishedAt    time.Time `json:"published_at,omitempty"`
	Technology     string    `json:"technology"`
	Host           string    `json:"host"`
	AssetID        int64     `json:"asset_id"`
	VersionInRange string    `json:"version_in_range"`
}

// VulnIntelAssetHits 把 assets.technologies 的每个技术名归一成 CPE product，
// 与 vuln_intel.cpe 求交集，只保留 CVSS>=7 或在 KEV 的条目。只做候选匹配，
// 不做版本判定（见 AssetVulnHit 注释）。
func (d *DB) VulnIntelAssetHits(ctx context.Context, limit int) ([]AssetVulnHit, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := d.QueryContext(ctx, `
WITH tech AS (
  SELECT a.id AS asset_id,
         COALESCE(NULLIF(a.domain,''), NULLIF(a.ip,''), NULLIF(a.url,''), a.app_name, '') AS host,
         t.tech AS raw,
         lower(regexp_replace(t.tech, '[^a-zA-Z0-9]+', '', 'g')) AS prod
  FROM assets a
  CROSS JOIN LATERAL unnest(a.technologies) AS t(tech)
  WHERE a.technologies IS NOT NULL AND cardinality(a.technologies) > 0
)
SELECT DISTINCT ON (t.asset_id, v.cve_id)
       v.cve_id, v.title, v.severity, v.cvss, v.kev,
       COALESCE(v.published_at, 'epoch'::timestamptz),
       t.raw, t.host, t.asset_id
FROM tech t
JOIN vuln_intel v ON EXISTS (
  SELECT 1 FROM unnest(v.cpe) AS c
  WHERE split_part(c, ':', 2) = t.prod
)
WHERE v.cvss >= 7 OR v.kev
ORDER BY t.asset_id, v.cve_id, v.cvss DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AssetVulnHit, 0, limit)
	for rows.Next() {
		var h AssetVulnHit
		if err := rows.Scan(&h.CVEID, &h.Title, &h.Severity, &h.CVSS, &h.KEV,
			&h.PublishedAt, &h.Technology, &h.Host, &h.AssetID); err != nil {
			return nil, err
		}
		h.VersionInRange = "unknown"
		out = append(out, h)
	}
	return out, rows.Err()
}
