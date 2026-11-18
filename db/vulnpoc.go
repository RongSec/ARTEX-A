package db

// GitHub PoC 聚合的存储层（V10-POC）。
//
// 数据边界与漏洞情报一致：只存「公开仓库的元数据」（repo 名、URL、star、描述），
// 不克隆、不缓存、不托管任何 PoC 代码。命中的仓库是把 CVE 编号当作关键词在
// GitHub 公开搜索里查到的，属于线索，不是可利用性结论。

import (
	"context"
	"time"
)

// VulnPoc 是一条 PoC 线索：某个公开仓库声称针对某个 CVE。
type VulnPoc struct {
	CVEID       string    `json:"cve_id"`
	Repo        string    `json:"repo"` // owner/name
	URL         string    `json:"url"`
	Description string    `json:"description"`
	Stars       int       `json:"stars"`
	Lang        string    `json:"lang"`
	PushedAt    time.Time `json:"pushed_at,omitempty"`
}

// VulnPocStats 是页面状态卡用的汇总。
type VulnPocStats struct {
	Repos int `json:"repos"` // 线索总条数（cve×repo）
	CVEs  int `json:"cves"`  // 已有 PoC 线索的 CVE 数
	Queue int `json:"queue"` // 待聚合的高危 CVE 数
}

// VulnPocQueue 取「还没查过 PoC」的高价值 CVE：KEV 优先、CVSS 高的优先、新的优先。
// 只查 poc_checked_at IS NULL 的——查过但没结果的也标时间，否则每轮都重复查同一批，
// 白烧 GitHub 配额。
func (d *DB) VulnPocQueue(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := d.QueryContext(ctx, `
SELECT cve_id FROM vuln_intel
WHERE poc_checked_at IS NULL
  AND (kev OR cvss >= 9)
ORDER BY kev DESC, cvss DESC, published_at DESC NULLS LAST
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// UpsertVulnPocs 用本次搜索结果整体替换某个 CVE 的线索，并记下「查过了」。
// 整体替换而不是累加：仓库被删/改名后旧链接会失效，留着只会误导。
func (d *DB) UpsertVulnPocs(ctx context.Context, cveID string, pocs []VulnPoc) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_pocs WHERE cve_id=$1`, cveID); err != nil {
		return err
	}
	for _, p := range pocs {
		if p.Repo == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO vuln_pocs(cve_id, repo, url, description, stars, lang, pushed_at)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (cve_id, repo) DO UPDATE SET
  url=EXCLUDED.url, description=EXCLUDED.description, stars=EXCLUDED.stars,
  lang=EXCLUDED.lang, pushed_at=EXCLUDED.pushed_at, created_at=now()`,
			cveID, p.Repo, p.URL, p.Description, p.Stars, p.Lang, nullableTime(p.PushedAt)); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE vuln_intel SET poc_count=$2, poc_checked_at=now(), updated_at=now() WHERE cve_id=$1`,
		cveID, len(pocs)); err != nil {
		return err
	}
	return tx.Commit()
}

// ListVulnPocs 取某个 CVE 的线索，star 高的在前。
func (d *DB) ListVulnPocs(ctx context.Context, cveID string) ([]VulnPoc, error) {
	rows, err := d.QueryContext(ctx, `
SELECT cve_id, repo, url, description, stars, lang, coalesce(pushed_at, to_timestamp(0))
FROM vuln_pocs WHERE cve_id=$1 ORDER BY stars DESC, repo LIMIT 20`, cveID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VulnPoc{}
	for rows.Next() {
		var p VulnPoc
		if err := rows.Scan(&p.CVEID, &p.Repo, &p.URL, &p.Description, &p.Stars, &p.Lang, &p.PushedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// VulnPocStats 汇总线索数、覆盖的 CVE 数与待查队列长度。
func (d *DB) VulnPocStats(ctx context.Context) (VulnPocStats, error) {
	var s VulnPocStats
	if err := d.QueryRowContext(ctx, `
SELECT (SELECT count(*) FROM vuln_pocs),
       (SELECT count(DISTINCT cve_id) FROM vuln_pocs),
       (SELECT count(*) FROM vuln_intel WHERE poc_checked_at IS NULL AND (kev OR cvss >= 9))`,
	).Scan(&s.Repos, &s.CVEs, &s.Queue); err != nil {
		return s, err
	}
	return s, nil
}

// PoCByCVE 批量取多个 CVE 的线索（每条最多 topN），给 search_vulns 工具用。
func (d *DB) PoCByCVE(ctx context.Context, cveIDs []string, topN int) (map[string][]VulnPoc, error) {
	if len(cveIDs) == 0 {
		return map[string][]VulnPoc{}, nil
	}
	rows, err := d.QueryContext(ctx, `
SELECT cve_id, repo, url, description, stars, lang, coalesce(pushed_at, to_timestamp(0))
FROM (
  SELECT *, row_number() OVER (PARTITION BY cve_id ORDER BY stars DESC, repo) AS rn
  FROM vuln_pocs WHERE cve_id = ANY($1::text[])
) t WHERE rn <= $2`, textArrayLiteral(cveIDs), topN)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]VulnPoc{}
	for rows.Next() {
		var p VulnPoc
		if err := rows.Scan(&p.CVEID, &p.Repo, &p.URL, &p.Description, &p.Stars, &p.Lang, &p.PushedAt); err != nil {
			return nil, err
		}
		out[p.CVEID] = append(out[p.CVEID], p)
	}
	return out, rows.Err()
}

// nullableTime 把零值时间写成 NULL，避免 0001-01-01 污染 pushed_at。
func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
