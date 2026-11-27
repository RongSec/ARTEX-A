package vulnintel

// 页面用的查询：关键词检索、资产命中、统计。
//
// 与 agent 的 search_vulns 分工：
//   - search_vulns 按**组件**查（已知「这是 httpd」，问它有哪些漏洞），走倒排表；
//   - 这里的 SearchCVEs 按**关键词**查（人想找 CVE-2024-3094 或「thinkphp」），
//     走 cve_id/title/description 的 ILIKE，带 KEV/CVSS/时间过滤。

import (
	"context"
	"strings"
)

// SearchFilter 是页面的筛选条件。
type SearchFilter struct {
	Query    string
	KEVOnly  bool
	MinCVSS  float64
	Severity string
	Since    string // YYYY-MM-DD
	Limit    int
	Offset   int
}

// CVESummary 是列表行（不含长描述，详情走 GetVuln）。
type CVESummary struct {
	CVEID     string   `json:"cve_id"`
	Title     string   `json:"title"`
	Severity  string   `json:"severity"`
	Score     *float64 `json:"cvss_score,omitempty"`
	KEV       bool     `json:"kev"`
	Published string   `json:"published,omitempty"`
	Source    string   `json:"source,omitempty"`
	PocCount  int      `json:"poc_count"`
}

// SearchCVEs 按关键词 + 过滤条件分页查询。返回当页与总数。
func (s *Store) SearchCVEs(ctx context.Context, f SearchFilter) ([]CVESummary, int, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	where := []string{"1=1"}
	args := []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", "$"+itoa(len(args))))
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		args = append(args, "%"+strings.ToLower(q)+"%")
		n := "$" + itoa(len(args))
		where = append(where, "(lower(cve_id) LIKE "+n+" OR lower(title) LIKE "+n+" OR lower(description) LIKE "+n+")")
	}
	if f.KEVOnly {
		where = append(where, "kev = true")
	}
	if f.MinCVSS > 0 {
		add("cvss_score >= ?", f.MinCVSS)
	}
	if sev := strings.TrimSpace(f.Severity); sev != "" {
		add("upper(severity) = upper(?)", sev)
	}
	if since := strings.TrimSpace(f.Since); since != "" {
		add("published_at >= ?::date", since)
	}
	cond := strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM vuln_cves WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.Limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, `
SELECT c.cve_id, COALESCE(c.title,''), COALESCE(c.severity,''), c.cvss_score, c.kev,
       COALESCE(c.published_at::text,''), COALESCE(c.source,''),
       (SELECT count(*) FROM vuln_poc_entries pe WHERE pe.cve_id=c.cve_id)
FROM vuln_cves c WHERE `+cond+`
ORDER BY c.published_at DESC NULLS LAST, c.kev DESC, c.cvss_score DESC NULLS LAST
LIMIT $`+itoa(len(args)-1)+` OFFSET $`+itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []CVESummary{}
	for rows.Next() {
		var h CVESummary
		if err := rows.Scan(&h.CVEID, &h.Title, &h.Severity, &h.Score, &h.KEV,
			&h.Published, &h.Source, &h.PocCount); err != nil {
			return nil, 0, err
		}
		out = append(out, h)
	}
	return out, total, rows.Err()
}

// AssetHit 是「命中我的资产」的一行：资产 × CVE。
type AssetHit struct {
	AssetID   int64    `json:"asset_id"`
	Asset     string   `json:"asset"`
	CVEID     string   `json:"cve_id"`
	Severity  string   `json:"severity"`
	Score     *float64 `json:"cvss_score,omitempty"`
	KEV       bool     `json:"kev"`
	Product   string   `json:"product"`
	MatchedOn string   `json:"matched_on"` // 命中的技术指纹原文
}

// AssetHits 把 service 资产的 technologies 与组件倒排表求交集。
//
// 与 LinkAssetsToVulns 的区别：那个按「新同步的 CVE」取候选（为了控制联动成本），
// 这里按「资产指纹」取候选（页面上要看到全部命中）。命中判定共用 techTokens/
// cpeTokens 的别名归一，所以两条路的召回一致。
//
// 版本一律标「可能受影响」：资产指纹里的版本号不保证可靠，判定留给任务实测。
func (s *Store) AssetHits(ctx context.Context, minScore float64, kevOnly bool, limit int) ([]AssetHit, error) {
	if limit <= 0 || limit > 2000 {
		limit = 300
	}
	type assetRow struct {
		id    int64
		value string
		techs []string
	}
	// assets 没有统一的 value 列：显示名按 url → domain → ip(+port) 兜底。
	//
	// 端口只在用 ip 时拼：url 里通常已经带了 :8088，无条件追加会变成
	// "http://192.0.2.10:8088:8088"（实测出现过，看着像 bug）。
	rows, err := s.db.QueryContext(ctx, `SELECT id,
		CASE
		  WHEN NULLIF(url,'')  IS NOT NULL THEN url
		  WHEN NULLIF(domain,'') IS NOT NULL THEN domain
		  WHEN NULLIF(ip,'')   IS NOT NULL THEN ip || COALESCE(':'||NULLIF(port,0)::text,'')
		  ELSE 'asset#'||id::text
		END,
		COALESCE(array_to_json(technologies)::text,'[]') FROM assets WHERE type='service'`)
	if err != nil {
		return nil, err
	}
	var assets []assetRow
	for rows.Next() {
		var a assetRow
		var techJSON string
		if err := rows.Scan(&a.id, &a.value, &techJSON); err == nil {
			_ = jsonUnmarshal(techJSON, &a.techs)
			if len(a.techs) > 0 {
				assets = append(assets, a)
			}
		}
	}
	rows.Close()
	if len(assets) == 0 {
		return []AssetHit{}, nil
	}

	// 收集全部 token（含别名展开），一次查库。
	tokenSet := map[string]bool{}
	perAsset := make([][]string, len(assets))
	for i, a := range assets {
		seen := map[string]bool{}
		for _, t := range a.techs {
			for _, tok := range techTokens(t) {
				if !seen[tok] {
					seen[tok] = true
					perAsset[i] = append(perAsset[i], tok)
					tokenSet[tok] = true
				}
			}
		}
	}
	tokens := make([]string, 0, len(tokenSet))
	for t := range tokenSet {
		tokens = append(tokens, t)
	}

	// product 在库里是小写；token 也已小写。= ANY 走 idx_vuln_cpe_product。
	crows, err := s.db.QueryContext(ctx, `
SELECT c.cve_id, COALESCE(c.severity,''), c.cvss_score, c.kev, p.product, p.vendor
FROM vuln_cpe_products p JOIN vuln_cves c ON c.cve_id = p.cve_id
WHERE p.product = ANY($1)`, tokens)
	if err != nil {
		return nil, err
	}
	type hit struct {
		cve, severity, product, vendor string
		score                          *float64
		kev                            bool
	}
	byProduct := map[string][]hit{}
	for crows.Next() {
		var h hit
		if err := crows.Scan(&h.cve, &h.severity, &h.score, &h.kev, &h.product, &h.vendor); err == nil {
			byProduct[h.product] = append(byProduct[h.product], h)
		}
	}
	crows.Close()

	out := []AssetHit{}
	seen := map[string]bool{} // asset|cve 去重（多个 token 命中同一 CVE）
	for i, a := range assets {
		for _, tok := range perAsset[i] {
			for _, h := range byProduct[tok] {
				if kevOnly && !h.kev {
					continue
				}
				if minScore > 0 && (h.score == nil || *h.score < minScore) {
					continue
				}
				key := itoa64(a.id) + "|" + h.cve
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, AssetHit{
					AssetID: a.id, Asset: a.value, CVEID: h.cve, Severity: h.severity,
					Score: h.score, KEV: h.kev, Product: h.product, MatchedOn: tok,
				})
				if len(out) >= limit {
					return out, nil
				}
			}
		}
	}
	return out, nil
}

// Counts 返回库内条数（状态页用）。
func (s *Store) Counts(ctx context.Context) map[string]int64 {
	out := map[string]int64{}
	for k, q := range map[string]string{
		"cves":     `SELECT count(*) FROM vuln_cves`,
		"kev":      `SELECT count(*) FROM vuln_cves WHERE kev`,
		"pocs":     `SELECT count(*) FROM vuln_poc_entries`,
		"ghsa":     `SELECT count(*) FROM vuln_cves WHERE source='ghsa'`,
		"products": `SELECT count(*) FROM vuln_cpe_products`,
	} {
		var n int64
		_ = s.db.QueryRowContext(ctx, q).Scan(&n)
		out[k] = n
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
