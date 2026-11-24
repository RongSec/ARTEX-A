package vulnintel

// 旧库迁移：vuln_intel / vuln_pocs（V10）→ vuln_cves / vuln_cpe_products /
// vuln_poc_entries（V2 组件倒排结构）。
//
// 为什么要迁：V10 的 vuln_intel 用 cpe TEXT[] 存 "vendor:product" 片段，只能
// 做关键词交集、判不了版本；新结构按 (vendor,product) 建倒排行并拆出四个版本
// 边界，「目标 2.4.49 是否受影响」才成为一次数值比较。
//
// 迁移语义：
//   - **只补不覆盖**：vuln_cves 里已有的 CVE（新同步进来的）保持原样，
//     旧数据 ON CONFLICT DO NOTHING。旧表没有版本区间，覆盖会把新数据降级。
//   - **幂等**：反复执行结果一致；调用方用 settings 标记避免每轮启动都扫。
//   - **旧表不删**：回滚依据。读路径全部切新表。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// LegacyMigrateResult 是一次迁移的统计。
type LegacyMigrateResult struct {
	CVEs  int // 旧表读到的 CVE 行数
	Pocs  int // 旧表读到的 PoC 行数
	NewCV int // 实际写入新表的 CVE 行数（冲突不计）
	NewPo int // 实际写入新表的 PoC 行数
}

// MigrateLegacy 把 V10 的两张情报表搬到 V2 结构。best-effort：单行失败跳过
// 并累计错误，不中断整轮——迁不完下次启动继续（幂等）。
func (s *Store) MigrateLegacy(ctx context.Context) (LegacyMigrateResult, error) {
	var res LegacyMigrateResult
	if s == nil || s.db == nil {
		return res, fmt.Errorf("vulnintel: store 未初始化")
	}
	// 旧表不存在（全新部署）直接返回：information_schema 判断比吞错误清晰。
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM information_schema.tables WHERE table_name='vuln_intel')`).Scan(&exists); err != nil {
		return res, fmt.Errorf("检查旧表: %w", err)
	}
	if !exists {
		return res, nil
	}

	rows, err := s.db.QueryContext(ctx, `SELECT cve_id, COALESCE(source,'nvd'), COALESCE(title,''),
		COALESCE(description,''), COALESCE(severity,'UNKNOWN'), cvss,
		published_at, modified_at, kev, kev_due,
		COALESCE(array_to_json(cpe)::text,'[]'), COALESCE(array_to_json(refs)::text,'[]')
		FROM vuln_intel`)
	if err != nil {
		return res, fmt.Errorf("读旧 CVE 表: %w", err)
	}
	type legacyRow struct {
		id, source, title, desc, severity string
		score                            float64
		published, modified, kevDue      *time.Time
		kev                              bool
		cpeJSON, refsJSON                string
	}
	var legacy []legacyRow
	for rows.Next() {
		var r legacyRow
		if err := rows.Scan(&r.id, &r.source, &r.title, &r.desc, &r.severity, &r.score,
			&r.published, &r.modified, &r.kev, &r.kevDue, &r.cpeJSON, &r.refsJSON); err != nil {
			continue
		}
		legacy = append(legacy, r)
	}
	rows.Close()
	res.CVEs = len(legacy)

	for _, r := range legacy {
		if ctx.Err() != nil {
			break
		}
		criteria, pairs := legacyCPEToCriteria(r.cpeJSON)
		var score any
		if r.score > 0 {
			score = r.score
		}
		tag, err := s.db.ExecContext(ctx, `INSERT INTO vuln_cves
			(cve_id, source, title, description, severity, cvss_score, published_at, modified_at,
			 cpe_criteria, refs, kev, kev_date_added, synced_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11,$12,now())
			ON CONFLICT (cve_id) DO NOTHING`,
			strings.ToUpper(strings.TrimSpace(r.id)), r.source, r.title, r.desc, r.severity, score,
			r.published, r.modified, marshalJSONB(criteria), r.refsJSON, r.kev, r.kevDue)
		if err != nil {
			continue
		}
		if n, _ := tag.RowsAffected(); n > 0 {
			res.NewCV++
		}
		// 倒排行独立写：INSERT DO NOTHING，冲突不影响主行。
		for _, p := range pairs {
			_, _ = s.db.ExecContext(ctx, `INSERT INTO vuln_cpe_products (cve_id, vendor, product)
				VALUES ($1,$2,$3) ON CONFLICT (cve_id, vendor, product) DO NOTHING`,
				strings.ToUpper(strings.TrimSpace(r.id)), p[0], p[1])
		}
	}

	// PoC：旧表主键 (cve_id, repo)，新表 (source, url)。url 为空时用 repo 名
	// 拼一个 GitHub 地址，避免空 url 撞主键。
	var pocExists bool
	_ = s.db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM information_schema.tables WHERE table_name='vuln_pocs')`).Scan(&pocExists)
	if pocExists {
		prows, err := s.db.QueryContext(ctx, `SELECT cve_id, repo, COALESCE(url,''),
			COALESCE(description,''), COALESCE(stars,0) FROM vuln_pocs`)
		if err == nil {
			type oldPoc struct {
				cve, repo, url, desc string
				stars                int
			}
			var pocs []oldPoc
			for prows.Next() {
				var p oldPoc
				if err := prows.Scan(&p.cve, &p.repo, &p.url, &p.desc, &p.stars); err == nil {
					pocs = append(pocs, p)
				}
			}
			prows.Close()
			res.Pocs = len(pocs)
			for _, p := range pocs {
				if ctx.Err() != nil {
					break
				}
				u := strings.TrimSpace(p.url)
				if u == "" {
					u = "https://github.com/" + p.repo
				}
				title := strings.TrimSpace(p.desc)
				if title == "" {
					title = p.repo
				}
				tag, err := s.db.ExecContext(ctx, `INSERT INTO vuln_poc_entries
					(cve_id, source, url, title, kind, stars, synced_at)
					VALUES ($1,'github',$2,$3,'poc',$4,now())
					ON CONFLICT (source, url) DO NOTHING`,
					strings.ToUpper(strings.TrimSpace(p.cve)), u, title, p.stars)
				if err != nil {
					continue
				}
				if n, _ := tag.RowsAffected(); n > 0 {
					res.NewPo++
				}
			}
		}
	}
	return res, nil
}

// legacyCPEToCriteria 把 V10 的 "vendor:product" 片段还原成 CPE 2.3 字符串，
// 同时返回倒排用的 (vendor, product)。
//
// 还原的意义：get_vuln 要回显 cpe_criteria 给模型看版本语法；老记录没有区间，
// 只能给一个 version=* 的等价串（语义正确：版本未知）。
func legacyCPEToCriteria(cpeJSON string) (criteria []string, pairs [][2]string) {
	var items []string
	if err := jsonUnmarshal(cpeJSON, &items); err != nil {
		return nil, nil
	}
	seen := map[string]bool{}
	for _, it := range items {
		vendor, product, ok := strings.Cut(strings.TrimSpace(it), ":")
		if !ok || vendor == "" || product == "" {
			continue
		}
		key := vendor + "\x00" + product
		if seen[key] {
			continue
		}
		seen[key] = true
		pairs = append(pairs, [2]string{vendor, product})
		criteria = append(criteria, "cpe:2.3:a:"+vendor+":"+product+":*:*:*:*:*:*:*:*")
	}
	return criteria, pairs
}

// jsonUnmarshal 是 encoding/json 的一层薄封装，避免 migrate 文件再引一个包名
// 与 db 包里的同名 helper 冲突。
func jsonUnmarshal(raw string, out any) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("empty")
	}
	return json.Unmarshal([]byte(raw), out)
}
