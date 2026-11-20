package db

// 路径模糊匹配与命中打分（V11-READER3）。
//
// 为什么需要：精确 match_key 只认「归一化后完全相等」。实测里同一套系统的
// /api/user/list 与 /api/user/info、/api/v1/user 与 /api/user 都不命中，阅读者
// 因此看不到本该是最相关的候选。
//
// 口径（用户认可）：
//   - 精确命中 1.0；
//   - 同 controller（前两段相同）至少 0.65；
//   - 段级 Jaccard 打底，上限 0.95（完全相等才给 1.0）；
//   - 单条模糊只到 weak，不进候选；两条模糊才够 medium。
//
// 模糊比对只在 endpoint 上做：组件/凭据/资产的 key 短，段级相似度没有意义，
// 它们是精确键（IntelMatchKey 已做粗化）。

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"strings"
)

// 单条命中的分值。聚合规则见 server 侧 aggregateReaderLinkCandidates：
// Σ≥2.0 strong / Σ≥1.0 medium / Σ>0 weak（weak 不进候选）。
const (
	EndpointExactScore = 1.0
	EndpointFuzzyScore = 0.6
	CredentialScore    = 1.2 // 可复用登录态，单条即可进候选
	AssetScore         = 0.8
	ComponentScore     = 0.3 // 仅旁证，单独命中不进候选
)

var (
	rePathParamSeg = regexp.MustCompile(`^(\{[^}]*\}|:[A-Za-z_][A-Za-z0-9_]*|\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`)
	rePathVersion  = regexp.MustCompile(`^v\d+$`)
)

// normalizePathForFuzzy 只做「比对用」的归一化：小写、去 query、去 fragment、
// 合并连续斜杠。不做 {id} 折叠——折叠在 pathSegments 里按段丢弃，避免
// "/api/user/123" 与 "/api/user" 因为折叠方式不同而不等。
func normalizePathForFuzzy(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if i := strings.IndexByte(p, ' '); i > 0 && !strings.HasPrefix(p, "/") {
		p = strings.TrimSpace(p[i+1:]) // "GET /path" 形态
	}
	p = strings.ToLower(p)
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if p != "/" {
		p = strings.TrimRight(p, "/")
	}
	return p
}

// pathSegments 把路径拆成有语义的段，丢掉参数占位段与版本段：
//
//	/api/user/{id}/detail → ["api","user","detail"]
//	/API/v1/user/123      → ["api","user"]
func pathSegments(p string) []string {
	out := []string{}
	for _, seg := range strings.Split(p, "/") {
		seg = strings.TrimSpace(seg)
		if seg == "" || rePathParamSeg.MatchString(seg) || rePathVersion.MatchString(seg) {
			continue
		}
		out = append(out, seg)
	}
	return out
}

// FuzzyPathScore 返回两条路径的相似度（0..1）。1.0 仅在归一化后完全相等时出现。
func FuzzyPathScore(a, b string) float64 {
	pa, pb := normalizePathForFuzzy(a), normalizePathForFuzzy(b)
	if pa == "" || pb == "" {
		return 0
	}
	if pa == pb {
		return 1
	}
	sa, sb := pathSegments(pa), pathSegments(pb)
	if len(sa) == 0 || len(sb) == 0 {
		return 0
	}
	// 段序列相同 = 同一路径模板：/api/user/{id} 与 /api/user/123 归一化后
	// 段都是 ["api","user"]，语义上就是同一个接口，给满分而不是 0.95。
	if len(sa) == len(sb) && segEqual(sa, sb) {
		return 1
	}
	// 前缀关系：/api/user 与 /api/user/list —— 父子资源，测法大体同构。
	if segPrefix(sa, sb) || segPrefix(sb, sa) {
		return 0.75
	}
	setA := make(map[string]bool, len(sa))
	for _, s := range sa {
		setA[s] = true
	}
	setB := make(map[string]bool, len(sb))
	for _, s := range sb {
		setB[s] = true
	}
	inter := 0
	for s := range setA {
		if setB[s] {
			inter++
		}
	}
	union := len(setA) + len(setB) - inter
	if union == 0 {
		return 0
	}
	score := float64(inter) / float64(union)
	// 同 controller：前两段相同。实测 /api/user/list 与 /api/user/info 的
	// Jaccard 只有 0.5，但它们是同一套接口的两种动作，测法同构，必须命中。
	common := 0
	for i := 0; i < len(sa) && i < len(sb); i++ {
		if sa[i] != sb[i] {
			break
		}
		common++
	}
	if common >= 2 && score < 0.65 {
		score = 0.65
	}
	if score > 0.95 {
		score = 0.95 // 非完全相等不给满分
	}
	return score
}

func segPrefix(a, b []string) bool {
	if len(a) == 0 || len(a) >= len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func segEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// EndpointHitScore 返回一条精确匹配的分值。
func EndpointHitScore(kind string) float64 {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case IntelKindEndpoint:
		return EndpointExactScore
	case IntelKindCredential:
		return CredentialScore
	case IntelKindAsset:
		return AssetScore
	case IntelKindComponent:
		return ComponentScore
	}
	return 0
}

// MatchStrengthOf 把累计分映射成档位：strong ≥2.0 / medium ≥1.0 / weak >0。
func MatchStrengthOf(score float64) string {
	switch {
	case score >= 2.0:
		return "strong"
	case score >= 1.0:
		return "medium"
	case score > 0:
		return "weak"
	}
	return ""
}

// pathPrefixOf 取路径的前 n 个非空段拼回前缀，用于 SQL LIKE 粗筛。
func pathPrefixOf(p string, n int) string {
	parts := []string{}
	for _, seg := range strings.Split(normalizePathForFuzzy(p), "/") {
		if strings.TrimSpace(seg) == "" {
			continue
		}
		parts = append(parts, seg)
		if len(parts) >= n {
			break
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "/" + strings.Join(parts, "/") + "%"
}

// MatchTaskIntelFuzzy 在 endpoint 上做模糊补漏：SQL 按路径前缀粗筛（避免全表
// 拉回），Go 侧算 FuzzyPathScore。分数 ≥ minScore 才返回。
//
// 与 MatchTaskIntel（精确 match_key JOIN）互补：调用方按 (task_id,kind,key)
// 合并去重，保留较高分。scope 语义与 MatchTaskIntel 一致。
func (d *DB) MatchTaskIntelFuzzy(ctx context.Context, projectID int64, keys []IntelKeyRef, excludeTaskID int64, cross bool, minScore float64) ([]IntelTaskMatch, error) {
	if projectID <= 0 || len(keys) == 0 {
		return nil, nil
	}
	if minScore <= 0 {
		minScore = 0.6
	}
	type qPath struct{ path string }
	var queries []qPath
	prefixSet := map[string]bool{}
	for _, k := range keys {
		if strings.ToLower(strings.TrimSpace(k.Kind)) != IntelKindEndpoint {
			continue
		}
		p := normalizePathForFuzzy(IntelMatchKey(k.Kind, k.Key))
		if p == "" {
			continue
		}
		queries = append(queries, qPath{path: p})
		// 粗筛取前两段：/api/user/list → /api/user%。只取一段太宽（/api%），
		// 取三段会漏掉 /api/user 与 /api/user/list 这种父子关系。
		if pre := pathPrefixOf(p, 2); pre != "" && pre != "/%" {
			prefixSet[pre] = true
		}
	}
	if len(queries) == 0 || len(prefixSet) == 0 {
		return nil, nil
	}

	args := []any{excludeTaskID, projectID}
	var scope string
	if cross {
		scope = `ti.project_id <> $2 AND ti.project_id IN (
SELECT id FROM projects WHERE reader_enabled = TRUE AND status = 'active')`
	} else {
		scope = "ti.project_id = $2"
	}
	conds := make([]string, 0, len(prefixSet))
	for pre := range prefixSet {
		args = append(args, pre)
		conds = append(conds, "ti.match_key LIKE $"+itoa(int64(len(args))))
	}
	q := `SELECT ti.id, ti.project_id, ti.task_id, ti.kind, ti.key, ti.match_key, ti.value, ti.detail,
       ti.source, ti.source_id, ti.rev, ti.created_at, ti.updated_at,
       COALESCE(t.name, ''),
       (SELECT COUNT(*) FROM findings f WHERE f.task_id = ti.task_id),
       (SELECT COUNT(*) FROM exploration_nodes en
          WHERE en.exploration_id = t.exploration_id AND en.kind = 'intent')
FROM task_intel ti
JOIN tasks t ON t.id = ti.task_id AND t.deleted_at IS NULL
WHERE ti.task_id <> $1 AND ` + scope + ` AND ti.kind = 'endpoint'
  AND (` + strings.Join(conds, " OR ") + `)
LIMIT 3000`

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
			&m.Source, &sourceID, &m.Rev, &m.CreatedAt, &m.UpdatedAt,
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
		best := 0.0
		for _, qp := range queries {
			if s := FuzzyPathScore(qp.path, m.MatchKey); s > best {
				best = s
			}
		}
		if best < minScore {
			continue
		}
		m.MatchScore = best
		if best >= 0.999 {
			m.MatchKind = "exact"
		} else {
			m.MatchKind = "fuzzy"
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
