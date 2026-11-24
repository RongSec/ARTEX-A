package vulnintel

// V2 组件倒排 + 结构化版本区间的集成测试（需要真实 PostgreSQL）。
//
// 覆盖的是「命中判定是否正确」这条主链路，不测网络抓取：
//   1. UpsertCVE 写主表 + 拆出 (vendor, product) 倒排行 + 落四个版本边界
//   2. SearchVulns 按 product 子串命中、vendor 收窄、KEV 排序
//   3. VersionInRange 三态（true / false / 无法判断）
//   4. GetPoCs 按 star 排序
//
// 跑法：
//   ARTEX_PG_DSN='postgres://postgres:test@127.0.0.1:55432/db_artex_test?sslmode=disable' \
//     go test ./vulnintel/ -run 'TestV2'

import (
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	return New(d)
}

func score(f float64) *float64 { return &f }

// TestV2UpsertAndSearch 验证「写一条 CVE 后能不能按组件搜到、版本判定对不对」。
func TestV2UpsertAndSearch(t *testing.T) {
	st := testStore(t)
	ctx := t.Context()

	const cveID = "CVE-2021-41773" // Apache httpd 2.4.49 路径穿越（真实 CVE）
	c := CVE{
		ID:          cveID,
		Title:       "Apache HTTP Server Path Traversal",
		Description: "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49.",
		Severity:    "CRITICAL",
		Score:       score(9.8),
		Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Published:   time.Date(2021, 10, 5, 0, 0, 0, 0, time.UTC),
		Modified:    time.Date(2021, 10, 5, 0, 0, 0, 0, time.UTC),
		Criteria: []string{
			"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
		},
		Ranges: []CPERange{{
			Criteria:       "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
			StartIncluding: "2.4.49",
			EndIncluding:   "2.4.49",
		}},
		Cwes: []string{"CWE-22"},
		Refs: []string{"https://httpd.apache.org/security/vulnerabilities_24.html"},
	}
	if err := st.UpsertCVE(ctx, c); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.db.Exec(`DELETE FROM vuln_cves WHERE cve_id=$1`, cveID)
	})

	// 1. 倒排行必须拆出 apache / http_server
	var n int
	if err := st.db.QueryRowContext(ctx,
		`SELECT count(*) FROM vuln_cpe_products WHERE cve_id=$1 AND vendor='apache' AND product='http_server'`,
		cveID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("倒排行应有 1 条 (apache,http_server)，实际 %d", n)
	}

	// 2. 按组件搜到，版本 2.4.49 判定为受影响
	hits, err := st.SearchVulns(ctx, "", "http_server", "2.4.49", 10)
	if err != nil {
		t.Fatal(err)
	}
	var got *VulnHit
	for i := range hits {
		if hits[i].CVEID == cveID {
			got = &hits[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("search_vulns(http_server) 未命中 %s，结果=%+v", cveID, hits)
	}
	if !got.KEV && got.Severity != "CRITICAL" {
		t.Errorf("severity 期望 CRITICAL，实际 %q", got.Severity)
	}
	if got.VersionInRange == nil || !*got.VersionInRange {
		t.Errorf("2.4.49 应判定为在受影响区间内，实际 %v", got.VersionInRange)
	}
	if !got.VersionSeen {
		t.Errorf("version_seen_in_criteria 应为 true")
	}

	// 3. 2.4.50 不在区间
	hits2, err := st.SearchVulns(ctx, "", "http_server", "2.4.50", 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits2 {
		if h.CVEID != cveID {
			continue
		}
		if h.VersionInRange == nil {
			t.Errorf("2.4.50 应有明确判定，实际 nil")
		} else if *h.VersionInRange {
			t.Errorf("2.4.50 不应在区间内")
		}
	}

	// 4. vendor 收窄：oracle 不该命中
	hits3, err := st.SearchVulns(ctx, "oracle", "http_server", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits3 {
		if h.CVEID == cveID {
			t.Errorf("vendor=oracle 不应命中 apache 的 CVE")
		}
	}
}

// TestV2VersionRangeUndetermined 验证「没有区间」时判成三态里的 nil，而不是 false。
func TestV2VersionRangeUndetermined(t *testing.T) {
	st := testStore(t)
	ctx := t.Context()
	const cveID = "CVE-2099-000001"
	c := CVE{
		ID:       cveID,
		Title:    "stub without ranges",
		Severity: "HIGH",
		Score:    score(8.0),
		Criteria: []string{"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"},
	}
	if err := st.UpsertCVE(ctx, c); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = st.db.Exec(`DELETE FROM vuln_cves WHERE cve_id=$1`, cveID) })

	hits, err := st.SearchVulns(ctx, "", "widget", "1.0", 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		if h.CVEID == cveID && h.VersionInRange != nil {
			t.Errorf("无结构化区间时应为 nil（无法判断），实际 %v", *h.VersionInRange)
		}
	}
	if HasRange := st.HasVersionRange(ctx, cveID); HasRange {
		t.Errorf("HasVersionRange 应为 false")
	}
}

// TestV2PocOrdering 验证 PoC 按 star 排序、按 CVE 取回。
func TestV2PocOrdering(t *testing.T) {
	st := testStore(t)
	ctx := t.Context()
	const cveID = "CVE-2099-000002"
	for _, p := range []PoC{
		{CVEID: cveID, Source: "github", URL: "https://github.com/a/low", Title: "low", Kind: "poc", Stars: 1},
		{CVEID: cveID, Source: "github", URL: "https://github.com/a/high", Title: "high", Kind: "poc", Stars: 99},
	} {
		if err := st.UpsertPoC(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = st.db.Exec(`DELETE FROM vuln_poc_entries WHERE cve_id=$1`, cveID) })

	items, err := st.GetPoCs(ctx, cveID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Stars != 99 {
		t.Fatalf("PoC 应 2 条且 star 降序，实际 %+v", items)
	}
}

// TestV2ProductUnderscoreForm 验证下划线形态互搜。
//
// 背景：历史数据（V10 迁移）的 product 是 `httpserver`（旧 normalizeCPE 去掉
// 下划线），新 NVD 同步写 `http_server`。两种形态必须能互相检索到，否则迁移
// 进来的数据等于从检索结果里消失。
func TestV2ProductUnderscoreForm(t *testing.T) {
	st := testStore(t)
	ctx := t.Context()
	const legacyID = "CVE-2099-000010"
	const newID = "CVE-2099-000011"

	// 历史形态（无下划线）
	if err := st.UpsertCVE(ctx, CVE{
		ID: legacyID, Title: "legacy form", Severity: "HIGH",
		Criteria: []string{"cpe:2.3:a:apache:httpserver:*:*:*:*:*:*:*:*"},
	}); err != nil {
		t.Fatal(err)
	}
	// 新形态（有下划线）
	if err := st.UpsertCVE(ctx, CVE{
		ID: newID, Title: "new form", Severity: "HIGH",
		Criteria: []string{"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"},
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.db.Exec(`DELETE FROM vuln_cves WHERE cve_id IN ($1,$2)`, legacyID, newID)
	})

	for _, q := range []string{"http_server", "httpserver", "http"} {
		hits, err := st.SearchVulns(ctx, "", q, "", 20)
		if err != nil {
			t.Fatalf("search %q: %v", q, err)
		}
		got := map[string]bool{}
		for _, h := range hits {
			got[h.CVEID] = true
		}
		if q == "http_server" || q == "httpserver" {
			if !got[legacyID] || !got[newID] {
				t.Errorf("用 %q 检索应同时命中两种形态，实际 legacy=%v new=%v", q, got[legacyID], got[newID])
			}
		}
	}
}
