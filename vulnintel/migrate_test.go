package vulnintel

// 旧库迁移测试：V10 的 vuln_intel / vuln_pocs → V2 的 vuln_cves /
// vuln_cpe_products / vuln_poc_entries。
//
// 重点验证三件事：
//   1. cpe TEXT[] 的 "vendor:product" 片段能还原成倒排行 + 等价 CPE 串；
//   2. 已有新记录不被旧数据覆盖（ON CONFLICT DO NOTHING）；
//   3. 重复执行幂等。

import (
	"testing"
)

func TestMigrateLegacy(t *testing.T) {
	st := testStore(t)
	ctx := t.Context()
	const cveID = "CVE-2017-10271" // WebLogic 反序列化（真实 CVE）

	// 造一条 V10 结构的数据。
	if _, err := st.db.ExecContext(ctx, `INSERT INTO vuln_intel
		(cve_id, source, title, description, severity, cvss, kev, cpe, refs)
		VALUES ($1,'nvd','WebLogic RCE','legacy description','CRITICAL',9.8,true,
		        ARRAY['oracle:weblogic_server'], ARRAY['https://example.com/adv'])
		ON CONFLICT (cve_id) DO NOTHING`, cveID); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.db.Exec(`DELETE FROM vuln_intel WHERE cve_id=$1`, cveID)
		_, _ = st.db.Exec(`DELETE FROM vuln_cves WHERE cve_id=$1`, cveID)
	})
	// 旧表里可能已有脏数据（别的测试留下的），先清掉目标 CVE。
	_, _ = st.db.Exec(`DELETE FROM vuln_cves WHERE cve_id=$1`, cveID)

	res, err := st.MigrateLegacy(ctx)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if res.CVEs == 0 {
		t.Fatalf("迁移应至少读到 1 条旧 CVE，实际 %+v", res)
	}

	var title string
	var kev bool
	if err := st.db.QueryRowContext(ctx,
		`SELECT title, kev FROM vuln_cves WHERE cve_id=$1`, cveID).Scan(&title, &kev); err != nil {
		t.Fatalf("迁移后查不到 %s: %v", cveID, err)
	}
	if title != "WebLogic RCE" || !kev {
		t.Errorf("字段未迁移正确: title=%q kev=%v", title, kev)
	}

	var product string
	if err := st.db.QueryRowContext(ctx,
		`SELECT product FROM vuln_cpe_products WHERE cve_id=$1`, cveID).Scan(&product); err != nil {
		t.Fatalf("倒排行未生成: %v", err)
	}
	if product != "weblogic_server" {
		t.Errorf("product 期望 weblogic_server，实际 %q", product)
	}

	// 用迁移后的数据做一次组件检索：能搜到、但版本判定必须是「无法判断」。
	hits, err := st.SearchVulns(ctx, "", "weblogic_server", "10.3.6.0", 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range hits {
		if h.CVEID == cveID {
			found = true
			if h.VersionInRange != nil {
				t.Errorf("旧数据没有版本区间，判定应为 nil，实际 %v", *h.VersionInRange)
			}
		}
	}
	if !found {
		t.Errorf("迁移后的组件索引应能被 search_vulns 命中")
	}

	// 幂等：再跑一次不应报错、不应重复插入。
	before := countRows(t, st, `SELECT count(*) FROM vuln_cpe_products WHERE cve_id=$1`, cveID)
	if _, err := st.MigrateLegacy(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	after := countRows(t, st, `SELECT count(*) FROM vuln_cpe_products WHERE cve_id=$1`, cveID)
	if before != after {
		t.Errorf("重复迁移产生了重复倒排行: %d → %d", before, after)
	}
}

// TestMigrateLegacyDoesNotOverwrite 验证「新数据不被旧数据降级」。
func TestMigrateLegacyDoesNotOverwrite(t *testing.T) {
	st := testStore(t)
	ctx := t.Context()
	const cveID = "CVE-2099-000003"

	// 新的 V2 记录（带完整区间）
	if err := st.UpsertCVE(ctx, CVE{
		ID: cveID, Title: "new record", Severity: "HIGH",
		Criteria: []string{"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"},
		Ranges:   []CPERange{{Criteria: "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", StartIncluding: "1.0", EndExcluding: "2.0"}},
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.db.Exec(`DELETE FROM vuln_intel WHERE cve_id=$1`, cveID)
		_, _ = st.db.Exec(`DELETE FROM vuln_cves WHERE cve_id=$1`, cveID)
	})
	// 同 ID 的旧记录（无区间、标题不同）
	if _, err := st.db.ExecContext(ctx, `INSERT INTO vuln_intel
		(cve_id, source, title, severity, cvss, cpe, refs)
		VALUES ($1,'nvd','old record','LOW',3.0,ARRAY['acme:widget'],ARRAY[]::text[])
		ON CONFLICT (cve_id) DO UPDATE SET title='old record'`, cveID); err != nil {
		t.Fatal(err)
	}

	if _, err := st.MigrateLegacy(ctx); err != nil {
		t.Fatal(err)
	}
	var title string
	if err := st.db.QueryRowContext(ctx, `SELECT title FROM vuln_cves WHERE cve_id=$1`, cveID).Scan(&title); err != nil {
		t.Fatal(err)
	}
	if title != "new record" {
		t.Errorf("旧数据覆盖了新记录: title=%q", title)
	}
	if !st.HasVersionRange(ctx, cveID) {
		t.Errorf("新记录的版本区间被旧数据覆盖掉了")
	}
}

func countRows(t *testing.T, st *Store, q string, args ...any) int {
	t.Helper()
	var n int
	if err := st.db.QueryRowContext(t.Context(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
