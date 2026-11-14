package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestNormalizeEndpoint 覆盖数字折叠、UUID 折叠、query 去值/排序、方法大小写、
// 省略 scheme、整行请求行与空输入。
func TestNormalizeEndpoint(t *testing.T) {
	cases := []struct {
		name           string
		method, rawurl string
		wantKey        string
		wantValue      string
	}{
		{
			name:   "数字段折叠+query去值",
			method: "POST", rawurl: "https://app.example.com/api/user/123/profile?id=1&x=2",
			wantKey:   "post /api/user/{id}/profile?id&x",
			wantValue: "https://app.example.com/api/user/123/profile?id=1&x=2",
		},
		{
			name:      "UUID段折叠",
			method:    "GET",
			rawurl:    "https://app.example.com/api/orders/550e8400-e29b-41d4-a716-446655440000/items",
			wantKey:   "get /api/orders/{id}/items",
			wantValue: "https://app.example.com/api/orders/550e8400-e29b-41d4-a716-446655440000/items",
		},
		{
			name:   "query参数名排序稳定",
			method: "get", rawurl: "/search?z=9&a=1",
			wantKey:   "get /search?a&z",
			wantValue: "/search?z=9&a=1",
		},
		{
			name:   "方法缺失按GET",
			method: "", rawurl: "/health",
			wantKey:   "get /health",
			wantValue: "/health",
		},
		{
			name:   "省略scheme的裸host",
			method: "GET", rawurl: "app.example.com/api/v1/users",
			wantKey:   "get /api/v1/users",
			wantValue: "app.example.com/api/v1/users",
		},
		{
			name:   "整行请求行",
			method: "", rawurl: "POST /api/login HTTP/1.1",
			wantKey:   "post /api/login",
			wantValue: "POST /api/login HTTP/1.1",
		},
		{name: "空输入", method: "GET", rawurl: "   ", wantKey: "", wantValue: ""},
	}
	for _, c := range cases {
		key, value := NormalizeEndpoint(c.method, c.rawurl)
		if key != c.wantKey || value != c.wantValue {
			t.Errorf("%s: got (%q,%q), want (%q,%q)", c.name, key, value, c.wantKey, c.wantValue)
		}
	}
}

// TestNormalizeComponent 覆盖版本截断、无版本、product 内嵌版本、v 前缀与空输入。
func TestNormalizeComponent(t *testing.T) {
	cases := []struct {
		name               string
		product, version   string
		wantKey, wantValue string
	}{
		{"三段版本截到major.minor", "Apache Tomcat", "9.0.65", "apachetomcat@9.0", "Apache Tomcat 9.0.65"},
		{"无版本记星号", "Redis", "", "redis@*", "Redis"},
		{"内嵌版本拆出", "nginx/1.18.0", "", "nginx@1.18", "nginx/1.18.0"},
		{"大小写与空格归一", "Apache HTTP Server", "2.4.49", "apachehttpserver@2.4", "Apache HTTP Server 2.4.49"},
		{"v前缀与后缀", "PHP", "v7.4.33-ubuntu", "php@7.4", "PHP v7.4.33-ubuntu"},
		{"只有major", "IIS", "10", "iis@10", "IIS 10"},
		{"空输入", "", "", "", ""},
	}
	for _, c := range cases {
		key, value := NormalizeComponent(c.product, c.version)
		if key != c.wantKey || value != c.wantValue {
			t.Errorf("%s: got (%q,%q), want (%q,%q)", c.name, key, value, c.wantKey, c.wantValue)
		}
	}
}

// TestNormalizeCredential 覆盖常规、空 username、kind 大小写、非法 kind、
// 双空、service 为空。
func TestNormalizeCredential(t *testing.T) {
	cases := []struct {
		name                    string
		kind, username, service string
		wantKey, wantValue      string
	}{
		{"常规", "Password", "Admin", "10.0.0.5", "password|admin|10.0.0.5", "password for Admin@10.0.0.5"},
		{"username为空用短横", "token", "", "api.example.com", "token|-|api.example.com", "token for api.example.com"},
		{"service为空", "hash", "root", "", "hash|root|-", "hash for root"},
		{"kind大小写归一", "COOKIE", "Bob", "web-01", "cookie|bob|web-01", "cookie for Bob@web-01"},
		{"非法kind", "passphrase", "root", "h", "", ""},
		{"双空", "password", "", "", "", ""},
		{"空kind", "", "root", "h", "", ""},
	}
	for _, c := range cases {
		key, value := NormalizeCredential(c.kind, c.username, c.service)
		if key != c.wantKey || value != c.wantValue {
			t.Errorf("%s: got (%q,%q), want (%q,%q)", c.name, key, value, c.wantKey, c.wantValue)
		}
	}
}

// TestIntelDeltaSummary 断言信号摘要的稳定格式：固定顺序、只列 >0、全 0 为空。
func TestIntelDeltaSummary(t *testing.T) {
	got := IntelDeltaSummary(12, map[string]int{
		IntelKindCredential: 1, IntelKindEndpoint: 3, IntelKindVuln: 0, IntelKindAsset: 2,
	})
	want := "task#12 新增接口情报 3 条 / 凭据 1 条 / 资产 2 条"
	if got != want {
		t.Fatalf("summary=%q, want %q", got, want)
	}
	if s := IntelDeltaSummary(1, map[string]int{IntelKindEndpoint: 0}); s != "" {
		t.Fatalf("all-zero summary must be empty, got %q", s)
	}
}

// TestIntelMatchKey 守跨任务比对的粗粒度键（V7-LINK2）：endpoint 去方法/query
// 只留路径、component 只留产品名、asset 只留 host、credential 丢 service、
// vuln 不做粗匹配；空输入/未知 kind 一律空串。
func TestIntelMatchKey(t *testing.T) {
	cases := []struct {
		name      string
		kind, key string
		want      string
	}{
		// endpoint：方法、query、末尾斜杠。
		{"endpoint 去方法去query", IntelKindEndpoint, "get /vulnerabilities/sqli/?id", "/vulnerabilities/sqli/"},
		{"endpoint 方法不同不影响", IntelKindEndpoint, "POST /vulnerabilities/sqli/", "/vulnerabilities/sqli/"},
		{"endpoint 无query无尾斜杠", IntelKindEndpoint, "post /api/user/{id}", "/api/user/{id}"},
		{"endpoint 多尾斜杠归一", IntelKindEndpoint, "get /a/b///", "/a/b/"},
		{"endpoint 根路径", IntelKindEndpoint, "get /", "/"},
		{"endpoint 空key", IntelKindEndpoint, "   ", ""},
		// component：版本段差异不断链。
		{"component 去版本", IntelKindComponent, "mariadb@10.1", "mariadb"},
		{"component 多段版本", IntelKindComponent, "postgresql@14.2", "postgresql"},
		{"component 无版本星号", IntelKindComponent, "nginx@*", "nginx"},
		{"component 空key", IntelKindComponent, "", ""},
		// asset：端口差异不断链。
		{"asset 去端口", IntelKindAsset, "127.0.0.1:9081", "127.0.0.1"},
		{"asset 域名带端口", IntelKindAsset, "app.example.com:443", "app.example.com"},
		{"asset 无端口", IntelKindAsset, "10.0.0.8", "10.0.0.8"},
		{"asset 空key", IntelKindAsset, "", ""},
		// credential：丢 service，kind|username 保留。
		{"credential 丢service", IntelKindCredential, "password|admin|10.0.0.5", "password|admin"},
		{"credential 空username", IntelKindCredential, "token|-|api.example.com", "token|-"},
		{"credential 无service段", IntelKindCredential, "hash|root|-", "hash|root"},
		{"credential 空key", IntelKindCredential, "", ""},
		// vuln：不做粗匹配。
		{"vuln 恒空", IntelKindVuln, "sql injection|10.0.0.1", ""},
		{"vuln 空key", IntelKindVuln, "", ""},
		// 边界。
		{"空kind", "", "get /a", ""},
		{"未知kind", "hostname", "x", ""},
	}
	for _, c := range cases {
		if got := IntelMatchKey(c.kind, c.key); got != c.want {
			t.Errorf("%s: IntelMatchKey(%q,%q)=%q, want %q", c.name, c.kind, c.key, got, c.want)
		}
	}
}

// TestSchemaContainsTaskIntel 无库断言 schema.sql 里有表/列/索引（防漏发迁移）。
func TestSchemaContainsTaskIntel(t *testing.T) {
	for _, w := range []string{
		"CREATE TABLE IF NOT EXISTS task_intel",
		"CREATE TABLE IF NOT EXISTS task_intel_links",
		"idx_tintel_match ON task_intel(kind, key)",
		"idx_tintel_matchkey ON task_intel(match_key)",
		"ADD COLUMN IF NOT EXISTS match_key TEXT NOT NULL DEFAULT ''",
		"UPDATE task_intel SET match_key",
		"idx_tintel_task  ON task_intel(task_id)",
		"idx_tintel_proj  ON task_intel(project_id, created_at DESC)",
		"UNIQUE (project_id, task_id, kind, key)",
		"UNIQUE (task_id, related_task_id)",
	} {
		if !strings.Contains(schemaSQL, w) {
			t.Errorf("schema.sql missing %q", w)
		}
	}
}

// intelTestTask 建一个「项目 + 任务」测试夹具，返回 (projectID, taskID)。
func intelTestTask(t *testing.T, d *DB) (int64, int64) {
	t.Helper()
	p, err := d.CreateProject(CreateProjectInput{Name: fmt.Sprintf("intel-test-%d", time.Now().UnixNano())})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM projects WHERE id=$1`, p.ID) })
	task, err := d.CreateTaskWithOptions("intel fixture", "goal", TaskCreateOptions{ProjectID: &p.ID})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	return p.ID, task.ID
}

// TestTaskIntelUpsertIdempotentPG 断言：upsert 幂等（行数不变、created_at 保留）、
// 第二次 inserted=0；IntelSince 水位增量；勾连结果表 upsert。
func TestTaskIntelUpsertIdempotentPG(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()
	pid, tid := intelTestTask(t, d)

	sid := int64(99)
	rows := []TaskIntel{
		{Kind: IntelKindEndpoint, Key: "get /api/user/{id}", Value: "https://h/api/user/7",
			Detail: json.RawMessage(`{"count":2}`), Source: "finding", SourceID: &sid},
		{Kind: IntelKindCredential, Key: "password|admin|10.0.0.5", Value: "password for admin@10.0.0.5",
			Detail: json.RawMessage(`{"secret_masked":"Su****t!"}`), Source: "fact"},
		{Kind: IntelKindComponent, Key: "nginx@1.18", Value: "nginx 1.18.0", Source: "asset"},
	}
	res, err := d.UpsertTaskIntel(ctx, pid, tid, rows)
	if err != nil {
		t.Fatal(err)
	}
	if res.Inserted != len(rows) || res.Total != len(rows) {
		t.Fatalf("first upsert: %+v", res)
	}
	if res.ByKind[IntelKindEndpoint] != 1 {
		t.Fatalf("by kind: %+v", res.ByKind)
	}
	// upsert 必须同步写 match_key（跨任务勾连只按它比对）。
	mks := map[string]string{}
	rowsMK, err := d.QueryContext(ctx, `SELECT kind, match_key FROM task_intel WHERE task_id=$1`, tid)
	if err != nil {
		t.Fatal(err)
	}
	for rowsMK.Next() {
		var kind, mk string
		if err := rowsMK.Scan(&kind, &mk); err != nil {
			rowsMK.Close()
			t.Fatal(err)
		}
		mks[kind] = mk
	}
	rowsMK.Close()
	if mks[IntelKindEndpoint] != "/api/user/{id}" || mks[IntelKindCredential] != "password|admin" || mks[IntelKindComponent] != "nginx" {
		t.Fatalf("upsert 未写 match_key: %+v", mks)
	}

	var firstCreated time.Time
	if err := d.QueryRowContext(ctx, `SELECT created_at FROM task_intel WHERE task_id=$1 AND kind=$2`,
		tid, IntelKindEndpoint).Scan(&firstCreated); err != nil {
		t.Fatal(err)
	}

	res2, err := d.UpsertTaskIntel(ctx, pid, tid, rows)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Inserted != 0 || res2.Updated != len(rows) {
		t.Fatalf("second upsert must be pure update: %+v", res2)
	}
	var n int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM task_intel WHERE task_id=$1`, tid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != len(rows) {
		t.Fatalf("idempotent upsert: rows=%d, want %d", n, len(rows))
	}
	var secondCreated time.Time
	if err := d.QueryRowContext(ctx, `SELECT created_at FROM task_intel WHERE task_id=$1 AND kind=$2`,
		tid, IntelKindEndpoint).Scan(&secondCreated); err != nil {
		t.Fatal(err)
	}
	if !firstCreated.Equal(secondCreated) {
		t.Fatalf("created_at must be preserved: first=%v second=%v", firstCreated, secondCreated)
	}

	list, watermark, err := d.IntelSince(ctx, pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != len(rows) || watermark == 0 {
		t.Fatalf("IntelSince: %d rows, watermark=%d", len(list), watermark)
	}
	if list[0].ID > list[len(list)-1].ID {
		t.Fatal("IntelSince must order by id asc")
	}
	rest, wm2, err := d.IntelSince(ctx, pid, watermark)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 || wm2 != watermark {
		t.Fatalf("after watermark: %d rows, wm=%d want %d", len(rest), wm2, watermark)
	}

	// 勾连结果：同 (task_id, related_task_id) 覆盖决策。
	linkID, err := d.SaveTaskIntelLink(ctx, TaskIntelLink{
		ProjectID: pid, TaskID: tid, RelatedTaskID: tid + 1, Decision: "candidate",
		Reason: "same endpoint", Matched: json.RawMessage(`[{"kind":"endpoint","key":"get /login"}]`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SaveTaskIntelLink(ctx, TaskIntelLink{
		ProjectID: pid, TaskID: tid, RelatedTaskID: tid + 1, Decision: "adopted", Reason: "downgraded check",
	}); err != nil {
		t.Fatal(err)
	}
	links, err := d.ListTaskIntelLinks(ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].ID != linkID || links[0].Decision != "adopted" {
		t.Fatalf("link upsert: %+v", links)
	}
	if _, err := d.SaveTaskIntelLink(ctx, TaskIntelLink{
		ProjectID: pid, TaskID: tid, RelatedTaskID: tid + 2, Decision: "maybe",
	}); err == nil {
		t.Fatal("invalid decision must be rejected")
	}
}

// TestSchemaApplyTwiceIdempotentPG 模拟存量库：在已建库上连续再应用两次
// schema.sql，均须 0 error（启动时每次都会 Exec 一遍，幂等是硬要求）。
func TestSchemaApplyTwiceIdempotentPG(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	for i := 0; i < 2; i++ {
		if _, err := d.Exec(schemaSQL); err != nil {
			t.Fatalf("re-apply schema #%d: %v", i+1, err)
		}
	}
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM information_schema.tables
WHERE table_schema='public' AND table_name IN ('task_intel','task_intel_links')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("task_intel tables: %d, want 2", n)
	}
}

// TestSchemaBackfillsMatchKeyPG 模拟存量库：match_key 尚为空的历史行，在
// schema 迁移里按 kind 回填；连续应用两次 0 error 且结果不变（幂等）。
func TestSchemaBackfillsMatchKeyPG(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	pid, tid := intelTestTask(t, d)

	legacy := []struct{ kind, key, want string }{
		{IntelKindEndpoint, "get /vulnerabilities/sqli/?id", "/vulnerabilities/sqli/"},
		{IntelKindComponent, "mariadb@10.1", "mariadb"},
		{IntelKindAsset, "127.0.0.1:9081", "127.0.0.1"},
		{IntelKindCredential, "password|admin|10.0.0.5:80", "password|admin"},
		{IntelKindVuln, "sql injection|127.0.0.1:80", ""},
	}
	for _, r := range legacy {
		if _, err := d.Exec(`INSERT INTO task_intel(project_id, task_id, kind, key, value, source, match_key)
VALUES ($1,$2,$3,$4,'v','manual','')`, pid, tid, r.kind, r.key); err != nil {
			t.Fatalf("insert legacy %s: %v", r.kind, err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := d.Exec(schemaSQL); err != nil {
			t.Fatalf("re-apply schema #%d: %v", i+1, err)
		}
		got := map[string]string{}
		rows, err := d.Query(`SELECT kind, match_key FROM task_intel WHERE task_id=$1`, tid)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var kind, mk string
			if err := rows.Scan(&kind, &mk); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			got[kind] = mk
		}
		rows.Close()
		for _, r := range legacy {
			if got[r.kind] != r.want {
				t.Fatalf("apply #%d: %s match_key=%q, want %q", i+1, r.kind, got[r.kind], r.want)
			}
		}
	}
}

// TestSchemaFreshDatabaseIdempotentPG 模拟全新库：临时建库后 Open 两次（Open
// 内部即应用 schema），均须成功且表齐全。无 CREATE DATABASE 权限时跳过。
func TestSchemaFreshDatabaseIdempotentPG(t *testing.T) {
	dsn := testDSN(t)
	u, err := url.Parse(dsn)
	if err != nil || u.Path == "" {
		t.Skipf("unparsable dsn — skipping")
	}
	name := fmt.Sprintf("artex_intel_%d", time.Now().UnixNano())
	adminURL := *u
	adminURL.Path = "/postgres"
	admin, err := sql.Open("pgx", adminURL.String())
	if err != nil {
		t.Skipf("admin connect: %v", err)
	}
	defer admin.Close()
	if err := admin.Ping(); err != nil {
		t.Skipf("admin ping: %v", err)
	}
	if _, err := admin.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		t.Skipf("no create-database privilege: %v", err)
	}
	defer admin.Exec(`DROP DATABASE IF EXISTS "` + name + `" WITH (FORCE)`) //nolint:errcheck

	fresh := *u
	fresh.Path = "/" + name
	for i := 0; i < 2; i++ {
		d, err := Open(fresh.String())
		if err != nil {
			t.Fatalf("open fresh db #%d: %v", i+1, err)
		}
		var n int
		if err := d.QueryRow(`SELECT count(*) FROM information_schema.tables
WHERE table_schema='public' AND table_name IN ('task_intel','task_intel_links')`).Scan(&n); err != nil {
			d.Close()
			t.Fatal(err)
		}
		d.Close()
		if n != 2 {
			t.Fatalf("fresh db tables: %d, want 2", n)
		}
	}
}
