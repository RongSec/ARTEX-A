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

// TestSchemaContainsTaskIntel 无库断言 schema.sql 里有表/列/索引（防漏发迁移）。
func TestSchemaContainsTaskIntel(t *testing.T) {
	for _, w := range []string{
		"CREATE TABLE IF NOT EXISTS task_intel",
		"CREATE TABLE IF NOT EXISTS task_intel_links",
		"idx_tintel_match ON task_intel(kind, key)",
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
