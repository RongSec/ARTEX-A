package db

// T09 纯逻辑单测（无库可跑）：投影过滤条件/数组字面量/资产键归一化/ILIKE
// 转义/摘要提取等纯函数的行为钉死。DDL 建表本身的验证靠既有惯例——起服务
// 幂等重放 schema（TestOpenSeed 连库时整段执行，本机无 PG 自动 skip）。

import (
	"reflect"
	"strings"
	"testing"
)

func TestMarshalInt64Array(t *testing.T) {
	cases := []struct {
		in   []int64
		want string
	}{
		{nil, "{}"},
		{[]int64{}, "{}"},
		{[]int64{7}, "{7}"},
		{[]int64{7, 7, 8}, "{7,8}"},   // 去重
		{[]int64{3, 1, 2}, "{3,1,2}"}, // 保序（调用方不依赖，但行为要稳定可测）
	}
	for _, c := range cases {
		if got := marshalInt64Array(c.in); got != c.want {
			t.Errorf("marshalInt64Array(%v)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestMarshalTextArray(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, "{}"},
		{[]string{""}, "{}"}, // 空串丢弃
		{[]string{"a.com", "a.com"}, `{"a.com"}`},   // 去重保序
		{[]string{`he"llo`}, `{"he\"llo"}`},         // 双引号转义
		{[]string{`back\slash`}, `{"back\\slash"}`}, // 反斜杠转义
	}
	for _, c := range cases {
		if got := marshalTextArray(c.in); got != c.want {
			t.Errorf("marshalTextArray(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestAssetKeyFor(t *testing.T) {
	cases := []struct {
		domain, root, ip, url, want string
	}{
		{"", "", "", "", ""},
		{"EXAMPLE.COM.", "", "", "", "example.com"},                                 // 域名归一化（小写/去尾点）
		{"", "Example.Com", "", "", "example.com"},                                  // root_domain 兜底
		{"", "", "10.0.0.1", "", "10.0.0.1"},                                        // IP
		{"example.com", "", "10.0.0.1", "", "example.com"},                          // 域名优先于 IP
		{"example.com", "", "", "http://example.com/api", "http://example.com/api"}, // URL 最优先
	}
	for _, c := range cases {
		if got := assetKeyFor(c.domain, c.root, c.ip, c.url); got != c.want {
			t.Errorf("assetKeyFor(%q,%q,%q,%q)=%q want %q", c.domain, c.root, c.ip, c.url, got, c.want)
		}
	}
}

// TestAssetKeyLevels 守 V5-C 障碍2 的父子两级键口径：endpoint 产
// host:port + host:port/path，service 产 host:port，domain 产 domain
// （已知端口时再加 host:port）；历史完整 URL 键必须保留（存量行只有它）。
func TestAssetKeyLevels(t *testing.T) {
	cases := []struct {
		name                       string
		typ, domain, root, ip, url string
		port                       int
		want                       []string
	}{
		{
			name: "endpoint 双键（站点级+页面级）",
			typ:  "endpoint", domain: "Example.COM", port: 8080,
			url:  "http://example.com:8080/login.php",
			want: []string{"example.com:8080", "example.com:8080/login.php", "http://example.com:8080/login.php"},
		},
		{
			name: "endpoint 根路径不产子键",
			typ:  "endpoint", domain: "example.com", port: 443,
			url:  "https://example.com",
			want: []string{"example.com:443", "https://example.com"},
		},
		{
			name: "service 单键 host:port（+历史 URL）",
			typ:  "service", domain: "example.com", port: 443,
			url:  "https://example.com",
			want: []string{"example.com:443", "https://example.com"},
		},
		{
			name: "domain 无端口只产域名",
			typ:  "root_domain", domain: "Example.COM.",
			want: []string{"example.com"},
		},
		{
			name: "domain 带 URL 时补 host:port",
			typ:  "subdomain", domain: "a.example.com",
			url:  "https://a.example.com/path",
			want: []string{"a.example.com", "a.example.com:443", "https://a.example.com/path"},
		},
		{
			name: "IP + 端口",
			typ:  "service", ip: "10.0.0.8", port: 8080,
			want: []string{"10.0.0.8:8080"},
		},
		{
			name: "全空",
			typ:  "endpoint",
			want: nil,
		},
		{
			name: "重复字段去重",
			typ:  "subdomain", domain: "dup.example.com", root: "dup.example.com",
			want: []string{"dup.example.com"},
		},
	}
	for _, c := range cases {
		got := assetKeyLevels(c.typ, c.domain, c.root, c.ip, c.port, c.url)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: assetKeyLevels()=%v want %v", c.name, got, c.want)
		}
	}
}

func TestBuildProjectIndexWhere(t *testing.T) {
	// 空过滤：只剩 project_id。
	where, args := buildProjectIndexWhere(42, ProjectIndexFilter{})
	if where != " WHERE project_id = $1" || len(args) != 1 || args[0] != int64(42) {
		t.Fatalf("empty filter: where=%q args=%v", where, args)
	}

	// 全条件：kind IN、severity IN、asset_keys 重叠、ILIKE 关键词。
	where, args = buildProjectIndexWhere(7, ProjectIndexFilter{
		Kinds:      []string{"finding", "fact"},
		Severities: []string{"high", "critical"},
		AssetKeys:  []string{"a.example.com", "b.example.com"},
		Query:      "  SQLi%  ",
	})
	wantWhere := ` WHERE project_id = $1 AND kind IN ($2,$3) AND severity IN ($4,$5)` +
		` AND asset_keys && $6::text[] AND summary ILIKE $7 ESCAPE '\'`
	if where != wantWhere {
		t.Errorf("where=%q\nwant=%q", where, wantWhere)
	}
	if len(args) != 7 {
		t.Fatalf("args len=%d want 7: %v", len(args), args)
	}
	if args[0] != int64(7) {
		t.Errorf("args[0]=%v want 7", args[0])
	}
	if !reflect.DeepEqual(args[1:5], []any{"finding", "fact", "high", "critical"}) {
		t.Errorf("args[1:5]=%v", args[1:5])
	}
	if args[5] != `{"a.example.com","b.example.com"}` {
		t.Errorf("asset_keys arg=%v", args[5])
	}
	// 关键词 trim 后转义 % 并按子串包 %：`SQLi%` → `%SQLi\%%`
	if args[6] != `%SQLi\%%` {
		t.Errorf("query arg=%q want %%SQLi\\%%%%", args[6])
	}

	// 占位符连续性自检：任意条件组合下 $N 必须从 1 连续到 len(args)。
	where, args = buildProjectIndexWhere(1, ProjectIndexFilter{Kinds: []string{"goal"}, Query: "x"})
	for i := range args {
		mark := "$" + itoa(int64(i+1))
		if !strings.Contains(where, mark) {
			t.Fatalf("missing placeholder %s in %q", mark, where)
		}
	}
}

func TestEscapeLikePattern(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{`back\slash`, `back\\slash`},
		{"50%", `50\%`},
		{"a_b", `a\_b`},
		{`%_\`, `\%\_\\`},
	}
	for _, c := range cases {
		if got := escapeLikePattern(c.in); got != c.want {
			t.Errorf("escapeLikePattern(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("short", 10); got != "short" {
		t.Errorf("no truncation expected, got %q", got)
	}
	// 中文按 rune 计：5 个汉字截 3 → 前 3 个 + 省略号，绝不切半字节。
	got := truncateRunes("漏洞发现呀", 3)
	if got != "漏洞发…" {
		t.Errorf("truncateRunes(rune)=%q want 漏洞发…", got)
	}
}

// TestSchemaContainsProjectGraphTables 守卫 T09 的四表 DDL 确已并入 embed 的
// schemaSQL（go:embed 的字符串在编译期来自 db/schema.sql，无库即可断言）。
// 只钉「表在、关键索引/约束在」，不重复解析 SQL——真正建表由启动幂等重放验证。
func TestSchemaContainsProjectGraphTables(t *testing.T) {
	wants := []string{
		"CREATE TABLE IF NOT EXISTS project_index",
		"CREATE TABLE IF NOT EXISTS project_graph_events",
		// 洞察两表在 V12-CLEANUP 移除，这里改为钉「确实有 DROP」——
		// 存量库升级时必须真删掉，不能留一张没人读的空表。
		"DROP TABLE IF EXISTS project_insights",
		// upsert 幂等键与 ON CONFLICT 目标必须同名可寻：
		"CREATE UNIQUE INDEX IF NOT EXISTS ux_pidx_proj_node ON project_index(project_id, node_id)",
		"idx_pidx_proj_kind", "idx_pidx_asset", // GIN(asset_keys) 交集命中
		"idx_pge_scan ON project_graph_events(project_id, id)", // 水位索引
		"observer_enabled",
		"trg_pidx_upd",
	}
	for _, w := range wants {
		if !strings.Contains(schemaSQL, w) {
			t.Errorf("schema.sql missing %q", w)
		}
	}
}

func TestNodeSummaryAndSeverity(t *testing.T) {
	payload := map[string]any{"summary": "s", "text": "t", "severity": "high"}
	if got := nodeSummaryOf(payload); got != "s" {
		t.Errorf("summary key wins: got %q", got)
	}
	if got := nodeSummaryOf(map[string]any{"text": "t"}); got != "t" {
		t.Errorf("text fallback: got %q", got)
	}
	if got := nodeSummaryOf(map[string]any{"summary": "  "}); got != "" {
		t.Errorf("blank summary: got %q", got)
	}
	if got := nodeSeverityOf(payload, KindFinding); got != "high" {
		t.Errorf("finding severity: got %q", got)
	}
	if got := nodeSeverityOf(payload, KindFact); got != "" {
		t.Errorf("non-finding severity must be empty, got %q", got)
	}
}
