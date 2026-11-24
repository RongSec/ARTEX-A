package server

// 库配置（vuln_sources）的集成测试：预置行、读写、开关生效。
//
// 这是「骨架」的验收：现在不加新源，但每类库都必须能在页面上被看到、被改、
// 状态可查。加源时只要插一行，这里的分页/排序/状态合并逻辑不用重写。

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func testServer(t *testing.T) *Server {
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
	return &Server{m: &Manager{pg: d}}
}

func TestVulnSourcesSeeded(t *testing.T) {
	s := testServer(t)
	ctx := t.Context()
	items, err := s.listVulnSources(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []string{"nvd", "kev", "ghsa", "github_poc", "nuclei_templates"}
	got := map[string]bool{}
	for _, it := range items {
		got[it.ID] = true
		if it.Name == "" || it.Kind == "" || it.Endpoint == "" {
			t.Errorf("库 %s 的静态字段不完整: %+v", it.ID, it)
		}
		if it.Status == "" {
			t.Errorf("库 %s 缺少状态（应为 ok/error/never）", it.ID)
		}
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("预置库缺少 %s（schema 里的 INSERT ... ON CONFLICT DO NOTHING 没生效？）", id)
		}
	}
	// 顺序必须稳定：页面按 sort_order 渲染，顺序抖动会让行错位。
	if len(items) >= 2 && items[0].ID != "nvd" {
		t.Errorf("首个库应为 nvd（sort_order 最小），实际 %s", items[0].ID)
	}
}

func TestVulnSourceUpdate(t *testing.T) {
	s := testServer(t)
	ctx := t.Context()

	before, err := s.listVulnSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var origEndpoint string
	var origEnabled bool
	for _, it := range before {
		if it.ID == "kev" {
			origEndpoint, origEnabled = it.Endpoint, it.Enabled
		}
	}
	if origEndpoint == "" {
		t.Fatal("找不到 kev 库")
	}
	t.Cleanup(func() {
		_ = s.updateVulnSource(ctx, "kev", patchVulnSource{Endpoint: &origEndpoint, Enabled: &origEnabled})
	})

	off := false
	newEP := "https://example.invalid/kev.json"
	if err := s.updateVulnSource(ctx, "kev", patchVulnSource{Enabled: &off, Endpoint: &newEP}); err != nil {
		t.Fatalf("update: %v", err)
	}
	after, err := s.listVulnSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range after {
		if it.ID != "kev" {
			continue
		}
		if it.Enabled {
			t.Errorf("enabled 应已改为 false")
		}
		if it.Endpoint != newEP {
			t.Errorf("endpoint 未更新: %q", it.Endpoint)
		}
	}
	// 开关必须能反过来被同步器读到。
	if s.vulnSourceEnabled("kev", true) {
		t.Errorf("vulnSourceEnabled(kev) 应为 false")
	}
}

func TestVulnSourceUpdateRejectsUnknown(t *testing.T) {
	s := testServer(t)
	on := true
	if err := s.updateVulnSource(t.Context(), "no-such-source", patchVulnSource{Enabled: &on}); err == nil {
		t.Fatal("未知库应报错")
	}
}
