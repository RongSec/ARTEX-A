package server

// T15(2/2) 无库纯函数测 + 路由注册冒烟测（Handler() 构造 ServeMux，重复/遮蔽
// 模式会在 HandleFunc 直接 panic；命中我们的路由时无 PG → 503 pgReportDBGuard，
// 与 404 区分即可证明注册成功。不依赖数据库环境，零回归。）

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestContentDispositionAttachment(t *testing.T) {
	h := contentDispositionAttachment("示例集团_门户渗透-20261111.docx")
	if !strings.Contains(h, `filename*=UTF-8''`) {
		t.Fatalf("missing RFC5987 param: %q", h)
	}
	// 中文被 percent-encode，ASCII 回退名里不残留多字节。
	if strings.Contains(h, "示例") {
		t.Errorf("raw utf8 leaked into header: %q", h)
	}
	if !strings.Contains(h, `%E4%B8%AD%E5%8C%96`) {
		t.Errorf("percent-encoding wrong: %q", h)
	}
	if !strings.HasPrefix(h, `attachment; filename="`) {
		t.Errorf("ascii fallback param missing: %q", h)
	}
	// 纯 ASCII 名回退段原样可用。
	h2 := contentDispositionAttachment("task-7.md")
	if !strings.Contains(h2, `filename="task-7.md"`) {
		t.Errorf("ascii name broken: %q", h2)
	}
}

func TestTruncateUTF8(t *testing.T) {
	s := "错误：中文中文中文"
	// 截到 rune 中间：回退到合法边界，结果仍是合法 UTF-8。
	got := truncateUTF8(s, 8) // "错误：" 占 9 字节 → 8 会切断 '：' 前一汉字
	if !strings.Contains(got, "错误") || strings.ContainsRune(got, 0xFFFD) {
		t.Errorf("rune-boundary truncation broken: %q", got)
	}
	if len(truncateUTF8("abc", 10)) != 3 {
		t.Error("short string must pass through")
	}
}

// TestReportRoutesRegistered 路由注册冒烟：零值 Manager（pg=nil）下，凡命中
// 我们的 handler 必回 503（pgReportDBGuard）；未注册路径是 mux 的 404。带合法
// JWT 过 requireAuth。全程不触库，无 PG 环境照常跑。
func TestReportRoutesRegistered(t *testing.T) {
	s := &Server{m: &Manager{}, jwtKey: []byte("t15-test-key")}
	h := s.Handler()
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/report-templates"},
		{http.MethodPost, "/api/report-templates"},
		{http.MethodPatch, "/api/report-templates/1"},
		{http.MethodDelete, "/api/report-templates/1"},
		{http.MethodPost, "/api/report-templates/1/set-default"},
		{http.MethodGet, "/api/report-settings"},
		{http.MethodPatch, "/api/report-settings"},
		{http.MethodPost, "/api/report/generate"},
		{http.MethodGet, "/api/report/jobs/1"},
		{http.MethodGet, "/api/report/jobs/1/download"},
		{http.MethodGet, "/api/reports"},
		{http.MethodDelete, "/api/reports/1"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("route %s %s: want 503 (registered, pg-guard), got %d body=%s",
				c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	// 原版快速预览路由零回归：GET /api/report 不带 ?task= 时走 taskFromQuery
	// 缺失 → 404 "no active task"（非 mux 的 404 page not found），说明新前缀
	// 没有把它遮蔽掉。
	req := httptest.NewRequest(http.MethodGet, "/api/report", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound && strings.Contains(rec.Body.String(), "404 page not found") {
		t.Error("GET /api/report got shadowed by new routes (mux 404)")
	}
}
