package server

// 事实台账路由注册冒烟（V4-A）。全程无库：pg=nil → 命中已注册路由必回 503
// （pgReportDBGuard），与 mux 404 区分；同 method+pattern 遮蔽在 Handler()
// 注册期即 panic。照 finding_evidence_test.go 范式。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFactRoutesRegistered(t *testing.T) {
	s := &Server{m: &Manager{}, jwtKey: []byte("v4a-facts-test-key")}
	h := s.Handler()
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	cases := []struct{ method, path, body string }{
		{http.MethodGet, "/api/facts", ""},
		{http.MethodGet, "/api/facts?project_id=1&task_id=2&q=x", ""},
		{http.MethodPatch, "/api/facts/123", `{"summary":"s"}`},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("route %s %s: want 503 (registered, pg-guard), got %d body=%s",
				c.method, c.path, rec.Code, rec.Body.String())
		}
	}
}
