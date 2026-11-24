package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestProbeURLSendsCredentialHeaders 锁住一个曾经真实存在的缺陷：
// 探测按匿名发请求，明明配了 token/key 仍报 403；PoC 那行还探 /rate_limit，
// 该端点不计额度、必然 200，等于永远「假通过」。
//
// 这里只验「凭据确实发出去了」——探针的端点选择由 intelProbe 决定，
// 已在代码里与同步路径对齐（search/repositories、/advisories）。
func TestProbeURLSendsCredentialHeaders(t *testing.T) {
	var got struct {
		auth, accept, apiKey string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.auth = r.Header.Get("Authorization")
		got.accept = r.Header.Get("Accept")
		got.apiKey = r.Header.Get("apiKey")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := probeURL(context.Background(), srv.Client(), "ghsa", srv.URL, map[string]string{
		"Authorization": "Bearer test-token",
		"Accept":        "application/vnd.github+json",
		"apiKey":        "nvd-key",
	}, "已认证", "")

	if !res.OK || res.Auth != "已认证" {
		t.Fatalf("探测应成功且标注已认证: %+v", res)
	}
	if got.auth != "Bearer test-token" {
		t.Fatalf("Authorization 未发出，实际 %q", got.auth)
	}
	if got.accept != "application/vnd.github+json" {
		t.Fatalf("Accept 未发出，实际 %q", got.accept)
	}
	if got.apiKey != "nvd-key" {
		t.Fatalf("apiKey 未发出，实际 %q", got.apiKey)
	}
}

// TestProbeURLAnonymousForbiddenHint 匿名 403 必须提示「去填凭据」，
// 而不是笼统的「权限不足」——后者会让人去查 token 权限，方向就错了。
func TestProbeURLAnonymousForbiddenHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	}))
	defer srv.Close()

	res := probeURL(context.Background(), srv.Client(), "ghsa", srv.URL, nil, "匿名", "")
	if res.OK || res.Status != http.StatusForbidden {
		t.Fatalf("应识别为失败: %+v", res)
	}
	if !strings.Contains(res.Hint, "匿名额度") {
		t.Fatalf("403 提示应指向凭据，实际 %q", res.Hint)
	}
}
