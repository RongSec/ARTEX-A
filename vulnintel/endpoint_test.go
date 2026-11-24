package vulnintel

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestClientBaseOverride 验证「库配置里改端点」真的改变请求地址。
//
// 为什么值得一条测试:端点写死在代码里时,页面上的输入框就是摆设——改完
// 照样打官方地址,用户只会看到「配置没生效」而查不出原因。这里用 httptest
// 起一个假源,断言 path 落在假源上。
func TestClientBaseOverride(t *testing.T) {
	var nvdPath, kevPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/rest/json/cves/2.0"):
			nvdPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"resultsPerPage":1,"totalResults":0,"vulnerabilities":[]}`)
		case strings.HasSuffix(r.URL.Path, "known_exploited_vulnerabilities.json"):
			kevPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"count":0,"vulnerabilities":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// 带 key 把限速闸门放到 0.7s,测试不至于等 6.5s。
	cfg := Config{NvdAPIKey: "test-key", NvdBase: srv.URL + "/", KevBase: srv.URL}

	nvd, err := newNvdClient(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nvd.FetchPage(context.Background(), 0, 1, time.Time{}, time.Time{}); err != nil {
		t.Fatalf("FetchPage: %v", err)
	}
	if nvdPath == "" {
		t.Fatal("NVD 请求没有打到库配置的端点")
	}

	kevClient, err := newNvdClient(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kevClient.FetchKEV(context.Background()); err != nil {
		t.Fatalf("FetchKEV: %v", err)
	}
	if kevPath == "" {
		t.Fatal("KEV 请求没有打到库配置的端点")
	}
}

// TestClientBaseDefault 空配置仍打官方地址(NvdClient.Base 保持默认)。
func TestClientBaseDefault(t *testing.T) {
	c, err := newNvdClient(Config{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Base != "https://services.nvd.nist.gov" {
		t.Fatalf("默认基址被改坏了: %q", c.Base)
	}
}
