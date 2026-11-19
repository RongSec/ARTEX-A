package agent

import (
	"strings"
	"testing"
)

// TestRedactTestMethod 断言「只保留测试方法」的脱敏口径：
// host / IP / 凭据值一律不出现，方法+路径/参数保留。
func TestRedactTestMethod(t *testing.T) {
	in := `POST http://oa.example-corp.com:8080/api/login?next=/home 返回 302，
Cookie: SESSION=abc123；password=Passw0rd!；内网 10.0.0.15:8080 也可访问，
GET https://admin.corp.local/api/user/1001 返回 200`
	out := redactTestMethod(in)

	for _, bad := range []string{"example-corp", "10.0.0.15", "Passw0rd", "abc123", "admin.corp.local"} {
		if strings.Contains(out, bad) {
			t.Fatalf("脱敏后不应出现 %q，got: %s", bad, out)
		}
	}
	for _, want := range []string{"/api/login?next=/home", "/api/user/1001"} {
		if !strings.Contains(out, want) {
			t.Fatalf("应保留路径 %q，got: %s", want, out)
		}
	}
}

// TestRequestsIn 断言请求行抽取：URL 只留 path，去重。
func TestRequestsIn(t *testing.T) {
	body := `先 GET http://a.example.com/api/list?page=1 200
再 GET http://a.example.com/api/list?page=2 200
最后 POST https://b.example.com/api/login {"user":"admin"}`
	got := requestsIn(body)
	if len(got) != 2 {
		t.Fatalf("应按 method+path 去重成 2 条，got %d: %v", len(got), got)
	}
	if got[0] != "GET /api/list" || got[1] != "POST /api/login" {
		t.Fatalf("请求行不对: %v", got)
	}
}
