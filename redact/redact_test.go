package redact

import (
	"strings"
	"testing"
)

func TestTestMethodHostPort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"资产 127.0.0.1:9081", "资产 <ip>"},
		{"凭据 password for admin@127.0.0.1:9081（掩码 pa****rd）", "凭据 password for admin@<ip>（掩码 pa****rd）"},
		{"接口 get /vulnerabilities/sqli/ — 注入点", "接口 get /vulnerabilities/sqli/ — 注入点"},
		{"http://oa.example.com:8080/api/user?id=1", "/api/user?id=1"},
		{"访问 oa.example.com 的登录口", "访问 <host> 的登录口"},
	}
	for _, c := range cases {
		if got := TestMethod(c.in); got != c.want {
			t.Fatalf("TestMethod(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestTestMethodKeepSecrets：worker 下钻保留凭据值（密码复用线索），但 host/IP 仍脱敏。
func TestTestMethodKeepSecrets(t *testing.T) {
	in := "curl -H 'Cookie: user_token=eyJhbGciOiJub25lIn0.abc' http://10.0.0.5:9091/api/sso/userinfo?user_id=2 password=Admin@123"
	got := TestMethodKeepSecrets(in)
	if !strings.Contains(got, "eyJhbGciOiJub25lIn0.abc") || !strings.Contains(got, "Admin@123") {
		t.Errorf("凭据值应保留：%s", got)
	}
	if strings.Contains(got, "10.0.0.5") || strings.Contains(got, ":9091") {
		t.Errorf("host/IP 仍应脱敏：%s", got)
	}
	if TestMethod(in) == got {
		t.Errorf("TestMethod 仍应抹掉凭据，两者不应相同")
	}
}
