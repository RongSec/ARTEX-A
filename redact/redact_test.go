package redact

import "testing"

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
