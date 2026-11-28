package server

import "testing"

func TestIntelCredentialNoise(t *testing.T) {
	cases := []struct {
		user, service, masked string
		want                  bool
	}{
		{"shown", "10.0.0.1", "65****32", true},          // nmap "Not shown: 65532"
		{"x-forwarded-host", "10.0.0.1", "ev****om", true}, // HTTP 头名
		{"clusterid", "10.0.0.1", "", true},              // 无密文掩码
		{"admin", "10.0.0.1:443", "Zm****==", false},     // 真口令
		{"", "value.status", "ba****6e", true},            // 配置键当服务
		{"", "10.0.0.1", "ba****6e", false},               // hash 无用户名
	}
	for _, c := range cases {
		if got := intelCredentialIsNoise(c.user, c.service, c.masked); got != c.want {
			t.Errorf("noise(%q,%q,%q)=%v want %v", c.user, c.service, c.masked, got, c.want)
		}
	}
}

func TestIntelPasswordShape(t *testing.T) {
	bad := []string{"65532", "null", "true", "****", "123456", "......"}
	for _, s := range bad {
		if intelPasswordShape(s) {
			t.Errorf("%q should be rejected", s)
		}
	}
	good := []string{"P@ssw0rd!", "abc123", "Zm9vYmFy=="}
	for _, s := range good {
		if !intelPasswordShape(s) {
			t.Errorf("%q should be accepted", s)
		}
	}
}
