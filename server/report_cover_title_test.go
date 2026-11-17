package server

import "testing"

func TestCoverTitle(t *testing.T) {
	cases := []struct {
		name     string
		fallback string
		targets  []string
		want     string
	}{
		{"host from url", "对 http://127.0.0.1:9082 上的 Web 应用做授权渗透测试", []string{"http://127.0.0.1:9082/"}, "127.0.0.1:9082渗透测试报告"},
		{"host plain", "任务名", []string{"mall.example.com"}, "mall.example.com渗透测试报告"},
		{"no target", "验收项目", nil, "验收项目渗透测试报告"},
		{"already report", "验收项目报告", nil, "验收项目报告"},
		{"empty all", "", nil, "目标系统渗透测试报告"},
		{"strip path", "x", []string{"10.1.2.3/admin"}, "10.1.2.3渗透测试报告"},
	}
	for _, c := range cases {
		if got := coverTitle(c.fallback, c.targets); got != c.want {
			t.Fatalf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
