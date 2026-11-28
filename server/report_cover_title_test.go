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

func TestReportSystemNameSkipsIP(t *testing.T) {
	if got := reportSystemName("task", 215, 0, []string{"https://140.207.94.175"}); got != "任务215" {
		t.Errorf("bare IP should fall back to task id, got %q", got)
	}
	if got := reportSystemName("task", 215, 0, []string{"http://10.0.0.5:8080/admin"}); got != "任务215" {
		t.Errorf("IP with port should fall back to task id, got %q", got)
	}
	if got := reportSystemName("task", 215, 0, []string{"https://mail.example.com"}); got != "任务215" {
		t.Errorf("domain must not be used as system name, got %q", got)
	}
	if got := reportSystemName("project", 0, 9, []string{"10.1.2.3"}); got != "项目9" {
		t.Errorf("project fallback wrong, got %q", got)
	}
	// 人工命名的任务名可以当系统名；URL/默认目标句不行。
	if got := reportSystemName("task", 215, 0, []string{"https://140.207.94.175"}, "示例经销商门户"); got != "示例经销商门户" {
		t.Errorf("named task should be system name, got %q", got)
	}
	if got := reportSystemName("task", 215, 0, []string{"https://140.207.94.175"}, "对给定的资产范围进行全面安全审计"); got != "任务215" {
		t.Errorf("default goal must not be system name, got %q", got)
	}
	if got := reportSystemName("task", 215, 0, []string{"https://140.207.94.175"}, "https://140.207.94.175"); got != "任务215" {
		t.Errorf("URL task name must not be system name, got %q", got)
	}
}
