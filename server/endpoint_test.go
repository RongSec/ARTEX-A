package server

import "testing"

// TestNormalizeEndpointBase 验证端点归一。
//
// 库配置预置的是完整请求地址(用户看得懂「请求什么」),客户端只吃基址。
// 归一错了 = 要么请求拼成 /rest/.../rest/...,要么镜像地址被误剥。
func TestNormalizeEndpointBase(t *testing.T) {
	cases := []struct{ id, raw, want string }{
		{"nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0", "https://services.nvd.nist.gov"},
		{"nvd", "https://mirror.internal/nvd/", "https://mirror.internal/nvd"},
		{"kev", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "https://www.cisa.gov"},
		{"ghsa", "https://api.github.com/advisories", "https://api.github.com"},
		{"github_poc", "https://ghe.corp/api/v3/search/repositories", "https://ghe.corp/api/v3"},
		{"nuclei_templates", "https://gitee.com/mirror/nuclei-templates.git", "https://gitee.com/mirror/nuclei-templates.git"},
		{"nvd", "  ", ""},
	}
	for _, c := range cases {
		if got := normalizeEndpointBase(c.id, c.raw); got != c.want {
			t.Errorf("normalizeEndpointBase(%q,%q)=%q want %q", c.id, c.raw, got, c.want)
		}
	}
}
