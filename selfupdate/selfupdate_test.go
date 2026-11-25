package selfupdate

import (
	"net/url"
	"testing"
)

// 程序内换装已删除（见 selfupdate.go 顶部），这里只保留仍然生效的两块逻辑：
// 版本号比较、以及 GitHub 域名白名单（查询接口仍然只允许访问 GitHub）。

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b       string
		want       int
		comparable bool
	}{
		{"0.3.7", "0.3.8", -1, true},
		{"0.3.8", "0.3.7", 1, true},
		{"0.3.7", "0.3.7", 0, true},
		{"v0.3.7", "0.3.8", -1, true}, // build.sh 去掉 v，tag 带 v，两边都要认
		{"0.3.7", "v0.3.7", 0, true},
		{"0.9.0", "0.10.0", -1, true}, // 按数字比而不是字典序
		{"1.0.0", "0.99.99", 1, true},
		// 开发构建必须判为不可比较，否则页面会把 dev 说成"有新版本"。
		{"dev", "0.3.8", 0, false},
		{"0.3.7-2-gabc1234", "0.3.8", 0, false},
		{"0.3.7-dirty", "0.3.8", 0, false},
		{"0.3", "0.3.8", 0, false},
		{"", "0.3.8", 0, false},
		// 本项目的版本号是四段式（0.3.16-hs.7 这类带后缀的形式）：
		// 它必须被判为不可比较，否则页面会对一个已发布的正式版说"有新版本"。
		{"v0.3.16-hs.7", "v0.3.16", 0, false},
	}
	for _, c := range cases {
		got, ok := CompareVersions(c.a, c.b)
		if ok != c.comparable {
			t.Errorf("CompareVersions(%q,%q) comparable=%v, 期望 %v", c.a, c.b, ok, c.comparable)
			continue
		}
		if ok && got != c.want {
			t.Errorf("CompareVersions(%q,%q)=%d, 期望 %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCheckURLRejectsNonGitHub(t *testing.T) {
	bad := []string{
		"http://github.com/x",           // 非 HTTPS
		"https://evil.com/artex.zip",    // 域名不在白名单
		"https://github.com.evil.com/x", // 后缀伪装
		"https://raw.githubusercontent.com.evil.com/x",
	}
	for _, raw := range bad {
		u := mustParse(t, raw)
		if err := checkURL(u); err == nil {
			t.Errorf("checkURL(%q) 应当拒绝", raw)
		}
	}
	good := []string{
		"https://api.github.com/repos/x/releases/latest",
		"https://objects.githubusercontent.com/blah",
		"https://GitHub.com/x", // 域名大小写不敏感
	}
	for _, raw := range good {
		u := mustParse(t, raw)
		if err := checkURL(u); err != nil {
			t.Errorf("checkURL(%q) 应当放行，却报错: %v", raw, err)
		}
	}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("解析 %q: %v", raw, err)
	}
	return u
}
