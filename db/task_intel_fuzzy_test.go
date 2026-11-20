package db

import "testing"

// 路径模糊匹配是「候选能不能被发现」的关键：精确 match_key 只认归一化后完全
// 相等，同 controller 的接口会漏。这里把口径钉死。
func TestFuzzyPathScore(t *testing.T) {
	cases := []struct {
		desc string
		a, b string
		min  float64
		max  float64
	}{
		{"完全相等", "/api/sso/userinfo", "/api/sso/userinfo", 1, 1},
		{"数字段折叠后相等", "/api/user/{id}", "/api/user/123", 1, 1},
		{"UUID 段折叠后相等", "/api/user/3f2504e0-4f89-11d3-9a0c-0305e82c3301", "/api/user/{uuid}", 1, 1},
		{"版本段丢弃后相等", "/api/v1/user", "/api/user", 1, 1},
		{"同 controller 不同动作", "/api/user/list", "/api/user/info", 0.6, 0.7},
		{"父子资源", "/api/user", "/api/user/list", 0.7, 0.8},
		{"不同 controller", "/api/order/list", "/api/user/list", 0, 0.55},
		{"短词不同", "/login", "/logout", 0, 0.4},
		{"空值", "", "/api/user", 0, 0},
		{"根路径与空", "/", "/api/user", 0, 0.1},
	}
	for _, c := range cases {
		got := FuzzyPathScore(c.a, c.b)
		if got < c.min || got > c.max {
			t.Errorf("%s: FuzzyPathScore(%q,%q)=%.3f，期望 [%.2f,%.2f]", c.desc, c.a, c.b, got, c.min, c.max)
		}
	}
}

// 对称性：a→b 与 b→a 必须一致，否则候选会因比较方向不同时有时无。
func TestFuzzyPathScoreSymmetric(t *testing.T) {
	pairs := [][2]string{
		{"/api/user/list", "/api/user/info"},
		{"/api/user", "/api/user/list/detail"},
		{"/a/b/c", "/a/b/d"},
	}
	for _, p := range pairs {
		if x, y := FuzzyPathScore(p[0], p[1]), FuzzyPathScore(p[1], p[0]); x != y {
			t.Errorf("不对称：%q/%q → %.3f vs %.3f", p[0], p[1], x, y)
		}
	}
}

// 档位阈值必须与提示词口径一致：Σ≥2.0 strong、Σ≥1.0 medium、Σ>0 weak。
func TestMatchStrengthOf(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0, ""},
		{0.6, "weak"},
		{0.99, "weak"},
		{1.0, "medium"},
		{1.9, "medium"},
		{2.0, "strong"},
		{3.2, "strong"},
	}
	for _, c := range cases {
		if got := MatchStrengthOf(c.score); got != c.want {
			t.Errorf("MatchStrengthOf(%.2f)=%q，期望 %q", c.score, got, c.want)
		}
	}
}

// 单条模糊（0.6）只到 weak，不能单独成候选；两条模糊（1.2）才够 medium。
// 这是用户口径：「至少 medium 才进候选」。
func TestSingleFuzzyIsNotCandidate(t *testing.T) {
	if MatchStrengthOf(EndpointFuzzyScore) != "weak" {
		t.Fatalf("单条模糊应为 weak，实际 %q", MatchStrengthOf(EndpointFuzzyScore))
	}
	if MatchStrengthOf(EndpointFuzzyScore*2) != "medium" {
		t.Fatalf("两条模糊应为 medium，实际 %q", MatchStrengthOf(EndpointFuzzyScore*2))
	}
	if MatchStrengthOf(EndpointExactScore*2) != "strong" {
		t.Fatalf("两条精确应为 strong，实际 %q", MatchStrengthOf(EndpointExactScore*2))
	}
}

// 前缀粗筛必须保留两段：只取一段会把整个 /api% 拉回来，取三段会漏掉
// /api/user 与 /api/user/list 这种父子关系。
func TestPathPrefixOf(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"/api/user/list", 2, "/api/user%"},
		{"/api/user", 2, "/api/user%"},
		{"/login", 2, "/login%"},
		{"/", 2, ""},
	}
	for _, c := range cases {
		if got := pathPrefixOf(c.in, c.n); got != c.want {
			t.Errorf("pathPrefixOf(%q,%d)=%q，期望 %q", c.in, c.n, got, c.want)
		}
	}
}
