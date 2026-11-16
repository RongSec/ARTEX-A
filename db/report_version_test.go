package db

import "testing"

// R1：版本号只在骨架结构变化时递增；jsonEqual 是判定基础（忽略键序/空白）。
func TestJSONEqual(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{`[{"key":"cover","title":"封面","enabled":true}]`, `[ { "enabled": true, "title": "封面", "key": "cover" } ]`, true},
		{`{"a":1,"b":2}`, `{"b":2,"a":1}`, true},
		{`[{"key":"cover"}]`, `[{"key":"summary"}]`, false},
		{`not-json`, `not-json`, true},
		{`not-json`, `other`, false},
	}
	for _, c := range cases {
		if got := jsonEqual([]byte(c.a), []byte(c.b)); got != c.want {
			t.Errorf("jsonEqual(%q,%q)=%v, want %v", c.a, c.b, got, c.want)
		}
	}
}
