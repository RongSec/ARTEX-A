package db

import (
	"encoding/json"
	"testing"
)

// T14(2/2) 纯函数 gate：HasReproSteps 判「有无可回填的步骤」——决定异步
// enricher 是否值得被派发、view-time 是否要空跑一次解析。与 T14(1/2) 的
// hasReproduction（判「要不要双写」）不同：后者认任何非空壳（如只填
// entry_point），前者必须真steps非空才有解析对象。

func TestHasReproSteps(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{``, false},
		{`{}`, false},
		{`null`, false},
		{`{"entry_point":"POST /a"}`, false},              // 无 steps 键
		{`{"steps":[]}`, false},                           // 空 steps
		{`{"steps":[{}]}`, true},                          // 最短合法形态
		{`{"steps":[{"request":"GET /a","exchange_id":""}]}`, true}, // 未关联也算有步骤
		{`{"steps":[{"request":"GET /a","exchange_id":"1-0001"}]}`, true}, // 已关联仍需（view-time gate 在上层判 done）
		{`not json`, false},                               // 脏输入宁可不跑
	}
	for _, c := range cases {
		if got := HasReproSteps(json.RawMessage(c.raw)); got != c.want {
			t.Errorf("HasReproSteps(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}
