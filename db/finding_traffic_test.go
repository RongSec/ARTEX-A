package db

import (
	"encoding/json"
	"testing"
)

// T14(1/2)：reproduction 判空的纯函数表驱动测（无库）。语义=「模型真填了才
// 触发双写」——空壳（nil/缺省/"{}"/"null"/纯空白）一律视为未填：findings 列
// 保持默认 '{}'、节点 payload 不带 reproduction 键（原版 report_finding 调用
// 的落库逐字节零回归）。真内容（哪怕只有一个键）即触发双写。
func TestHasReproduction(t *testing.T) {
	cases := []struct {
		name string
		in   json.RawMessage
		want bool
	}{
		{"缺省-nil", nil, false},
		{"空串", json.RawMessage(""), false},
		{"空对象", json.RawMessage("{}"), false},
		{"空对象带空白", json.RawMessage("  {}  "), false},
		{"null 字面量", json.RawMessage("null"), false},
		{"纯空白", json.RawMessage("   \t "), false},
		{"单键对象即算填了", json.RawMessage(`{"entry_point":"POST /upload"}`), true},
		{"完整复现", json.RawMessage(`{"entry_point":"/a","steps":[{"request":"GET /a HTTP/1.1"}],"provenance":"chain"}`), true},
		{"steps 空数组也算填了（模型填了结构只是没步骤，按内容存）", json.RawMessage(`{"steps":[]}`), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasReproduction(c.in); got != c.want {
				t.Fatalf("hasReproduction(%q)=%v want %v", string(c.in), got, c.want)
			}
		})
	}
}
