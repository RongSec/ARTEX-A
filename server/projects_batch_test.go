package server

import (
	"reflect"
	"testing"
)

// splitBatchTargets 是批量下发拆行的纯函数（无库可跑，T06 验收项）。
// 语义：按行切 → TrimSpace → 丢空行 → 去重（保留首条，重复行进 skipped 回显）。
func TestSplitBatchTargets(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantTargets []string
		wantSkipped []string
	}{
		{
			name:        "基本拆行",
			in:          "http://a.com\nhttp://b.com",
			wantTargets: []string{"http://a.com", "http://b.com"},
		},
		{
			name:        "空行与纯空白行丢弃",
			in:          " 10.0.0.1 \n\n\t\n10.0.0.2\n   ",
			wantTargets: []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name:        "重复保留首条并进 skipped",
			in:          "a.com\nb.com\na.com\nA.com",
			wantTargets: []string{"a.com", "b.com", "A.com"},
			wantSkipped: []string{"a.com"},
		},
		{
			name:        "CRLF 行尾（textarea 粘贴常见）",
			in:          "a.com\r\nb.com\r\n",
			wantTargets: []string{"a.com", "b.com"},
		},
		{
			name:        "全空输入",
			in:          "\n\n  \n",
			wantTargets: nil,
		},
		{
			name:        "空串",
			in:          "",
			wantTargets: nil,
		},
		{
			name:        "去重按 Trim 后形态（大小写敏感）",
			in:          "Target-A\nTarget-A\nTarget-B",
			wantTargets: []string{"Target-A", "Target-B"},
			wantSkipped: []string{"Target-A"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotTargets, gotSkipped := splitBatchTargets(c.in)
			if !reflect.DeepEqual(gotTargets, c.wantTargets) {
				t.Fatalf("targets: want %#v got %#v", c.wantTargets, gotTargets)
			}
			if !reflect.DeepEqual(gotSkipped, c.wantSkipped) {
				t.Fatalf("skipped: want %#v got %#v", c.wantSkipped, gotSkipped)
			}
		})
	}
}

// 上限保护语义在 handler（len(targets)>maxBatchCreate→400）；这里钉住常量
// 本身，防止有人悄悄把它调大绕过保护（单批 200 是评审定值）。
func TestMaxBatchCreateConstant(t *testing.T) {
	if maxBatchCreate != 200 {
		t.Fatalf("maxBatchCreate 应为 200，实际 %d", maxBatchCreate)
	}
}
