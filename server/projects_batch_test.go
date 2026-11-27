package server

import (
	"reflect"
	"testing"
)

// splitBatchTargets 是批量下发拆行的纯函数（无库可跑，T06 验收项）。
// V12-TARGET 起语义升级为 ParseTargets：按行切 → TrimSpace → 丢空行/注释 →
// 校验并规范化（域名转小写）→ 去重（保留首条，重复行进 skipped）→ 非法行进 invalid。
func TestSplitBatchTargets(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantTargets []string
		wantSkipped []string
		wantInvalid []string
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
			name: "域名小写归一后去重",
			in:   "a.com\nb.com\na.com\nA.com",
			// A.com 归一到 a.com，与首条相同 → 进 skipped。
			wantTargets: []string{"a.com", "b.com"},
			wantSkipped: []string{"a.com", "a.com"},
		},
		{
			name:        "非法目标进 invalid 不建任务",
			in:          "10.0.0.1\n10.0.0.\nhttp://\n8080",
			wantTargets: []string{"10.0.0.1"},
			wantInvalid: []string{"10.0.0.", "http://", "8080"},
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
			name:        "单标签主机名小写归一",
			in:          "Target-A\nTarget-A\nTarget-B",
			wantTargets: []string{"target-a", "target-b"},
			wantSkipped: []string{"target-a"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotTargets, gotSkipped, gotInvalid := splitBatchTargets(c.in)
			if !reflect.DeepEqual(gotTargets, c.wantTargets) {
				t.Fatalf("targets: want %#v got %#v", c.wantTargets, gotTargets)
			}
			if !reflect.DeepEqual(gotSkipped, c.wantSkipped) {
				t.Fatalf("skipped: want %#v got %#v", c.wantSkipped, gotSkipped)
			}
			if !reflect.DeepEqual(gotInvalid, c.wantInvalid) {
				t.Fatalf("invalid: want %#v got %#v", c.wantInvalid, gotInvalid)
			}
		})
	}
}

// 批量下发不再设单批行数上限（用户明确要求），这里保留用例位以便后续
// 需要时补其它保护语义。
