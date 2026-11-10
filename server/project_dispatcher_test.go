package server

import "testing"

// projectDispatchPlan 是 T07 放行判定纯函数（无库单测，验收项）。
// 参数：globalEnabled, globalLimit, globalRunning, projRunning, concurrency, pending。
func TestProjectDispatchPlan(t *testing.T) {
	cases := []struct {
		name       string
		ge         bool
		gl, gr     int
		pr, cc, pk int
		want       int
	}{
		{"项目额度=1 串行：无在跑→放 1", true, 10, 0, 0, 1, 3, 1},
		{"项目额度=1：已有 1 在跑→0（严格串行）", true, 10, 0, 1, 1, 3, 0},
		{"项目额度=2：无在跑→放 2（两任务并行）", true, 10, 0, 0, 2, 5, 2},
		{"项目额度=2：已 1 在跑→只放 1", true, 10, 0, 1, 2, 5, 1},
		{"项目额度=2：已 2 在跑→0", true, 10, 0, 2, 2, 5, 0},
		{"全局满→0（即便项目额度充足）", true, 5, 5, 0, 2, 5, 0},
		{"全局剩 1、项目额度 2→只放 1（叠加不破全局）", true, 5, 4, 0, 2, 5, 1},
		{"全局剩 1、项目已 1 在跑额度 2→1（两边各剩 1，取小）", true, 5, 4, 1, 2, 5, 1},
		{"全局未启用→只看项目额度", false, 0, 99, 0, 3, 9, 3},
		{"pending 少于额度→只放 pending", true, 10, 0, 0, 4, 2, 2},
		{"pending=0→0", true, 10, 0, 0, 2, 0, 0},
		{"pending 负数（防御）→0", true, 10, 0, 0, 2, -1, 0},
		{"并发额度边界：cc=0（防御，store 已归一 ≥1）→0", true, 10, 0, 0, 0, 3, 0},
		{"全局 limit 被调低于 running（热改窗口）→0 不放行", true, 2, 3, 0, 2, 3, 0},
		{"多项目并行竞争全局余量：running 由调用方 tick 内自增后传入", true, 3, 2, 0, 2, 4, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := projectDispatchPlan(c.ge, c.gl, c.gr, c.pr, c.cc, c.pk); got != c.want {
				t.Fatalf("plan(%v,%d,%d,%d,%d,%d)=%d, want %d", c.ge, c.gl, c.gr, c.pr, c.cc, c.pk, got, c.want)
			}
		})
	}
}

// Step 的 nil-safe：未初始化 dispatcher（或 Server 为 nil）必须直接返回，
// 不 panic——保证零回归路径上任何调用点都无害。
func TestDispatcherStepNilSafe(t *testing.T) {
	var pd *ProjectDispatcher
	pd.Step(t.Context()) // must not panic
	(&ProjectDispatcher{}).Step(t.Context())
}
