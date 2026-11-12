package server

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestProjectSettled 覆盖去抖判定纯函数的四种形态（无库）。
func TestProjectSettled(t *testing.T) {
	cases := []struct {
		name         string
		all, term    map[int64]bool
		wantSettled  bool
		wantTaskCount int
	}{
		{"空项目不算收官", map[int64]bool{}, map[int64]bool{}, false, 0},
		{"部分终态=未收官", map[int64]bool{1: true, 2: true}, map[int64]bool{1: true}, false, 2},
		{"全终态=收官", map[int64]bool{1: true, 2: true, 3: true}, map[int64]bool{1: true, 2: true, 3: true}, true, 3},
		{"单任务终态即收官", map[int64]bool{7: true}, map[int64]bool{7: true}, true, 1},
	}
	for _, c := range cases {
		settled, n := projectSettled(c.all, c.term)
		if settled != c.wantSettled || n != c.wantTaskCount {
			t.Errorf("%s: got (%v,%d), want (%v,%d)", c.name, settled, n, c.wantSettled, c.wantTaskCount)
		}
	}
	// terminal 里有多余键（不在 all 中）不影响判定：以 all 为准。
	if settled, _ := projectSettled(map[int64]bool{1: true}, map[int64]bool{1: true, 99: true}); !settled {
		t.Error("extra terminal keys must not block settlement")
	}
}

// TestEmitTaskTerminalNilShortCircuit 验证钩子未装配=零行为（原版零回归红线）。
func TestEmitTaskTerminalNilShortCircuit(t *testing.T) {
	m := &Manager{}
	// OnTaskTerminal==nil：不得 panic、不得记标记。
	m.emitTaskTerminal(1, "done")
	if _, ok := m.terminalEmitted.Load(int64(1)); ok {
		t.Fatal("nil hook must not mark the task as emitted")
	}
}

// TestEmitTaskTerminalIdempotent 验证同一任务重复终态只派发一次，
// 且非终态会清除标记允许再次收官派发。
func TestEmitTaskTerminalIdempotent(t *testing.T) {
	var mu sync.Mutex
	var got []string
	fired := make(chan struct{}, 16)
	m := &Manager{OnTaskTerminal: func(taskID int64, status string) {
		mu.Lock()
		got = append(got, status)
		mu.Unlock()
		fired <- struct{}{}
	}}
	waitFires := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			select {
			case <-fired:
			case <-time.After(2 * time.Second):
				t.Fatalf("timed out waiting for hook fire %d/%d", i+1, n)
			}
		}
	}

	m.emitTaskTerminal(42, "done")
	waitFires(1)
	// 重复派发同一任务终态：防重标记命中，第二次不得再触发。
	m.emitTaskTerminal(42, "done")
	m.emitTaskTerminal(42, "timeout")
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	if len(got) != 1 {
		mu.Unlock()
		t.Fatalf("duplicate terminal emits must fire once, got %v", got)
	}
	mu.Unlock()

	// 任务复活（非终态）→ 清标记 → 再次收官应重新派发。
	m.emitTaskTerminal(42, "running")
	m.emitTaskTerminal(42, "done")
	waitFires(1)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got[1] != "done" {
		t.Fatalf("re-settlement after revive must re-fire, got %v", got)
	}
}

// TestEmitTaskTerminalConcurrent 多协程并发派发同一任务终态只触发一次。
func TestEmitTaskTerminalConcurrent(t *testing.T) {
	var calls atomic.Int64
	fired := make(chan struct{}, 64)
	m := &Manager{OnTaskTerminal: func(int64, string) {
		calls.Add(1)
		fired <- struct{}{}
	}}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.emitTaskTerminal(7, "done")
		}()
	}
	wg.Wait()
	// 等可能的派发落地。
	time.Sleep(200 * time.Millisecond)
	if n := calls.Load(); n != 1 {
		t.Fatalf("concurrent emits must collapse to one fire, got %d", n)
	}
}
