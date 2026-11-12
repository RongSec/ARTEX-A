package server

// T10 纯逻辑单测（无库）：攒批阈值、归属/开关过滤、drop 限频告警、
// exploration→project 缓存骨架的命中/miss/失败不缓存三条路径、事件摘要
// 拼法与 digest 载荷。全部注入 fake/零值对象，不触 PG。

import (
	"encoding/json"
	"reflect"
	"sync"
	"testing"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
)

func evOf(expID, nodeID int64, kind, state string) indexedEvent {
	return indexedEvent{taskID: 100 + expID, ev: pgdb.GraphChange{
		ExplorationID: expID, NodeID: nodeID, Kind: kind, State: state,
	}}
}

func TestFilterAdmitted(t *testing.T) {
	// [已核实 T12 定稿] 投影常开：消费侧只按归属过滤（查询失败/无归属丢弃），
	// 不再过 observer_enabled——关闭观察者的项目也要能看大图（T11 的触发过滤
	// 在 scheduler JOIN projects 处，不在这里）。
	batch := []indexedEvent{
		evOf(1, 10, pgdb.KindFact, "confirmed"),    // 归属查询失败 → 丢（下条自愈）
		evOf(2, 20, pgdb.KindFact, "confirmed"),    // pid=0（原版任务/已摘除）→ 丢
		evOf(3, 30, pgdb.KindGoal, "open"),         // pid=8（开关关的项目）→ 过（投影常开）
		evOf(4, 40, pgdb.KindFinding, "confirmed"), // pid=7 → 过
		evOf(4, 41, pgdb.KindIntent, "done"),       // 同项目第二条 → 过（平行数组对齐）
	}
	resolve := func(expID int64) (int64, bool) {
		switch expID {
		case 1:
			return 0, false
		case 2:
			return 0, true
		case 3:
			return 8, true
		default:
			return 7, true
		}
	}

	rows, pids := filterAdmitted(batch, resolve)
	if len(rows) != 3 || len(pids) != 3 {
		t.Fatalf("admitted len=%d/%d want 3/3", len(rows), len(pids))
	}
	if rows[0].ev.NodeID != 30 || rows[1].ev.NodeID != 40 || rows[2].ev.NodeID != 41 {
		t.Errorf("wrong rows survived: %v, %v, %v", rows[0].ev.NodeID, rows[1].ev.NodeID, rows[2].ev.NodeID)
	}
	if pids[0] != 8 || pids[1] != 7 || pids[2] != 7 {
		t.Errorf("pids misaligned: %v", pids)
	}

	// 全部无归属 → 空。
	none := func(int64) (int64, bool) { return 0, true }
	rows, pids = filterAdmitted(batch, none)
	if len(rows) != 0 || len(pids) != 0 {
		t.Errorf("all-unowned must yield empty, got %d/%d", len(rows), len(pids))
	}
}

func TestShouldFlushNow(t *testing.T) {
	if shouldFlushNow(indexBatchMax-1, indexBatchMax) {
		t.Error("must not flush below threshold")
	}
	if !shouldFlushNow(indexBatchMax, indexBatchMax) {
		t.Error("must flush at threshold")
	}
	if !shouldFlushNow(indexBatchMax+5, indexBatchMax) {
		t.Error("must flush above threshold")
	}
	if shouldFlushNow(0, indexBatchMax) {
		t.Error("empty batch must not trigger count-flush (time window owns it)")
	}
}

func TestEnqueueNonBlockingAndDropCount(t *testing.T) {
	// 小容量通道模拟"满"：入队必须永不阻塞，溢出只加计数。
	ix := &ProjectIndexer{ch: make(chan indexedEvent, 2)}
	ix.Enqueue(1, pgdb.GraphChange{NodeID: 1})
	ix.Enqueue(1, pgdb.GraphChange{NodeID: 2})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ix.Enqueue(1, pgdb.GraphChange{NodeID: 3}) // 第 3 条：满 → drop
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Enqueue blocked on a full channel")
	}
	if got := ix.drops.Load(); got != 1 {
		t.Errorf("drops=%d want 1", got)
	}
	if n := len(ix.ch); n != 2 {
		t.Errorf("queued=%d want 2", n)
	}

	// nil indexer：调用无害（链路未启用时的热路径形态）。
	var nilIx *ProjectIndexer
	nilIx.Enqueue(1, pgdb.GraphChange{}) // must not panic
}

func TestMaybeWarnDropRateLimit(t *testing.T) {
	base := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	cur := base
	ix := &ProjectIndexer{now: func() time.Time { return cur }}

	if !ix.maybeWarnDrop(1) {
		t.Fatal("first drop must warn")
	}
	cur = base.Add(indexWarnEvery / 2)
	if ix.maybeWarnDrop(9) {
		t.Error("second call inside window must not warn")
	}
	cur = base.Add(indexWarnEvery + time.Millisecond)
	if !ix.maybeWarnDrop(10) {
		t.Error("call after window must warn again")
	}
	// 并发同时到点：CAS 保证同一时刻至多一条告警。
	var wg sync.WaitGroup
	hits := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hits <- ix.maybeWarnDrop(20)
		}()
	}
	wg.Wait()
	close(hits)
	// 此刻距上次告警 < 30s，8 个 goroutine 都应静默。
	for h := range hits {
		if h {
			t.Error("warn fired inside rate-limit window")
		}
	}
}

func TestCachedResolve(t *testing.T) {
	var m sync.Map
	loads := 0

	// miss → loader 成功 → 写缓存；同 key 再查命中缓存，loader 不再被调。
	v, ok, fromCache := cachedResolve[int64](&m, 5, func() (int64, bool) { loads++; return 42, true })
	if v != 42 || !ok || fromCache || loads != 1 {
		t.Fatalf("first resolve: v=%v ok=%v cached=%v loads=%d", v, ok, fromCache, loads)
	}
	v, ok, fromCache = cachedResolve[int64](&m, 5, func() (int64, bool) { loads++; return -1, true })
	if v != 42 || !ok || !fromCache || loads != 1 {
		t.Fatalf("second resolve must hit cache: v=%v ok=%v cached=%v loads=%d", v, ok, fromCache, loads)
	}

	// loader 失败 → ok=false 且不写缓存：下次仍会重查（自愈语义）。
	_, ok, _ = cachedResolve[int64](&m, 6, func() (int64, bool) { return 0, false })
	if ok {
		t.Fatal("failed load must report ok=false")
	}
	loads2 := 0
	v, ok, _ = cachedResolve[int64](&m, 6, func() (int64, bool) { loads2++; return 9, true })
	if v != 9 || !ok || loads2 != 1 {
		t.Fatalf("failed load must not poison cache: v=%v ok=%v loads=%d", v, ok, loads2)
	}

	// 零值命中（"无归属=0"也走缓存）：确认泛型对 int64 零值不误判 miss。
	_, _, _ = cachedResolve[int64](&m, 7, func() (int64, bool) { return 0, true })
	v, ok, fromCache = cachedResolve[int64](&m, 7, func() (int64, bool) { t.Fatal("loader must not run for cached zero"); return 0, true })
	if v != 0 || !ok || !fromCache {
		t.Fatalf("cached zero: v=%v ok=%v cached=%v", v, ok, fromCache)
	}

	// 失效：Delete 后 loader 重新执行（挂/摘项目钩子语义）。键须与 Store 时
	// 同为 int64——sync.Map 按动态类型比较，int(7) 删不掉 int64(7)。
	m.Delete(int64(7))
	v, ok, _ = cachedResolve[int64](&m, 7, func() (int64, bool) { return 3, true })
	if v != 3 || !ok {
		t.Fatalf("after invalidate loader must rerun: v=%v ok=%v", v, ok)
	}

	// bool 值型：false 也是"有效缓存值"而非 miss（泛型骨架的通用契约；
	// T12 投影常开删掉了 projGate 用例，骨架保留给 taskPID 与后续复用）。
	var gm sync.Map
	_, _, _ = cachedResolve[bool](&gm, 1, func() (bool, bool) { return false, true })
	b, ok, fromCache := cachedResolve[bool](&gm, 1, func() (bool, bool) { t.Fatal("loader rerun"); return true, true })
	if b || !ok || !fromCache {
		t.Fatalf("cached false must hit: b=%v ok=%v cached=%v", b, ok, fromCache)
	}
}

func TestGraphDeltaSummary(t *testing.T) {
	// 纯 kind（AddNode 初始事件常无终态/severity/摘要）不留悬空箭头/冒号。
	if got := graphDeltaSummary(9, "intent", "", "", ""); got != "task#9 intent" {
		t.Errorf("bare kind got %q want %q", got, "task#9 intent")
	}
	// severity/状态/摘要的组合形态钉死（observer 触发语的可读性依赖这个格式）。
	got := graphDeltaSummary(7, "finding", "confirmed", "high", "SQLi 于 /api/user")
	if want := "task#7 finding[high]→confirmed: SQLi 于 /api/user"; got != want {
		t.Errorf("got %q want %q", got, want)
	}
	// 有状态无 severity：跳过方括号段。
	if got := graphDeltaSummary(3, "goal", "met", "", ""); got != "task#3 goal→met" {
		t.Errorf("got %q want %q", got, "task#3 goal→met")
	}
}

func TestGraphChangeDigest(t *testing.T) {
	ev := pgdb.GraphChange{ExplorationID: 11, NodeID: 22, Kind: pgdb.KindFact, State: "confirmed", AssetIDs: []int64{3, 4}}
	raw := graphChangeDigest(5, ev)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("digest not valid json: %v", err)
	}
	want := map[string]any{"exploration_id": 11.0, "source_task_id": 5.0, "node_id": 22.0, "asset_ids": []any{3.0, 4.0}}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("digest=%v want %v", m, want)
	}
}
