package server

// V5-A planner 洞察闭环的宿主侧测：reject_insight 工具语义 + 跨项目条目真的
// 出现在 resolver 输出里（端到端串起 projects.reader_enabled → open 意图锚定
// 资产键 → global_insights 交集 → 渲染段）。
//
// 都是 PG 集成测（无库自动 skip，照仓库 testDSN 范式）：注入链路本质是 SQL
// 交集，纯函数测（project_insight_test.go）只覆盖渲染与筛选。

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// newInsightTestPG 打开共享开发库（跳不过就 skip），并返回一个只带 pg 与任务
// 表的 Server——resolver/工具都只依赖这两样。
func newInsightTestPG(t *testing.T) (*Server, *db.DB) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { pg.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &Server{ctx: ctx,
		m:          &Manager{pg: pg, dir: t.TempDir(), tasks: map[string]*Task{}},
		chatBusy:   map[string]bool{},
		chatCancel: map[string]context.CancelCauseFunc{}}
	return s, pg
}

// TestRejectInsightTool 验工具语义：参数校验、成功置 rejected、幂等重复否决、
// id 不存在返回「未找到」而不是错误；且否决后跨项目注入不再返回该行。
func TestRejectInsightTool(t *testing.T) {
	s, pg := newInsightTestPG(t)
	ctx := context.Background()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%1000000)
	key := "reject-tool-" + suffix + ".example.com"
	g, err := pg.WriteGlobalInsight(ctx, "跨项目洞察（待 planner 否决）", []int64{1, 2}, []string{key})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Exec(`DELETE FROM project_insights WHERE id=$1`, g.ID) //nolint:errcheck

	if l, err := pg.ListCrossProjectInsights(ctx, []string{key}, 5); err != nil || len(l) != 1 {
		t.Fatalf("前置条件：洞察应可注入，got %d err=%v", len(l), err)
	}

	tool := s.toolRejectInsight()
	call := func(input any) (string, bool) {
		t.Helper()
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		r, err := tool.Call(ctx, raw, nil)
		if err != nil {
			t.Fatalf("tool call: %v", err)
		}
		return r.Flatten(), r.IsError
	}

	// kind 非法 → 明确报错（防把两类洞察表搞混）。
	if msg, isErr := call(map[string]any{"kind": "insight", "id": g.ID}); !isErr {
		t.Errorf("非法 kind 应报错，got %q", msg)
	}
	// id 非法 → 报错（不落库）。
	if msg, isErr := call(map[string]any{"kind": "global", "id": 0}); !isErr {
		t.Errorf("非法 id 应报错，got %q", msg)
	}

	msg, isErr := call(map[string]any{"kind": "global", "id": g.ID, "reason": "该资产已被修复"})
	if isErr {
		t.Fatalf("reject 不应报错: %q", msg)
	}
	if !strings.Contains(msg, "rejected") {
		t.Errorf("确认文本应提 rejected: %q", msg)
	}
	if l, err := pg.ListCrossProjectInsights(ctx, []string{key}, 5); err != nil || len(l) != 0 {
		t.Errorf("否决后不该再被注入，got %d err=%v", len(l), err)
	}
	var status, reason string
	if err := pg.QueryRow(`SELECT status, rejected_reason FROM project_insights WHERE id=$1`, g.ID).
		Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != db.InsightStatusRejected || reason != "该资产已被修复" {
		t.Errorf("落库 status=%q reason=%q", status, reason)
	}

	// 幂等：再拒一次不报错，且不改写已有 reason。
	msg, isErr = call(map[string]any{"kind": "global", "id": g.ID, "reason": "另一个理由"})
	if isErr || !strings.Contains(msg, "无需重复否决") {
		t.Errorf("重复否决应幂等: isErr=%v msg=%q", isErr, msg)
	}
	if err := pg.QueryRow(`SELECT rejected_reason FROM project_insights WHERE id=$1`, g.ID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "该资产已被修复" {
		t.Errorf("幂等重复否决改写了 reason: %q", reason)
	}

	// id 不存在 → 文本「未找到」，不报错（planner 可继续干活）。
	msg, isErr = call(map[string]any{"kind": "global", "id": 999999999})
	if isErr || !strings.Contains(msg, "未找到") {
		t.Errorf("不存在的 id 应返回未找到文本: isErr=%v msg=%q", isErr, msg)
	}
}

// TestProjectInsightResolverInjectsProjectOnly 是 S1 的端到端验收（V7-LINK
// 口径）：项目内观察者洞察照旧按「本任务 open 意图锚定资产键」命中注入；
// 即使存在同资产的跨项目洞察、且 reader_enabled=true，也**不再自动注入**
// 【跨项目】——跨项目情报改由 planner 主动 request_reader_links 拉取（S2 移除）。
func TestProjectInsightResolverInjectsProjectOnly(t *testing.T) {
	s, pg := newInsightTestPG(t)
	ctx := context.Background()

	n := time.Now().UnixNano()
	key := fmt.Sprintf("cross-inject-%d.example.com", n%100000000)
	p, err := pg.CreateProject(db.CreateProjectInput{
		Name: fmt.Sprintf("cross-inject-%d", n%1000000), ObserverEnabled: true, ReaderEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	pid := p.ID
	task, err := s.m.CreateTaskWithOptions("resolver cross inject", "goal", db.TaskCreateOptions{ProjectID: &pid})
	if err != nil {
		t.Fatal(err)
	}
	// 造一个该资产的行，并把一个 open 意图锚到它上面——resolver 的命中键就来自这里。
	var assetID int64
	if err := pg.QueryRow(`INSERT INTO assets(type, domain) VALUES ('root_domain', $1) RETURNING id`, key).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := task.Store.AddIntent(map[string]any{"summary": "打这个资产"}, 1, []int64{assetID}, "planner"); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.WriteInsight(ctx, pid, "项目经验：该主机历史上有未认证后台", 0, []string{key}); err != nil {
		t.Fatal(err)
	}
	crossIns, err := pg.WriteGlobalInsight(ctx, "跨项目经验：同资产在另一项目已打通该入口", []int64{pid, 999}, []string{key})
	if err != nil {
		t.Fatal(err)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatalf("task id %q 不是数字: %v", task.ID, err)
	}
	t.Cleanup(func() {
		pg.Exec(`DELETE FROM project_insights WHERE id=$1`, crossIns.ID) //nolint:errcheck
		pg.Exec(`DELETE FROM tasks WHERE id=$1`, taskID)                 //nolint:errcheck
		pg.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExpID)      //nolint:errcheck
		pg.Exec(`DELETE FROM assets WHERE id=$1`, assetID)               //nolint:errcheck
		pg.Exec(`DELETE FROM projects WHERE id=$1`, pid)                 //nolint:errcheck // project_insights 级联删
	})

	got := s.projectInsightResolverFor()(taskID)
	if !strings.Contains(got, "项目经验：该主机历史上有未认证后台") {
		t.Errorf("项目洞察缺失: %q", got)
	}
	if strings.Contains(got, "【跨项目") || strings.Contains(got, "跨项目经验：同资产在另一项目已打通该入口") {
		t.Errorf("V7-LINK：跨项目条目不得再自动注入: %q", got)
	}
	if strings.Contains(got, "洞察#"+strconv.FormatInt(crossIns.ID, 10)) {
		t.Errorf("跨项目洞察 id 不该出现在注入正文: %q", got)
	}

	// observer_enabled=false → 项目洞察也不注入（reader_enabled 不再补位）。
	if _, err := pg.Exec(`UPDATE projects SET observer_enabled=false, reader_enabled=true WHERE id=$1`, pid); err != nil {
		t.Fatal(err)
	}
	if got := s.projectInsightResolverFor()(taskID); got != "" {
		t.Errorf("observer 关 / reader 开时也应为零注入，got %q", got)
	}
}

// createV5CInsightFixture 造「项目 + 任务」并注册清理；返回 project id 与数字
// taskID。V5-C 的三个障碍测试共用（名称/主机都带纳秒后缀，避免与库里既有行
// 串味，尤其是 asset_keys 交集与 global_insights 的同资产覆盖逻辑）。
func createV5CInsightFixture(t *testing.T, s *Server, pg *db.DB, label, goal string) (int64, int64) {
	t.Helper()
	n := time.Now().UnixNano()
	p, err := pg.CreateProject(db.CreateProjectInput{
		Name: fmt.Sprintf("%s-%d", label, n%1000000), ObserverEnabled: true, ReaderEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	pid := p.ID
	task, err := s.m.CreateTaskWithOptions(label, goal, db.TaskCreateOptions{ProjectID: &pid})
	if err != nil {
		t.Fatal(err)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatalf("task id %q 不是数字: %v", task.ID, err)
	}
	t.Cleanup(func() {
		pg.Exec(`DELETE FROM tasks WHERE id=$1`, taskID)            //nolint:errcheck
		pg.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExpID) //nolint:errcheck
		pg.Exec(`DELETE FROM projects WHERE id=$1`, pid)            //nolint:errcheck // project_insights 级联删
	})
	return pid, taskID
}

// insertV5CEndpoint 插一个 endpoint 资产并挂到 task_ids（V5-C 命中键来源）。
func insertV5CEndpoint(t *testing.T, pg *db.DB, host string, port int, path string, taskID int64) int64 {
	t.Helper()
	var id int64
	err := pg.QueryRow(`INSERT INTO assets(type, url, method, domain, port, task_ids)
VALUES ('endpoint', $1, 'GET', $2, $3, ARRAY[$4]::bigint[]) RETURNING id`,
		fmt.Sprintf("http://%s:%d%s", host, port, path), host, port, taskID).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Exec(`DELETE FROM assets WHERE id=$1`, id) }) //nolint:errcheck
	return id
}

// TestInsightMatchKeysThreeLevels 守 V5-C 障碍1：命中键三级并集且「任一级非空
// 即停止」——目标文本 → 任务资产 → 意图锚定（含 running）。
func TestInsightMatchKeysThreeLevels(t *testing.T) {
	s, pg := newInsightTestPG(t)
	ctx := context.Background()
	n := time.Now().UnixNano()
	goalHost := fmt.Sprintf("v5c-goal-%d.example.com", n%100000000)
	assetHost := fmt.Sprintf("v5c-asset-%d.example.com", n%100000000)
	anchorHost := fmt.Sprintf("v5c-anchor-%d.example.com", n%100000000)

	_, taskID := createV5CInsightFixture(t, s, pg, "v5c-levels",
		"对 http://"+goalHost+":9443/login.php 做未授权测试")
	tctx, err := pg.TaskInsightContext(ctx, taskID)
	if err != nil {
		t.Fatal(err)
	}

	// c 级：意图锚定与任务资产都为空，只能从目标文本提取。
	keys := s.insightMatchKeys(ctx, pg, tctx, taskID)
	if !containsKey(keys, goalHost+":9443") {
		t.Errorf("目标文本应提取出 %s:9443，got %v", goalHost, keys)
	}

	// b 级：任务资产非空后停止，不再走目标文本提取。
	insertV5CEndpoint(t, pg, assetHost, 8081, "/x.php", taskID)
	keys = s.insightMatchKeys(ctx, pg, tctx, taskID)
	if !containsKey(keys, assetHost+":8081") || !containsKey(keys, assetHost+":8081/x.php") {
		t.Errorf("任务资产应产出父子两级键，got %v", keys)
	}
	if containsKey(keys, goalHost+":9443") {
		t.Errorf("b 级非空时应停止，不该再含目标文本键: %v", keys)
	}

	// a 级：锚定意图（running——真实时序下 worker 已认领）优先于任务资产。
	anchorAsset := insertV5CEndpoint(t, pg, anchorHost, 8082, "/admin/login.php", 0)
	task, ok := s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok {
		t.Fatal("任务不在内存表")
	}
	nodeID, err := task.Store.AddIntent(map[string]any{"summary": "打这个资产"}, 1, []int64{anchorAsset}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := task.Store.SetNodeState(nodeID, "running"); err != nil {
		t.Fatal(err)
	}
	keys = s.insightMatchKeys(ctx, pg, tctx, taskID)
	if !containsKey(keys, anchorHost+":8082") {
		t.Errorf("running 意图的锚定资产应产出命中键（障碍1），got %v", keys)
	}
	if containsKey(keys, assetHost+":8081") {
		t.Errorf("a 级非空时不该再回落到任务资产: %v", keys)
	}
}

// TestCrossLevelKeyHitEndToEnd 守 V5-C 障碍2（项目内）：站点级键（host:port）
// 与页面级 endpoint 锚定必须能互相命中——项目洞察 keywords 写站点级，任务
// 锚定的是页面级 endpoint；同资产的跨项目洞察不再自动注入（V7-LINK）。
func TestCrossLevelKeyHitEndToEnd(t *testing.T) {
	s, pg := newInsightTestPG(t)
	ctx := context.Background()
	n := time.Now().UnixNano()
	host := fmt.Sprintf("v5c-cross-%d.example.com", n%100000000)

	pid, taskID := createV5CInsightFixture(t, s, pg, "v5c-cross", "打 "+host)
	assetID := insertV5CEndpoint(t, pg, host, 8081, "/admin/login.php", taskID)
	task, ok := s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok {
		t.Fatal("任务不在内存表")
	}
	if _, err := task.Store.AddIntent(map[string]any{"summary": "打登录页"}, 1, []int64{assetID}, "planner"); err != nil {
		t.Fatal(err)
	}

	siteKey := fmt.Sprintf("%s:8081", host)
	if _, err := pg.WriteInsight(ctx, pid, "项目经验：该站点后台可未授权进入", 0, []string{siteKey}); err != nil {
		t.Fatal(err)
	}
	cross, err := pg.WriteGlobalInsight(ctx, "跨项目经验：同站点同端口在别的项目已打通", []int64{pid, 999}, []string{siteKey})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Exec(`DELETE FROM project_insights WHERE id=$1`, cross.ID) }) //nolint:errcheck

	got := s.projectInsightResolverFor()(taskID)
	if !strings.Contains(got, "项目经验：该站点后台可未授权进入") {
		t.Errorf("站点级 keywords 应命中页面级锚定（障碍2）: %q", got)
	}
	if strings.Contains(got, "【跨项目") || strings.Contains(got, "跨项目经验：同站点同端口在别的项目已打通") {
		t.Errorf("V7-LINK：跨项目条目不得自动注入（即便站点级键命中）: %q", got)
	}
}

// TestProjectInsightQuotaNoCross 守 V7-LINK 的预算口径：项目洞察最多 3 条，
// 不再为跨项目条目让位（跨项目交集查询已从 resolver 移除）。
func TestProjectInsightQuotaNoCross(t *testing.T) {
	s, pg := newInsightTestPG(t)
	ctx := context.Background()
	n := time.Now().UnixNano()
	host := fmt.Sprintf("v5c-quota-%d.example.com", n%100000000)

	pid, taskID := createV5CInsightFixture(t, s, pg, "v5c-quota", "打 "+host)
	assetID := insertV5CEndpoint(t, pg, host, 8082, "/p.php", taskID)
	task, ok := s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok {
		t.Fatal("任务不在内存表")
	}
	if _, err := task.Store.AddIntent(map[string]any{"summary": "打"}, 1, []int64{assetID}, "planner"); err != nil {
		t.Fatal(err)
	}

	siteKey := fmt.Sprintf("%s:8082", host)
	for i := 0; i < 5; i++ {
		if _, err := pg.WriteInsight(ctx, pid, fmt.Sprintf("项目经验-%d", i), 0, []string{siteKey}); err != nil {
			t.Fatal(err)
		}
	}
	cross, err := pg.WriteGlobalInsight(ctx, "跨项目经验：不再自动注入", []int64{pid, 999}, []string{siteKey})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Exec(`DELETE FROM project_insights WHERE id=$1`, cross.ID) }) //nolint:errcheck

	got := s.projectInsightResolverFor()(taskID)
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != insightInjectMax {
		t.Fatalf("项目洞察应占满 %d 条（不再给跨项目留位），got %d: %q", insightInjectMax, len(lines), got)
	}
	for _, ln := range lines {
		if strings.HasPrefix(ln, "- 【跨项目") {
			t.Errorf("不得出现跨项目条目: %q", got)
		}
	}
}

// containsKey 是测试用的键集合判定（大小写不敏感，键口径与生产一致）。
func containsKey(keys []string, want string) bool {
	for _, k := range keys {
		if strings.EqualFold(strings.TrimSpace(k), want) {
			return true
		}
	}
	return false
}
