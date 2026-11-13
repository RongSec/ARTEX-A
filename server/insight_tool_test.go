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
	defer pg.Exec(`DELETE FROM global_insights WHERE id=$1`, g.ID) //nolint:errcheck

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
	if err := pg.QueryRow(`SELECT status, rejected_reason FROM global_insights WHERE id=$1`, g.ID).
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
	if err := pg.QueryRow(`SELECT rejected_reason FROM global_insights WHERE id=$1`, g.ID).Scan(&reason); err != nil {
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

// TestProjectInsightResolverInjectsCrossProject 是 A1 的端到端验收：同一项目
// 里（observer 洞察 + 跨项目洞察）都按「本任务 open 意图锚定资产键」命中，
// resolver 输出项目洞察在前、跨项目条目在后并带不确定性标注；把
// projects.reader_enabled 关掉后跨项目条目消失（项目洞察保留）。
func TestProjectInsightResolverInjectsCrossProject(t *testing.T) {
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
	projIns, err := pg.WriteInsight(ctx, pid, "项目经验：该主机历史上有未认证后台", 0, []string{key})
	if err != nil {
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
		pg.Exec(`DELETE FROM global_insights WHERE id=$1`, crossIns.ID) //nolint:errcheck
		pg.Exec(`DELETE FROM tasks WHERE id=$1`, taskID)                //nolint:errcheck
		pg.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExpID)     //nolint:errcheck
		pg.Exec(`DELETE FROM assets WHERE id=$1`, assetID)              //nolint:errcheck
		pg.Exec(`DELETE FROM projects WHERE id=$1`, pid)                //nolint:errcheck // project_insights 级联删
	})
	_ = projIns

	got := s.projectInsightResolverFor()(taskID)
	if !strings.Contains(got, "项目经验：该主机历史上有未认证后台") {
		t.Errorf("项目洞察缺失: %q", got)
	}
	if !strings.Contains(got, "【跨项目】") || !strings.Contains(got, "跨项目经验：同资产在另一项目已打通该入口") {
		t.Errorf("跨项目条目缺失: %q", got)
	}
	if !strings.Contains(got, "来自其他项目，仅作假设，须在本目标验证）") {
		t.Errorf("跨项目条目缺不确定性标注: %q", got)
	}
	if !strings.Contains(got, fmt.Sprintf("洞察#%d", crossIns.ID)) {
		t.Errorf("跨项目条目应带洞察 id（reject_insight 的句柄）: %q", got)
	}
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines (项目在前/跨项目在后), got %d: %q", len(lines), got)
	}
	if !strings.HasPrefix(lines[0], "- 来源任务#") && !strings.HasPrefix(lines[0], "- 项目经验") {
		t.Errorf("line0 应是项目洞察: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "- 【跨项目】") {
		t.Errorf("line1 应是跨项目条目（项目洞察优先占位）: %q", lines[1])
	}

	// reader_enabled=false → 跨项目条目不注入（opt-in 门控），项目洞察不受影响。
	if _, err := pg.Exec(`UPDATE projects SET reader_enabled=false WHERE id=$1`, pid); err != nil {
		t.Fatal(err)
	}
	got = s.projectInsightResolverFor()(taskID)
	if strings.Contains(got, "【跨项目】") {
		t.Errorf("reader_enabled=false 时不应注入跨项目条目: %q", got)
	}
	if !strings.Contains(got, "项目经验：该主机历史上有未认证后台") {
		t.Errorf("关掉 reader_enabled 不该影响 observer 洞察: %q", got)
	}
}
