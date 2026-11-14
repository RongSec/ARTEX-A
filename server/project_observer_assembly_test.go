package server

import (
	"context"
	"testing"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// 跨任务阅读者/跨项目阅读者的六个专用工具名（口径与 project_observer.go 的 seed
// 绑定列表一致）。
//
// 回归背景（2026-11-11 实跑发现）：六工具在 DB 侧已 SeedTool 入库并经
// AddAgentToToolBinding 绑定 observer/reader（tools 表绑定行 enabled=true），
// 但运行时装配链不含它们——server/assembly.go 的 wireAgentAugment 只装配
// skills+MCP+hostTools，而 hostTools() 当时仅聚合 orchestration/retest/
// platform/custom 四类；assembly.go 里 ToolResolve 的「DB 已绑定但运行列表
// 缺失 → 从 domainReg 补注」兜底又只覆盖 agent.BuiltinToolSeeds() 注册进
// domainReg 的域工具，observer 六工具从未进 domainReg，因此永远补不上，
// 触发会话里 agent 只能即兴自救（对照：reporter 的 update_finding_report
// 等可用，正是 orchestrationTools() 真实提供了实例）。
//
// 修复 = 把 projectObserverTools()/projectReaderTools() 并入 hostTools()。
// 以下两个测分别守住该不变式的两层：
//  1. 聚合出口自身的工具集（无库可跑）——名字/数量是 hostTools 并入的前提；
//  2. 装配链出口 hostTools()（需 PG，与仓库现有 orchestration/retest 测同
//     守卫）——六个工具名必须出现在喂给 ToolAugment 的全量列表里。
//     注意此测刻意不看 tools 表绑定：provider 全量提供、按 agent 过滤是
//     ToolResolve 的既有职责，这里只证明「运行列表不再缺实例」。
var (
	projectObserverToolNames = []string{
		"query_project_index", "get_task_graph_digest", "write_project_insight", "push_task_hint",
	}
	projectReaderToolNames = []string{
		"read_all_project_insights", "write_global_insight",
	}
)

func toolNameSet(ts []actool.CoreTool) map[string]bool {
	m := make(map[string]bool, len(ts))
	for _, t := range ts {
		m[t.Name()] = true
	}
	return m
}

// assertNamesPresent fails when any want name is missing from got.
func assertNamesPresent(t *testing.T, from string, got map[string]bool, want []string) {
	t.Helper()
	for _, n := range want {
		if !got[n] {
			t.Errorf("%s 缺少工具 %q（装配链缺实例 → 该 agent 运行时调不到）", from, n)
		}
	}
}

// TestProjectToolsAggregates 无库守卫地校验两聚合出口：这是 seed 入库与
// hostTools 并入共用的单源列表，名字写错/漏一个都会在此暴露。
func TestProjectToolsAggregates(t *testing.T) {
	// 构造工具实例只是建闭包，不解引用 pg，故无需数据库。
	s := &Server{m: &Manager{tasks: map[string]*Task{}}}

	obs := toolNameSet(s.projectObserverTools())
	assertNamesPresent(t, "projectObserverTools()", obs, projectObserverToolNames)
	if len(s.projectObserverTools()) != len(projectObserverToolNames) {
		t.Errorf("projectObserverTools() = %d 个，期望 %d 个", len(s.projectObserverTools()), len(projectObserverToolNames))
	}

	rd := toolNameSet(s.projectReaderTools())
	assertNamesPresent(t, "projectReaderTools()", rd, projectReaderToolNames)
	if len(s.projectReaderTools()) != len(projectReaderToolNames) {
		t.Errorf("projectReaderTools() = %d 个，期望 %d 个", len(s.projectReaderTools()), len(projectReaderToolNames))
	}
}

// TestHostToolsIncludesProjectTools 断言喂给 ToolAugment 的装配出口 hostTools()
// 含 observer/reader 全部六个工具名。hostTools() 会经 customTools() 读自定义
// 工具表，故与仓库现有 orchestration/retest 测一样用 PG skip 守卫。
func TestHostToolsIncludesProjectTools(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{ctx: ctx,
		m:          &Manager{pg: pg, dir: t.TempDir(), tasks: map[string]*Task{}},
		chatBusy:   map[string]bool{},
		chatCancel: map[string]context.CancelCauseFunc{}}

	tools, deferred := s.hostTools()
	got := toolNameSet(tools)
	assertNamesPresent(t, "hostTools()", got, projectObserverToolNames)
	assertNamesPresent(t, "hostTools()", got, projectReaderToolNames)

	// 六工具不得被标为 deferred：它们该像 reporter 工具一样从会话开始即可调用
	// （deferred 只属于用户自建且显式勾选 deferred 的 custom tool）。
	for _, n := range append(append([]string{}, projectObserverToolNames...), projectReaderToolNames...) {
		if _, ok := deferred[n]; ok {
			t.Errorf("hostTools() 把 observer/reader 工具 %q 误标为 deferred", n)
		}
	}
}
