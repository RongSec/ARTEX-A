package server

// T11 纯逻辑单测（无库）：observer 触发消息渲染（事件清单→prompt 正文、
// ≤renderEventLimit 截断、空清单防御）、fireProjectGraph 的项目分组（顺序+
// 组内保序）、validateTrigger 对新增 on_project_graph 条件的放行。全部注入
// 数据直接断言返回值，不触 PG。

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func ev(id, pid, taskID int64, kind, summary string) db.GraphEvent {
	return db.GraphEvent{ID: id, ProjectID: pid, TaskID: taskID, Kind: kind, DeltaSummary: summary}
}

func TestRenderProjectGraphMessage(t *testing.T) {
	events := []db.GraphEvent{
		ev(1, 7, 101, "finding", "task#101 finding[high]→confirmed: SQLi 于 /api/user"),
		ev(2, 7, 102, "fact", "task#102 fact→confirmed: 端口 8080 开放"),
	}
	got := renderProjectGraphMessage(7, events)
	// 头部含项目号 + 本批条数；每条摘要各占一行。
	if !strings.Contains(got, "项目 #7") {
		t.Errorf("missing project header: %q", got)
	}
	if !strings.Contains(got, "本批 2 条变更") {
		t.Errorf("missing batch count: %q", got)
	}
	for _, e := range events {
		if !strings.Contains(got, "- "+e.DeltaSummary) {
			t.Errorf("event line missing: %q\nfull=%q", e.DeltaSummary, got)
		}
	}
	// 恰 renderEventLimit 条：不出现"另有未列出"折叠行。
	full := make([]db.GraphEvent, renderEventLimit)
	for i := range full {
		full[i] = ev(int64(i+1), 1, 1, "fact", "x")
	}
	if g := renderProjectGraphMessage(1, full); strings.Contains(g, "另有") {
		t.Errorf("exactly-limit batch must not truncate: %q", g)
	}
	// 超 renderEventLimit：折叠成一行计数，正文只渲染前 N 条。
	over := append(full, ev(int64(renderEventLimit+1), 1, 1, "fact", "extra"))
	g := renderProjectGraphMessage(1, over)
	if !strings.Contains(g, "另有 1 条未列出") {
		t.Errorf("overflow must fold count: %q", g)
	}
	if strings.Contains(g, "extra") {
		t.Errorf("overflowed event must NOT be rendered verbatim: %q", g)
	}
	// 空清单：返回 ""（调用方提前拦，纯函数仍须防御）。
	if g := renderProjectGraphMessage(1, nil); g != "" {
		t.Errorf("empty events must yield empty string, got %q", g)
	}
}

func TestGroupGraphEventsByProject(t *testing.T) {
	events := []db.GraphEvent{
		ev(1, 7, 101, "finding", "a"),
		ev(2, 9, 102, "fact", "b"),
		ev(3, 7, 103, "fact", "c"), // 7 的第二条，回到 7 → 组内追加
		ev(4, 9, 104, "hint", "d"),
	}
	groups := groupGraphEventsByProject(events)
	if len(groups) != 2 {
		t.Fatalf("want 2 groups, got %d", len(groups))
	}
	// 组顺序=项目首事件出现顺序：7 在前（id=1），9 在后（id=2）。
	if groups[0].projectID != 7 || groups[1].projectID != 9 {
		t.Errorf("group order wrong: %d then %d", groups[0].projectID, groups[1].projectID)
	}
	// 组内保序（按 id 升序原样落组）：7→[1,3]，9→[2,4]。
	if len(groups[0].events) != 2 || groups[0].events[0].ID != 1 || groups[0].events[1].ID != 3 {
		t.Errorf("project 7 group events wrong: %+v", groups[0].events)
	}
	if len(groups[1].events) != 2 || groups[1].events[0].ID != 2 || groups[1].events[1].ID != 4 {
		t.Errorf("project 9 group events wrong: %+v", groups[1].events)
	}
	// 空输入→空分组。
	if g := groupGraphEventsByProject(nil); len(g) != 0 {
		t.Errorf("nil events must yield no groups, got %d", len(g))
	}
}

func TestValidateTriggerOnProjectGraph(t *testing.T) {
	// 仅 on_project_graph=true：合法（新条件计入"至少一种"）。
	on := true
	off := false
	if msg := validateTrigger(&triggerReq{OnProjectGraph: &on}); msg != "" {
		t.Errorf("on_project_graph alone must be a valid condition, got %q", msg)
	}
	// 全 false（含 on_project_graph=false）：仍报"至少一种"。
	if msg := validateTrigger(&triggerReq{OnProjectGraph: &off}); msg == "" {
		t.Error("all-false must be rejected")
	}
	// on_project_graph 缺省（nil）等同未选该条件；靠别的条件满足即可。
	if msg := validateTrigger(&triggerReq{OnFinding: true, OnProjectGraph: nil}); msg != "" {
		t.Errorf("on_finding alone must pass, got %q", msg)
	}
	// 全零值（nil 指针）：无触发条件 → 拒。
	if msg := validateTrigger(&triggerReq{}); msg == "" {
		t.Error("empty trigger must be rejected")
	}
}

// TestTriggerReqOnProjectGraphWireFormat 锁定 JSON 线格式：指针字段缺键反序列化为
// nil（PUT 表单不认识该字段时=保持原值），显式 false 反序列化为 &false（用户显式关）。
// 这是"老前端编辑别的触发器不会静默拆掉 observer 图变更开关"的核心契约。
func TestTriggerReqOnProjectGraphWireFormat(t *testing.T) {
	var absent triggerReq
	if err := json.Unmarshal([]byte(`{"on_finding":true}`), &absent); err != nil {
		t.Fatal(err)
	}
	if absent.OnProjectGraph != nil {
		t.Errorf("absent key must unmarshal to nil pointer, got %v", *absent.OnProjectGraph)
	}
	var explicitFalse triggerReq
	if err := json.Unmarshal([]byte(`{"on_finding":true,"on_project_graph":false}`), &explicitFalse); err != nil {
		t.Fatal(err)
	}
	if explicitFalse.OnProjectGraph == nil || *explicitFalse.OnProjectGraph != false {
		t.Error("explicit false must unmarshal to &false")
	}
}
