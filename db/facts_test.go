package db

// 事实台账纯函数单测（V4-A）：分组/解析/编辑合并，全程无库。

import (
	"encoding/json"
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }

func factPayload(summary, desc, detail string) json.RawMessage {
	m := map[string]any{"summary": summary}
	if desc != "" {
		m["description"] = desc
	}
	if detail != "" {
		m["detail"] = detail
	}
	raw, _ := json.Marshal(m)
	return raw
}

func TestParseFactRowUnifiedDescription(t *testing.T) {
	// worker fact：正文在 detail → 统一视图 description 回退 detail。
	r := FactRow{NodeID: 1, Payload: factPayload("s1", "", "d1"), Origin: "work#3",
		CreatedAt: time.Unix(100, 0), UpdatedAt: time.Unix(101, 0)}
	n := ParseFactRow(r)
	if n.Description != "d1" {
		t.Errorf("detail fallback: got %q want d1", n.Description)
	}
	if n.Source != "worker" {
		t.Errorf("work#3 → worker, got %q", n.Source)
	}
	// origin fact：description 在，优先生效。
	r2 := FactRow{NodeID: 2, Payload: factPayload("s2", "d2", "ignored"), Origin: "system",
		CreatedAt: time.Unix(100, 0), UpdatedAt: time.Unix(101, 0)}
	if n2 := ParseFactRow(r2); n2.Description != "d2" {
		t.Errorf("description priority: got %q want d2", n2.Description)
	}
	// main agent 直写（origin=human）→ 来源 human。
	r3 := FactRow{NodeID: 3, Payload: factPayload("s3", "", ""), Origin: "human"}
	if n3 := ParseFactRow(r3); n3.Source != "human" {
		t.Errorf("origin human → source human, got %q", n3.Source)
	}
	// 任务起点种子（state='origin'）→ OriginFact=true（裁决④：保留+灰徽，不排除）。
	r0 := FactRow{NodeID: 30, Payload: factPayload("任务起点", "d", ""), Origin: "system", State: StateOrigin}
	if n0 := ParseFactRow(r0); !n0.OriginFact {
		t.Errorf("state=origin → OriginFact true, got false")
	}
	if n := ParseFactRow(FactRow{NodeID: 31, Payload: factPayload("s", "", ""), Origin: "work#1", State: "confirmed"}); n.OriginFact {
		t.Errorf("state=confirmed must not be OriginFact")
	}
	// observer 分支（当前无写入方，契约保留）。
	r4 := FactRow{NodeID: 4, Payload: factPayload("s4", "", ""), Origin: "observer"}
	if n4 := ParseFactRow(r4); n4.Source != "observer" {
		t.Errorf("origin observer → source observer, got %q", n4.Source)
	}
	// 人工编辑过的 worker fact → 来源升级为 human，且 machine_original 解出。
	pj := map[string]any{"summary": "改后", "detail": "旧详情",
		"edited_by": "human", "machine_original": map[string]any{"summary": "旧摘要", "description": "旧详情"}}
	raw, _ := json.Marshal(pj)
	r5 := FactRow{NodeID: 5, Payload: raw, Origin: "work#1"}
	n5 := ParseFactRow(r5)
	if n5.Source != "human" || !n5.Edited {
		t.Errorf("edited fact: source=%q edited=%v", n5.Source, n5.Edited)
	}
	if n5.MachineOriginal == nil || n5.MachineOriginal.Summary != "旧摘要" || n5.MachineOriginal.Description != "旧详情" {
		t.Errorf("machine_original not parsed: %+v", n5.MachineOriginal)
	}
}

func TestGroupFactRows(t *testing.T) {
	// 输入按 fact id DESC。P1 两任务交错出现（T1/T2 首见序=T1 在前因 id 更大者属 T1：
	// rows: f5(T1,P1) f4(T2,P1) f3(T2,P1) f2(T0,nil) f1(T1,P1)——
	// 项目首见：P1(第一行) 先、未挂项目 后；P1 内任务首见 T1 先 T2 后；
	// 组内事实保持输入倒序。
	p1, p1b := int64(7), int64(7)
	rows := []FactRow{
		{NodeID: 5, Payload: factPayload("f5", "", ""), Origin: "work#1", TaskID: 1, TaskName: "T1", TaskStatus: "done", ProjectID: &p1, ProjectName: "P1"},
		{NodeID: 4, Payload: factPayload("f4", "", ""), Origin: "work#2", TaskID: 2, TaskName: "T2", TaskStatus: "running", ProjectID: &p1b, ProjectName: "P1"},
		{NodeID: 3, Payload: factPayload("f3", "", ""), Origin: "work#2", TaskID: 2, TaskName: "T2", TaskStatus: "running", ProjectID: &p1b, ProjectName: "P1"},
		{NodeID: 2, Payload: factPayload("f2", "", ""), Origin: "system", TaskID: 9, TaskName: "T0", TaskStatus: "created", ProjectID: nil},
		{NodeID: 1, Payload: factPayload("f1", "", ""), Origin: "work#1", TaskID: 1, TaskName: "T1", TaskStatus: "done", ProjectID: &p1, ProjectName: "P1"},
	}
	anchors := map[int64][]FactAnchor{
		5: {{ID: 11, Type: "ip", Label: "10.0.0.1"}},
	}
	groups := GroupFactRows(rows, anchors)
	if len(groups) != 2 {
		t.Fatalf("want 2 project groups, got %d", len(groups))
	}
	g0, g1 := groups[0], groups[1]
	if g0.ProjectID == nil || *g0.ProjectID != 7 || g0.ProjectName != "P1" {
		t.Errorf("first group should be P1, got %+v", g0)
	}
	if g1.ProjectID != nil {
		t.Errorf("last group should be unassigned, got project_id=%v", *g1.ProjectID)
	}
	if len(g0.Tasks) != 2 || g0.Tasks[0].TaskID != 1 || g0.Tasks[1].TaskID != 2 {
		t.Fatalf("task order wrong: %+v", g0.Tasks)
	}
	if len(g0.Tasks[0].Facts) != 2 || g0.Tasks[0].Facts[0].ID != 5 || g0.Tasks[0].Facts[1].ID != 1 {
		t.Errorf("facts order wrong: %+v", g0.Tasks[0].Facts)
	}
	if len(g0.Tasks[1].Facts) != 2 {
		t.Errorf("T2 facts want 2, got %d", len(g0.Tasks[1].Facts))
	}
	if len(g1.Tasks) != 1 || g1.Tasks[0].TaskID != 9 || len(g1.Tasks[0].Facts) != 1 {
		t.Errorf("unassigned group wrong: %+v", g1.Tasks)
	}
	// 锚点按 node 挂载。
	if len(g0.Tasks[0].Facts[0].Anchors) != 1 || g0.Tasks[0].Facts[0].Anchors[0].Label != "10.0.0.1" {
		t.Errorf("anchor attach wrong: %+v", g0.Tasks[0].Facts[0].Anchors)
	}
	// 空输入 → nil。
	if GroupFactRows(nil, nil) != nil {
		t.Error("empty rows should group to nil")
	}
}

func TestMergeFactEditFirstEditKeepsMachineOriginal(t *testing.T) {
	existing := factPayload("机器摘要", "", "机器详情")
	out, err := MergeFactEdit(existing, KindFact, FactEditPatch{Summary: ptr("人改摘要")})
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(out, &p); err != nil {
		t.Fatal(err)
	}
	if p["summary"] != "人改摘要" {
		t.Errorf("summary not applied: %v", p["summary"])
	}
	if p["edited_by"] != "human" {
		t.Errorf("edited_by missing: %v", p["edited_by"])
	}
	mo, ok := p["machine_original"].(map[string]any)
	if !ok {
		t.Fatalf("machine_original missing: %v", p["machine_original"])
	}
	// 原文回退链：description 缺省存 detail。
	if mo["summary"] != "机器摘要" || mo["description"] != "机器详情" {
		t.Errorf("machine_original wrong: %v", mo)
	}
	// 白名单外键不动：detail 保留。
	if p["detail"] != "机器详情" {
		t.Errorf("detail should be untouched: %v", p["detail"])
	}
}

func TestMergeFactEditSecondEditDoesNotOverwriteOriginal(t *testing.T) {
	first, err := MergeFactEdit(factPayload("机器摘要", "机器描述", ""), KindFact,
		FactEditPatch{Summary: ptr("第一次改")})
	if err != nil {
		t.Fatal(err)
	}
	second, err := MergeFactEdit(first, KindFact, FactEditPatch{Summary: ptr("第二次改"), Description: ptr("新描述")})
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	_ = json.Unmarshal(second, &p)
	mo := p["machine_original"].(map[string]any)
	if mo["summary"] != "机器摘要" || mo["description"] != "机器描述" {
		t.Errorf("second edit must not touch machine_original: %v", mo)
	}
	if p["summary"] != "第二次改" || p["description"] != "新描述" {
		t.Errorf("fields not applied: %v", p)
	}
}

func TestMergeFactEditRejectsNonFact(t *testing.T) {
	for _, kind := range []string{"intent", "finding", "goal", "hint"} {
		if _, err := MergeFactEdit(factPayload("s", "", ""), kind, FactEditPatch{Summary: ptr("x")}); err == nil {
			t.Errorf("kind=%s should be rejected", kind)
		}
	}
}

func TestMergeFactEditCategory(t *testing.T) {
	// 合法枚举 → 落键。
	out, err := MergeFactEdit(factPayload("s", "", ""), KindFact, FactEditPatch{Category: ptr("凭据")})
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	_ = json.Unmarshal(out, &p)
	if p["category"] != "凭据" {
		t.Errorf("category not stored: %v", p["category"])
	}
	// 空串 → 删键（展示回"其他"）。
	out2, err := MergeFactEdit(out, KindFact, FactEditPatch{Category: ptr("")})
	if err != nil {
		t.Fatal(err)
	}
	var p2 map[string]any
	_ = json.Unmarshal(out2, &p2)
	if _, exists := p2["category"]; exists {
		t.Errorf("empty category should delete key: %v", p2["category"])
	}
	// 非法值 → 报错且不落盘。
	if _, err := MergeFactEdit(factPayload("s", "", ""), KindFact, FactEditPatch{Category: ptr("不存在的类别")}); err == nil {
		t.Error("invalid category should error")
	}
}

func TestMergeFactEditInvalidPayload(t *testing.T) {
	if _, err := MergeFactEdit(json.RawMessage(`{bad`), KindFact, FactEditPatch{Summary: ptr("x")}); err == nil {
		t.Error("invalid existing json should error")
	}
	// 空 payload 视为 {}。
	out, err := MergeFactEdit(nil, KindFact, FactEditPatch{Summary: ptr("x")})
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	_ = json.Unmarshal(out, &p)
	if p["summary"] != "x" {
		t.Errorf("empty payload: %v", p)
	}
}

func TestValidFactCategory(t *testing.T) {
	if !ValidFactCategory("") {
		t.Error("empty is valid (means 其他)")
	}
	for _, o := range FactCategoryOptions {
		if !ValidFactCategory(o) {
			t.Errorf("option %q should be valid", o)
		}
	}
	if ValidFactCategory("随便写的") {
		t.Error("unknown category should be invalid")
	}
}
