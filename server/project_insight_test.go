package server

// T12 纯逻辑单测（无库）：项目洞察注入正文的渲染（格式/来源回链/rune 截断/
// 空列表）。限量 ≤3 由调用方（resolver 传给 ListInsights 的 limit）保证，
// 这里断言渲染器对任意长度列表的忠实输出；命中排序在 db.ListInsights 的
// matchKeywords SQL 侧（T09 已测交集语义）。

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

func TestRenderProjectInsights(t *testing.T) {
	list := []db.Insight{
		{Content: "canal v1.1.5 未认证RCE已验证，可借鉴", SourceTaskID: 12},
		{Content: "同一 nginx 指纹的后台入口在 3 号任务已打通", SourceTaskID: 3},
	}
	got := renderProjectInsights(list)
	lines := strings.Split(got, "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), got)
	}
	// 每条带项目符号与「来源任务#N：」前缀（任务书 T12-3 钉死的格式）。
	if !strings.HasPrefix(lines[0], "- 来源任务#12：") || !strings.Contains(lines[0], "canal v1.1.5") {
		t.Errorf("line0 format wrong: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "- 来源任务#3：") {
		t.Errorf("line1 source prefix missing: %q", lines[1])
	}

	// SourceTaskID<=0：省略来源段（observer 批量/未知来源）。
	got2 := renderProjectInsights([]db.Insight{{Content: "通用经验", SourceTaskID: 0}})
	if got2 != "- 通用经验" {
		t.Errorf("no-source line = %q want %q", got2, "- 通用经验")
	}

	// 空列表→空串（resolver 靠它决定整段不出现）。
	if g := renderProjectInsights(nil); g != "" {
		t.Errorf("nil must render empty, got %q", g)
	}
	if g := renderProjectInsights([]db.Insight{}); g != "" {
		t.Errorf("empty slice must render empty, got %q", g)
	}

	// 正文按 rune 截断：205 个汉字截到 200 + 省略号（绝不切半字节——rune 截）。
	long := strings.Repeat("经", insightInjectMaxRunes+5)
	out := renderProjectInsights([]db.Insight{{Content: long}})
	body := strings.TrimPrefix(out, "- ")
	body = strings.TrimSuffix(body, "…")
	if utf8.RuneCountInString(body) != insightInjectMaxRunes {
		t.Errorf("truncated body rune count = %d want %d", utf8.RuneCountInString(body), insightInjectMaxRunes)
	}
	if !strings.HasSuffix(out, "…") {
		t.Errorf("truncated line must end with ellipsis, got tail %q", out[len(out)-8:])
	}
	// 短正文不截、不加省略号。
	short := renderProjectInsights([]db.Insight{{Content: "短经验"}})
	if strings.Contains(short, "…") {
		t.Errorf("short content must not gain ellipsis: %q", short)
	}

	// 正文首尾空白被 trim（防 observer 写入带换行的脏内容破坏注入段版式）。
	ws := renderProjectInsights([]db.Insight{{Content: "\n  带空白  \n"}})
	if ws != "- 带空白" {
		t.Errorf("whitespace not trimmed: %q", ws)
	}
}

// TestRenderCrossProjectInsight 守 V5-A 跨项目条目的渲染口径：前缀、来源项目
// 引用、不确定性标注、rune 截断（与项目洞察共用同一截断实现）。
func TestRenderCrossProjectInsight(t *testing.T) {
	list := []db.GlobalInsight{
		{ID: 12, Content: "canal v1.1.5 未认证RCE在 #1 已打通，同版本组件可复用", SourceProjects: []int64{2, 3}},
		{ID: 9, Content: "10.0.0.8:8080 的弱口令面与 #7 一致", SourceProjects: []int64{7}},
	}
	got := renderCrossProjectInsight(list)
	lines := strings.Split(got, "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), got)
	}
	if !strings.HasPrefix(lines[0], "- 【跨项目】来源项目#2/#3：") {
		t.Errorf("line0 prefix wrong: %q", lines[0])
	}
	if !strings.HasSuffix(lines[0], "（洞察#12，来自其他项目，仅作假设，须在本目标验证）") {
		t.Errorf("line0 must carry insight id + uncertainty marker: %q", lines[0])
	}
	if !strings.Contains(lines[1], "来源项目#7：") || !strings.Contains(lines[1], "洞察#9") {
		t.Errorf("single source ref / id wrong: %q", lines[1])
	}

	// 无来源项目（历史/异常行）：省来源段，但保留【跨项目】与标注。
	noSrc := renderCrossProjectInsight([]db.GlobalInsight{{Content: "同组件指纹"}})
	if !strings.HasPrefix(noSrc, "- 【跨项目】同组件指纹（来自其他项目") {
		t.Errorf("no-source render wrong: %q", noSrc)
	}

	// 截断：正文按 rune 截 200 + 省略号，标注仍完整跟在后面。
	long := strings.Repeat("验", insightInjectMaxRunes+5)
	out := renderCrossProjectInsight([]db.GlobalInsight{{Content: long, SourceProjects: []int64{1}}})
	body := strings.TrimPrefix(out, "- 【跨项目】来源项目#1：")
	body = strings.TrimSuffix(body, "（来自其他项目，仅作假设，须在本目标验证）")
	if !strings.HasSuffix(body, "…") {
		t.Fatalf("truncated body must end with ellipsis: tail %q", body[len(body)-6:])
	}
	if n := utf8.RuneCountInString(strings.TrimSuffix(body, "…")); n != insightInjectMaxRunes {
		t.Errorf("truncated body rune count = %d want %d", n, insightInjectMaxRunes)
	}

	// 空列表 → 空串（resolver 靠它决定整段不出现）。
	if g := renderCrossProjectInsight(nil); g != "" {
		t.Errorf("nil must render empty, got %q", g)
	}
}

// TestRenderInsightCarriesID 守「注入行带洞察 id」——reject_insight 只能靠它
// 定位；「来源任务#N」是任务 id，不是洞察 id（历史格式里两者混用易误判）。
func TestRenderInsightCarriesID(t *testing.T) {
	proj := renderProjectInsights([]db.Insight{{ID: 31, Content: "经验", SourceTaskID: 7}})
	if proj != "- 来源任务#7：经验（洞察#31）" {
		t.Errorf("project line with id = %q", proj)
	}
	cross := renderCrossProjectInsight([]db.GlobalInsight{{ID: 42, Content: "经验", SourceProjects: []int64{2}}})
	if cross != "- 【跨项目】来源项目#2：经验（洞察#42，来自其他项目，仅作假设，须在本目标验证）" {
		t.Errorf("cross line with id = %q", cross)
	}
}

// TestFilterInjectableCross 守跨项目注入的筛选语义（纯函数，无库）：
// reader_enabled=false 全空、status≠active 剔除、asset_keys 不交为空、
// 剩余名额截断。
func TestFilterInjectableCross(t *testing.T) {
	match := []string{"Canal.Example.com", "10.0.0.8"}
	rows := []db.GlobalInsight{
		{ID: 1, Content: "命中且 active", AssetKeys: []string{"canal.example.com"}, Status: db.InsightStatusActive},
		{ID: 2, Content: "命中但被否决", AssetKeys: []string{"canal.example.com"}, Status: db.InsightStatusRejected},
		{ID: 3, Content: "命中但被覆盖", AssetKeys: []string{"canal.example.com"}, Status: db.InsightStatusSuperseded},
		{ID: 4, Content: "不交", AssetKeys: []string{"other.example.com"}, Status: db.InsightStatusActive},
		{ID: 5, Content: "无键", AssetKeys: nil, Status: db.InsightStatusActive},
		{ID: 6, Content: "零值 status 按 active", AssetKeys: []string{"10.0.0.8"}},
	}

	// reader_enabled=false → 一条都不注入（与写出侧 opt-in 同阈）。
	if got := filterInjectableCross(rows, match, false, 3); len(got) != 0 {
		t.Fatalf("reader off must inject nothing, got %d 条", len(got))
	}
	// 本任务无锚定键 → 跨项目经验无据可验，不注入。
	if got := filterInjectableCross(rows, nil, true, 3); len(got) != 0 {
		t.Fatalf("empty match must inject nothing, got %d 条", len(got))
	}
	if got := filterInjectableCross(rows, []string{"  "}, true, 3); len(got) != 0 {
		t.Fatalf("blank match must inject nothing, got %d 条", len(got))
	}

	got := filterInjectableCross(rows, match, true, insightInjectMax)
	if len(got) != 2 || got[0].ID != 1 || got[1].ID != 6 {
		t.Fatalf("active+intersect rows only, got %+v", idsOfGlobal(got))
	}
	// 大小写不敏感（归一化键本应小写，防御脏数据）。
	if got := filterInjectableCross(rows, []string{"CANAL.example.COM"}, true, 3); len(got) != 1 || got[0].ID != 1 {
		t.Errorf("match must be case-insensitive, got %+v", idsOfGlobal(got))
	}
	// 剩余名额截断（项目洞察优先占位的另一半）。
	if got := filterInjectableCross(rows, match, true, 1); len(got) != 1 || got[0].ID != 1 {
		t.Errorf("limit must cut to 1, got %+v", idsOfGlobal(got))
	}
	if got := filterInjectableCross(rows, match, true, 0); len(got) != 0 {
		t.Errorf("zero remaining quota must inject nothing, got %d", len(got))
	}
}

func idsOfGlobal(list []db.GlobalInsight) []int64 {
	out := make([]int64, 0, len(list))
	for _, g := range list {
		out = append(out, g.ID)
	}
	return out
}
