package server

// V6-XPROJ 跨项目退化注入的纯逻辑单测（无库）：本任务没有锚定资产键（或只有
// 名称/描述分词这类弱键）时，跨项目洞察不应归零，而应退化为「最近 N 条 active
// 的 scope='cross'」全局参照。这里直接构造 TaskInsightContext 与候选行，覆盖
// 档位选择、reader 双开关、渲染标签、配额与新增的两级命中键。

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

var globalFallbackRows = []db.GlobalInsight{
	{ID: 11, Content: "同类组件的未授权入口在别的项目已打通", SourceProjects: []int64{2}, AssetKeys: []string{"other.example.com"}},
	{ID: 90, Content: "已被否决的经验", SourceProjects: []int64{3}, Status: db.InsightStatusRejected},
	{ID: 12, Content: "相似接口的越权面可作为假设", SourceProjects: []int64{4}},
	{ID: 13, Content: "第三条全局参照", SourceProjects: []int64{5}},
}

// TestCrossFallbackInjectsGlobalScope 守退化档的正向语义：无锚定键 + reader
// 打开 → 注入最多 insightCrossMax 条最近 active 跨项目条目，标签是
// 【跨项目·全局参照】且不确定性标注原样保留，被否决行不得混入。
func TestCrossFallbackInjectsGlobalScope(t *testing.T) {
	tctx := &db.TaskInsightContext{ProjectID: 1, ObserverOn: true, ReaderOn: true}
	// 只有弱键（名称/描述分词）——不构成锚定，必须走 global 档。
	m := insightMatch{Weak: []string{"nginx", "未授权"}}

	body, scope, n := buildInsightBody(tctx, m, nil, nil, globalFallbackRows)
	if scope != insightCrossScopeGlobal {
		t.Fatalf("scope = %q want %q", scope, insightCrossScopeGlobal)
	}
	if n != insightCrossMax {
		t.Fatalf("退化注入条数 = %d want %d", n, insightCrossMax)
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), body)
	}
	for _, ln := range lines {
		if !strings.HasPrefix(ln, "- 【跨项目·全局参照】") {
			t.Errorf("退化档标签错误: %q", ln)
		}
		if !strings.Contains(ln, "来自其他项目，仅作假设，须在本目标验证）") {
			t.Errorf("退化档也不得削弱不确定性标注: %q", ln)
		}
	}
	if strings.Contains(body, "- 【跨项目】") {
		t.Errorf("退化档不得复用精确档标签: %q", body)
	}
	if !strings.Contains(body, "洞察#11") || !strings.Contains(body, "洞察#12") {
		t.Errorf("应取最近两条 active（11/12），got %q", body)
	}
	if strings.Contains(body, "洞察#90") {
		t.Errorf("rejected 行不得注入: %q", body)
	}
}

// TestCrossFallbackReaderGate 守双开关语义：reader_enabled=false 时退化档一条
// 都不注入（另一张单恢复独立开关后，该闸门就是唯一 opt-in 入口）。
func TestCrossFallbackReaderGate(t *testing.T) {
	tctx := &db.TaskInsightContext{ProjectID: 1, ObserverOn: true, ReaderOn: false}
	body, scope, n := buildInsightBody(tctx, insightMatch{Weak: []string{"nginx"}}, nil, nil, globalFallbackRows)
	if body != "" || n != 0 || scope != "" {
		t.Fatalf("reader 关必须零注入，got body=%q scope=%q n=%d", body, scope, n)
	}
	if got := filterRecentCross(globalFallbackRows, false, insightCrossMax); len(got) != 0 {
		t.Fatalf("filterRecentCross reader 关 = %d 条 want 0", len(got))
	}
	if _, ok := insightCrossPlan(tctx, insightMatch{}); ok {
		t.Fatal("reader 关时 insightCrossPlan 必须 ok=false")
	}
}

// TestCrossAnchoredKeepsExactLabel 守「有锚定命中仍走原精确路径」：即便调用方
// 同时喂了全局候选，anchored 档也只取 asset_keys 相交行，标签是【跨项目】。
func TestCrossAnchoredKeepsExactLabel(t *testing.T) {
	tctx := &db.TaskInsightContext{ProjectID: 1, ObserverOn: true, ReaderOn: true}
	m := insightMatch{Anchors: []string{"a.example.com"}}
	anchored := []db.GlobalInsight{
		{ID: 21, Content: "同资产经验", SourceProjects: []int64{2}, AssetKeys: []string{"A.example.com"}},
	}
	body, scope, n := buildInsightBody(tctx, m, nil, anchored, globalFallbackRows)
	if scope != insightCrossScopeAnchored {
		t.Fatalf("scope = %q want %q", scope, insightCrossScopeAnchored)
	}
	if n != 1 {
		t.Fatalf("精确命中的跨项目条数 = %d want 1", n)
	}
	if !strings.HasPrefix(body, "- 【跨项目】来源项目#2：") {
		t.Errorf("精确档标签/来源错误: %q", body)
	}
	if strings.Contains(body, "全局参照") {
		t.Errorf("精确档不得出现全局参照标签: %q", body)
	}
	if strings.Contains(body, "洞察#11") {
		t.Errorf("anchored 档不得回落到全局候选: %q", body)
	}
}

// TestCrossFallbackQuotaKeepsProject 守配额不变：项目段 2 + 跨项目 1，总 3；
// 退化档不得把项目段挤没（insightQuota 规则原样作用于两档）。
func TestCrossFallbackQuotaKeepsProject(t *testing.T) {
	tctx := &db.TaskInsightContext{ProjectID: 1, ObserverOn: true, ReaderOn: true}
	projects := []db.Insight{
		{ID: 1, Content: "项目经验-1", SourceTaskID: 11},
		{ID: 2, Content: "项目经验-2", SourceTaskID: 12},
		{ID: 3, Content: "项目经验-3", SourceTaskID: 13},
		{ID: 4, Content: "项目经验-4", SourceTaskID: 14},
		{ID: 5, Content: "项目经验-5", SourceTaskID: 15},
	}
	body, scope, n := buildInsightBody(tctx, insightMatch{}, projects, nil, globalFallbackRows[:1])
	if scope != insightCrossScopeGlobal || n != 1 {
		t.Fatalf("scope=%q n=%d want global/1", scope, n)
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) != insightInjectMax {
		t.Fatalf("总条数 = %d want %d: %q", len(lines), insightInjectMax, body)
	}
	projectLines, crossLines := 0, 0
	for _, ln := range lines {
		switch {
		case strings.HasPrefix(ln, "- 来源任务#"):
			projectLines++
		case strings.HasPrefix(ln, "- 【跨项目·全局参照】"):
			crossLines++
		}
	}
	if projectLines != insightProjectMax || crossLines != 1 {
		t.Fatalf("配额应为 2+1，got 项目=%d 跨项目=%d: %q", projectLines, crossLines, body)
	}
	if !strings.HasPrefix(lines[len(lines)-1], "- 【跨项目·全局参照】") {
		t.Errorf("跨项目条目应排在项目段之后: %q", body)
	}
}

// TestInsightMatchNewDimensions 守 V6-XPROJ 新增两级的纯函数语义：
//   - 名称/描述分词产出弱键（Anchors 为空，Weak 命中组件名）；
//   - finding 资产键（resolve 回调注入）产出 Anchors，优先于分词；
//   - 全空返回零值（不制造假键）。
func TestInsightMatchNewDimensions(t *testing.T) {
	// 名称分词：英文组件名小写化命中，停用词/纯数字噪声被剔除。
	m := collectInsightMatch(nil, nil, nil, nil, "Canal v1.1.5 未授权后台排查")
	if len(m.Anchors) != 0 {
		t.Fatalf("无资产线索时 Anchors 应为空，got %v", m.Anchors)
	}
	if !containsKey(m.Weak, "canal") {
		t.Errorf("名称分词应产出 canal 弱键，got %v", m.Weak)
	}
	if containsKey(m.Weak, "the") || containsKey(m.Weak, "9081") {
		t.Errorf("停用词/纯数字不应成为弱键: %v", m.Weak)
	}

	// finding 资产：findings.asset_ids → 资产键，命中即锚定（先于分词）。
	resolve := func(ids []int64) []string {
		if len(ids) == 1 && ids[0] == 7 {
			return []string{"FINDING.example.com:8443", "finding.example.com"}
		}
		return nil
	}
	m = collectInsightMatch(nil, nil, []int64{7}, resolve, "Canal 组件排查")
	if !containsKey(m.Anchors, "finding.example.com:8443") || !containsKey(m.Anchors, "finding.example.com") {
		t.Fatalf("finding 资产键应进 Anchors，got %v", m.Anchors)
	}
	if len(m.Weak) != 0 {
		t.Errorf("finding 资产非空时不该再产出弱键: %v", m.Weak)
	}

	// 三级+两级全空：零值（跨项目走退化档，而不是伪造键）。
	empty := collectInsightMatch(nil, nil, nil, resolve, "")
	if len(empty.Anchors) != 0 || len(empty.Weak) != 0 {
		t.Fatalf("全空应返回零值，got anchors=%v weak=%v", empty.Anchors, empty.Weak)
	}
	if keys := empty.keys(); len(keys) != 0 {
		t.Fatalf("全空 keys() 应为空，got %v", keys)
	}
}

// TestInsightMatchFindingAfterTaskAssets 守层级优先级：任务资产（b）非空时
// 不再下探 finding 资产（c），保持「强键先到先得」。
func TestInsightMatchFindingAfterTaskAssets(t *testing.T) {
	resolve := func(ids []int64) []string {
		switch {
		case len(ids) == 1 && ids[0] == 1:
			return []string{"task.example.com"}
		case len(ids) == 1 && ids[0] == 2:
			return []string{"finding.example.com"}
		}
		return nil
	}
	m := collectInsightMatch(nil, []int64{1}, []int64{2}, resolve, "")
	if !containsKey(m.Anchors, "task.example.com") {
		t.Fatalf("任务资产应优先，got %v", m.Anchors)
	}
	if containsKey(m.Anchors, "finding.example.com") {
		t.Fatalf("b 级非空时不该再取 finding 资产: %v", m.Anchors)
	}
}

// TestTokenizeInsightKeywords 守分词边界：长度≥3、停用词剔除、长中文按 3 字
// 窗口近似切分、结果去重。
func TestTokenizeInsightKeywords(t *testing.T) {
	got := tokenizeInsightKeywords("The nginx api 未授权访问 测试 8080")
	for _, want := range []string{"nginx", "api", "未授权访问"} {
		if !containsKey(got, want) {
			t.Errorf("缺少分词键 %q: %v", want, got)
		}
	}
	for _, bad := range []string{"the", "测试", "8080"} {
		if containsKey(got, bad) {
			t.Errorf("不该产出 %q: %v", bad, got)
		}
	}
	// 去重：重复文本只产一次。
	dup := tokenizeInsightKeywords("nginx nginx nginx")
	count := 0
	for _, k := range dup {
		if k == "nginx" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("分词未去重: %v", dup)
	}
	// 空文本零值。
	if got := tokenizeInsightKeywords("   "); len(got) != 0 {
		t.Errorf("空白文本应返回空: %v", got)
	}
}
