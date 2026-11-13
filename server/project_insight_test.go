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

// TestExtractHostKeys 守 V5-C 障碍1 第三级来源：从任务名称/目标文本里轻量提取
// host:port 与 host（父键），并挡掉 "login.php" 这类把路径当域名的误命中。
func TestExtractHostKeys(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []string
	}{
		{
			name: "URL 里的 host:port",
			text: "对 http://127.0.0.1:9081/login.php 做未授权测试",
			want: []string{"127.0.0.1:9081", "127.0.0.1"},
		},
		{
			name: "裸域名与 host:port",
			text: "打 demo.example.com:8443 与 api.example.com 两个面",
			want: []string{"demo.example.com:8443", "demo.example.com", "api.example.com"},
		},
		{
			name: "端口越界只留 host",
			text: "example.com:99999 不是合法端口",
			want: []string{"example.com"},
		},
		{
			name: "路径片段不当域名",
			text: "登录页是 login.php，接口是 api.json",
			want: nil,
		},
		{
			name: "无资产线索",
			text: "把后台打穿",
			want: nil,
		},
	}
	for _, c := range cases {
		got := extractHostKeys(c.text)
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: extractHostKeys()=%v want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: extractHostKeys()[%d]=%q want %q (all %v)", c.name, i, got[i], c.want[i], got)
			}
		}
	}
}

// TestInsightQuota 守 V5-C 障碍3 的配额：存在跨项目行时项目洞察压到 2、至少留
// 1 位给跨项目；无跨项目时项目可占满 3；总数永不超过 3、跨项目永不超过 2。
func TestInsightQuota(t *testing.T) {
	cases := []struct {
		name                     string
		projectAvail, crossAvail int
		wantProject, wantCross   int
	}{
		{"项目占满且跨项目存在 → 2+1", 18, 5, 2, 1},
		{"项目只有 1 条 → 1+2", 1, 5, 1, 2},
		{"项目 0 条 → 跨项目最多 2", 0, 5, 0, 2},
		{"无跨项目 → 项目可用满 3", 18, 0, 3, 0},
		{"都很少", 1, 1, 1, 1},
		{"都空", 0, 0, 0, 0},
		{"负值按 0", -1, -1, 0, 0},
	}
	for _, c := range cases {
		p, x := insightQuota(c.projectAvail, c.crossAvail)
		if p != c.wantProject || x != c.wantCross {
			t.Errorf("%s: insightQuota(%d,%d)=(%d,%d) want (%d,%d)",
				c.name, c.projectAvail, c.crossAvail, p, x, c.wantProject, c.wantCross)
		}
		if p+x > insightInjectMax {
			t.Errorf("%s: total %d exceeds %d", c.name, p+x, insightInjectMax)
		}
		if x > insightCrossMax {
			t.Errorf("%s: cross %d exceeds %d", c.name, x, insightCrossMax)
		}
	}
}
