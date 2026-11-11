package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
)

// TestSkillSlugFor 导出目录名规范：纯 ASCII 名→report-<slug>；含中文/空名
// 回退 report-t<id>；输出恒过 validSkillName（或为 report-t<id> 兜底形态）。
func TestSkillSlugFor(t *testing.T) {
	cases := []struct {
		name string
		id   int64
		want string
	}{
		{"标准交付模板", 12, "report-t12"},
		{"Spring Pentest Report", 7, "report-spring-pentest-report"},
		{"UPPER Case", 5, "report-upper-case"},
		{"with--double-dash", 6, "report-with-double-dash"},
		{"", 9, "report-t9"},
		{"   ", 3, "report-t3"},
		{"v1.2 报告", 4, "report-t4"},
	}
	for _, c := range cases {
		got := skillSlugFor(c.name, c.id)
		if got != c.want {
			t.Errorf("skillSlugFor(%q,%d)=%q want %q", c.name, c.id, got, c.want)
		}
		if !validSkillName(got) {
			t.Errorf("slug %q fails validSkillName", got)
		}
	}
}

// TestCanOverwriteSkillExport 哨兵判定纯函数：含哨兵=可幂等覆盖，否则拒。
func TestCanOverwriteSkillExport(t *testing.T) {
	if !canOverwriteSkillExport("---\nname: x\n---\n\n" + skillSentinel + "\n正文") {
		t.Fatal("sentinel-bearing SKILL.md must be overwriteable")
	}
	if canOverwriteSkillExport("# 手工维护的 skill\n没有任何标记") {
		t.Fatal("hand-authored skill must NOT be overwriteable")
	}
	if canOverwriteSkillExport("") {
		t.Fatal("empty must not be overwriteable")
	}
	// 导出的 markdown 模板 JSON 里若恰好出现哨兵字样……只在 frontmatter 后
	// 独立行，Contains 判定够用（设计明示的防御层级）。
}

// TestMapOutlineToTemplate 规则映射：level≤2 标题语义命中→章节 title 覆盖
// +enabled；核心章（vuln_detail/summary）恒开；空标题→默认骨架+保底开。
func TestMapOutlineToTemplate(t *testing.T) {
	o := &report.DocxOutline{
		Headings: []report.DocxHeading{
			{Text: "项目概览", Level: 1},
			{Text: "漏洞发现清单", Level: 2},
			{Text: "附录：工具列表", Level: 3}, // level>2 不参与映射
		},
	}
	tmpl := mapOutlineToTemplate(o, "春季报告")
	if tmpl.Name != "春季报告" {
		t.Fatalf("name=%q", tmpl.Name)
	}
	byKey := map[db.ReportSectionKey]db.ReportSection{}
	for _, s := range tmpl.Skeleton {
		byKey[s.Key] = s
	}
	if !byKey[db.SectionSummary].Enabled || byKey[db.SectionSummary].Title != "项目概览" {
		t.Fatalf("summary=%+v", byKey[db.SectionSummary])
	}
	if !byKey[db.SectionVulnDetail].Enabled || byKey[db.SectionVulnDetail].Title != "漏洞发现清单" {
		t.Fatalf("vuln_detail=%+v", byKey[db.SectionVulnDetail])
	}
	if byKey[db.SectionConclusion].Enabled || byKey[db.SectionCover].Enabled {
		t.Fatal("unmatched non-core sections should stay off")
	}
	// 无任何标题：核心保底开、非核心关、默认名。
	empty := mapOutlineToTemplate(&report.DocxOutline{}, "")
	if empty.Name != "导入模板" {
		t.Fatalf("default name=%q", empty.Name)
	}
	eb := map[db.ReportSectionKey]bool{}
	for _, s := range empty.Skeleton {
		eb[s.Key] = s.Enabled
	}
	if !eb[db.SectionVulnDetail] || !eb[db.SectionSummary] {
		t.Fatal("core sections must stay enabled with no headings")
	}
	if eb[db.SectionStatement] || eb[db.SectionCover] || eb[db.SectionTargets] || eb[db.SectionConclusion] {
		t.Fatal("non-core sections should default off when unmatched")
	}
	// 骨架整体可过校验（store 写入口同口径）。
	if err := db.ValidateSkeleton(tmpl.Skeleton); err != nil {
		t.Fatal(err)
	}
}

// TestNormalizeImportedDraft LLM 草稿合并：合法值为准、空名回退、非法语言
// 归一、vuln_detail 被关强制恢复、非法 style/prompts/personnel 丢默认。
func TestNormalizeImportedDraft(t *testing.T) {
	rule := mapOutlineToTemplate(&report.DocxOutline{}, "兜底名")
	good := &db.ReportTemplate{
		Name:       "LLM起名",
		OutputLang: "en-US",
		Skeleton:   []db.ReportSection{{Key: db.SectionVulnDetail, Title: "F", Enabled: true}},
		Style:      json.RawMessage(`{"body_font":"Arial"}`),
	}
	m := normalizeImportedDraft(good, rule)
	if m.Name != "LLM起名" || m.OutputLang != "en-US" {
		t.Fatalf("merge lost LLM values: %+v", m)
	}
	blank := &db.ReportTemplate{Skeleton: []db.ReportSection{{Key: db.SectionVulnDetail, Enabled: true}}}
	m2 := normalizeImportedDraft(blank, rule)
	if m2.Name != rule.Name {
		t.Fatalf("blank name must fallback, got %q", m2.Name)
	}
	if m2.OutputLang != "zh-CN" {
		t.Fatalf("bad lang must normalize zh-CN, got %q", m2.OutputLang)
	}
	off := &db.ReportTemplate{Name: "x", Skeleton: []db.ReportSection{{Key: db.SectionVulnDetail, Enabled: false}}}
	m3 := normalizeImportedDraft(off, rule)
	if !m3.Skeleton[0].Enabled {
		t.Fatal("vuln_detail must be force-reenabled")
	}
	bad := &db.ReportTemplate{
		Name:     "x",
		Skeleton: []db.ReportSection{{Key: db.SectionVulnDetail, Enabled: true}},
		Style:    json.RawMessage(`not json`),
	}
	m4 := normalizeImportedDraft(bad, rule)
	if string(m4.Style) != "{}" {
		t.Fatalf("bad style must default, got %s", m4.Style)
	}
}

// TestDraftTemplateFromRaw render-draft inline template 解析：缺骨架→默认
// 全章节、合法骨架 title 空回退默认名、非法 key/非法 JSON→报错。
func TestDraftTemplateFromRaw(t *testing.T) {
	tmpl, err := draftTemplateFromRaw(json.RawMessage(`{"name":"裸草稿"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpl.Skeleton) != len(db.DefaultSectionKeys) {
		t.Fatalf("skeleton default lost: %d", len(tmpl.Skeleton))
	}
	if string(tmpl.Style) != "{}" || string(tmpl.Prompts) != "{}" || string(tmpl.Personnel) != "[]" {
		t.Fatalf("defaults not filled: %s %s %s", tmpl.Style, tmpl.Prompts, tmpl.Personnel)
	}
	tmpl2, err := draftTemplateFromRaw(json.RawMessage(`{"name":"x","skeleton":[{"key":"summary","title":"","enabled":true}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpl2.Skeleton) != 1 || tmpl2.Skeleton[0].Title != "风险等级汇总" {
		t.Fatalf("normalize title fallback broken: %+v", tmpl2.Skeleton)
	}
	if _, err := draftTemplateFromRaw(json.RawMessage(`{"skeleton":[{"key":"bogus","enabled":true}]}`)); err == nil {
		t.Fatal("unknown key must error")
	}
	if _, err := draftTemplateFromRaw(json.RawMessage(`{bad`)); err == nil {
		t.Fatal("malformed json must error")
	}
}

// TestRenderDraftBytesDispatch 三 format 分派纯函数：md/html 出字节 pure=true、
// docx pure=false（调用方走 GenerateDocx 子进程）；html 证据图按 origin 拼绝对。
func TestRenderDraftBytesDispatch(t *testing.T) {
	in := &report.ReportInput{
		Title:    "T",
		Scope:    "task",
		Chapters: db.ParseSkeletonJSON(nil),
		Findings: []report.VulnSection{{
			FindingID: 1, Name: "X", Severity: "high",
			Reproduction: json.RawMessage(`{"steps":[{"request":"GET / HTTP/1.1\r\nHost: e.com\r\n\r\n","response":"HTTP/1.1 200\r\n\r\nok"}]}`),
			Images:       []report.EvidenceImage{{StepIndex: 0, APIPath: "/api/findings/1/evidence/9"}},
		}},
	}
	if data, pure := renderDraftBytes("md", in, ""); !pure || !strings.Contains(string(data), "# T") {
		t.Fatal("md dispatch broken")
	}
	data, pure := renderDraftBytes("html", in, "http://h:1/")
	if !pure || !strings.Contains(string(data), "<html") {
		t.Fatalf("html dispatch broken: %.80s", string(data))
	}
	if !strings.Contains(string(data), `src="http://h:1/api/findings/1/evidence/9"`) {
		t.Fatal("html must prefix origin on evidence img")
	}
	// origin 空=相对路径保持。
	relData, _ := renderDraftBytes("html", in, "")
	if !strings.Contains(string(relData), `src="/api/findings/1/evidence/9"`) {
		t.Fatal("empty origin must keep relative src")
	}
	if data2, pure2 := renderDraftBytes("docx", in, ""); pure2 || data2 != nil {
		t.Fatal("docx must be delegated (pure=false, no bytes)")
	}
	if _, pure := renderDraftBytes("  HTML ", in, ""); !pure {
		t.Fatal("html case/trim broken")
	}
}
