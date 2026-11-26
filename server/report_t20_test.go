package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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

// TestToSkillCreatesSlugDir BUG-1 回归（V2 实跑：首导必 500）：新模板（中文名
// →回退 report-t<id>，slug 子目录此前不存在）首次 to-skill 必须成功建目录+三
// 文件；重复导出幂等 200；skillDir 下同名目录存在但 SKILL.md 无哨兵 → 409 且
// 不覆写。
func TestToSkillCreatesSlugDir(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	skillDir := t.TempDir()
	s := New(context.Background(), m, skillDir, t.TempDir(), t.TempDir())
	h := s.Handler()
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	post := func(path string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(""))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	postJSON := func(path, body string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	tpl, err := m.pg.CreateReportTemplate(db.ReportTemplateInput{
		Name:       "BUG1 中文模板",
		OutputLang: "zh-CN",
		Skeleton:   db.ParseSkeletonJSON(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	slug := skillSlugFor(tpl.Name, tpl.ID)
	dir := filepath.Join(skillDir, slug)

	// 首导：dir 不存在 → 必须 200 且三文件齐（BUG-1 旧行为=500）。
	code, body := post("/api/report-templates/" + strconv.FormatInt(tpl.ID, 10) + "/to-skill")
	if code != 200 {
		t.Fatalf("first export must succeed, got %d %s", code, body)
	}
	for _, f := range []string{"SKILL.md", "template.json", "manifest.json"} {
		if b, err := os.ReadFile(filepath.Join(dir, f)); err != nil || len(b) == 0 {
			t.Fatalf("%s missing/empty in %s: %v", f, dir, err)
		}
	}

	// 重导：未确认覆盖必须 409（V13-SKILLBIND：不再静默覆盖用户改过的 skill）；
	// 带 overwrite=true 才允许覆盖。
	if code, body = post("/api/report-templates/" + strconv.FormatInt(tpl.ID, 10) + "/to-skill"); code != 409 {
		t.Fatalf("re-export without overwrite must 409, got %d %s", code, body)
	}
	if code, body = postJSON("/api/report-templates/"+strconv.FormatInt(tpl.ID, 10)+"/to-skill", `{"overwrite":true}`); code != 200 {
		t.Fatalf("re-export with overwrite must succeed, got %d %s", code, body)
	}
	// 绑定必须落库：模板 → skill 名。
	if got, err := m.pg.GetReportTemplate(tpl.ID); err != nil || got == nil || got.SkillName != slug {
		t.Fatalf("template must bind skill %q, got %+v err=%v", slug, got, err)
	}

	// 非哨兵同名目录 → 409 且不覆写。
	tpl2, err := m.pg.CreateReportTemplate(db.ReportTemplateInput{
		Name:       "Another 中文模板",
		OutputLang: "zh-CN",
		Skeleton:   db.ParseSkeletonJSON(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	slug2 := skillSlugFor(tpl2.Name, tpl2.ID)
	dir2 := filepath.Join(skillDir, slug2)
	if err := os.MkdirAll(dir2, 0o755); err != nil {
		t.Fatal(err)
	}
	manual := "# 手工维护的 skill\n无哨兵"
	if err := os.WriteFile(filepath.Join(dir2, "SKILL.md"), []byte(manual), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _ = post("/api/report-templates/" + strconv.FormatInt(tpl2.ID, 10) + "/to-skill"); code != 409 {
		t.Fatalf("non-sentinel dir must 409, got %d", code)
	}
	if b, _ := os.ReadFile(filepath.Join(dir2, "SKILL.md")); string(b) != manual {
		t.Fatal("409 path must not overwrite manual skill")
	}
	// 409 路径不得新建不存在的目录：先造一个从未导出的模板验证。
	tpl3, err := m.pg.CreateReportTemplate(db.ReportTemplateInput{
		Name:       "Never Exported 三",
		OutputLang: "zh-CN",
		Skeleton:   db.ParseSkeletonJSON(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	dir3 := filepath.Join(skillDir, skillSlugFor(tpl3.Name, tpl3.ID))
	if code, _ = post("/api/report-templates/" + strconv.FormatInt(tpl3.ID, 10) + "/to-skill"); code != 200 {
		t.Fatalf("fresh export want 200 got %d", code)
	}
	if _, err := os.Stat(dir3); err != nil {
		t.Fatalf("fresh export must create dir: %v", err)
	}
}
