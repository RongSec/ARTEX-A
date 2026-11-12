package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func htmlTestInput() *ReportInput {
	repro := json.RawMessage(`{"entry_point":"GET /x","prerequisites":["未登录"],"steps":[
	  {"request":"GET /x?a=<script>alert(1)</script> HTTP/1.1\r\nHost: demo.example.com\r\n\r\n","response":"HTTP/1.1 200 OK\r\n\r\n<html>hi & bye</html>","expected":"403","proves":"200 回显"}
	]}`)
	return &ReportInput{
		Title:  "测试&报告",
		Scope:  "task",
		Locale: "zh-CN",
		Chapters: []db.ReportSection{
			{Key: db.SectionCover, Title: "封面", Enabled: true},
			{Key: db.SectionTargets, Title: "检测目标", Enabled: true},
			{Key: db.SectionSummary, Title: "风险等级汇总", Enabled: true},
			{Key: db.SectionVulnDetail, Title: "漏洞明细", Enabled: true},
		},
		Targets: []string{"demo.example.com"},
		Findings: []VulnSection{{
			FindingID: 1, Name: "XSS <img onerror=1>", Severity: "high",
			Description:  "描述里带 <b>html</b> 标签",
			Reproduction: repro,
			Images: []EvidenceImage{
				{StepIndex: 1, APIPath: "/api/findings/1/evidence/9", Caption: `图"注`},
				{StepIndex: 1, APIPath: "", Caption: "空路径应跳过"},
			},
		}},
	}
}

// TestHTMLFromInputEnabledFilter enabled=false 的章节不渲染；enabled 的渲染。
func TestHTMLFromInputEnabledFilter(t *testing.T) {
	in := htmlTestInput()
	// 关汇总表。
	for i := range in.Chapters {
		if in.Chapters[i].Key == db.SectionSummary {
			in.Chapters[i].Enabled = false
		}
	}
	out := HTMLFromInput(in)
	if strings.Contains(out, "风险等级汇总") {
		t.Fatal("disabled chapter must not render")
	}
	if !strings.Contains(out, "漏洞明细") {
		t.Fatal("enabled chapter missing")
	}
	// 汇总表里的 <table>（critical 行）也应消失；漏洞明细的表头 h2 仍在。
	if strings.Contains(out, "<tr><td>严重</td>") {
		t.Fatal("summary table leaked into disabled output")
	}
}

// TestHTMLPacketEscape 报文逐字进 <pre class="packet"> 且一律转义（红线：
// XSS 样例里 <script> 不得成对出现）。
func TestHTMLPacketEscape(t *testing.T) {
	out := HTMLFromInput(htmlTestInput())
	if !strings.Contains(out, `<pre class="packet">`) {
		t.Fatal("packet pre missing")
	}
	if strings.Contains(out, "<script>") {
		t.Fatal("script tag must be escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatal("escaped script missing")
	}
	if !strings.Contains(out, "hi &amp; bye") {
		t.Fatal("response ampersand escaped")
	}
	// 漏洞名/描述里的标签同样转义。
	if !strings.Contains(out, "XSS &lt;img onerror=1&gt;") {
		t.Fatal("vuln name not escaped")
	}
}

// TestHTMLEvidenceImg APIPath 渲染 <img>；空 APIPath 跳过；origin 拼绝对前缀。
func TestHTMLEvidenceImg(t *testing.T) {
	rel := HTMLFromInput(htmlTestInput())
	if !strings.Contains(rel, `src="/api/findings/1/evidence/9"`) {
		t.Fatalf("relative img missing: %s", rel)
	}
	abs := HTMLPreviewFromInput(htmlTestInput(), "http://host:8787/")
	if !strings.Contains(abs, `src="http://host:8787/api/findings/1/evidence/9"`) {
		t.Fatal("origin-prefixed img missing")
	}
	if strings.Contains(rel, "空路径应跳过") {
		t.Fatal("empty-APIPath image must be skipped")
	}
	if !strings.Contains(rel, `alt="图&#34;注"`) {
		t.Fatal("caption quote must be escaped")
	}
}

// TestDemoFixtureLoads fixture 可解析、3 条漏洞、域名统一 demo.example.com、
// 每漏洞带逐字报文步骤。
func TestDemoFixtureLoads(t *testing.T) {
	in := DemoInput()
	if len(in.Findings) != 3 {
		t.Fatalf("findings=%d want 3", len(in.Findings))
	}
	sevs := map[string]int{}
	for _, f := range in.Findings {
		sevs[f.Severity]++
		var rp Reproduction
		if json.Unmarshal(f.Reproduction, &rp) != nil || len(rp.Steps) == 0 {
			t.Fatalf("finding %d has no repro steps", f.FindingID)
		}
		for _, st := range rp.Steps {
			if !strings.Contains(st.Request, "demo.example.com") {
				t.Fatalf("fixture request must stay on demo domain: %.80q", st.Request)
			}
		}
		if strings.TrimSpace(f.Harm) == "" || strings.TrimSpace(f.Remediation) == "" {
			t.Fatalf("fixture finding %d lacks harm/remediation", f.FindingID)
		}
	}
	if sevs["critical"] != 1 || sevs["high"] != 1 || sevs["medium"] != 1 {
		t.Fatalf("severity spread=%v", sevs)
	}
	// DemoInput 深拷贝：改副本不污染缓存。
	cp := DemoInput()
	cp.Findings[0].Name = "改过的"
	if DemoInput().Findings[0].Name == "改过的" {
		t.Fatal("DemoInput must deep-copy")
	}
	// fixture 直接过 HTML 渲染不炸、含全部三漏洞。
	page := HTMLFromInput(in)
	for _, want := range []string{"未授权访问", "SQL 注入", "XSS", "demo_shop"} {
		if !strings.Contains(page, want) {
			t.Fatalf("fixture html missing %q", want)
		}
	}
	// Markdown 渲染同样吃这份数据（契约字段互通）。
	if md := MarkdownFromInput(in); !strings.Contains(md, "SQL 注入") {
		t.Fatal("fixture markdown missing finding")
	}
}

// TestDraftTemplateRawShape fixture 的 skeleton 段与 db.ParseSkeletonJSON 契约
// 兼容（demo 模板覆盖用）。
func TestDraftTemplateRawShape(t *testing.T) {
	var probe struct {
		Chapters []db.ReportSection `json:"chapters"`
	}
	if err := json.Unmarshal(DemoInputRaw(), &probe); err != nil {
		t.Fatal(err)
	}
	if err := db.ValidateSkeleton(probe.Chapters); err != nil {
		t.Fatalf("fixture chapters must be a valid skeleton: %v", err)
	}
}
