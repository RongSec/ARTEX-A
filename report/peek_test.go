package report

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

// docxXML 是一段最小可用的 word/document.xml：Title + Heading1/2 + 一张表
// 的表头行 + 普通正文段。字段用 OOXML 真实命名（w: 前缀，decoder 只认 Local）。
const docxXML = `<?xml version="1.0"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
 <w:body>
  <w:p><w:pPr><w:pStyle w:val="Title"/></w:pPr><w:r><w:t>渗透测试报告</w:t></w:r></w:p>
  <w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>风险等级汇总</w:t></w:r></w:p>
  <w:p><w:pPr><w:pStyle w:val="Heading2"/></w:pPr><w:r><w:t>漏洞明细</w:t></w:r></w:p>
  <w:p><w:r><w:t>这是一段普通正文，</w:t></w:r><w:r><w:t>用于样本抽取。</w:t></w:r></w:p>
  <w:tbl>
   <w:tr><w:tc><w:p><w:r><w:t>严重等级</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>数量</w:t></w:r></w:p></w:tc></w:tr>
   <w:tr><w:tc><w:p><w:r><w:t>严重</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>3</w:t></w:r></w:p></w:tc></w:tr>
  </w:tbl>
  <w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>结论与建议</w:t></w:r></w:p>
 </w:body>
</w:document>`

// TestParseDocxOutline 直接喂 XML 字节验证纯函数内核：标题层级、表头、正文样本。
func TestParseDocxOutline(t *testing.T) {
	out, err := parseDocxOutline([]byte(docxXML))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"渗透测试报告": 1, "风险等级汇总": 1, "漏洞明细": 2, "结论与建议": 1}
	if len(out.Headings) != len(want) {
		t.Fatalf("headings=%d want %d: %+v", len(out.Headings), len(want), out.Headings)
	}
	for _, h := range out.Headings {
		if lvl, ok := want[h.Text]; !ok || lvl != h.Level {
			t.Fatalf("unexpected heading %q level=%d", h.Text, h.Level)
		}
	}
	if len(out.TableHeads) != 1 || strings.Join(out.TableHeads[0], "|") != "严重等级|数量" {
		t.Fatalf("table head wrong: %v", out.TableHeads)
	}
	if !strings.Contains(out.TextSample, "这是一段普通正文") {
		t.Fatalf("text sample missing body: %q", out.TextSample)
	}
	// 单元格文本不进正文样本。
	if strings.Contains(out.TextSample, "严重等级") {
		t.Fatal("table cell leaked into text sample")
	}
}

// TestPeekDocxZip 走完整 PeekDocx（内存构造一个真 docx zip），验证端到端解包。
func TestPeekDocxZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create("word/document.xml")
	f.Write([]byte(docxXML))
	g, err := zw.Create("[Content_Types].xml")
	if err != nil {
		t.Fatal(err)
	}
	g.Write([]byte("<Types/>"))
	zw.Close()
	data := buf.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	out, err := PeekDocx(zr)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Headings) != 4 {
		t.Fatalf("headings=%d want 4", len(out.Headings))
	}
}

// TestPeekDocxMissingDocument 无 word/document.xml → 明确报错（不是合法 docx）。
func TestPeekDocxMissingDocument(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h, err := zw.Create("word/styles.xml")
	if err != nil {
		t.Fatal(err)
	}
	h.Write([]byte("<x/>"))
	zw.Close()
	data := buf.Bytes()
	zr, _ := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if _, err := PeekDocx(zr); err == nil || !strings.Contains(err.Error(), "document.xml") {
		t.Fatalf("want missing-document error, got %v", err)
	}
}

// TestPeekMarkdown 标题序列抽取（#..######→level，正文样本）。
func TestPeekMarkdown(t *testing.T) {
	md := "# 封面\n\n前言文本\n\n## 漏洞明细\n\n正文一\n正文二\n### 高危项\n#hashtag无空格\n"
	out := PeekMarkdown(md)
	byText := map[string]int{}
	for _, h := range out.Headings {
		byText[h.Text] = h.Level
	}
	if byText["封面"] != 1 || byText["漏洞明细"] != 2 || byText["高危项"] != 3 {
		t.Fatalf("headings=%v", byText)
	}
	if !strings.Contains(out.TextSample, "正文一") {
		t.Fatalf("sample=%q", out.TextSample)
	}
	// 井号后必须有空格才算标题：`#hashtag` 是正文。
	for _, h := range out.Headings {
		if h.Text == "hashtag" {
			t.Fatal("#hashtag must not count as heading")
		}
	}
}

// TestHeadingLevel pStyle→层级映射边角。
func TestHeadingLevel(t *testing.T) {
	if headingLevel("Title") != 1 || headingLevel("Heading3") != 3 || headingLevel("Normal") != 0 || headingLevel("Heading7") != 0 {
		t.Fatal("headingLevel mapping broken")
	}
}
