package report

// T20（N1-E）docx 反推：解 zip 读 word/document.xml，抽标题层级 + 表首行 +
// 前 N 段正文，供 import-docx 交给 LLM 归纳模板骨架（同 B 的 Complete 路径）。
// 纯标准库 archive/zip + encoding/xml，零新依赖（Go 读 docx=读 OOXML，不需要
// LibreOffice/mammoth）。md 反推走 strings 直接扫 #/## 标题序列，见 PeekMarkdown。
//
// 安全（设计 §1.2E 红线）：
//   - zip-bomb 守卫：document.xml 解压后字节上限，超限报错。
//   - 只抽结构 + 截断正文，绝不原样回显整篇文档；抽出的文本只进 LLM prompt
//     与响应 outline，前端展示走 React 转义。

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// docxPeekMaxBytes 是 word/document.xml 的解压后字节上限（10MB——正常报告
// 远小于此，超限=zip bomb/异常文件）。
const docxPeekMaxBytes = 10 << 20

// docxPeekMaxRunes 是喂 LLM 的样本正文 rune 上限。
const docxPeekMaxRunes = 8000

// docxPeekMaxEntries 是 docx 归档条目数上限（正常几十条，超限=异常）。
const docxPeekMaxEntries = 5000

// DocxOutline 是 docx/md 反推的结构骨架：标题层级 + 表首行 + 样本正文。
type DocxOutline struct {
	Headings   []DocxHeading `json:"headings"`
	TableHeads [][]string    `json:"table_heads,omitempty"` // 每张表的表头行
	TextSample string        `json:"text_sample,omitempty"`
	TotalBytes int           `json:"total_bytes"`
}

// DocxHeading 是一个标题：文本 + 层级（1..6，源自 pStyle HeadingN / Title）。
type DocxHeading struct {
	Text  string `json:"text"`
	Level int    `json:"level"`
}

// PeekDocx 从已打开的 docx *zip.Reader 抽结构。找不到 document.xml / 条目数
// 超限 / 解析失败 / 解压超字节上限 → 返回 error（调用方映射 4xx/5xx）。
func PeekDocx(zr *zip.Reader) (*DocxOutline, error) {
	if len(zr.File) > docxPeekMaxEntries {
		return nil, fmt.Errorf("归档条目数 %d 超上限 %d（异常文档）", len(zr.File), docxPeekMaxEntries)
	}
	var entry *zip.File
	for i := range zr.File {
		if zr.File[i].Name == "word/document.xml" {
			entry = zr.File[i]
			break
		}
	}
	if entry == nil {
		return nil, errors.New("不是合法 docx（缺 word/document.xml）")
	}
	rc, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, docxPeekMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > docxPeekMaxBytes {
		return nil, fmt.Errorf("document.xml 解压超过 %d 字节上限（疑似异常文档）", docxPeekMaxBytes)
	}
	return parseDocxOutline(raw)
}

// parseDocxOutline 是 docx 结构解析的纯函数内核（单测直接喂 XML 字节）。
// OOXML 段落=w:p（兄弟不嵌套），段内样式=w:pStyle(val=HeadingN/Title)，文本
// run=w:t，表格=w:tbl>w:tr>w:tc（格内各含自己的 w:p）。Token 流小状态机：
// CharData 只在 p 内收集（元素间缩进空白不进文本），p 结束统一结算——
// 格内段落归当前行、标题样式进 Headings、其余进正文样本。
func parseDocxOutline(xmlBytes []byte) (*DocxOutline, error) {
	dec := xml.NewDecoder(bytes.NewReader(xmlBytes))
	out := &DocxOutline{TotalBytes: len(xmlBytes)}

	var para strings.Builder
	var curStyle string
	inPara, inCell := false, false
	inTable, tableFirstRow := false, false
	var curRow []string
	var paras []string

	flushPara := func() {
		txt := strings.TrimSpace(para.String())
		para.Reset()
		style := curStyle
		curStyle = ""
		if txt == "" {
			return
		}
		if inCell {
			// 单元格文本：进当前行的列，不作标题、不进正文样本。
			if inTable {
				curRow = append(curRow, txt)
			}
			return
		}
		if lvl := headingLevel(style); lvl > 0 {
			out.Headings = append(out.Headings, DocxHeading{Text: txt, Level: lvl})
			return
		}
		paras = append(paras, txt)
	}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("document.xml 解析失败: %w", err)
		}
		switch se := tok.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "p":
				inPara = true
			case "pStyle":
				curStyle = attrVal(se.Attr, "val")
			case "tbl":
				inTable, tableFirstRow = true, true
			case "tr":
				curRow = nil
			case "tc":
				inCell = true
			}
		case xml.CharData:
			if inPara {
				para.Write([]byte(se))
			}
		case xml.EndElement:
			switch se.Name.Local {
			case "p":
				inPara = false
				flushPara()
			case "tc":
				inCell = false
			case "tr":
				if inTable && tableFirstRow && len(curRow) > 0 {
					out.TableHeads = append(out.TableHeads, curRow)
					tableFirstRow = false
				}
				curRow = nil
			case "tbl":
				inTable = false
			}
		}
	}
	out.TextSample = clampRunesJoin(paras, docxPeekMaxRunes)
	return out, nil
}

// headingLevel 把 pStyle val 映射到层级：Title=1，HeadingN=N(1..6)；非标题=0。
func headingLevel(style string) int {
	if style == "Title" {
		return 1
	}
	if strings.HasPrefix(style, "Heading") {
		var n int
		if _, err := fmt.Sscanf(style, "Heading%d", &n); err == nil && n >= 1 && n <= 6 {
			return n
		}
	}
	return 0
}

// clampRunesJoin 用空行拼接段落，直到总 rune 数逼近上限（截尾整段，够用即可）。
func clampRunesJoin(paras []string, max int) string {
	var b strings.Builder
	used := 0
	for _, p := range paras {
		n := len([]rune(p))
		if used+n > max {
			rem := max - used
			if rem <= 0 {
				break
			}
			p = string([]rune(p)[:rem])
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(p)
			break
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(p)
		used += n
	}
	return b.String()
}

// PeekMarkdown 从 md 文本抽标题序列成同款 outline（#..###### → level 1..6），
// 供 .md 上传复用同一 LLM 归纳路径。
func PeekMarkdown(md string) *DocxOutline {
	out := &DocxOutline{TotalBytes: len(md)}
	var paras []string
	for _, line := range strings.Split(md, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		lvl := 0
		for lvl < len(t) && lvl < 7 && t[lvl] == '#' {
			lvl++
		}
		if lvl >= 1 && lvl <= 6 && lvl < len(t) && t[lvl] == ' ' {
			out.Headings = append(out.Headings, DocxHeading{Text: strings.TrimSpace(t[lvl+1:]), Level: lvl})
			continue
		}
		paras = append(paras, t)
	}
	out.TextSample = clampRunesJoin(paras, docxPeekMaxRunes)
	return out
}

func attrVal(attrs []xml.Attr, name string) string {
	for _, a := range attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}
