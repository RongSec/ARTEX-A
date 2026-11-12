package server

// T20（N1-E）报告模板「从文档导入」：POST /api/report-templates/import-docx
// （multipart file=.docx|.md，≤20MB）。
//
// 流程：解包抽结构（report.PeekDocx / PeekMarkdown，纯标准库）→ LLM 归纳调用
// （同 chat 的 Complete 路径）产出模板草稿 → 返回预填体。**不自动建模板**：
// 前端弹「新建模板」表单（用户可改名）→ POST /api/report-templates 落库。
// LLM 失败/输出不可用 → 回退规则映射（heading→skeleton 改名，其余默认），
// 响应带 degraded:true——导入功能不被 LLM 可用性绑架。
//
// 安全：zip-bomb 守卫在 report/peek.go（document.xml 解压 ≤10MB、条目数上限）；
// 抽出的文本只进 LLM prompt 与响应 outline（JSON 序列化后原样回传，页面展示
// 由 React 转义）。

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
	"github.com/Autumn-27/norma/llm"
)

// importDocxMaxBytes 上传体上限（20MB，设计 §1.2E）。
const importDocxMaxBytes = 20 << 20

// reportTemplateImportDocx POST /api/report-templates/import-docx。
func (s *Server) reportTemplateImportDocx(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, importDocxMaxBytes+1<<20)
	if err := r.ParseMultipartForm(importDocxMaxBytes); err != nil {
		writeErr(w, 400, "解析上传失败或超出 20MB 上限: "+err.Error())
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, 400, `缺少 file 字段（multipart，.docx/.md）`)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, importDocxMaxBytes+1))
	if err != nil {
		writeErr(w, 400, "读取上传失败: "+err.Error())
		return
	}
	if len(data) > importDocxMaxBytes {
		writeErr(w, 400, "文件超过 20MB 上限")
		return
	}
	name := strings.ToLower(strings.TrimSpace(hdr.Filename))
	var outline *report.DocxOutline
	switch {
	case strings.HasSuffix(name, ".docx"):
		zr, zerr := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if zerr != nil {
			writeErr(w, 400, "docx 解包失败: "+zerr.Error())
			return
		}
		outline, err = report.PeekDocx(zr)
	case strings.HasSuffix(name, ".md"), strings.HasSuffix(name, ".markdown"), strings.HasSuffix(name, ".txt"):
		if !utf8.Valid(data) {
			writeErr(w, 400, "文本文件不是合法 UTF-8")
			return
		}
		outline = report.PeekMarkdown(string(data))
	default:
		writeErr(w, 400, "仅支持 .docx 或 .md/.markdown/.txt")
		return
	}
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if len(outline.Headings) == 0 && strings.TrimSpace(outline.TextSample) == "" {
		writeErr(w, 400, "文档里没有可识别的标题或正文结构")
		return
	}
	fallbackName := strings.TrimSuffix(hdr.Filename, ".docx")
	fallbackName = strings.TrimSuffix(fallbackName, ".md")
	fallbackName = strings.TrimSuffix(fallbackName, ".markdown")
	fallbackName = strings.TrimSuffix(fallbackName, ".txt")

	// 规则映射兜底草稿（LLM 不可用/输出非法时原样返回它 + degraded:true）。
	ruleDraft := mapOutlineToTemplate(outline, fallbackName)

	// LLM 归纳（可选增强，失败不阻断）。
	warnings := []string{}
	draft := ruleDraft
	degraded := true
	prov, _, ok := s.globalProvider()
	if ok && prov != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		sys := "你是渗透测试报告模板归纳器。输入是一份既有报告的章节结构（标题层级/表头/正文样本），输出一个报告模板 JSON。\n" +
			"纪律：只输出一个 ```json 围栏内的对象，形如 {\"name\":..,\"output_lang\":\"zh-CN\",\"skeleton\":[{key,title,enabled}..],\"style\":{..},\"issuer\":..,\"remark\":..}。" +
			"skeleton 的 key 只能是 cover|statement|targets|summary|vuln_detail|conclusion；把输入标题尽量映射进这六个章节（语义最近的），映射不进的**丢弃**；" +
			"cover/statement/targets/summary/vuln_detail/conclusion 至少保留 vuln_detail 与 summary（enabled=true），其余可 enabled=false。" +
			"style 只允许 body_font/west_font/head_font/body_size/h1_size/vuln_size 键。不得虚构人员与联系方式；issuer 若文档里明显有出具方才填，否则留空。"
		req := llm.CompletionRequest{
			System:    []string{sys},
			Messages:  []llm.Message{llm.UserText(outlinePrompt(outline))},
			MaxTokens: 3000,
			Thinking:  "disabled",
		}
		if msg, _, _, callErr := prov.Complete(ctx, req); callErr == nil {
			if body, okJSON := extractFencedJSON(msg.Text()); okJSON {
				var llmDraft db.ReportTemplate
				if json.Unmarshal([]byte(body), &llmDraft) == nil && len(llmDraft.Skeleton) > 0 && db.ValidateSkeleton(llmDraft.Skeleton) == nil {
					draft = normalizeImportedDraft(&llmDraft, ruleDraft)
					degraded = false
				} else {
					warnings = append(warnings, "模型输出的骨架非法，已回退规则映射")
				}
			} else {
				warnings = append(warnings, "模型输出不含合法 JSON，已回退规则映射")
			}
		} else {
			warnings = append(warnings, "LLM 归纳失败（"+callErr.Error()+"），已回退规则映射")
		}
	} else {
		warnings = append(warnings, "LLM 未配置，已回退规则映射")
	}

	writeJSON(w, 200, map[string]any{
		"draft":    templateDraftView(draft),
		"outline":  outline,
		"degraded": degraded,
		"warnings": warnings,
	})
}

// outlinePrompt 把 outline 压成喂 LLM 的紧凑文本（标题层级 + 表头 + 样本截断）。
func outlinePrompt(o *report.DocxOutline) string {
	var b strings.Builder
	b.WriteString("【标题层级】\n")
	for _, h := range o.Headings {
		fmt.Fprintf(&b, "%s%s\n", strings.Repeat("  ", h.Level-1), h.Text)
	}
	if len(o.TableHeads) > 0 {
		b.WriteString("【表头样本】\n")
		for i, row := range o.TableHeads {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&b, "- %s\n", strings.Join(row, " | "))
		}
	}
	sample := o.TextSample
	if r := []rune(sample); len(r) > 1500 {
		sample = string(r[:1500]) + "…"
	}
	if sample != "" {
		fmt.Fprintf(&b, "【正文样本】\n%s\n", sample)
	}
	return b.String()
}

// mapOutlineToTemplate 是 LLM 失败时的规则映射（纯函数，单测）：
//   - level≤2 标题按关键词表语义匹配六个已知章节（封面/声明/目标/汇总/漏洞/
//     结论），命中=该章 title 覆盖 + enabled；
//   - 未命中的已知章节里 vuln_detail/summary 恒 enabled（骨架语义核心章）、
//     其余 enabled=false；
//   - 没有任何可映射标题 → 默认全章节骨架（ParseSkeletonJSON(nil) 现成语义）；
//   - name=文件名（空则「导入模板」），其余元字段留空。
func mapOutlineToTemplate(o *report.DocxOutline, fileName string) *db.ReportTemplate {
	hit := map[db.ReportSectionKey]bool{}
	titles := map[db.ReportSectionKey]string{}
	// 关键词→章节：中文标题常直接同名；另收常见近义（概览/概要→summary，
	// 风险/漏洞/发现→vuln_detail，目标/范围→targets，结论/建议→conclusion，
	// 声明/免责→statement）。
	for _, h := range o.Headings {
		if h.Level > 2 {
			continue
		}
		t := strings.ToLower(h.Text)
		var key db.ReportSectionKey
		switch {
		case strings.Contains(t, "封面") || t == "cover":
			key = db.SectionCover
		case strings.Contains(t, "声明") || strings.Contains(t, "免责") || strings.Contains(t, "statement"):
			key = db.SectionStatement
		case strings.Contains(t, "目标") || strings.Contains(t, "范围") || strings.Contains(t, "target"):
			key = db.SectionTargets
		case strings.Contains(t, "汇总") || strings.Contains(t, "概览") || strings.Contains(t, "概要") || strings.Contains(t, "summary"):
			key = db.SectionSummary
		case strings.Contains(t, "漏洞") || strings.Contains(t, "发现") || strings.Contains(t, "finding") || strings.Contains(t, "vulnerabilit"):
			key = db.SectionVulnDetail
		case strings.Contains(t, "结论") || strings.Contains(t, "建议") || strings.Contains(t, "conclusion"):
			key = db.SectionConclusion
		default:
			continue
		}
		if _, dup := hit[key]; !dup {
			hit[key] = true
			titles[key] = h.Text
		}
	}
	skel := make([]db.ReportSection, 0, len(db.DefaultSectionKeys))
	for _, k := range db.DefaultSectionKeys {
		sec := db.ReportSection{Key: k, Enabled: false}
		if t, ok := titles[k]; ok {
			sec.Title = t
			sec.Enabled = true
		} else if !hit[k] {
			// 恒开保底：漏洞明细与汇总表没标题也出（骨架语义核心章）。
			if k == db.SectionVulnDetail || k == db.SectionSummary {
				sec.Enabled = true
			}
		}
		skel = append(skel, sec)
	}
	name := strings.TrimSpace(fileName)
	if name == "" {
		name = "导入模板"
	}
	return &db.ReportTemplate{
		Name:       name,
		OutputLang: "zh-CN",
		Skeleton:   db.NormalizeSkeleton(skel),
		Style:      json.RawMessage("{}"),
		Prompts:    json.RawMessage("{}"),
		Personnel:  json.RawMessage("[]"),
	}
}

// normalizeImportedDraft 把 LLM 草稿与规则草稿合并成可信形态：LLM 值为准，
// 空字段回退规则草稿；style/prompts 非法 JSON 时丢给默认。
func normalizeImportedDraft(llmDraft, rule *db.ReportTemplate) *db.ReportTemplate {
	m := *llmDraft
	if strings.TrimSpace(m.Name) == "" {
		m.Name = rule.Name
	}
	if m.OutputLang != "zh-CN" && m.OutputLang != "en-US" {
		m.OutputLang = "zh-CN"
	}
	for _, sec := range m.Skeleton {
		if sec.Key == db.SectionVulnDetail && sec.Enabled {
			goto styleOK
		}
	}
	// 模型把漏洞明细关了=明显不合理，强制恢复（保底章）。
	for i := range m.Skeleton {
		if m.Skeleton[i].Key == db.SectionVulnDetail {
			m.Skeleton[i].Enabled = true
		}
	}
styleOK:
	if len(m.Style) == 0 || !json.Valid(m.Style) {
		m.Style = json.RawMessage("{}")
	}
	if len(m.Prompts) == 0 || !json.Valid(m.Prompts) {
		m.Prompts = json.RawMessage("{}")
	}
	if len(m.Personnel) == 0 || !json.Valid(m.Personnel) {
		m.Personnel = json.RawMessage("[]")
	}
	return &m
}
