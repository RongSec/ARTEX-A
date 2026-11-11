package report

// T20（N1-C）HTML 预览渲染器：与 MarkdownFromInput（input.go）平级的独立渲染
// 器，直接消费同一 ReportInput——模板 JSON 是唯一事实源，不走 docx→HTML 转换
// （0.3.15/antifox 均无先例，设计 §1.1 已核实；mammoth/LibreOffice 全是新增
// 重依赖，且我们没有理由绕道 docx）。
//
// 定位=**结构预览**：章节序/enabled 过滤、汇总表、目标表、漏洞小节（描述/
// 漏洞证明/逐字报文/证据图/危害/修复）与 docx 交付同构，版式（内联 CSS 仿宋
// 近似）不追求像素级一致——「预览看结构，交付以 docx 为准」的文案由前端标注。
//
// 安全红线：所有动态内容一律 template.HTMLEscapeString（报文逐字进 <pre>，
// 里面的 HTML/脚本字符必须转义）；证据图 src 用 server 侧预解析好的 APIPath
// （/api/findings/{fid}/evidence/{eid}），渲染器不碰 dataDir 绝对路径。

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// esc 是 HTML 文本转义（唯一允许的写文本通道）。
func esc(s string) string { return html.EscapeString(s) }

const htmlInlineCSS = `
body{font-family:"FangSong","仿宋","STFangsong","Noto Serif CJK SC",serif;margin:2rem auto;max-width:52rem;color:#1f2328;line-height:1.7;font-size:15px}
h1{font-size:26px;text-align:center;margin:1.2rem 0 2rem}
h2{font-size:20px;border-bottom:1px solid #d0d7de;padding-bottom:.3rem;margin-top:2rem}
h3{font-size:17px;margin-top:1.5rem}
h4{font-size:15px;margin:1.2rem 0 .4rem}
table{border-collapse:collapse;margin:.6rem 0;width:100%}
th,td{border:1px solid #d0d7de;padding:.35rem .6rem;font-size:14px;text-align:left}
th{background:#f6f8fa}
ul{margin:.3rem 0 .8rem 1.2rem;padding:0}
.meta{color:#57606a;font-size:14px}
pre.packet{background:#0d1117;color:#c9d1d9;font-family:ui-monospace,Consolas,monospace;font-size:12.5px;line-height:1.5;padding:.7rem .9rem;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;margin:.4rem 0 .8rem}
.sev{display:inline-block;font-size:12px;font-weight:600;padding:.05rem .45rem;border-radius:4px;margin-right:.4rem;color:#fff}
.sev-critical{background:#b42318}.sev-high{background:#d92d20}.sev-medium{background:#dc6803}.sev-low{background:#667085}.sev-info{background:#667085}
img.evidence{max-width:100%;border:1px solid #d0d7de;border-radius:6px;margin:.4rem 0}
.md-pre{white-space:pre-wrap;word-break:break-all;border:1px dashed #d0d7de;border-radius:6px;padding:.6rem .8rem;font-size:13px;color:#57606a}
`

// sevBadgeHTML 渲染一个严重度徽章（与 Markdown 桩的 [SEVERITY] 标签同语义）。
func sevBadgeHTML(sev string) string {
	key := strings.TrimSpace(strings.ToLower(sev))
	switch key {
	case "critical", "high", "medium", "low":
	default:
		key = "info"
	}
	return fmt.Sprintf(`<span class="sev sev-%s">%s</span>`, key, esc(sevLabelCN(key)))
}

func sevLabelCN(key string) string {
	switch key {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	default:
		return "其他"
	}
}

// HTMLFromInput 按章节骨架渲染结构预览 HTML（自洽单文件，内联 CSS）。
// 章节遍历序=骨架序（enabled 过滤），与 MarkdownFromInput/docx pybuilder 同一
// 口径；漏洞明细在项目级按资产分节（GroupVulnsByAsset），任务级扁平。
// origin="" = 证据图用相对 API 路径；带值时拼成绝对 URL（blob 预览必需，
// 见 HTMLPreviewFromInput）。
func HTMLFromInput(in *ReportInput) string { return htmlFromInput(in, "") }

// HTMLPreviewFromInput 与 HTMLFromInput 同渲染，额外接受站点 origin（如
// "http://host:8787"）：证据截图 <img src> 拼成绝对 URL。**这是为 blob URL
// 预览通道设计的**——iframe.src 指向 blob: 时，相对 /api/... 会解析到
// blob: 协议下而全部失效；srcdoc 通道同源相对路径可用、origin 传 "" 即可。
// server 侧 origin 取 notify_public_base_url（未配置时回退请求头 Host 拼
// http://，见 server 装配；偏差已记交付报告）。
func HTMLPreviewFromInput(in *ReportInput, origin string) string { return htmlFromInput(in, origin) }

func htmlFromInput(in *ReportInput, origin string) string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="` + esc(orDefault(in.Locale, "zh-CN")) + `"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + esc(orDefault(in.Title, "渗透测试报告")) + `</title>
<style>` + htmlInlineCSS + `</style></head><body>
`)
	fmt.Fprintf(&b, "<h1>%s</h1>\n", esc(orDefault(in.Title, "渗透测试报告")))

	for _, ch := range in.EnabledChapters() {
		switch ch.Key {
		case db.SectionCover:
			b.WriteString("<section>\n")
			if in.Issuer != "" {
				fmt.Fprintf(&b, `<p class="meta">出具方：%s</p>`+"\n", esc(in.Issuer))
			}
			for _, t := range in.Tasks {
				fmt.Fprintf(&b, `<p class="meta">来源任务：%s（#%d）</p>`+"\n", esc(t.DisplayName()), t.ID)
			}
			fmt.Fprintf(&b, `<p class="meta">生成时间：%s</p>`+"\n", in.GeneratedAt.Format("2006-01-02 15:04:05"))
			b.WriteString("</section>\n")
		case db.SectionStatement:
			fmt.Fprintf(&b, "<h2>%s</h2>\n<p>本报告仅供委托方内部安全改进使用，未经出具方书面许可不得外传或用于任何非法用途。</p>\n", esc(orDefault(ch.Title, "声明")))
		case db.SectionTargets:
			fmt.Fprintf(&b, "<h2>%s</h2>\n", esc(orDefault(ch.Title, "检测目标")))
			if len(in.Targets) == 0 {
				b.WriteString(`<p class="meta">（无可验证的漏洞目标）</p>` + "\n")
			} else {
				b.WriteString("<ul>\n")
				for _, t := range in.Targets {
					fmt.Fprintf(&b, "<li>%s</li>\n", esc(t))
				}
				b.WriteString("</ul>\n")
			}
		case db.SectionSummary:
			fmt.Fprintf(&b, "<h2>%s</h2>\n", esc(orDefault(ch.Title, "风险等级汇总")))
			counts := in.SeverityCounts()
			b.WriteString("<table><tr><th>严重等级</th><th>数量</th></tr>\n")
			for _, k := range []string{"critical", "high", "medium", "low", "info"} {
				fmt.Fprintf(&b, "<tr><td>%s</td><td>%d</td></tr>\n", sevLabelCN(k), counts[k])
			}
			b.WriteString("</table>\n")
		case db.SectionVulnDetail:
			fmt.Fprintf(&b, "<h2>%s</h2>\n", esc(orDefault(ch.Title, "漏洞明细")))
			if len(in.Findings) == 0 {
				b.WriteString(`<p class="meta">本次未确认漏洞。</p>` + "\n")
			}
			n := 0
			if in.Scope == "project" {
				for _, g := range GroupVulnsByAsset(in.Findings) {
					fmt.Fprintf(&b, "<h3>资产：%s</h3>\n", esc(orDefault(g.Asset, "未关联资产")))
					for _, f := range g.Sections {
						n++
						b.WriteString(vulnSectionHTML(f, n, origin))
					}
				}
			} else {
				for _, f := range in.Findings {
					n++
					b.WriteString(vulnSectionHTML(f, n, origin))
				}
			}
		case db.SectionConclusion:
			fmt.Fprintf(&b, "<h2>%s</h2>\n<p>建议按严重等级优先修复上述问题，并在修复后安排复测。</p>\n", esc(orDefault(ch.Title, "结论与建议")))
		}
	}
	b.WriteString("</body></html>\n")
	return b.String()
}

// vulnSectionHTML 渲染一个漏洞小节：标题徽章/资产/描述/漏洞证明（复现报文
// 逐步穿插证据图，红线：逐字不省略）/回退 ReportMD/危害/修复建议。
func vulnSectionHTML(f VulnSection, n int, origin string) string {
	var b strings.Builder
	src := ""
	if len(f.SourceTasks) > 1 {
		ids := make([]string, 0, len(f.SourceTasks))
		for _, t := range f.SourceTasks {
			ids = append(ids, fmt.Sprintf("#%d", t))
		}
		src = fmt.Sprintf("（来源任务 %s）", strings.Join(ids, "、"))
	}
	fmt.Fprintf(&b, "<h4>%d. %s%s%s</h4>\n", n, sevBadgeHTML(f.Severity), esc(f.Name), esc(src))
	if f.Asset != "" {
		fmt.Fprintf(&b, `<p class="meta">资产：%s</p>`+"\n", esc(f.Asset))
	}
	if f.Description != "" {
		fmt.Fprintf(&b, "<p>%s</p>\n", esc(f.Description))
	}
	if imgHTML := renderReproductionHTML(f.Reproduction, f.Images, origin); imgHTML != "" {
		b.WriteString(imgHTML)
	} else if strings.TrimSpace(f.ReportMD) != "" {
		// 无结构化复现 → 「漏洞证明」回退详细报告原文（硬规范③，与 docx 同
		// 语义）。预览不做 Markdown 转换，逐字 <pre> 呈现保真。
		b.WriteString("<h5>漏洞证明</h5>\n")
		fmt.Fprintf(&b, `<div class="md-pre">%s</div>`+"\n", esc(f.ReportMD))
	}
	if f.Harm != "" {
		fmt.Fprintf(&b, "<h5>危害</h5>\n<p>%s</p>\n", esc(f.Harm))
	}
	if f.Remediation != "" {
		fmt.Fprintf(&b, "<h5>修复建议</h5>\n<p>%s</p>\n", esc(f.Remediation))
	}
	return b.String()
}

// renderReproductionHTML 把 T14 reproduction JSON 渲染成「漏洞证明」小节：
// 入口点/前置/逐步 request+response <pre class="packet">，证据截图按 step_index
// 穿插在对应步骤之后（step_index 0=漏洞级，置于步骤序之前）。空/'{}'/无步骤
// → ""（调用方回退 ReportMD）。报文一律转义进 <pre>。origin 见 HTMLPreviewFromInput。
func renderReproductionHTML(raw json.RawMessage, images []EvidenceImage, origin string) string {
	if len(raw) == 0 {
		return ""
	}
	var rp Reproduction
	if json.Unmarshal(raw, &rp) != nil || len(rp.Steps) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("<h5>漏洞证明</h5>\n")
	if rp.EntryPoint != "" {
		fmt.Fprintf(&b, `<p class="meta">入口点：<code>%s</code></p>`+"\n", esc(rp.EntryPoint))
	}
	if len(rp.Prerequisites) > 0 {
		b.WriteString(`<p class="meta">前置条件：</p><ul>` + "\n")
		for _, p := range rp.Prerequisites {
			fmt.Fprintf(&b, "<li>%s</li>\n", esc(p))
		}
		b.WriteString("</ul>\n")
	}
	byStep := map[int][]EvidenceImage{}
	for _, img := range images {
		byStep[img.StepIndex] = append(byStep[img.StepIndex], img)
	}
	b.WriteString(evidenceImgHTML(byStep[0], origin))
	for i, st := range rp.Steps {
		fmt.Fprintf(&b, "<p><strong>步骤 %d</strong>", i+1)
		if st.Expected != "" {
			fmt.Fprintf(&b, `<span class="meta">（预期：%s）</span>`, esc(st.Expected))
		}
		b.WriteString("</p>\n")
		if st.Request != "" {
			fmt.Fprintf(&b, `<p class="meta">请求：</p><pre class="packet">%s</pre>`+"\n", esc(st.Request))
		}
		if st.Response != "" {
			fmt.Fprintf(&b, `<p class="meta">响应：</p><pre class="packet">%s</pre>`+"\n", esc(st.Response))
		}
		b.WriteString(evidenceImgHTML(byStep[i+1], origin))
	}
	return b.String()
}

// evidenceImgHTML 渲染一组证据截图。src=APIPath（server 组装时拼的
// /api/findings/{fid}/evidence/{eid}；finding_evidence.go:205 的字节流端点
// 支持 cookie/?token= 过 JWT，同源 iframe 直接可显）。origin 非空时拼成绝对
// URL——预览走 blob URL 时相对路径会解析到 blob: 协议下而失效（偏差项，见
// 交付报告；srcdoc 形态则相对 /api 可用）。APIPath 为空的条目跳过（fixture/
// 无图——宁缺毋滥不留破图）。
func evidenceImgHTML(imgs []EvidenceImage, origin string) string {
	var b strings.Builder
	for _, img := range imgs {
		api := strings.TrimSpace(img.APIPath)
		if api == "" {
			continue
		}
		src := api
		if origin != "" && strings.HasPrefix(api, "/") {
			src = strings.TrimSuffix(origin, "/") + api
		}
		caption := img.Caption
		if caption == "" {
			caption = "证据截图"
		}
		fmt.Fprintf(&b, `<img class="evidence" src="%s" alt="%s" title="%s">`+"\n", esc(src), esc(caption), esc(caption))
	}
	return b.String()
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
