package server

// T16(1/3) 默认交付模板 seed：首次启动幂等插一条 is_default 的「标准交付模板」
// （skeleton 六章全开 / style=用户交付硬规范显式值 / prompts 预留 AI 叙述占位），
// 供报告中心开箱即用。settings flag 守卫，照 reseed*/seedReporterAgent 范式：
// 只尝试一次，删掉模板不会复活（用户意志优先）。

import (
	"encoding/json"
	"log"

	"github.com/Autumn-27/artex/db"
)

// defaultReportTemplateStyle 是用户交付硬规范的显式样式表（与
// report/pybuilder DEFAULTS 同名键；模板里落一份让前端编辑器可见可改）。
const defaultReportTemplateStyle = `{
	"body_font": "仿宋",
	"west_font": "Times New Roman",
	"head_font": "黑体",
	"code_font": "Consolas",
	"body_size": 12.0,
	"h1_size": 16.0,
	"h2_size": 15.0,
	"vuln_size": 18.0,
	"label_size": 12.0,
	"table_size": 10.5,
	"code_size": 9.0,
	"line_spacing": 1.5,
	"first_line_indent": true,
	"proof_gap_paragraphs": 2,
	"proof_label": "漏洞证明：",
	"table_style": "Table Grid"
}`

// defaultReportTemplatePrompts 预留按章节 key 组织的 AI 叙述模板占位；空串 =
// 该章不调 AI（当前行为）。后续棒（AI 叙述）填实后 pybuilder 无感消费。
const defaultReportTemplatePrompts = `{
	"summary": "",
	"vuln_detail": "",
	"conclusion": ""
}`

// seedDefaultReportTemplate inserts the built-in 「标准交付模板」 ONCE
// (settings-flag guarded, like reseed*/seedReporterAgent). Skips silently when
// any template already exists — user-created templates take precedence and
// CreateReportTemplate auto-flags the first row as default.
func (s *Server) seedDefaultReportTemplate() {
	const flag = "report_default_template_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成败只尝试一次

	ts, err := s.m.pg.ListReportTemplates()
	if err != nil || len(ts) > 0 {
		return // 已有模板（用户建/历史 seed）→ 不插第二条默认
	}
	// 六章全开骨架（顺序=交付规范章节序；显式 title 让前端编辑器直接可读）。
	skeleton := []db.ReportSection{
		{Key: db.SectionCover, Title: "封面", Enabled: true},
		{Key: db.SectionStatement, Title: "声明", Enabled: true},
		{Key: db.SectionTargets, Title: "检测目标", Enabled: true},
		{Key: db.SectionSummary, Title: "风险等级汇总", Enabled: true},
		{Key: db.SectionVulnDetail, Title: "漏洞明细", Enabled: true},
		{Key: db.SectionConclusion, Title: "结论与建议", Enabled: true},
	}
	in := db.ReportTemplateInput{
		Name:        "标准交付模板",
		OutputLang:  "zh-CN",
		Skeleton:    skeleton,
		Style:       json.RawMessage(defaultReportTemplateStyle),
		Prompts:     json.RawMessage(defaultReportTemplatePrompts),
		Issuer:      "",
		Personnel:   json.RawMessage("[]"),
		CVSSEnabled: false,
		Remark:      "内置默认：仿宋正文/黑体标题/漏洞证明独立段等交付规范，见报告中心样式说明",
	}
	if _, err := s.m.pg.CreateReportTemplate(in); err != nil {
		log.Printf("[reportseed] 内置默认模板 seed 失败: %v", err)
		return
	}
	log.Printf("[reportseed] 已预置「标准交付模板」（is_default，一次性）")
}
