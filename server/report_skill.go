package server

// T20（N1-F）报告模板 ↔ skill 双向搬运。
//
//   POST /api/report-templates/{id}/to-skill
//     模板 → <skillDir>/report-<slug>/{SKILL.md,template.json,manifest.json}。
//     幂等：目录已存在且 SKILL.md 含哨兵注释 → 覆盖 template.json/manifest.json
//     与 SKILL.md；目录存在但**无哨兵**（手工 skill/其它来源）→ 409 拒覆盖。
//     响应 {skill_name}。
//   GET /api/report-templates/from-skill/{name}
//     读该 skill 的 template.json 校验后返回预填体（不建模板——前端拿去弹
//     「新建模板」，用户可改名后 POST /api/report-templates；闭环= A 机导出
//     → 拷 skills/ → B 机导入成模板 → 继续对话调）。remark 追加
//     "skill:<name>" 溯源标记（模板 DB 里的 skill 来源按此识别）。
//
// 映射语义（设计 §1.2F）：模板→skill 每次产出/覆盖一个同名 skill；模板改名
// 再导出=新 skill（旧的不自动删，SKILL.md 注明来源模板 id）。报告生成读取链
// 本期**不接** skill 内容（模板仍在 DB，skill=交付物/复用载体/导入源）。
//
// slug 规则：模板名纯 ASCII 时规范化为合法 skill 名（小写、非字母数字→'-'、
// 收边、前缀 report-）；含非 ASCII（中文常态）回退 report-t<id>。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Autumn-27/artex/db"
)

// skillSentinel 是导出型 SKILL.md 的归属哨兵：只有带它的目录才允许被
// to-skill 覆盖（防误盖手工维护的 skill）。
const skillSentinel = "<!-- artex-report-template-skill -->"

// skillTemplateFile / skillManifestFile 是导出目录里的固定文件名。
const (
	skillTemplateFile = "template.json"
	skillManifestFile = "manifest.json"
)

// reportSkillManifest 是 manifest.json 的内容（双向映射元数据）。
type reportSkillManifest struct {
	TemplateID              int64     `json:"template_id"`
	ExportedAt              time.Time `json:"exported_at"`
	TemplateUpdatedAt       time.Time `json:"template_updated_at"`
	SourceTemplateName      string    `json:"source_template_name"`
	SourceTemplateIsDefault bool      `json:"source_template_is_default"`
}

// reportSkillTemplateView 是 template.json 的形态：模板全量 DB 内容字段
// （去 id/is_default/时间戳——跨机导入时这些是本机事实，不该带走）。
type reportSkillTemplateView struct {
	Name        string             `json:"name"`
	OutputLang  string             `json:"output_lang"`
	Skeleton    []db.ReportSection `json:"skeleton"`
	Style       json.RawMessage    `json:"style"`
	Prompts     json.RawMessage    `json:"prompts"`
	Issuer      string             `json:"issuer"`
	Personnel   json.RawMessage    `json:"personnel"`
	CVSSEnabled bool               `json:"cvss_enabled"`
	Remark      string             `json:"remark"`
}

// skillSlugFor 把模板名规范成 skill 目录名（设计 §1.2F：纯 ASCII 才用名称
// slug；含中文回退 report-t<id>）。输出恒过 validSkillName（兜底路径也不
// 产生非法目录名）。
func skillSlugFor(name string, id int64) string {
	fallback := fmt.Sprintf("report-t%d", id)
	if strings.TrimSpace(name) == "" {
		return fallback
	}
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			return fallback // 非 ASCII 字母/数字（中文等）
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	s := "report-" + strings.Trim(b.String(), "-")
	if s == "report-" || len([]rune(s)) > 64 || !validSkillName(s) {
		return fallback
	}
	return s
}

// reportTemplateToSkill POST /api/report-templates/{id}/to-skill。
func (s *Server) reportTemplateToSkill(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "非法模板 id")
		return
	}
	t, err := s.m.pg.GetReportTemplate(id)
	if err != nil {
		writeErr(w, 500, "读取模板失败: "+err.Error())
		return
	}
	if t == nil {
		writeErr(w, 404, "模板不存在")
		return
	}
	slug := skillSlugFor(t.Name, t.ID)
	dir := filepath.Join(s.skillDir, slug)
	if err := os.MkdirAll(s.skillDir, 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 哨兵判定：目录已有 SKILL.md 且不含哨兵 = 非本机制创建 → 409；
	// 含哨兵 = 幂等覆盖。判定抽成 canOverwriteSkillExport（纯函数，单测）。
	mdPath := filepath.Join(dir, "SKILL.md")
	if old, err := os.ReadFile(mdPath); err == nil {
		if !canOverwriteSkillExport(string(old)) {
			writeErr(w, 409, fmt.Sprintf("skills/%s 已存在且不是报告模板导出的 skill，拒绝覆盖", slug))
			return
		}
	} else if !os.IsNotExist(err) {
		writeErr(w, 500, "读取 skill 目录失败: "+err.Error())
		return
	}
	view := reportSkillTemplateView{
		Name: t.Name, OutputLang: t.OutputLang, Skeleton: t.Skeleton,
		Style: t.Style, Prompts: t.Prompts, Issuer: t.Issuer,
		Personnel: t.Personnel, CVSSEnabled: t.CVSSEnabled, Remark: t.Remark,
	}
	tmplJSON, err := json.MarshalIndent(view, "", "  ")
	if err != nil {
		writeErr(w, 500, "序列化模板失败: "+err.Error())
		return
	}
	manifestJSON, err := json.MarshalIndent(reportSkillManifest{
		TemplateID: t.ID, ExportedAt: time.Now().UTC(), TemplateUpdatedAt: t.UpdatedAt,
		SourceTemplateName: t.Name, SourceTemplateIsDefault: t.IsDefault,
	}, "", "  ")
	if err != nil {
		writeErr(w, 500, "序列化 manifest 失败: "+err.Error())
		return
	}
	skillMD := reportSkillMarkdown(slug, view, t.ID)
	for name, content := range map[string][]byte{
		"SKILL.md":        []byte(skillMD),
		skillTemplateFile: tmplJSON,
		skillManifestFile: manifestJSON,
	} {
		// 0o644 足够：skill 是纯文本投影，无执行位。
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			writeErr(w, 500, "写 "+name+" 失败: "+err.Error())
			return
		}
	}
	writeJSON(w, 200, map[string]any{"skill_name": slug, "dir": filepath.ToSlash(dir)})
}

// reportSkillMarkdown 生成 SKILL.md（frontmatter + 哨兵 + 人类可读说明 +
// 模板 JSON 全文）。description 保持单行（frontmatter 解析约束）。
func reportSkillMarkdown(slug string, v reportSkillTemplateView, templateID int64) string {
	desc := fmt.Sprintf("渗透测试报告模板「%s」的导出 skill：含完整章节骨架/样式/叙述提示词，可导入 artex 报告中心继续对话调整。", strings.Join(strings.Fields(v.Name), " "))
	var b strings.Builder
	b.WriteString("---\nname: " + slug + "\ndescription: " + desc + "\n---\n\n")
	b.WriteString(skillSentinel + "\n\n")
	b.WriteString("# 报告模板 skill：" + v.Name + "\n\n")
	fmt.Fprintf(&b, "来源模板 id=%d，导出自 ARTEX 报告中心。\n\n", templateID)
	b.WriteString("## 用法\n\n")
	b.WriteString("在报告中心「导入模板 → 从 Skill 导入」选择本 skill，即可把下方模板反哺为平台模板继续编辑/生成。报告生成读取链不直接消费本文件（模板事实源在 DB）。\n\n")
	b.WriteString("## 模板 JSON\n\n```json\n")
	raw, _ := json.MarshalIndent(v, "", "  ")
	b.Write(raw)
	b.WriteString("\n```\n")
	return b.String()
}

// canOverwriteSkillExport 判定已有 SKILL.md 是否可被 to-skill 覆盖：含哨兵
// 注释=报告模板导出机制创建、幂等覆盖；否则=手工维护/其它来源，拒覆盖（409）。
// 纯函数，单测可直接喂样例串断言（不依赖具体机器路径）。
func canOverwriteSkillExport(existing string) bool {
	return strings.Contains(existing, skillSentinel)
}

// reportTemplateFromSkill GET /api/report-templates/from-skill/{name}：
// 读 template.json 校验后返回预填体（不建模板，前端 POST /api/report-templates
// 落库）。404=目录/文件不存在；422=内容非法（错误文本说明哪一段坏）。
func (s *Server) reportTemplateFromSkill(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	if !validSkillName(name) {
		writeErr(w, 400, "非法 skill 名")
		return
	}
	// 读盘限定在 skillDir 之内（validSkillName 已挡路径字符，这里再 Eval 兜底）。
	dir := filepath.Join(s.skillDir, name)
	raw, err := os.ReadFile(filepath.Join(dir, skillTemplateFile))
	if err != nil {
		if os.IsNotExist(err) {
			writeErr(w, 404, "skill 或其 template.json 不存在")
			return
		}
		writeErr(w, 500, "读取失败: "+err.Error())
		return
	}
	var v reportSkillTemplateView
	if err := json.Unmarshal(raw, &v); err != nil {
		writeErr(w, 422, "template.json 不是合法模板 JSON: "+err.Error())
		return
	}
	if strings.TrimSpace(v.Name) == "" {
		writeErr(w, 422, "template.json 缺 name")
		return
	}
	if len(v.Skeleton) == 0 {
		v.Skeleton = db.ParseSkeletonJSON(nil)
	} else if err := db.ValidateSkeleton(v.Skeleton); err != nil {
		writeErr(w, 422, "template.json skeleton 非法: "+err.Error())
		return
	}
	// 溯源标记：remark 追加 skill:<name>（已有同标记则不重复）。
	marker := "skill:" + name
	remark := strings.TrimSpace(v.Remark)
	if remark == "" {
		remark = marker
	} else if !strings.Contains(remark, marker) {
		remark += "；" + marker
	}
	writeJSON(w, 200, map[string]any{
		"draft": map[string]any{
			"name":         v.Name,
			"output_lang":  v.OutputLang,
			"skeleton":     v.Skeleton,
			"style":        v.Style,
			"prompts":      v.Prompts,
			"issuer":       v.Issuer,
			"personnel":    v.Personnel,
			"cvss_enabled": v.CVSSEnabled,
			"remark":       remark,
		},
		"skill_name": name,
	})
}
