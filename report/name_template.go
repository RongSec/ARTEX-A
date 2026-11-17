package report

// V9-NAME：报告名称占位符模板（纯函数，便于单测）。
//
// 设计口径（用户原话）：
//   - 报告设置可配置名称模板，空值用默认 {system}渗透测试报告-{YYYY-MM-DD}。
//   - {system} 系统名：能识别资产 host 用 host（去 scheme/端口/路径）；
//     否则 task 用 任务<id>、project 用 项目<id>；永远不可为空。
//   - {title} 封面标题（仍是「系统名+渗透测试报告」）。
//   - 时间分量按 UTC+8；{date}/{DATE} 默认 YYYY-MM-DD，也支持 {date:布局}。
//   - 非法/未知占位符原样保留，便于用户自检；绝不 panic。
//   - 文件名非法字符替换为 _，限长 120 字符。

import (
	"fmt"
	"strings"
	"time"
)

// DefaultReportNameTemplate 是 report_settings.name_template 为空时的默认模板。
const DefaultReportNameTemplate = "{system}渗透测试报告-{YYYY-MM-DD}"

// ReportNameData 是模板渲染所需的全部事实（由 server 侧查库/资产后填充）。
type ReportNameData struct {
	System      string // 系统名（host 或 任务N/项目N）
	Title       string // 封面标题
	TaskID      int64
	ProjectID   int64
	TaskName    string
	ProjectName string
}

// ReportTimezone 是名称模板时间分量的固定时区（UTC+8）。
var ReportTimezone = time.FixedZone("UTC+8", 8*3600)

// RenderReportName 渲染名称模板。空模板使用默认模板。
func RenderReportName(tmpl string, d ReportNameData, at time.Time) string {
	if strings.TrimSpace(tmpl) == "" {
		tmpl = DefaultReportNameTemplate
	}
	if at.IsZero() {
		at = time.Now()
	}
	at = at.In(ReportTimezone)
	system := strings.TrimSpace(d.System)
	if system == "" {
		// 系统名缺失一律不可为空（兜底，正常路径已保证）。
		switch {
		case d.TaskID > 0:
			system = fmt.Sprintf("任务%d", d.TaskID)
		case d.ProjectID > 0:
			system = fmt.Sprintf("项目%d", d.ProjectID)
		default:
			system = "目标系统"
		}
	}
	title := strings.TrimSpace(d.Title)
	if title == "" {
		title = system + "渗透测试报告"
	}

	var b strings.Builder
	for i := 0; i < len(tmpl); {
		if tmpl[i] != '{' {
			b.WriteByte(tmpl[i])
			i++
			continue
		}
		end := strings.IndexByte(tmpl[i+1:], '}')
		if end < 0 {
			// 未闭合的花括号原样输出。
			b.WriteString(tmpl[i:])
			break
		}
		end += i + 1
		token := tmpl[i+1 : end]
		value, ok := renderNameToken(token, d, system, title, at)
		if ok {
			b.WriteString(value)
		} else {
			b.WriteString(tmpl[i : end+1]) // 未知占位符原样保留
		}
		i = end + 1
	}
	return b.String()
}

// renderNameToken 解析一个占位符（不含花括号）。ok=false 表示未知，调用方原样保留。
func renderNameToken(token string, d ReportNameData, system, title string, at time.Time) (string, bool) {
	// {date:布局} 需要保留布局原文，先单独处理。
	if len(token) > 5 && strings.EqualFold(token[:5], "date:") {
		layout := token[5:]
		return formatNameLayout(layout, at), true
	}
	// mm=分钟、MM=月份：大小写敏感优先（否则两个 token 无法区分）。
	switch token {
	case "mm":
		return at.Format("04"), true
	case "MM":
		return at.Format("01"), true
	}
	switch strings.ToLower(token) {
	case "system":
		return system, true
	case "title":
		return title, true
	case "yyyy":
		return at.Format("2006"), true
	case "yy":
		return at.Format("06"), true
	case "m":
		return at.Format("1"), true
	case "dd":
		return at.Format("02"), true
	case "d":
		return at.Format("2"), true
	case "hh":
		return at.Format("15"), true
	case "ss":
		return at.Format("05"), true
	case "date":
		return at.Format("2006-01-02"), true
	case "task_id":
		return i64OrEmpty(d.TaskID), true
	case "project_id":
		return i64OrEmpty(d.ProjectID), true
	case "task":
		return strings.TrimSpace(d.TaskName), true
	case "project":
		return strings.TrimSpace(d.ProjectName), true
	}
	// 复合时间 token（默认模板的 {YYYY-MM-DD}）：整段只由时间分量与分隔符
	// 组成时按布局渲染；含未知字母则视为未知占位符原样保留。
	if out, ok := tryFormatLayoutToken(token, at); ok {
		return out, true
	}
	return "", false
}

// nameLayoutTokens 是日期布局的白名单 token（长 token 在前，避免 M 吃掉 MM）。
var nameLayoutTokens = []struct {
	key string
	fmt string
}{
	{"YYYY", "2006"},
	{"YY", "06"},
	{"MM", "01"},
	{"DD", "02"},
	{"HH", "15"},
	{"mm", "04"},
	{"ss", "05"},
	{"M", "1"},
	{"D", "2"},
}

// tryFormatLayoutToken 把 `YYYY-MM-DD` 这类复合 token 当作布局渲染。
// 只有整段全部由已知 token 或非字母数字字面量（- . / _ 空格 年月日 :）组成
// 时才接受，避免把 {unknown} 之类误当布局。
func tryFormatLayoutToken(token string, at time.Time) (string, bool) {
	var b strings.Builder
	consumed := false
	for i := 0; i < len(token); {
		matched := false
		for _, t := range nameLayoutTokens {
			if strings.HasPrefix(token[i:], t.key) {
				b.WriteString(at.Format(t.fmt))
				i += len(t.key)
				matched = true
				consumed = true
				break
			}
		}
		if matched {
			continue
		}
		r := rune(token[i])
		// ASCII 字母/数字未命中 token → 不是布局，交回未知占位符处理。
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return "", false
		}
		b.WriteByte(token[i])
		i++
	}
	if !consumed {
		return "", false
	}
	return b.String(), true
}

func i64OrEmpty(v int64) string {
	if v <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", v)
}

// formatNameLayout 是一个小格式化器：白名单 token 为
// YYYY|YY|MM|M|DD|D|HH|mm|ss 与中文年月日；未知字符原样输出。
// 例：YYYY年M月D日 → 2026年1月5日。
func formatNameLayout(layout string, at time.Time) string {
	tokens := []struct {
		key string
		fmt string
	}{
		{"YYYY", "2006"},
		{"YY", "06"},
		{"MM", "01"},
		{"DD", "02"},
		{"HH", "15"},
		{"mm", "04"},
		{"ss", "05"},
		{"M", "1"},
		{"D", "2"},
	}
	var b strings.Builder
	for i := 0; i < len(layout); {
		matched := false
		for _, t := range tokens {
			if strings.HasPrefix(layout[i:], t.key) {
				b.WriteString(at.Format(t.fmt))
				i += len(t.key)
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		// 未知字符（含中文/分隔符/其它字母）原样输出。
		b.WriteByte(layout[i])
		i++
	}
	return b.String()
}

// NameDataFromInput 把 ReportInput 的命名事实映射成 ReportNameData。
func NameDataFromInput(in *ReportInput) ReportNameData {
	if in == nil {
		return ReportNameData{}
	}
	return ReportNameData{
		System:      in.SystemName,
		Title:       in.Title,
		TaskID:      in.TaskID,
		ProjectID:   in.ProjectID,
		TaskName:    in.TaskName,
		ProjectName: in.ProjectName,
	}
}

// ReportTime 取渲染时刻（GeneratedAt 零值回退 now）。
func ReportTime(in *ReportInput) time.Time {
	if in != nil && !in.GeneratedAt.IsZero() {
		return in.GeneratedAt
	}
	return time.Now()
}

// SanitizeReportFileName 清理文件名：非法字符 / \ : * ? " < > | 替换为 _，
// 折叠空白，限长 120 rune（按 rune 计，避免截断 UTF-8 中间）。
func SanitizeReportFileName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			b.WriteByte('_')
		case '\r', '\n', '\t':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	out = strings.Trim(out, " .")
	if out == "" {
		out = "渗透测试报告"
	}
	if r := []rune(out); len(r) > 120 {
		out = string(r[:120])
	}
	return out
}

// ReportFileName 返回渲染后的名称 + 扩展名（扩展名不带点也可）。
// 模板名先清洗再拼后缀，长度上限约束的是完整文件名（含 .docx）。
func ReportFileName(tmpl string, d ReportNameData, at time.Time, ext string) string {
	name := SanitizeReportFileName(RenderReportName(tmpl, d, at))
	ext = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(ext), "."))
	if ext == "" {
		ext = "docx"
	}
	full := name + "." + ext
	// 完整名再限一次长：极长 ext 或名称边界场景。
	if r := []rune(full); len(r) > 120 {
		keep := 120 - len([]rune("."+ext))
		if keep < 1 {
			keep = 1
		}
		if len([]rune(name)) > keep {
			name = string([]rune(name)[:keep])
		}
		full = name + "." + ext
	}
	return full
}
