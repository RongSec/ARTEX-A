package report

// T15 报告输入组装器：把「模板 + 任务/项目 + findings」压成一份自洽的
// ReportInput（元信息/章节骨架/检测目标表/漏洞章节序列），并提供 Markdown 桩
// 渲染。核心算法（去重合并、伪资产反向校验、URL 模板提取）全部是纯函数，
// 无 DB 可单测；DB 取数在 server/reportgen.go 的 buildReportInput 完成。
//
// T16 pybuilder docx 管线将直接消费同一 ReportInput 的 JSON 序列化，本文件的
// 结构体 json tag 即交付契约，改动需同步 report/pybuilder。

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// TaskMeta 是报告引用的一个来源任务的元信息（封面时间窗/来源标注用）。
type TaskMeta struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`        // 空=未命名，展示回退描述
	Description string    `json:"description"` // 任务描述（目标清单常写在这里）
	Goal        string    `json:"goal"`
	CreatedAt   time.Time `json:"created_at"`
	FirstRunAt  time.Time `json:"first_run_at,omitempty"` // 零值=尚未运行
}

// DisplayName 返回任务短名：名称 → 描述首行 → 「任务#id」。
func (t TaskMeta) DisplayName() string {
	if n := strings.TrimSpace(t.Name); n != "" {
		return n
	}
	if d := firstLine(t.Description); d != "" {
		return d
	}
	return fmt.Sprintf("任务#%d", t.ID)
}

// VulnSection 是报告中一个漏洞章节的数据（去重合并后）。
type VulnSection struct {
	FindingID    int64           `json:"finding_id"`
	Name         string          `json:"name"`                   // 受控短名（finding.name，空回退 vulnclass）
	Severity     string          `json:"severity"`               // critical|high|medium|low|''
	VulnClass    string          `json:"vulnclass"`              // 漏洞类别（去重键成员）
	Asset        string          `json:"asset"`                  // 归属资产 label（去重键成员；空=未关联）
	URLTemplate  string          `json:"url_template"`           // 去重键成员：复现首个请求的 host+path（无 query）
	Description  string          `json:"description"`            // 漏洞摘要
	Reproduction json.RawMessage `json:"reproduction,omitempty"` // T14 结构化复现（直读列，空/'{}'=未填）
	SourceTasks  []int64         `json:"source_tasks"`           // 来源任务号（项目级合并后保留全部）

	// T16 docx 渲染扩展（数据契约 v2，pybuilder 消费；全部 omitempty，
	// T15 Markdown 桩忽略不影响）：
	// ReportMD = finding.report 详细报告 Markdown 原文——无 reproduction 的
	// 漏洞其「漏洞证明」段回退渲染此文本（硬规范③）。
	ReportMD string `json:"report_md,omitempty"`
	// Harm/Remediation = 危害/修复建议。本棒由 DB 现有字段能填则填、暂无
	// 来源则空（AI 叙述注入后续棒），字段先行进契约。
	Harm        string `json:"harm,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	// Images = 证据截图（T16(3/3) finding_evidence_images 注入；按 step_index
	// 穿插在对应步骤代码块之后）。Path 为绝对路径，py 端缺文件跳过。
	Images []EvidenceImage `json:"images,omitempty"`
}

// EvidenceImage 是一张按复现步骤索引的证据截图引用。
type EvidenceImage struct {
	StepIndex int    `json:"step_index"`
	Path      string `json:"path"`
	Caption   string `json:"caption,omitempty"`
	// APIPath 是同源可访问的 API 相对路径（/api/findings/{fid}/evidence/{eid}，
	// T20 HTML 预览 <img> 用；server 组装时填）。omitempty=不进旧契约消费方
	// （pybuilder 读 path 插图，忽略此键零影响）。
	APIPath string `json:"api_path,omitempty"`
}

// ReportInput 是一次报告生成的完整输入（任务级/项目级共用）。
type ReportInput struct {
	Title       string    `json:"title"`  // 报告标题（任务名/项目名 + 报告词）
	Scope       string    `json:"scope"`  // task | project
	Locale      string    `json:"locale"` // 输出语言（入参>模板>zh-CN）
	GeneratedAt time.Time `json:"generated_at"`

	// V9-NAME：名称模板渲染字段（文件命名/下载名用；pybuilder 忽略）。
	SystemName   string `json:"system_name,omitempty"`
	NameTemplate string `json:"name_template,omitempty"`
	TaskID       int64  `json:"task_id,omitempty"`
	ProjectID    int64  `json:"project_id,omitempty"`
	TaskName     string `json:"task_name,omitempty"`
	ProjectName  string `json:"project_name,omitempty"`

	// 封面/组织元信息（来自模板；模板缺省时为空串/默认值）。
	Issuer   string `json:"issuer"`
	LogoPath string `json:"logo_path"`
	// LogoAbs 是 LogoPath 相对 dataDir 解析后的绝对路径（server 组装时填；
	// 文件不存在则留空）。pybuilder 插图只认 LogoAbs，不回读 dataDir。
	LogoAbs     string          `json:"logo_abs,omitempty"`
	Personnel   json.RawMessage `json:"personnel,omitempty"` // [{name,role,contact}]
	CVSSEnabled bool            `json:"cvss_enabled"`
	Remark      string          `json:"remark,omitempty"`
	Style       json.RawMessage `json:"style,omitempty"`   // T16 pybuilder 消费
	Prompts     json.RawMessage `json:"prompts,omitempty"` // AI 叙述模板（T16 消费）
	// TemplateDocx 是模板原件的绝对路径（模板有 docx_path 且文件存在时由
	// server 填）。非空 → docx 走 template_filler.py 在原件上填充；空 → 走
	// report_builder.py 按章节重建。不进 pybuilder 数据契约（脚本以 argv 收）。
	TemplateDocx string `json:"template_docx,omitempty"`

	Chapters []db.ReportSection `json:"chapters"` // 章节骨架（含 enabled=false 的关闭章节，渲染端过滤）
	Tasks    []TaskMeta         `json:"tasks"`    // 来源任务（任务级 1 个；项目级多个）

	// Targets 是检测目标表行：候选地址（任务 Goal/锚定资产抽取）经
	// FilterPseudoTargets 反向校验后的保留集；剔除项写入 job warning。
	Targets []string `json:"targets"`

	Findings []VulnSection `json:"findings"` // 漏洞章节序列（已去重合并、severity 降序）
}

// EnabledChapters 返回骨架里 enabled=true 的章节（渲染端遍历用）。
func (in *ReportInput) EnabledChapters() []db.ReportSection {
	out := make([]db.ReportSection, 0, len(in.Chapters))
	for _, c := range in.Chapters {
		if c.Enabled {
			out = append(out, c)
		}
	}
	return out
}

// HasChapter 判断报告是否启用了某章节。
func (in *ReportInput) HasChapter(key db.ReportSectionKey) bool {
	for _, c := range in.Chapters {
		if c.Key == key {
			return c.Enabled
		}
	}
	return false
}

// SeverityCounts 汇总各严重等级数量（summary 章用）。
func (in *ReportInput) SeverityCounts() map[string]int {
	m := map[string]int{}
	for _, f := range in.Findings {
		key := strings.TrimSpace(f.Severity)
		if key == "" {
			key = "info"
		}
		m[key]++
	}
	return m
}

// ---------- 纯函数：去重合并 ----------

// VulnFromFinding 把一行 DBFinding 映射成 VulnSection。assetLabel 回调把资产
// id 换成展示 label（server 侧查 assets 表注入；nil=用 "asset#<id>"，纯测注入
// 假映射）。URL 模板取自 reproduction 首个请求（无复现回退 entry_point）。
func VulnFromFinding(f *db.DBFinding, assetLabel func(int64) string) VulnSection {
	v := VulnSection{
		FindingID:    f.ID,
		Name:         nz(f.Name, nz(f.VulnClass, "未分类")),
		Severity:     strings.TrimSpace(f.Severity),
		VulnClass:    strings.TrimSpace(f.VulnClass),
		Description:  strings.TrimSpace(f.Summary),
		Reproduction: f.Reproduction,
		ReportMD:     strings.TrimSpace(f.Report),
	}
	if len(f.AssetIDs) > 0 {
		if assetLabel != nil {
			v.Asset = assetLabel(f.AssetIDs[0])
		} else {
			v.Asset = fmt.Sprintf("asset#%d", f.AssetIDs[0])
		}
	}
	var tid int64
	if f.TaskID != nil {
		tid = *f.TaskID
	}
	if tid > 0 {
		v.SourceTasks = []int64{tid}
	}
	v.URLTemplate = ExtractURLTemplate(f.Reproduction)
	return v
}

// MergeVulns 按去重键 (asset, url模板, vulnclass) 合并漏洞：
// severity 取最高；来源任务号合并去重（全部保留，标注用）；其余字段先入者
// （调用方按 severity 降序喂入）胜出。空键也参与合并（同键=同漏洞）。
func MergeVulns(in []VulnSection) []VulnSection {
	type key struct{ asset, url, class string }
	byKey := map[key]int{} // key → out 下标
	out := make([]VulnSection, 0, len(in))
	for _, v := range in {
		k := key{strings.ToLower(strings.TrimSpace(v.Asset)), v.URLTemplate, strings.ToLower(v.VulnClass)}
		if i, ok := byKey[k]; ok {
			m := &out[i]
			if sevRankOf(v.Severity) < sevRankOf(m.Severity) {
				m.Severity = v.Severity // 取最高（rank 小=严重）
			}
			// 证据互补：胜者缺的结构化证据用败者的补上（同漏洞重复登记时，
			// 后登记者可能带 reproduction/report）。
			if !db.HasReproSteps(m.Reproduction) && db.HasReproSteps(v.Reproduction) {
				m.Reproduction = v.Reproduction
			}
			if m.ReportMD == "" {
				m.ReportMD = v.ReportMD
			}
			if m.Description == "" {
				m.Description = v.Description
			}
			m.Images = append(m.Images, v.Images...)
			m.SourceTasks = mergeInt64Unique(m.SourceTasks, v.SourceTasks)
			continue
		}
		cp := v
		cp.SourceTasks = append([]int64(nil), v.SourceTasks...)
		byKey[k] = len(out)
		out = append(out, cp)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := sevRankOf(out[i].Severity), sevRankOf(out[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return out[i].FindingID < out[j].FindingID // 稳定序兜底
	})
	return out
}

// sevRankOf 复用 report.go 的 sevRank 表，但把未知等级（含 "info"）统一垫到
// 已知等级之后——sevRank 的 map 缺失键返回 0，会被误判成「比 critical 更严重」。
func sevRankOf(s string) int {
	if r, ok := sevRank[s]; ok {
		return r
	}
	return len(sevRank)
}

func mergeInt64Unique(a, b []int64) []int64 {
	seen := map[int64]bool{}
	out := make([]int64, 0, len(a)+len(b))
	for _, n := range append(append([]int64{}, a...), b...) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ---------- 纯函数：URL 模板提取 ----------

// requestLineRE 抓标准 HTTP 请求行：`GET /path?x=1 HTTP/1.1`。
var requestLineRE = regexp.MustCompile(`(?m)^\s*([A-Z]+)\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?\s*$`)

// hostHeaderRE 抓 Host 头行。
var hostHeaderRE = regexp.MustCompile(`(?im)^\s*host\s*:\s*([^\s\r\n]+)`)

// ExtractURLTemplate 从 reproduction JSON 提取漏洞的 URL 归一化模板：
// 首个 step request 的 host + path（剥 query/fragment、host 小写、去默认端口；
// 绝对形式的 curl/URL 请求同规则）。无复现/解析失败 → 回退 entry_point 的
// host+path；再没有 → ""。去重键用，不做语义判断。
func ExtractURLTemplate(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var rp Reproduction
	if json.Unmarshal(raw, &rp) != nil {
		return ""
	}
	for _, st := range rp.Steps {
		if t := urlTemplateFromPacket(st.Request); t != "" {
			return t
		}
	}
	if t := urlTemplateFromPacket(rp.EntryPoint); t != "" {
		return t
	}
	return ""
}

// urlTemplateFromPacket 从一段 HTTP 报文（或 curl/命令串）提取 host+path 模板。
func urlTemplateFromPacket(packet string) string {
	packet = strings.TrimSpace(packet)
	if packet == "" {
		return ""
	}
	var host, path string
	// 1) 请求行里的绝对 URL（curl 'http://host/path' 或 "GET http://host/path"）。
	if u := absURLRE.FindString(packet); u != "" {
		if parsed, err := url.Parse(u); err == nil {
			host = normalizeHostPort(parsed.Host, parsed.Scheme)
			path = cleanPath(parsed.Path)
		}
	}
	// 2) 标准请求行（method + origin-form path）。
	if host == "" {
		if m := requestLineRE.FindStringSubmatch(packet); m != nil {
			path = cleanPath(m[2])
		}
	}
	// 3) Host 头。
	if m := hostHeaderRE.FindStringSubmatch(packet); m != nil {
		host = normalizeHostPort(m[1], "http")
	}
	if host == "" {
		return ""
	}
	if path == "" || path == "*" {
		path = "/"
	}
	return host + path
}

var absURLRE = regexp.MustCompile(`https?://[^\s'"]+`)

// normalizeHostPort 小写 host、剥 :port（默认端口 80/443 省略、其余保留以区分
// 站点）。输入允许带 scheme 前缀不带端口的裸 host。
func normalizeHostPort(hp, scheme string) string {
	hp = strings.TrimSpace(strings.ToLower(hp))
	if hp == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(hp)
	if err != nil { // 无端口分隔符
		host = strings.TrimPrefix(hp, "[")
		host = strings.TrimSuffix(host, "]")
		return host
	}
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return host
	}
	return net.JoinHostPort(host, port)
}

func cleanPath(p string) string {
	p = strings.SplitN(p, "?", 2)[0]
	p = strings.SplitN(p, "#", 2)[0]
	if p == "" {
		return "/"
	}
	return p
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len([]rune(s)) > 60 {
		s = string([]rune(s)[:60])
	}
	return s
}

// ---------- 纯函数：伪资产反向校验（本层硬规则/用户红线） ----------

// hostCandidateRE 从自由文本（任务 Goal/描述）里抽候选目标：URL、域名或 IPv4。
var hostCandidateRE = regexp.MustCompile(`(?i)(https?://[^\s，,、;"'<>]+|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b|\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\b)`)

// CandidateTargets 从任务目标文本 + 锚定资产 host 列表抽取「检测目标表」候选
// 地址集合：抽 hostname（剥协议/path/query/端口、小写）、去重、字典序。
// 纯函数，不查库；证据过滤见 FilterPseudoTargets。
func CandidateTargets(goalTexts []string, anchorHosts []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(raw string) {
		h := candidateHost(raw)
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, g := range goalTexts {
		for _, m := range hostCandidateRE.FindAllString(g, -1) {
			add(m)
		}
	}
	for _, h := range anchorHosts {
		add(h)
	}
	sort.Strings(out)
	return out
}

// candidateHost 把一段候选串归一化成 hostname：URL→Hostname；host:port→host；
// 裸域名/IP 原样小写。非法/空返回 ""。
func candidateHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	if ip := net.ParseIP(raw); ip != nil {
		return strings.ToLower(raw)
	}
	if strings.ContainsAny(raw, "/?# ") {
		return ""
	}
	return strings.ToLower(raw)
}

// FilterPseudoTargets 伪资产反向校验：候选目标地址逐个回查漏洞证据——候选
// host 必须出现在任一证据文本（复现请求报文/命令串）里，且以「host 边界」
// 命中（前后不得粘连域名字符，杜绝 10.0.0.1 误命中 10.0.0.10、
// v1.example.com 误命中 v1.example.com.evil 一类版本串/子域串）。
// 未命中 → 剔除。返回 (保留, 剔除)；纯函数，剔除集由调用方拼进 warning。
func FilterPseudoTargets(candidates []string, evidence []string) (kept, removed []string) {
	joined := strings.ToLower(strings.Join(evidence, "\n\x00\n"))
	for _, c := range candidates {
		host := candidateHost(c)
		if host != "" && hostContained(joined, host) {
			kept = append(kept, c)
		} else {
			removed = append(removed, c)
		}
	}
	return kept, removed
}

// hostContained 在已小写的 evidence 全文里找 host 的边界出现：匹配片段前一
// 字符不属于 host 字符集（字母数字及 . - _），后一字符同理；IP/域名的版本串
// 粘连（.10、v1.example.comX 等）因此不会误判。
func hostContained(evidence, host string) bool {
	if host == "" || evidence == "" {
		return false
	}
	isHostChar := func(b byte) bool {
		return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '.' || b == '-' || b == '_'
	}
	from := 0
	for {
		i := strings.Index(evidence[from:], host)
		if i < 0 {
			return false
		}
		i += from
		startOK := i == 0 || !isHostChar(evidence[i-1])
		end := i + len(host)
		endOK := end >= len(evidence) || !isHostChar(evidence[end])
		if startOK && endOK {
			return true
		}
		from = i + 1
	}
}

// ---------- 纯函数：项目级按资产分章节 ----------

// AssetGroup 是项目级报告的一个资产章节：同一资产上的全部漏洞小节。
type AssetGroup struct {
	Asset    string        `json:"asset"` // label；未关联资产桶 = ""
	Sections []VulnSection `json:"sections"`
}

// GroupVulnsByAsset 把合并后的漏洞按资产 label 分组（项目级章节结构）：
// 组内保持传入序（已按 severity 降序），组间按「组内最高 severity」降序、
// 同档按资产名序；未关联资产（""）排最后。纯函数。
func GroupVulnsByAsset(in []VulnSection) []AssetGroup {
	byAsset := map[string][]VulnSection{}
	for _, v := range in {
		byAsset[v.Asset] = append(byAsset[v.Asset], v)
	}
	groups := make([]AssetGroup, 0, len(byAsset))
	for a, secs := range byAsset {
		groups = append(groups, AssetGroup{Asset: a, Sections: secs})
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Asset == "" {
			return false // 未关联桶恒最后
		}
		if groups[j].Asset == "" {
			return true
		}
		ri, rj := sevRankOf(groups[i].Sections[0].Severity), sevRankOf(groups[j].Sections[0].Severity)
		if ri != rj {
			return ri < rj
		}
		return groups[i].Asset < groups[j].Asset
	})
	return groups
}

// ---------- 交付文件名（纯函数） ----------

// ReportBaseName 生成 <任务名|项目名>-<YYYYMMDD>.<ext>：标题清洗（剥路径分隔
// 与控制字符、空白折叠为下划线、限长 80 rune）、扩展名小写。中文保留（前端
// 下载走 RFC5987 filename*，服务端落盘用 job id 前缀防撞名，见 reportgen）。
func ReportBaseName(title string, at time.Time, ext string) string {
	name := strings.Join(strings.Fields(title), "_")
	name = unsafeFilenameChars.ReplaceAllString(name, "_")
	name = strings.Trim(name, "._")
	if name == "" {
		name = "渗透测试报告"
	}
	if len([]rune(name)) > 80 {
		name = string([]rune(name)[:80])
	}
	ext = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(ext), "."))
	if ext == "" {
		ext = "docx"
	}
	return fmt.Sprintf("%s-%s.%s", name, at.Format("20060102"), ext)
}

// ---------- Markdown 桩渲染（T16 docx 实装前的默认 ReportRenderer 用） ----------

// MarkdownFromInput 按章节骨架渲染 Markdown 交付（report.Markdown 的骨架感知
// 版；桩实现输出 data/reports/<id>.md）。只尊重 enabled 章节，顺序=skeleton。
func MarkdownFromInput(in *ReportInput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", nz(in.Title, "渗透测试报告"))
	if in.HasChapter(db.SectionCover) {
		if in.Issuer != "" {
			fmt.Fprintf(&b, "- **出具方**：%s\n", in.Issuer)
		}
		for _, t := range in.Tasks {
			fmt.Fprintf(&b, "- **来源任务**：%s（#%d）\n", t.DisplayName(), t.ID)
		}
		fmt.Fprintf(&b, "- **生成时间**：%s\n\n", in.GeneratedAt.Format("2006-01-02 15:04:05"))
	}
	if in.HasChapter(db.SectionStatement) {
		b.WriteString("## 声明\n\n本报告仅供委托方内部安全改进使用，未经出具方书面许可不得外传或用于任何非法用途。\n\n")
	}
	if in.HasChapter(db.SectionTargets) {
		b.WriteString("## 检测目标\n\n")
		if len(in.Targets) == 0 {
			b.WriteString("_（无可验证的漏洞目标）_\n\n")
		} else {
			for _, t := range in.Targets {
				fmt.Fprintf(&b, "- %s\n", t)
			}
			b.WriteString("\n")
		}
	}
	if in.HasChapter(db.SectionSummary) {
		b.WriteString("## 风险等级汇总\n\n| 严重等级 | 数量 |\n| --- | --- |\n")
		counts := in.SeverityCounts()
		for _, s := range []struct{ key, label string }{
			{"critical", "严重"}, {"high", "高危"}, {"medium", "中危"}, {"low", "低危"}, {"info", "其他"},
		} {
			fmt.Fprintf(&b, "| %s | %d |\n", s.label, counts[s.key])
		}
		b.WriteString("\n")
	}
	if in.HasChapter(db.SectionVulnDetail) {
		b.WriteString("## 漏洞明细\n\n")
		if len(in.Findings) == 0 {
			b.WriteString("_本次未确认漏洞。_\n\n")
		}
		// 项目级=按资产分章节（规格 T15(2/2)）；任务级=扁平序列。
		if in.Scope == "project" {
			n := 0
			for _, g := range GroupVulnsByAsset(in.Findings) {
				asset := nz(g.Asset, "未关联资产")
				fmt.Fprintf(&b, "### 资产：%s\n\n", asset)
				for _, f := range g.Sections {
					n++
					b.WriteString(vulnHeadingMD(f, n))
					b.WriteString(renderReproductionMD(f.Reproduction))
				}
			}
		} else {
			for i, f := range in.Findings {
				b.WriteString(vulnHeadingMD(f, i+1))
				if rp := renderReproductionMD(f.Reproduction); rp != "" {
					b.WriteString(rp)
				}
			}
		}
	}
	if in.HasChapter(db.SectionConclusion) {
		b.WriteString("## 结论与建议\n\n建议按严重等级优先修复上述问题，并在修复后安排复测。\n")
	}
	return b.String()
}

// vulnHeadingMD 渲染一个漏洞小节的标题+元信息段（不含复现过程）。
func vulnHeadingMD(f VulnSection, n int) string {
	var b strings.Builder
	src := ""
	if len(f.SourceTasks) > 1 {
		ids := make([]string, 0, len(f.SourceTasks))
		for _, t := range f.SourceTasks {
			ids = append(ids, fmt.Sprintf("#%d", t))
		}
		src = fmt.Sprintf("（来源任务 %s）", strings.Join(ids, "、"))
	}
	fmt.Fprintf(&b, "#### %d. [%s] %s%s\n\n", n, strings.ToUpper(nz(f.Severity, "info")), f.Name, src)
	if f.Asset != "" {
		fmt.Fprintf(&b, "- **资产**：%s\n", f.Asset)
	}
	if f.Description != "" {
		fmt.Fprintf(&b, "%s\n\n", f.Description)
	} else {
		b.WriteString("\n")
	}
	return b.String()
}

// renderReproductionMD 把 T14 reproduction JSON 渲染成「复现过程」小节；
// 空/'{}'/无步骤 → ""。request/response 用代码块逐字呈现（红线：不省略）。
func renderReproductionMD(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var rp Reproduction
	if json.Unmarshal(raw, &rp) != nil || len(rp.Steps) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("**复现过程：**\n\n")
	if rp.EntryPoint != "" {
		fmt.Fprintf(&b, "- 入口点：`%s`\n", rp.EntryPoint)
	}
	for _, p := range rp.Prerequisites {
		fmt.Fprintf(&b, "- 前置条件：%s\n", p)
	}
	b.WriteString("\n")
	for i, st := range rp.Steps {
		fmt.Fprintf(&b, "步骤 %d", i+1)
		if st.Expected != "" {
			fmt.Fprintf(&b, "（预期：%s）", st.Expected)
		}
		b.WriteString("\n\n")
		if st.Request != "" {
			fmt.Fprintf(&b, "请求：\n\n```\n%s\n```\n\n", st.Request)
		}
		if st.Response != "" {
			fmt.Fprintf(&b, "响应：\n\n```\n%s\n```\n\n", st.Response)
		}
	}
	return b.String()
}
