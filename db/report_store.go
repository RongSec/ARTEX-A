package db

// T15 报告中心 store：report_templates（模板 CRUD + 默认模板单事务维护）、
// reports（生成 job + 交付历史一体，状态机 pending→running→done|failed）、
// report_settings（全局单例）。语义参考 antifox/db/report_store.go（0.1.1 分叉，
// 只借语义不拷实现），结构按 artex-hs 0.3.15 表设计重写。

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// ---------- skeleton 校验（纯函数，handler 与 store 共用） ----------

// ReportSectionKey 是报告章节骨架的一个章节标识。T16 pybuilder 按 key 渲染
// 对应章节；新增章节需同时扩这里与 pybuilder 的映射表。
type ReportSectionKey string

// 章节 key 枚举（起步集）。顺序即默认骨架顺序。
const (
	SectionCover      ReportSectionKey = "cover"       // 封面
	SectionStatement  ReportSectionKey = "statement"   // 声明
	SectionTargets    ReportSectionKey = "targets"     // 检测目标表
	SectionSummary    ReportSectionKey = "summary"     // 风险等级汇总统计
	SectionVulnDetail ReportSectionKey = "vuln_detail" // 漏洞明细（每漏洞一节）
	SectionConclusion ReportSectionKey = "conclusion"  // 结论/建议
)

// DefaultSectionKeys 是默认章节顺序（骨架归一化时的缺省 title 来源）。
var DefaultSectionKeys = []ReportSectionKey{
	SectionCover, SectionStatement, SectionTargets, SectionSummary, SectionVulnDetail, SectionConclusion,
}

// defaultSectionTitles 是各章节的缺省中文标题（可被骨架里的 title 覆盖）。
var defaultSectionTitles = map[ReportSectionKey]string{
	SectionCover:      "封面",
	SectionStatement:  "声明",
	SectionTargets:    "检测目标",
	SectionSummary:    "风险等级汇总",
	SectionVulnDetail: "漏洞明细",
	SectionConclusion: "结论与建议",
}

// ReportSection 是 skeleton JSONB 数组的一个元素：有序章节定义。
type ReportSection struct {
	Key     ReportSectionKey `json:"key"`
	Title   string           `json:"title"`
	Enabled bool             `json:"enabled"`
}

// ErrReportSkeletonInvalid 是骨架校验的统一错误包装。
var ErrReportSkeletonInvalid = errors.New("invalid report skeleton")

// ValidateSkeleton 校验章节骨架数组：非空、元素 key 必须是已知枚举、key 不得
// 重复。纯函数，供 handler 入参校验与 store 写入前共用。
func ValidateSkeleton(sections []ReportSection) error {
	if len(sections) == 0 {
		return fmt.Errorf("%w: skeleton is empty", ErrReportSkeletonInvalid)
	}
	seen := map[ReportSectionKey]bool{}
	for _, s := range sections {
		if !isKnownSectionKey(s.Key) {
			return fmt.Errorf("%w: unknown section key %q", ErrReportSkeletonInvalid, string(s.Key))
		}
		if seen[s.Key] {
			return fmt.Errorf("%w: duplicate section key %q", ErrReportSkeletonInvalid, string(s.Key))
		}
		seen[s.Key] = true
	}
	return nil
}

// NormalizeSkeleton 在写入前归一化骨架：TrimSpace title，空 title 回退默认章节
// 标题。非法输入原样返回（调用方先 Validate）。纯函数。
func NormalizeSkeleton(sections []ReportSection) []ReportSection {
	out := make([]ReportSection, 0, len(sections))
	for _, s := range sections {
		s.Title = strings.Join(strings.Fields(s.Title), " ")
		if s.Title == "" {
			s.Title = defaultSectionTitles[s.Key]
		}
		out = append(out, s)
	}
	return out
}

// ParseSkeletonJSON 解析 skeleton 列值：合法 JSON 数组直接返回；空/`'{}'`/解析
// 失败（历史脏值）→ 返回默认全章节骨架（enabled=true），保证读取端零特判。
func ParseSkeletonJSON(raw []byte) []ReportSection {
	if len(raw) > 0 && strings.TrimSpace(string(raw)) != "{}" {
		var out []ReportSection
		if json.Unmarshal(raw, &out) == nil && len(out) > 0 {
			return NormalizeSkeleton(out)
		}
	}
	def := make([]ReportSection, 0, len(DefaultSectionKeys))
	for _, k := range DefaultSectionKeys {
		def = append(def, ReportSection{Key: k, Title: defaultSectionTitles[k], Enabled: true})
	}
	return def
}

func isKnownSectionKey(k ReportSectionKey) bool {
	for _, d := range DefaultSectionKeys {
		if d == k {
			return true
		}
	}
	return false
}

// ---------- report_templates ----------

// ReportTemplate is a row in report_templates: reusable cover/section/style/AI
// prompt preset for generated reports.
type ReportTemplate struct {
	ID          int64           `json:"id"`
	Name        string          `json:"name"`
	Version     int             `json:"version"` // 骨架版本号；结构变更时 +1（R1）
	IsDefault   bool            `json:"is_default"`
	OutputLang  string          `json:"output_lang"`
	Skeleton    []ReportSection `json:"skeleton"`
	Style       json.RawMessage `json:"style"`
	Prompts     json.RawMessage `json:"prompts"`
	Issuer      string          `json:"issuer"`
	LogoPath    string          `json:"logo_path"`
	Personnel   json.RawMessage `json:"personnel"` // [{name,role,contact}]
	CVSSEnabled bool            `json:"cvss_enabled"`
	Remark      string          `json:"remark"`
	// DocxPath = 用户上传的模板原件（相对 dataDir）。非空且文件存在时报告
	// 渲染走模板填充（保留原版式）；空=按章节重建。
	DocxPath  string    `json:"docx_path"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ReportTemplateVersion 是 report_template_versions 的一行：模板结构变更前的
// 旧骨架快照（R1：重复上传模板时保留历史，不覆盖丢弃）。
type ReportTemplateVersion struct {
	ID         int64           `json:"id"`
	TemplateID int64           `json:"template_id"`
	Version    int             `json:"version"`
	Skeleton   []ReportSection `json:"skeleton"`
	Style      json.RawMessage `json:"style"`
	CreatedAt  time.Time       `json:"created_at"`
}

// ReportTemplateInput is the create/payload-normalized form used by handlers.
// Skeleton nil/empty → store rejects with ErrReportSkeletonInvalid（handler 侧应
// 先 ValidateSkeleton）。
type ReportTemplateInput struct {
	Name        string
	OutputLang  string
	Skeleton    []ReportSection
	Style       json.RawMessage
	Prompts     json.RawMessage
	Issuer      string
	LogoPath    string
	Personnel   json.RawMessage
	CVSSEnabled bool
	Remark      string
	DocxPath    string
}

var (
	ErrReportTemplateInvalid  = errors.New("invalid report template")
	ErrReportTemplateNotFound = errors.New("report template not found")
	ErrReportNotFound         = errors.New("report not found")
	ErrReportBadTransition    = errors.New("illegal report status transition")
)

const reportTemplateCols = `id, name, COALESCE(version,1), is_default, output_lang,
	COALESCE(skeleton, '[]'::jsonb), COALESCE(style, '{}'::jsonb), COALESCE(prompts, '{}'::jsonb),
	COALESCE(issuer, ''), COALESCE(logo_path, ''), COALESCE(personnel, '[]'::jsonb),
	COALESCE(cvss_enabled, false), COALESCE(remark, ''), COALESCE(docx_path, ''), created_at, updated_at`

func scanReportTemplate(row interface{ Scan(...any) error }) (*ReportTemplate, error) {
	t := &ReportTemplate{}
	var skel, style, prompts, personnel []byte
	if err := row.Scan(&t.ID, &t.Name, &t.Version, &t.IsDefault, &t.OutputLang,
		&skel, &style, &prompts,
		&t.Issuer, &t.LogoPath, &personnel,
		&t.CVSSEnabled, &t.Remark, &t.DocxPath, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	if t.Version <= 0 {
		t.Version = 1
	}
	t.Skeleton = ParseSkeletonJSON(skel)
	t.Style = json.RawMessage(nonEmptyJSON(style, "{}"))
	t.Prompts = json.RawMessage(nonEmptyJSON(prompts, "{}"))
	t.Personnel = json.RawMessage(nonEmptyJSON(personnel, "[]"))
	return t, nil
}

func nonEmptyJSON(raw []byte, def string) []byte {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return []byte(def)
	}
	return raw
}

// styleNumericKeys 是样式表里必须是数字的键；字符串键与布尔键分开处理。
// 键名与 report/pybuilder/report_builder.py 的 DEFAULTS 一一对应，两边
// 必须同时改（Python 侧 _sanitize_style 是运行时兜底，这里是落库前收口）。
var styleNumericKeys = map[string]bool{
	"body_size": true, "h1_size": true, "h2_size": true, "vuln_size": true,
	"label_size": true, "table_size": true, "code_size": true,
	"line_spacing": true, "proof_gap_paragraphs": true,
}

var styleBoolKeys = map[string]bool{"first_line_indent": true}

var styleStringKeys = map[string]bool{
	"body_font": true, "west_font": true, "head_font": true, "code_font": true,
	"proof_label": true, "table_style": true, "code_bg": true, "proves_label": true,
}

// SanitizeStyleJSON 把模板样式表收敛成"只含有效键值"的对象。
//
// 背景：模板编辑器的输入框被清空时会提交 `""`，这些键直接覆盖 Python 侧
// DEFAULTS 后，`Pt("")` 抛 TypeError，整份报告渲染 502（用户实测：导入模板
// 后预览报"渲染失败"）。纪律与 Python 侧一致：空串/空值=未设置，数字键必须
// 能解析，布尔键只认真假，未知键丢弃。解析失败时原样返回，交给渲染侧兜底。
func SanitizeStyleJSON(raw json.RawMessage) json.RawMessage {
	var in map[string]any
	if err := json.Unmarshal(raw, &in); err != nil {
		return raw
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			switch {
			case styleNumericKeys[k]:
				if f, err := strconv.ParseFloat(s, 64); err == nil {
					out[k] = f
				}
			case styleBoolKeys[k]:
				switch strings.ToLower(s) {
				case "1", "true", "yes", "是":
					out[k] = true
				case "0", "false", "no", "否":
					out[k] = false
				}
			case styleStringKeys[k]:
				out[k] = s
			}
			continue
		}
		switch {
		case styleNumericKeys[k]:
			if f, ok := v.(float64); ok {
				out[k] = f
			}
		case styleBoolKeys[k]:
			if b, ok := v.(bool); ok {
				out[k] = b
			}
		case styleStringKeys[k]:
			out[k] = v
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return raw
	}
	return json.RawMessage(b)
}

// normalizeTemplateInput trims whitespace, applies defaults and validates the
// skeleton. Shared by create/update paths.
func normalizeTemplateInput(in ReportTemplateInput) (ReportTemplateInput, error) {
	in.Name = strings.Join(strings.Fields(in.Name), " ")
	if in.Name == "" {
		return in, fmt.Errorf("%w: name is required", ErrReportTemplateInvalid)
	}
	if strings.TrimSpace(in.OutputLang) == "" {
		in.OutputLang = "zh-CN"
	} else {
		in.OutputLang = strings.TrimSpace(in.OutputLang)
	}
	if err := ValidateSkeleton(in.Skeleton); err != nil {
		return in, err
	}
	in.Skeleton = NormalizeSkeleton(in.Skeleton)
	if len(in.Style) == 0 {
		in.Style = json.RawMessage("{}")
	} else {
		in.Style = SanitizeStyleJSON(in.Style)
	}
	if len(in.Prompts) == 0 {
		in.Prompts = json.RawMessage("{}")
	}
	if len(in.Personnel) == 0 {
		in.Personnel = json.RawMessage("[]")
	}
	in.Issuer = strings.TrimSpace(in.Issuer)
	in.LogoPath = strings.TrimSpace(in.LogoPath)
	in.Remark = strings.TrimSpace(in.Remark)
	in.DocxPath = strings.TrimSpace(in.DocxPath)
	return in, nil
}

func marshalSkeleton(sections []ReportSection) ([]byte, error) {
	if sections == nil {
		sections = []ReportSection{}
	}
	return json.Marshal(sections)
}

// CreateReportTemplate inserts one template. The first template ever created is
// automatically flagged default (zero-config usability); later ones never steal
// the default role implicitly — use SetDefaultTemplate.
func (d *DB) CreateReportTemplate(in ReportTemplateInput) (*ReportTemplate, error) {
	in, err := normalizeTemplateInput(in)
	if err != nil {
		return nil, err
	}
	skel, err := marshalSkeleton(in.Skeleton)
	if err != nil {
		return nil, err
	}
	var hasAny bool
	if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM report_templates)`).Scan(&hasAny); err != nil {
		return nil, err
	}
	t, err := scanReportTemplate(d.QueryRow(`
INSERT INTO report_templates(name, is_default, output_lang, skeleton, style, prompts,
	issuer, logo_path, personnel, cvss_enabled, remark, docx_path)
VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb, $7, $8, $9::jsonb, $10, $11, $12)
RETURNING `+reportTemplateCols,
		in.Name, !hasAny, in.OutputLang, skel, in.Style, in.Prompts,
		in.Issuer, in.LogoPath, in.Personnel, in.CVSSEnabled, in.Remark, in.DocxPath))
	if err != nil {
		return nil, err
	}
	return t, nil
}

// ListReportTemplates returns all templates: default first, then newest.
func (d *DB) ListReportTemplates() ([]*ReportTemplate, error) {
	rows, err := d.Query(`SELECT ` + reportTemplateCols + `
		FROM report_templates ORDER BY is_default DESC, updated_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ReportTemplate{}
	for rows.Next() {
		t, err := scanReportTemplate(rows)
		if err != nil {
			return out, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetReportTemplate returns one template by id, or nil when absent.
func (d *DB) GetReportTemplate(id int64) (*ReportTemplate, error) {
	t, err := scanReportTemplate(d.QueryRow(`SELECT `+reportTemplateCols+` FROM report_templates WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

// GetDefaultReportTemplate resolves the effective default template: the one
// flagged is_default; if none is flagged but rows exist, falls back to the most
// recently updated row (keeps report generation working after data edits).
// Returns nil when no template exists at all.
func (d *DB) GetDefaultReportTemplate() (*ReportTemplate, error) {
	t, err := scanReportTemplate(d.QueryRow(`SELECT ` + reportTemplateCols + `
		FROM report_templates WHERE is_default LIMIT 1`))
	if err == nil {
		return t, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}
	t, err = scanReportTemplate(d.QueryRow(`SELECT ` + reportTemplateCols + `
		FROM report_templates ORDER BY updated_at DESC, id DESC LIMIT 1`))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

// UpdateReportTemplate overwrites the editable fields of one template. The
// is_default flag is NOT touched here (single-transaction invariant is only
// maintainable through SetDefaultTemplate).
//
// R1：骨架结构发生变化时在同一事务内 version+1，并把**旧**骨架/样式快照写入
// report_template_versions（历史可回溯）。名称/样式等非结构改动不动版本号。
func (d *DB) UpdateReportTemplate(id int64, in ReportTemplateInput) (*ReportTemplate, error) {
	in, err := normalizeTemplateInput(in)
	if err != nil {
		return nil, err
	}
	skel, err := marshalSkeleton(in.Skeleton)
	if err != nil {
		return nil, err
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	var oldSkel, oldStyle []byte
	var oldVersion int
	if err := tx.QueryRow(`SELECT COALESCE(skeleton,'[]'::jsonb), COALESCE(style,'{}'::jsonb), COALESCE(version,1)
		FROM report_templates WHERE id=$1 FOR UPDATE`, id).Scan(&oldSkel, &oldStyle, &oldVersion); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrReportTemplateNotFound
		}
		return nil, err
	}
	if oldVersion <= 0 {
		oldVersion = 1
	}
	version := oldVersion
	if !jsonEqual(oldSkel, skel) {
		version = oldVersion + 1
		if _, err := tx.Exec(`INSERT INTO report_template_versions(template_id, version, skeleton, style)
			VALUES ($1,$2,$3::jsonb,$4::jsonb)`, id, oldVersion, nonEmptyJSON(oldSkel, "[]"), nonEmptyJSON(oldStyle, "{}")); err != nil {
			return nil, err
		}
	}
	t, err := scanReportTemplate(tx.QueryRow(`
UPDATE report_templates SET
	name=$2, output_lang=$3, skeleton=$4::jsonb, style=$5::jsonb, prompts=$6::jsonb,
	issuer=$7, logo_path=$8, personnel=$9::jsonb, cvss_enabled=$10, remark=$11,
	docx_path=$12, version=$13
WHERE id=$1
RETURNING `+reportTemplateCols,
		id, in.Name, in.OutputLang, skel, in.Style, in.Prompts,
		in.Issuer, in.LogoPath, in.Personnel, in.CVSSEnabled, in.Remark, in.DocxPath, version))
	if err == sql.ErrNoRows {
		return nil, ErrReportTemplateNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return t, nil
}

// SetReportTemplateDocxPath 只更新模板原件路径（导入落盘/替换时用，避免为了
// 一个路径字段走整行 UpdateReportTemplate 的版本快照逻辑）。
func (d *DB) SetReportTemplateDocxPath(id int64, path string) error {
	res, err := d.Exec(`UPDATE report_templates SET docx_path=$2 WHERE id=$1`,
		id, strings.TrimSpace(path))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrReportTemplateNotFound
	}
	return nil
}

// jsonEqual 比较两段 JSON 的语义等价（忽略对象键序/空白）。解析失败退回字节
// 比较——坏数据也能给出稳定判定，不因一侧非法直接 panic。
func jsonEqual(a, b []byte) bool {
	var av, bv any
	if json.Unmarshal(a, &av) != nil || json.Unmarshal(b, &bv) != nil {
		return strings.TrimSpace(string(a)) == strings.TrimSpace(string(b))
	}
	return reflect.DeepEqual(av, bv)
}

// ListReportTemplateVersions 返回某模板的历史快照（新→旧）。空列表=无历史。
func (d *DB) ListReportTemplateVersions(templateID int64) ([]*ReportTemplateVersion, error) {
	rows, err := d.Query(`SELECT id, template_id, version, COALESCE(skeleton,'[]'::jsonb), COALESCE(style,'{}'::jsonb), created_at
		FROM report_template_versions WHERE template_id=$1 ORDER BY version DESC, id DESC`, templateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ReportTemplateVersion{}
	for rows.Next() {
		v := &ReportTemplateVersion{}
		var skel, style []byte
		if err := rows.Scan(&v.ID, &v.TemplateID, &v.Version, &skel, &style, &v.CreatedAt); err != nil {
			return out, err
		}
		v.Skeleton = ParseSkeletonJSON(skel)
		v.Style = json.RawMessage(nonEmptyJSON(style, "{}"))
		out = append(out, v)
	}
	return out, rows.Err()
}

// DeleteReportTemplate removes a template; returns false when the id was absent.
// Deleting the default template leaves report_settings.template_id dangling —
// callers resolve the default via GetDefaultReportTemplate fallback, so no
// orphan-flag cleanup is needed (flag rows live only on template rows).
func (d *DB) DeleteReportTemplate(id int64) (bool, error) {
	res, err := d.Exec(`DELETE FROM report_templates WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// SetDefaultTemplate atomically clears the previous default and flags the new
// one. Single transaction, so the "at most one is_default" invariant holds
// under concurrent calls. Returns ErrReportTemplateNotFound when id is absent.
func (d *DB) SetDefaultTemplate(id int64) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	var exists bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM report_templates WHERE id=$1)`, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrReportTemplateNotFound
	}
	if _, err := tx.Exec(`UPDATE report_templates SET is_default=(id=$1) WHERE is_default OR id=$1`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// ---------- reports（job + 历史一体） ----------

// Report job statuses. The state machine: pending→running→done|failed.
const (
	ReportPending = "pending"
	ReportRunning = "running"
	ReportDone    = "done"
	ReportFailed  = "failed"
)

// Report scopes.
const (
	ReportScopeTask    = "task"
	ReportScopeProject = "project"
)

// CanAdvanceReport is the PURE state-transition matrix: pending→running,
// running→done, running→failed. Everything else (self-loops, skips, terminal
// exits) is illegal. Unit-tested exhaustively; DB layer enforces it via the
// WHERE status=from guard in AdvanceReportStatus.
func CanAdvanceReport(from, to string) bool {
	switch from {
	case ReportPending:
		return to == ReportRunning
	case ReportRunning:
		return to == ReportDone || to == ReportFailed
	default: // done/failed are terminal; unknown from states never advance
		return false
	}
}

// Report is a row in reports: one generation job and (once done) its delivery
// history entry. TaskID holds the source task for scope='task' (the column is
// named task_ids in DDL for spec fidelity but carries a single bigint id).
type Report struct {
	ID         int64     `json:"id"`
	Scope      string    `json:"scope"`
	TaskID     *int64    `json:"task_id,omitempty"`
	ProjectID  *int64    `json:"project_id,omitempty"`
	TemplateID *int64    `json:"template_id,omitempty"`
	Locale     string    `json:"locale"`
	Format     string    `json:"format"`
	Status     string    `json:"status"`
	FilePath   string    `json:"file_path"`
	Error      string    `json:"error"`
	Warning    string    `json:"warning"`
	FindingIDs []int64   `json:"finding_ids"`
	CreatedAt  time.Time `json:"created_at"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
}

const reportCols = `id, scope, task_ids, project_id, template_id, locale, format, status,
	COALESCE(file_path, ''), COALESCE(error, ''), COALESCE(warning, ''),
	array_to_json(COALESCE(finding_ids, '{}'))::text, created_at, started_at, finished_at`

func scanReport(row interface{ Scan(...any) error }) (*Report, error) {
	r := &Report{}
	var aids []byte
	var started, finished sql.NullTime
	if err := row.Scan(&r.ID, &r.Scope, &r.TaskID, &r.ProjectID, &r.TemplateID, &r.Locale, &r.Format, &r.Status,
		&r.FilePath, &r.Error, &r.Warning, &aids, &r.CreatedAt, &started, &finished); err != nil {
		return nil, err
	}
	r.FindingIDs = unmarshalInt64Array(aids)
	if started.Valid {
		r.StartedAt = started.Time
	}
	if finished.Valid {
		r.FinishedAt = finished.Time
	}
	return r, nil
}

// unmarshalInt64Array parses a PG bigint[] rendered as text ("{1,2}") or JSON
// array text ("[1,2]") — both shapes occur depending on driver/serialization,
// mirror of assets.go's array_to_json(... ) reads which use json.Unmarshal.
// The reportCols select returns raw bigint[] text, hence the {} parser.
// unmarshalInt64Array parses finding_ids read via array_to_json(...)::text, so
// the input is a JSON array literal ("[1,2]" / "[]" / "null"). Mirrors the
// assets.go convention of JSON-rendering bigint[] before scanning.
func unmarshalInt64Array(raw []byte) []int64 {
	out := []int64{}
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return out
	}
	_ = json.Unmarshal([]byte(s), &out)
	if out == nil {
		out = []int64{}
	}
	return out
}

// InsertReport creates a job row in pending state and returns it.
func (d *DB) InsertReport(scope string, taskID, projectID, templateID int64, locale, format string, findingIDs []int64) (*Report, error) {
	// 用 sql.NullInt64 而不是 any(nil)：PostgreSQL 无法从无类型 nil 推断
	// 参数类型，会直接报 "could not determine data type of parameter $3"
	// （任务级报告 project_id 为空时必现）。
	var tid, pid, tmpl sql.NullInt64
	if taskID > 0 {
		tid = sql.NullInt64{Int64: taskID, Valid: true}
	}
	if projectID > 0 {
		pid = sql.NullInt64{Int64: projectID, Valid: true}
	}
	if templateID > 0 {
		tmpl = sql.NullInt64{Int64: templateID, Valid: true}
	}
	if locale == "" {
		locale = "zh-CN"
	}
	if format == "" {
		format = "docx"
	}
	r, err := scanReport(d.QueryRow(`
INSERT INTO reports(scope, task_ids, project_id, template_id, locale, format, status, finding_ids)
VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7::bigint[])
RETURNING `+reportCols,
		scope, tid, pid, tmpl, locale, format, marshalInt64Array(findingIDs)))
	if err != nil {
		return nil, err
	}
	return r, nil
}

// AdvanceReportStatus performs one guarded state transition: the UPDATE only
// lands when the row is still in `from`, and the transition matrix
// (CanAdvanceReport) is checked first so illegal edges never hit SQL.
// Returns ErrReportNotFound when the id is absent, ErrReportBadTransition when
// the row moved on (or was in another state) — callers treat both as terminal.
func (d *DB) AdvanceReportStatus(id int64, from, to string) error {
	if !CanAdvanceReport(from, to) {
		return fmt.Errorf("%w: %s -> %s", ErrReportBadTransition, from, to)
	}
	var q string
	switch to {
	case ReportRunning:
		q = `UPDATE reports SET status=$2, started_at=now() WHERE id=$1 AND status=$3`
	default: // done / failed write finished_at
		q = `UPDATE reports SET status=$2, finished_at=now() WHERE id=$1 AND status=$3`
	}
	res, err := d.Exec(q, id, to, from)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		var exists bool
		if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM reports WHERE id=$1)`, id).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrReportNotFound
		}
		return ErrReportBadTransition
	}
	return nil
}

// FinishReportDone transitions running→done and records the artifact path plus
// an optional warning (e.g. pseudo-target filter notes) in one UPDATE.
func (d *DB) FinishReportDone(id int64, filePath, warning string) error {
	res, err := d.Exec(`UPDATE reports SET status='done', finished_at=now(), file_path=$2, warning=$3
		WHERE id=$1 AND status='running'`, id, filePath, warning)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrReportBadTransition
	}
	return nil
}

// FinishReportFailed transitions running→failed with a (truncated) error text.
func (d *DB) FinishReportFailed(id int64, errorText string) error {
	res, err := d.Exec(`UPDATE reports SET status='failed', finished_at=now(), error=$2
		WHERE id=$1 AND status='running'`, id, errorText)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrReportBadTransition
	}
	return nil
}

// HasOpenProjectReport 返回某项目是否已有未收尾（pending/running）的 project 级
// 报告 job（T18 自动报告去抖：并发双终态时后到的钩子看到前一个已入队的 job
// 就跳过，防重复建报告）。
func (d *DB) HasOpenProjectReport(projectID int64) (bool, error) {
	var exists bool
	err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM reports
WHERE project_id=$1 AND scope='project' AND status IN ('pending','running'))`, projectID).Scan(&exists)
	return exists, err
}

// GetReport returns one report/job row, or nil when absent.
func (d *DB) GetReport(id int64) (*Report, error) {
	r, err := scanReport(d.QueryRow(`SELECT `+reportCols+` FROM reports WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// ListReports returns a page of report history rows (newest first) plus the
// total count. page is 1-based; optional status filter ("" = all).
func (d *DB) ListReports(status string, page, pageSize int) ([]*Report, int, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	var cond string
	var args []any
	if status != "" {
		cond = ` WHERE status=$1`
		args = append(args, status)
	}
	var total int
	if err := d.QueryRow(`SELECT COUNT(*) FROM reports`+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if total == 0 || page > (total-1)/pageSize+1 {
		return []*Report{}, total, nil
	}
	q := fmt.Sprintf(`SELECT %s FROM reports%s ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d`,
		reportCols, cond, len(args)+1, len(args)+2)
	rows, err := d.Query(q, append(append([]any{}, args...), pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*Report{}
	for rows.Next() {
		r, err := scanReport(rows)
		if err != nil {
			return out, total, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// DeleteReport removes a history row; the caller deletes the on-disk file.
func (d *DB) DeleteReport(id int64) (bool, error) {
	res, err := d.Exec(`DELETE FROM reports WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ---------- report_settings（单例） ----------

// ReportSettings is the singleton row in report_settings: the org-wide default
// template pointer + fallback output locale + report name template.
type ReportSettings struct {
	TemplateID    *int64 `json:"template_id,omitempty"`
	DefaultLocale string `json:"default_locale"`
	// NameTemplate 是报告名称占位符模板（V9-NAME）；空串=使用默认模板
	// {system}渗透测试报告-{YYYY-MM-DD}（渲染侧兜底）。
	NameTemplate string `json:"name_template"`
}

// GetReportSettings returns the singleton (zero defaults when the row has never
// been written).
func (d *DB) GetReportSettings() (*ReportSettings, error) {
	rs := &ReportSettings{DefaultLocale: "zh-CN"}
	err := d.QueryRow(`SELECT template_id, default_locale, name_template FROM report_settings WHERE key='default'`).
		Scan(&rs.TemplateID, &rs.DefaultLocale, &rs.NameTemplate)
	if err == sql.ErrNoRows {
		return rs, nil
	}
	if err != nil {
		return nil, err
	}
	return rs, nil
}

// SaveReportSettings upserts the singleton. templateID 0 = NULL（回退 is_default
// 模板解析链）。locale 空值落 'zh-CN'；nameTemplate 原样落库（空串=默认模板）。
func (d *DB) SaveReportSettings(templateID int64, locale, nameTemplate string) (*ReportSettings, error) {
	var tid any
	if templateID > 0 {
		tid = templateID
	}
	if strings.TrimSpace(locale) == "" {
		locale = "zh-CN"
	}
	rs := &ReportSettings{DefaultLocale: locale, NameTemplate: strings.TrimSpace(nameTemplate)}
	if err := d.QueryRow(`
INSERT INTO report_settings(key, template_id, default_locale, name_template)
VALUES ('default', $1, $2, $3)
ON CONFLICT (key) DO UPDATE SET template_id=EXCLUDED.template_id, default_locale=EXCLUDED.default_locale, name_template=EXCLUDED.name_template
RETURNING template_id`, tid, locale, rs.NameTemplate).Scan(&rs.TemplateID); err != nil {
		return nil, err
	}
	return rs, nil
}

// ---------- 报告取数（带 detail 列：report 全文 + T14 reproduction） ----------

// FindingsForReport 返回报告组装所需的 findings 明细（含 report/reproduction 大
// 列，故不能复用列表查询）。taskIDs=来源任务集合；ids 非空时进一步限定 finding
// 子集（勾选导出语义，同 ListFindingsForExport）。排序：severity 降序→时间倒序。
// 任务集合为空时返回空切片（调用方在入队前已校验任务存在性）。
func (d *DB) FindingsForReport(taskIDs, ids []int64) ([]*DBFinding, error) {
	if len(taskIDs) == 0 {
		return []*DBFinding{}, nil
	}
	// 用 = ANY($n::bigint[]) 而不是逐值展开 IN ($1,$2,...)：库驱动在部分
	// 环境下无法为展开后的中间参数推断类型，PostgreSQL 直接报
	// "could not determine data type of parameter $3"（任务级+勾选子集必现）。
	args := []any{taskIDs}
	where := `WHERE f.task_id = ANY($1::bigint[])`
	if len(ids) > 0 {
		args = append(args, ids)
		where += ` AND f.id = ANY($2::bigint[])`
	}
	q := `SELECT ` + findingDetailCols + `
		FROM findings f
		LEFT JOIN tasks t ON f.task_id = t.id
		` + where + `
		ORDER BY CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, f.created_at DESC`
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DBFinding
	for rows.Next() {
		f := &DBFinding{}
		var aidsJSON string
		if err := rows.Scan(&f.ID, &f.TaskID, &f.NodeID, &f.VulnClass, &f.Name, &f.Severity,
			&f.Summary, &f.Evidence, &f.Worker, &aidsJSON, &f.Status, &f.CreatedAt,
			&f.TaskDescription, &f.EvidenceVersion, &f.ReportEvidenceVersion, &f.TrafficCount, &f.Report, &f.Reproduction); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(aidsJSON), &f.AssetIDs)
		out = append(out, f)
	}
	return out, rows.Err()
}

// ResolveTemplateIDBySettings applies the template resolution chain:
// explicit id (>0) → settings.template_id (if the row still exists) →
// is_default template → nil. Returns nil,nil when nothing resolves.
func (d *DB) ResolveTemplateIDBySettings(explicit int64) (*ReportTemplate, error) {
	if explicit > 0 {
		return d.GetReportTemplate(explicit)
	}
	st, err := d.GetReportSettings()
	if err == nil && st.TemplateID != nil && *st.TemplateID > 0 {
		if t, err := d.GetReportTemplate(*st.TemplateID); err == nil && t != nil {
			return t, nil
		}
	}
	return d.GetDefaultReportTemplate()
}
