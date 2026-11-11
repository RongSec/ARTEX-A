package server

// T15 报告中心 API + 生成 job 骨架（artex-hs F4）。
//
// 端点（全部挂 /api/ 前缀 → 自动过 requireAuth(JWT)+CORS）：
//   GET/POST            /api/report-templates            模板列表/新建
//   PATCH/DELETE        /api/report-templates/{id}       模板改/删
//   POST                /api/report-templates/{id}/set-default  设默认（单事务）
//   GET/PATCH           /api/report-settings             全局设置读/改
//   POST                /api/report/generate             建 job（pending）→ 异步协程跑
//   GET                 /api/report/jobs/{id}            状态轮询（status/error/warning）
//   GET                 /api/report/jobs/{id}/download   done 后下载产物
//   GET                 /api/reports                     历史列表（分页；重下不重生成）
//   DELETE              /api/reports/{id}                删行+删文件
//
// 前缀零遮蔽核查：新前缀 /api/report-templates、/api/report-settings、
// /api/report/generate|jobs、/api/reports 与既有 GET /api/report（?task= 快速
// Markdown 预览，原版）是不同精确路径，Go ServeMux 互不遮蔽。
//
// 渲染实现挂点：ReportRenderer 接口。本棒默认桩 = buildReportInput 组装数据 →
// report.MarkdownFromInput 写 data/reports/<id>.md。**T16 换 pybuilder docx
// 实装时只需替换（或按 job.Format 分派）s.reportRenderer，表结构与 API 不动。**

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
)

// ReportRenderer 渲染一个已置 running 的 job，返回产物绝对路径 + 可选 warning
// （例：伪资产剔除清单）+ 错误。这是 T16 docx（pybuilder）实装的挂点：替换
// Server.reportRenderer 字段即可，job 生命周期 / API / 表结构零改动。
type ReportRenderer func(ctx context.Context, job *db.Report) (filePath string, warning string, err error)

// reportErrorStoreTruncate 是 error/warning 入库前的截断上限（字节）。渲染
// 错误常带堆栈/命令输出，整段入库撑爆列表接口。
const reportErrorStoreTruncate = 2000

// ---------- 模板 CRUD ----------

// reportTemplateBody 是 POST 的线格式（骨架/样式/人员原样 JSON 透传；指针字段
// 供 PATCH 区分「未传=保留旧值」与「显式清空」，见 reportTemplatePatchBody）。
type reportTemplateBody struct {
	Name        string             `json:"name"`
	OutputLang  string             `json:"output_lang"`
	Skeleton    []db.ReportSection `json:"skeleton"`
	Style       json.RawMessage    `json:"style"`
	Prompts     json.RawMessage    `json:"prompts"`
	Issuer      string             `json:"issuer"`
	LogoPath    string             `json:"logo_path"`
	Personnel   json.RawMessage    `json:"personnel"`
	CVSSEnabled bool               `json:"cvss_enabled"`
	Remark      string             `json:"remark"`
}

func (b *reportTemplateBody) toInput() db.ReportTemplateInput {
	return db.ReportTemplateInput{
		Name: b.Name, OutputLang: b.OutputLang, Skeleton: b.Skeleton,
		Style: b.Style, Prompts: b.Prompts,
		Issuer: b.Issuer, LogoPath: b.LogoPath, Personnel: b.Personnel,
		CVSSEnabled: b.CVSSEnabled, Remark: b.Remark,
	}
}

// reportTemplatePatchBody 是 PATCH 的线格式：全部指针化，nil=不改该字段。
// style/prompts/personnel 传 json.RawMessage：nil=不改，要清空由前端显式传
// {} / []（语义足够，不需要三态）。skeleton 同理用指针保「未传」。
type reportTemplatePatchBody struct {
	Name        *string             `json:"name"`
	OutputLang  *string             `json:"output_lang"`
	Skeleton    *[]db.ReportSection `json:"skeleton"`
	Style       json.RawMessage     `json:"style"`
	Prompts     json.RawMessage     `json:"prompts"`
	Issuer      *string             `json:"issuer"`
	LogoPath    *string             `json:"logo_path"`
	Personnel   json.RawMessage     `json:"personnel"`
	CVSSEnabled *bool               `json:"cvss_enabled"`
	Remark      *string             `json:"remark"`
}

func (s *Server) pgReportDBGuard(w http.ResponseWriter) bool {
	if s.m.pg == nil {
		writeErr(w, 503, "数据库不可用")
		return false
	}
	return true
}

// GET /api/report-templates
func (s *Server) reportTemplateList(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	ts, err := s.m.pg.ListReportTemplates()
	if err != nil {
		writeErr(w, 500, "读取模板失败: "+err.Error())
		return
	}
	writeJSON(w, 200, ts)
}

// POST /api/report-templates
func (s *Server) reportTemplateCreate(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	var body reportTemplateBody
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	// 骨架缺省 = 服务端默认全章节（前端未显式传时可用）。
	if len(body.Skeleton) == 0 {
		body.Skeleton = db.ParseSkeletonJSON(nil)
	} else if err := db.ValidateSkeleton(body.Skeleton); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	t, err := s.m.pg.CreateReportTemplate(body.toInput())
	if err != nil {
		reportTemplateWriteErr(w, err)
		return
	}
	writeJSON(w, 200, t)
}

// PATCH /api/report-templates/{id} — 局部更新：请求体里出现的字段才改（全字段
// 指针化）；未传的字段保留旧行值。skeleton 传了就整体覆盖并全量校验。
func (s *Server) reportTemplateUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "非法模板 id")
		return
	}
	old, err := s.m.pg.GetReportTemplate(id)
	if err != nil {
		writeErr(w, 500, "读取模板失败: "+err.Error())
		return
	}
	if old == nil {
		writeErr(w, 404, "模板不存在")
		return
	}
	var body reportTemplatePatchBody
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	// 以旧行为底，逐字段按「传了才覆盖」合并（UpdateReportTemplate 是全列
	// 覆盖语义，故 merge 必须在 handler 做完）。
	in := db.ReportTemplateInput{
		Name:        old.Name,
		OutputLang:  old.OutputLang,
		Skeleton:    old.Skeleton,
		Style:       old.Style,
		Prompts:     old.Prompts,
		Issuer:      old.Issuer,
		LogoPath:    old.LogoPath,
		Personnel:   old.Personnel,
		CVSSEnabled: old.CVSSEnabled,
		Remark:      old.Remark,
	}
	if body.Name != nil {
		in.Name = *body.Name
	}
	if body.OutputLang != nil {
		in.OutputLang = *body.OutputLang
	}
	if body.Skeleton != nil {
		in.Skeleton = *body.Skeleton
	}
	if len(body.Style) > 0 {
		in.Style = body.Style
	}
	if len(body.Prompts) > 0 {
		in.Prompts = body.Prompts
	}
	if body.Issuer != nil {
		in.Issuer = *body.Issuer
	}
	if body.LogoPath != nil {
		in.LogoPath = *body.LogoPath
	}
	if len(body.Personnel) > 0 {
		in.Personnel = body.Personnel
	}
	if body.CVSSEnabled != nil {
		in.CVSSEnabled = *body.CVSSEnabled
	}
	if body.Remark != nil {
		in.Remark = *body.Remark
	}
	if body.Skeleton != nil {
		if err := db.ValidateSkeleton(in.Skeleton); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	}
	t, err := s.m.pg.UpdateReportTemplate(id, in)
	if err != nil {
		reportTemplateWriteErr(w, err)
		return
	}
	writeJSON(w, 200, t)
}

// DELETE /api/report-templates/{id}
func (s *Server) reportTemplateDelete(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "非法模板 id")
		return
	}
	ok, err := s.m.pg.DeleteReportTemplate(id)
	if err != nil {
		writeErr(w, 500, "删除失败: "+err.Error())
		return
	}
	if !ok {
		writeErr(w, 404, "模板不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/report-templates/{id}/set-default — 单事务先清旧再置新。
func (s *Server) reportTemplateSetDefault(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "非法模板 id")
		return
	}
	if err := s.m.pg.SetDefaultTemplate(id); err != nil {
		if errors.Is(err, db.ErrReportTemplateNotFound) {
			writeErr(w, 404, "模板不存在")
			return
		}
		writeErr(w, 500, "设置默认失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func reportTemplateWriteErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrReportTemplateNotFound):
		writeErr(w, 404, err.Error())
	case errors.Is(err, db.ErrReportSkeletonInvalid), errors.Is(err, db.ErrReportTemplateInvalid):
		writeErr(w, 400, err.Error())
	default:
		writeErr(w, 500, "保存失败: "+err.Error())
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ---------- 全局设置 ----------

// GET /api/report-settings
func (s *Server) reportSettingsGet(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	st, err := s.m.pg.GetReportSettings()
	if err != nil {
		writeErr(w, 500, "读取设置失败: "+err.Error())
		return
	}
	writeJSON(w, 200, st)
}

// PATCH /api/report-settings {template_id?, default_locale?} — 局部更新。
// template_id 显式传 null（json null → 这里收到指针字段）= 清除（回退
// is_default 解析链）。
func (s *Server) reportSettingsPatch(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	var body struct {
		TemplateID    *int64  `json:"template_id"`
		DefaultLocale *string `json:"default_locale"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if body.TemplateID == nil && body.DefaultLocale == nil {
		writeErr(w, 400, "无可更新字段")
		return
	}
	old, err := s.m.pg.GetReportSettings()
	if err != nil {
		writeErr(w, 500, "读取设置失败: "+err.Error())
		return
	}
	tid := int64(0)
	if old.TemplateID != nil {
		tid = *old.TemplateID
	}
	if body.TemplateID != nil {
		tid = *body.TemplateID
		if tid > 0 {
			t, err := s.m.pg.GetReportTemplate(tid)
			if err != nil {
				writeErr(w, 500, "读取模板失败: "+err.Error())
				return
			}
			if t == nil {
				writeErr(w, 400, "模板不存在")
				return
			}
		} else {
			tid = 0 // null/0 = 清除
		}
	}
	locale := old.DefaultLocale
	if body.DefaultLocale != nil {
		locale = strings.TrimSpace(*body.DefaultLocale)
	}
	st, err := s.m.pg.SaveReportSettings(tid, locale)
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	writeJSON(w, 200, st)
}

// ---------- 生成 job ----------

// POST /api/report/generate
//
//	{scope:"task"|"project", task_id?, project_id?, finding_ids?, template_id?, locale?, format:"docx"|"md"}
//
// template_id 空 → settings/is_default 解析链；format 本棒两种都走 Markdown 桩
// （T16 起 docx 走 pybuilder）。校验通过 → 插 pending 行 → go 协程推进状态机 →
// 立即 202 返回 job。
func (s *Server) reportGenerate(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	var body struct {
		Scope      string  `json:"scope"`
		TaskID     int64   `json:"task_id"`
		ProjectID  int64   `json:"project_id"`
		FindingIDs []int64 `json:"finding_ids"`
		TemplateID int64   `json:"template_id"`
		Locale     string  `json:"locale"`
		Format     string  `json:"format"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	body.Scope = strings.TrimSpace(body.Scope)
	if body.Scope != db.ReportScopeTask && body.Scope != db.ReportScopeProject {
		writeErr(w, 400, "scope 必须是 task 或 project")
		return
	}
	body.Format = strings.ToLower(strings.TrimSpace(body.Format))
	if body.Format == "" {
		body.Format = "docx"
	}
	if body.Format != "docx" && body.Format != "md" {
		writeErr(w, 400, "format 仅支持 docx|md")
		return
	}

	// 作用域对象存在性 + 取 findings（空则拒绝：无米之炊不进队列）。
	var taskIDs []int64
	switch body.Scope {
	case db.ReportScopeTask:
		t, err := s.m.pg.GetTask(body.TaskID)
		if err != nil {
			writeErr(w, 500, "读取任务失败: "+err.Error())
			return
		}
		if t == nil {
			writeErr(w, 404, "任务不存在")
			return
		}
		taskIDs = []int64{t.ID}
	default:
		p, err := s.m.pg.GetProject(body.ProjectID)
		if err != nil {
			writeErr(w, 500, "读取项目失败: "+err.Error())
			return
		}
		if p == nil {
			writeErr(w, 404, "项目不存在")
			return
		}
		tasks, err := s.m.pg.ProjectTasks(p.ID)
		if err != nil {
			writeErr(w, 500, "读取项目任务失败: "+err.Error())
			return
		}
		for _, t := range tasks {
			taskIDs = append(taskIDs, t.ID)
		}
	}
	fs, err := s.m.pg.FindingsForReport(taskIDs, body.FindingIDs)
	if err != nil {
		writeErr(w, 500, "读取发现失败: "+err.Error())
		return
	}
	if len(fs) == 0 {
		writeErr(w, 400, "所选范围没有漏洞发现，无法生成报告")
		return
	}

	// 模板解析（显式 id → settings → is_default；可不存在=全默认骨架渲染）。
	tmpl, err := s.m.pg.ResolveTemplateIDBySettings(body.TemplateID)
	if err != nil {
		writeErr(w, 500, "读取模板失败: "+err.Error())
		return
	}
	if body.TemplateID > 0 && tmpl == nil {
		writeErr(w, 400, "模板不存在")
		return
	}
	locale := strings.TrimSpace(body.Locale)
	if locale == "" {
		if tmpl != nil {
			locale = tmpl.OutputLang
		}
	}
	if locale == "" {
		if st, err := s.m.pg.GetReportSettings(); err == nil {
			locale = st.DefaultLocale
		}
	}
	tmplID := int64(0)
	if tmpl != nil {
		tmplID = tmpl.ID
	}
	var findIDs []int64
	for _, f := range fs {
		findIDs = append(findIDs, f.ID)
	}

	job, err := s.m.pg.InsertReport(body.Scope, taskOfScope(body.Scope, body.TaskID), projectOfScope(body.Scope, body.ProjectID), tmplID, locale, body.Format, findIDs)
	if err != nil {
		writeErr(w, 500, "创建报告任务失败: "+err.Error())
		return
	}
	go s.runReportJob(job)
	writeJSON(w, 202, job)
}

// taskOfScope/projectOfScope 把 scope 下的两个 id 之一落到对应参数位（另一个
// 传 0 → NULL）。写法保持一行可读。
func taskOfScope(scope string, id int64) int64 {
	if scope == db.ReportScopeTask {
		return id
	}
	return 0
}

func projectOfScope(scope string, id int64) int64 {
	if scope == db.ReportScopeProject {
		return id
	}
	return 0
}

// runReportJob 在后台协程里推进一个 job 的状态机：pending→running→渲染→
// done(file_path,warning)|failed(error)。panic 兜底置 failed（防行卡 running）。
// 渲染器 = s.reportRenderer 注入点；nil → 内置 Markdown 桩 renderReportStub。
// s.ctx 取消（进程退出）时渲染提前失败 → 行落 failed，不悬挂。
func (s *Server) runReportJob(job *db.Report) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[reportgen] job %d panic: %v", job.ID, rec)
			// 只走带 error 文本的 failed 收尾；若 panic 发生在 pending 阶段
			// （行不在 running），FinishReportFailed 不命中、行留 pending，
			// 由轮询端按 DB 状态展示（无僵尸 running 行即可接受）。
			s.finishReport(job.ID, "", "", fmt.Sprintf("报告生成异常：%v", rec))
		}
	}()
	if err := s.m.pg.AdvanceReportStatus(job.ID, db.ReportPending, db.ReportRunning); err != nil {
		log.Printf("[reportgen] job %d start: %v", job.ID, err)
		return
	}
	// job 用入队时的快照即可（渲染所需 scope/ids/template/locale 建后不改）。
	// 10min 是桩渲染的宽松上限；T16 docx（AI 叙述并发+py 子进程）按各自预算。
	base := s.ctx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithTimeout(base, 10*time.Minute)
	defer cancel()

	renderer := s.reportRenderer
	if renderer == nil {
		renderer = s.renderReportStub
	}
	path, warning, err := renderer(ctx, job)
	if err != nil {
		s.finishReport(job.ID, "", "", err.Error())
		return
	}
	if err := s.m.pg.FinishReportDone(job.ID, path, truncateUTF8(warning, reportErrorStoreTruncate)); err != nil {
		log.Printf("[reportgen] job %d finish done: %v", job.ID, err)
	}
}

// finishReport 把 running 行落到 failed（带截断 error）。二次失败（行已不在
// running）只记日志——行状态由轮询端按 DB 为准。
func (s *Server) finishReport(id int64, path, warning, errText string) {
	if errText == "" {
		if err := s.m.pg.FinishReportDone(id, path, warning); err != nil {
			log.Printf("[reportgen] job %d finish: %v", id, err)
		}
		return
	}
	if err := s.m.pg.FinishReportFailed(id, truncateUTF8(errText, reportErrorStoreTruncate)); err != nil {
		log.Printf("[reportgen] job %d finish failed: %v", id, err)
	}
}

// renderReportStub 是 T15 的默认渲染器（Markdown 桩）：buildReportInput 组装
// 数据 → report.MarkdownFromInput 渲染 → 写 <dataDir>/reports/<jobID>-<名称>-
// <日期>.md。**T16 替换为 pybuilder docx 实装的挂点即 s.reportRenderer 字段；
// 本函数（含 ReportInput 组装/伪资产剔除 warning 链）是 T16 复用的数据入口。**
func (s *Server) renderReportStub(ctx context.Context, job *db.Report) (string, string, error) {
	in, warning, err := s.buildReportInput(ctx, job)
	if err != nil {
		return "", "", err
	}
	if err := ctx.Err(); err != nil {
		return "", "", fmt.Errorf("报告渲染被取消: %w", err)
	}
	path, err := s.renderMarkdownArtifact(in, fmt.Sprintf("%d", job.ID), job.CreatedAt)
	return path, warning, err
}

// renderMarkdownArtifact 把 ReportInput 渲染成 Markdown 落 <dataDir>/reports/
// （临时文件原子改名）。prefix 拼在交付名前防撞（job 渲染=job id；回退链
// 附 "-md" 标记）。warning 由调用方保留（回退场景=docx 失败原因）。
func (s *Server) renderMarkdownArtifact(in *report.ReportInput, prefix string, at time.Time) (string, error) {
	md := report.MarkdownFromInput(in)
	dir := filepath.Join(s.m.dir, "reports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("创建报告目录失败: %w", err)
	}
	name := fmt.Sprintf("%s-%s", prefix, report.ReportBaseName(in.Title, at, "md"))
	path := filepath.Join(dir, name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(md), 0o644); err != nil {
		return "", fmt.Errorf("写入报告失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("落位报告失败: %w", err)
	}
	return path, nil
}

// ---------- T16 docx 分派器（默认 reportRenderer） ----------

// renderReportDispatch 是 Server 启动时注入的默认渲染分派器：
//   - format=md → Markdown 桩（T15 行为）；
//   - format=docx → 组 ReportInput → report.GenerateDocx（pybuilder 子进程）；
//     渲染失败**不判 job 失败**，回退 Markdown 桩交付、把 docx 失败原因追加进
//     warning（交付可用性优先；无 python 环境也能拿到报告——验收红线）。
//     产物名 = <jobID>-<任务名|项目名>-<YYYYMMDD>.<实际ext>（规范⑤交付名
//     <名称>-<YYYYMMDD>.<ext> 加 job id 防撞前缀；下载端以真实产物后缀命名，
//     ReportBaseName 防穿越）。
func (s *Server) renderReportDispatch(ctx context.Context, job *db.Report) (string, string, error) {
	in, warning, err := s.buildReportInput(ctx, job)
	if err != nil {
		return "", "", err
	}
	if err := ctx.Err(); err != nil {
		return "", "", fmt.Errorf("报告渲染被取消: %w", err)
	}
	if strings.ToLower(strings.TrimSpace(job.Format)) != "docx" {
		path, err := s.renderMarkdownArtifact(in, fmt.Sprintf("%d", job.ID), job.CreatedAt)
		return path, warning, err
	}
	dir := filepath.Join(s.m.dir, "reports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", warning, fmt.Errorf("创建报告目录失败: %w", err)
	}
	// 先写临时名（job 前缀+docx 扩展），成功后原子改名；失败走 md 回退链。
	path := filepath.Join(dir, fmt.Sprintf("%d-%s", job.ID, report.ReportBaseName(in.Title, job.CreatedAt, "docx")))
	tmp := path + ".tmp"
	if err := report.GenerateDocx(ctx, in, tmp); err != nil {
		_ = os.Remove(tmp)
		mdPath, mdErr := s.renderMarkdownArtifact(in, fmt.Sprintf("%d", job.ID), job.CreatedAt)
		if mdErr != nil {
			return "", warning, fmt.Errorf("docx 渲染失败: %v；Markdown 回退也失败: %w", err, mdErr)
		}
		fb := truncateUTF8("docx 渲染失败已回退 Markdown: "+err.Error(), 800)
		return mdPath, joinWarnings(warning, fb), nil
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", warning, fmt.Errorf("落位报告失败: %w", err)
	}
	return path, warning, nil
}

// joinWarnings 拼接两条告警（空者跳过），保证列表/详情单字段展示完整。
func joinWarnings(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "；" + b
	}
}

// ---------- POST /api/report/render-draft ----------

// reportRenderDraft 同步渲染模板调试小样：不落库、不进队列、不占 job 状态机。
// 入参 {template_id?, scope:"task"|"project", task_id?|project_id?, finding_ids?,
// locale?, format:"docx"|"md"}（缺 template_id=默认模板解析链；缺 format=docx）。
// 与正式生成的差异仅是「临时目录出文件 → 字节流回传 → 即删」，数据组装/伪资产
// 红线校验走同一条 buildReportInput 逻辑（调试所见=交付所得）。60s 超时保护。
func (s *Server) reportRenderDraft(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	var body struct {
		TemplateID int64   `json:"template_id"`
		Scope      string  `json:"scope"`
		TaskID     int64   `json:"task_id"`
		ProjectID  int64   `json:"project_id"`
		FindingIDs []int64 `json:"finding_ids"`
		Locale     string  `json:"locale"`
		Format     string  `json:"format"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	body.Scope = strings.TrimSpace(body.Scope)
	if body.Scope == "" {
		body.Scope = db.ReportScopeTask
	}
	if body.Scope != db.ReportScopeTask && body.Scope != db.ReportScopeProject {
		writeErr(w, 400, "scope 必须是 task 或 project")
		return
	}
	body.Format = strings.ToLower(strings.TrimSpace(body.Format))
	if body.Format == "" {
		body.Format = "docx"
	}
	if body.Format != "docx" && body.Format != "md" {
		writeErr(w, 400, "format 仅支持 docx|md")
		return
	}
	tmpl, err := s.m.pg.ResolveTemplateIDBySettings(body.TemplateID)
	if err != nil {
		writeErr(w, 500, "读取模板失败: "+err.Error())
		return
	}
	if body.TemplateID > 0 && tmpl == nil {
		writeErr(w, 400, "模板不存在")
		return
	}
	locale := strings.TrimSpace(body.Locale)
	if locale == "" && tmpl != nil {
		locale = tmpl.OutputLang
	}
	if locale == "" {
		locale = "zh-CN"
	}

	// 组一条「虚拟 job」直接喂 buildReportInput（不插 reports 表）。
	vjob := &db.Report{
		Scope:      body.Scope,
		Format:     body.Format,
		Locale:     locale,
		FindingIDs: body.FindingIDs,
		CreatedAt:  time.Now(),
	}
	if body.Scope == db.ReportScopeProject {
		vjob.ProjectID = &body.ProjectID
	} else {
		vjob.TaskID = &body.TaskID
	}
	if tmpl != nil {
		tid := tmpl.ID
		vjob.TemplateID = &tid
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	in, warning, err := s.buildReportInput(ctx, vjob)
	if err != nil {
		writeErr(w, 400, "组装失败: "+err.Error()) // 任务/项目不存在、无 findings 等 → 400（调试语义）
		return
	}
	if warning != "" {
		w.Header().Set("X-Report-Warning", url.PathEscape(warning)) // 伪资产剔除在调试端同样透传
	}

	// 文件名 = draft-<模板名>-<YYYYMMDD>.<ext>（调试语义，防与正式交付混淆）。
	tmplName := "默认模板"
	if tmpl != nil && strings.TrimSpace(tmpl.Name) != "" {
		tmplName = tmpl.Name
	}
	base := report.ReportBaseName("draft-"+tmplName, time.Now(), body.Format)

	tmpDir, err := os.MkdirTemp("", "artex-draft-")
	if err != nil {
		writeErr(w, 500, "创建临时目录失败")
		return
	}
	defer os.RemoveAll(tmpDir)
	outPath := filepath.Join(tmpDir, base)

	if body.Format == "md" {
		md := report.MarkdownFromInput(in)
		if err := os.WriteFile(outPath, []byte(md), 0o644); err != nil {
			writeErr(w, 500, "渲染失败: "+err.Error())
			return
		}
	} else {
		if err := report.GenerateDocx(ctx, in, outPath); err != nil {
			writeErr(w, 502, "docx 渲染失败（无 python/python-docx？）: "+err.Error())
			return
		}
	}
	w.Header().Set("Content-Type", reportContentType(outPath))
	w.Header().Set("Content-Disposition", contentDispositionAttachment(base))
	http.ServeFile(w, r, outPath)
}

// ---------- ReportInput 组装（DB 取数 + 纯函数合并/校验） ----------

// buildReportInput 按 job 取数组装 ReportInput：
//   - 任务级：该任务 findings（job.FindingIDs 勾子集，空=全部）→ 直接映射；
//   - 项目级：项目内多任务 findings 去重合并（MergeVulns，severity 取最高、
//     来源任务全保留）；
//   - 检测目标表：候选地址（任务 Goal/描述抽取 + 任务锚定/资产 host）经
//     FilterPseudoTargets 伪资产反向校验，剔除项写 warning（用户红线）。
func (s *Server) buildReportInput(ctx context.Context, job *db.Report) (*report.ReportInput, string, error) {
	if s.m.pg == nil {
		return nil, "", errors.New("数据库不可用")
	}
	// 1) 来源任务元信息。
	var tasks []report.TaskMeta
	var title string
	switch job.Scope {
	case db.ReportScopeProject:
		p, err := s.m.pg.GetProject(valueOr0(job.ProjectID))
		if err != nil {
			return nil, "", err
		}
		if p == nil {
			return nil, "", fmt.Errorf("项目 #%d 已不存在", valueOr0(job.ProjectID))
		}
		title = p.Name
		pTasks, err := s.m.pg.ProjectTasks(p.ID)
		if err != nil {
			return nil, "", err
		}
		for _, t := range pTasks {
			tasks = append(tasks, taskMetaOf(t))
		}
	default:
		t, err := s.m.pg.GetTask(valueOr0(job.TaskID))
		if err != nil {
			return nil, "", err
		}
		if t == nil {
			return nil, "", fmt.Errorf("任务 #%d 已不存在", valueOr0(job.TaskID))
		}
		title = taskMetaOf(t).DisplayName()
		tasks = append(tasks, taskMetaOf(t))
	}
	if title == "" {
		title = "渗透测试项目"
	}

	// 2) findings 取数（detail 列）。
	taskIDs := make([]int64, 0, len(tasks))
	for _, t := range tasks {
		taskIDs = append(taskIDs, t.ID)
	}
	fs, err := s.m.pg.FindingsForReport(taskIDs, job.FindingIDs)
	if err != nil {
		return nil, "", err
	}
	if ctx.Err() != nil {
		return nil, "", ctx.Err()
	}

	// 3) 资产 label（VulnFromFinding 回调）。
	assetMap := s.resolveFindingAssets(fs)
	label := func(id int64) string {
		if a, ok := assetMap[id]; ok {
			return assetDisplayLabel(a)
		}
		return fmt.Sprintf("asset#%d", id)
	}
	vs := make([]report.VulnSection, 0, len(fs))
	for _, f := range fs {
		vs = append(vs, report.VulnFromFinding(f, label))
	}
	merged := report.MergeVulns(vs)

	// 4) 检测目标表：候选抽取 + 伪资产反向校验。
	var goalTexts []string
	var anchorHosts []string
	for _, t := range tasks {
		goalTexts = append(goalTexts, t.Goal, t.Description)
		if hosts, err := s.m.pg.Assets().HostsByTask(t.ID); err == nil {
			anchorHosts = append(anchorHosts, hosts...)
		}
	}
	candidates := report.CandidateTargets(goalTexts, anchorHosts)
	var evidence []string
	for _, v := range merged {
		evidence = append(evidence, reproductionEvidenceText(v.Reproduction)...)
	}
	kept, removed := report.FilterPseudoTargets(candidates, evidence)
	warning := ""
	if len(removed) > 0 {
		warning = "剔除无漏洞证据的目标: " + strings.Join(removed, ", ")
	}

	// 5) 模板元信息。
	var tmpl *db.ReportTemplate
	if job.TemplateID != nil && *job.TemplateID > 0 {
		tmpl, _ = s.m.pg.GetReportTemplate(*job.TemplateID)
	}
	chapters := db.ParseSkeletonJSON(nil)
	personnel := json.RawMessage("[]")
	if tmpl != nil {
		chapters = tmpl.Skeleton
		personnel = tmpl.Personnel
	}

	in := &report.ReportInput{
		Title:       title,
		Scope:       job.Scope,
		Locale:      job.Locale,
		GeneratedAt: time.Now(),
		Chapters:    chapters,
		Tasks:       tasks,
		Targets:     kept,
		Findings:    merged,
		Personnel:   personnel,
	}
	if tmpl != nil {
		in.Issuer = tmpl.Issuer
		in.LogoPath = tmpl.LogoPath
		in.CVSSEnabled = tmpl.CVSSEnabled
		in.Remark = tmpl.Remark
		in.Style = tmpl.Style
		in.Prompts = tmpl.Prompts
		// logo 存相对 dataDir 路径；pybuilder 插图只认绝对路径，这里解析并在
		// 缺文件时留空（封面跳过插图，不影响其余渲染）。
		if rel := strings.TrimSpace(tmpl.LogoPath); rel != "" {
			abs := filepath.Join(s.m.dir, rel)
			if fi, err := os.Stat(abs); err == nil && !fi.IsDir() {
				in.LogoAbs = abs
			}
		}
	}
	return in, warning, nil
}

func taskMetaOf(t *db.Task) report.TaskMeta {
	m := report.TaskMeta{ID: t.ID, Name: t.Name, Description: t.Description, Goal: t.Goal, CreatedAt: t.CreatedAt}
	if t.FirstRunAt != nil {
		m.FirstRunAt = *t.FirstRunAt
	}
	return m
}

func valueOr0(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

// assetDisplayLabel 给资产一个稳定展示名（章节归属/去重键成员）。
func assetDisplayLabel(a *db.Asset) string {
	switch a.Type {
	case "endpoint", "service":
		if a.URL != "" {
			return a.URL
		}
		if a.IP != "" {
			if a.Port != nil {
				return fmt.Sprintf("%s:%d", a.IP, *a.Port)
			}
			return a.IP
		}
		return firstNonEmpty(a.Domain, a.RootDomain, a.ServiceName, fmt.Sprintf("asset#%d", a.ID))
	case "app":
		return firstNonEmpty(a.AppName, a.BundleID, fmt.Sprintf("asset#%d", a.ID))
	default: // root_domain / subdomain / ip
		return firstNonEmpty(a.Domain, a.IP, a.RootDomain, fmt.Sprintf("asset#%d", a.ID))
	}
}

// reproductionEvidenceText 把一条 reproduction 的复现文本摊平（供伪资产反向
// 校验的 host 回查）：entry_point + 每步 request（含命令串）。response 不入证
// 据（响应里可能出现第三方域名造成误保留，红线宁严勿宽）。
func reproductionEvidenceText(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var rp report.Reproduction
	if json.Unmarshal(raw, &rp) != nil {
		return nil
	}
	out := make([]string, 0, len(rp.Steps)+1)
	if rp.EntryPoint != "" {
		out = append(out, rp.EntryPoint)
	}
	for _, st := range rp.Steps {
		if st.Request != "" {
			out = append(out, st.Request)
		}
	}
	return out
}

// truncateUTF8 按字节截断并回退到 rune 边界，防止切断中文产生非法 UTF-8。
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// ---------- job 查询 / 下载 / 历史 ----------

// GET /api/report/jobs/{id}
func (s *Server) reportJobGet(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "非法 job id")
		return
	}
	job, err := s.m.pg.GetReport(id)
	if err != nil {
		writeErr(w, 500, "读取失败: "+err.Error())
		return
	}
	if job == nil {
		writeErr(w, 404, "报告任务不存在")
		return
	}
	writeJSON(w, 200, job)
}

// GET /api/report/jobs/{id}/download — done 且文件存在才给。
// 文件名 = <任务名|项目名>-<YYYYMMDD>.<ext>，中文名走 RFC5987 filename*。
func (s *Server) reportJobDownload(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "非法 job id")
		return
	}
	job, err := s.m.pg.GetReport(id)
	if err != nil || job == nil {
		writeErr(w, 404, "报告任务不存在")
		return
	}
	if job.Status != db.ReportDone || job.FilePath == "" {
		writeErr(w, 409, "报告尚未生成完成")
		return
	}
	path := job.FilePath
	if _, err := os.Stat(path); err != nil {
		// 可移植回退：产物恒在 <dataDir>/reports/，按 base name 重解析
		// （dataDir 迁移/DB 恢复后旧绝对路径失效场景，照 antifox 语义）。
		fallback := filepath.Join(s.m.dir, "reports", filepath.Base(path))
		if _, err := os.Stat(fallback); err != nil {
			writeErr(w, 404, "报告文件已不存在")
			return
		}
		path = fallback
	}
	name := s.reportDownloadName(job, path)
	w.Header().Set("Content-Type", reportContentType(path))
	w.Header().Set("Content-Disposition", contentDispositionAttachment(name))
	http.ServeFile(w, r, path)
}

// reportDownloadName 计算交付文件名 <任务名|项目名>-<YYYYMMDD>.<ext>。ext 取
// 产物文件真实后缀（artpath 扩展名），而非 job.Format：本棒桩即使 format=docx
// 也产 .md，下载名应如实反映字节内容；T16 docx 实装后产物即 .docx，无需改这里。
// 任务/项目名解析失败回退「渗透测试报告」。
func (s *Server) reportDownloadName(job *db.Report, artifactPath string) string {
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(artifactPath)), ".")
	title := "渗透测试报告"
	switch job.Scope {
	case db.ReportScopeProject:
		if p, err := s.m.pg.GetProject(valueOr0(job.ProjectID)); err == nil && p != nil && p.Name != "" {
			title = p.Name
		}
	default:
		if t, err := s.m.pg.GetTask(valueOr0(job.TaskID)); err == nil && t != nil {
			if n := taskMetaOf(t).DisplayName(); n != "" {
				title = n
			}
		}
	}
	day := job.CreatedAt
	if job.FinishedAt.IsZero() {
		day = time.Now()
	}
	return report.ReportBaseName(title, day, ext)
}

// reportContentType 按扩展名给下载 MIME（docx/md，T16 交付 zip 预留）。
func reportContentType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".md":
		return "text/markdown; charset=utf-8"
	case ".zip":
		return "application/zip"
	default:
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	}
}

// contentDispositionAttachment 生成带 RFC5987 filename* 的响应头（中文文件名
// 兼容现代浏览器；filename= 段给 ASCII 回退名）。
func contentDispositionAttachment(name string) string {
	fallback := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '_'
		}
		return r
	}, name)
	if strings.TrimSpace(fallback) == "" {
		fallback = "report"
	}
	return fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, fallback, url.PathEscape(name))
}

// GET /api/reports?page=&page_size=&status=
func (s *Server) reportsList(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	rs, total, err := s.m.pg.ListReports(strings.TrimSpace(q.Get("status")), page, pageSize)
	if err != nil {
		writeErr(w, 500, "读取失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": rs, "total": total})
}

// DELETE /api/reports/{id} — 删行 + best-effort 删文件。
func (s *Server) reportsDelete(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "非法报告 id")
		return
	}
	job, err := s.m.pg.GetReport(id)
	if err != nil || job == nil {
		writeErr(w, 404, "报告不存在")
		return
	}
	ok, err := s.m.pg.DeleteReport(id)
	if err != nil {
		writeErr(w, 500, "删除失败: "+err.Error())
		return
	}
	if !ok {
		writeErr(w, 404, "报告不存在")
		return
	}
	if job.FilePath != "" {
		_ = os.Remove(job.FilePath)
		_ = os.Remove(filepath.Join(s.m.dir, "reports", filepath.Base(job.FilePath)))
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
