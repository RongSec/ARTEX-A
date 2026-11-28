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
	DocxPath    string             `json:"docx_path"`
}

func (b *reportTemplateBody) toInput() db.ReportTemplateInput {
	return db.ReportTemplateInput{
		Name: b.Name, OutputLang: b.OutputLang, Skeleton: b.Skeleton,
		Style: b.Style, Prompts: b.Prompts,
		Issuer: b.Issuer, LogoPath: b.LogoPath, Personnel: b.Personnel,
		CVSSEnabled: b.CVSSEnabled, Remark: b.Remark, DocxPath: b.DocxPath,
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
	DocxPath    *string             `json:"docx_path"`
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
	// 绑定字段上线前已蒸馏过的模板：按 manifest 回填 skill_name，
	// 否则列表上看不到绑定，再次蒸馏又会生成一个新 skill。
	for _, t := range ts {
		s.adoptSkillBinding(t)
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
	if rel := strings.TrimSpace(body.DocxPath); rel != "" {
		abs, rerr := s.resolveTemplateDocx(rel)
		if rerr == nil {
			if fi, serr := os.Stat(abs); serr != nil || fi.IsDir() || fi.Size() == 0 {
				rerr = fmt.Errorf("模板原件不存在或为空: %s", rel)
			}
		}
		if rerr != nil {
			writeErr(w, 400, rerr.Error())
			return
		}
	}
	t, err := s.m.pg.CreateReportTemplate(body.toInput())
	if err != nil {
		reportTemplateWriteErr(w, err)
		return
	}
	if rel := strings.TrimSpace(t.DocxPath); rel != "" {
		final, ferr := s.finalizeTemplateDocx(t.ID, rel)
		if ferr != nil {
			_, _ = s.m.pg.DeleteReportTemplate(t.ID) // 回滚半成品，不留无原件的模板行
			writeErr(w, 500, "模板原件落盘失败: "+ferr.Error())
			return
		}
		if final != t.DocxPath {
			if err := s.m.pg.SetReportTemplateDocxPath(t.ID, final); err != nil {
				writeErr(w, 500, "写入 docx_path 失败: "+err.Error())
				return
			}
			t.DocxPath = final
		}
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
		DocxPath:    old.DocxPath,
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
	if body.DocxPath != nil {
		rel := strings.TrimSpace(*body.DocxPath)
		if rel != "" {
			abs, rerr := s.resolveTemplateDocx(rel)
			if rerr == nil {
				if fi, serr := os.Stat(abs); serr != nil || fi.IsDir() || fi.Size() == 0 {
					rerr = fmt.Errorf("模板原件不存在或为空: %s", rel)
				}
			}
			if rerr != nil {
				writeErr(w, 400, rerr.Error())
				return
			}
		}
		in.DocxPath = rel
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
	if rel := strings.TrimSpace(t.DocxPath); rel != "" {
		final, ferr := s.finalizeTemplateDocx(t.ID, rel)
		if ferr != nil {
			writeErr(w, 400, "模板原件不存在或为空: "+ferr.Error())
			return
		}
		if final != t.DocxPath {
			if err := s.m.pg.SetReportTemplateDocxPath(t.ID, final); err != nil {
				writeErr(w, 500, "写入 docx_path 失败: "+err.Error())
				return
			}
			t.DocxPath = final
		}
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
	tmpl, err := s.m.pg.GetReportTemplate(id)
	if err != nil {
		writeErr(w, 500, "读取模板失败: "+err.Error())
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
	// 模板原件（templates/<id>-*.docx）没有外键跟着行走，不显式删就永远留在盘上。
	// 删不掉只记日志：行已经没了，回滚没有意义。
	if tmpl != nil && strings.TrimSpace(tmpl.DocxPath) != "" {
		if abs, rerr := s.resolveTemplateDocx(tmpl.DocxPath); rerr == nil {
			if rmErr := os.Remove(abs); rmErr != nil && !os.IsNotExist(rmErr) {
				log.Printf("[report-template] 模板 %d 已删，原件清理失败 %s: %v", id, abs, rmErr)
			}
		}
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
		NameTemplate  *string `json:"name_template"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if body.TemplateID == nil && body.DefaultLocale == nil && body.NameTemplate == nil {
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
	nameTemplate := old.NameTemplate
	if body.NameTemplate != nil {
		nameTemplate = strings.TrimSpace(*body.NameTemplate)
	}
	st, err := s.m.pg.SaveReportSettings(tid, locale, nameTemplate)
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
		s.finishReport(job.ID, "", "", "报告生成失败: "+err.Error())
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
	path, err := s.renderMarkdownArtifact(in, job.CreatedAt)
	return path, warning, err
}

// renderMarkdownArtifact 把 ReportInput 渲染成 Markdown 落 <dataDir>/reports/
// （临时文件原子改名）。文件名走 V9-NAME 名称模板（渲染后的名称 + .md）。
func (s *Server) renderMarkdownArtifact(in *report.ReportInput, at time.Time) (string, error) {
	md := report.MarkdownFromInput(in)
	dir := filepath.Join(s.m.dir, "reports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("创建报告目录失败: %w", err)
	}
	name := report.ReportFileName(in.NameTemplate, report.NameDataFromInput(in), at, "md")
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
//     产物名 = <渲染后的名称>.<实际ext>（V9-NAME 名称模板；下载端以真实产物
//     后缀命名，ReportBaseName 防穿越）。
func (s *Server) renderReportDispatch(ctx context.Context, job *db.Report) (string, string, error) {
	in, warning, err := s.buildReportInput(ctx, job)
	if err != nil {
		return "", "", err
	}
	if err := ctx.Err(); err != nil {
		return "", "", fmt.Errorf("报告渲染被取消: %w", err)
	}
	if strings.ToLower(strings.TrimSpace(job.Format)) != "docx" {
		path, err := s.renderMarkdownArtifact(in, job.CreatedAt)
		return path, warning, err
	}
	dir := filepath.Join(s.m.dir, "reports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", warning, fmt.Errorf("创建报告目录失败: %w", err)
	}
	// 先写临时名，成功后原子改名；失败走 md 回退链。
	path := filepath.Join(dir, report.ReportFileName(in.NameTemplate, report.NameDataFromInput(in), job.CreatedAt, "docx"))
	tmp := path + ".tmp"
	if err := report.GenerateDocx(ctx, in, tmp); err != nil {
		_ = os.Remove(tmp)
		mdPath, mdErr := s.renderMarkdownArtifact(in, job.CreatedAt)
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
// reportRenderDraft 同步渲染模板调试小样：不落库、不进队列、不占 job 状态机。
// 入参 {template_id?|template?|demo?, scope:"task"|"project", task_id?|project_id?,
// finding_ids?, locale?, format:"docx"|"md"|"html"}（缺 template_id=默认模板解析链；
// 缺 format=docx）。
//
// T20（N1-C/D）扩展：
//   - format="html"：走 report.HTMLFromInput 纯 Go 结构预览渲染（零子进程，
//     对话调模板的实时预览通道）；docx/md 分支行为逐字节不变=零回归。
//   - inline template=<完整模板 JSON>：**优先于 template_id**——未保存的 draft
//     直接试渲染（对话预览关键路径）。只取内容字段（骨架/样式/提示词/元信息），
//     id/is_default 等只读键忽略。
//   - demo=true + task_id=0：数据=内置 fixture（report.DemoInput()），模板 meta
//     按 inline template（或 template_id 解析链）覆盖；**跳过伪资产校验**
//     （红线针对真实交付，fixture 的 targets 自洽即可——设计 §1.2D 显式绕开）。
func (s *Server) reportRenderDraft(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	var body struct {
		TemplateID int64           `json:"template_id"`
		Template   json.RawMessage `json:"template"`
		Demo       bool            `json:"demo"`
		Scope      string          `json:"scope"`
		TaskID     int64           `json:"task_id"`
		ProjectID  int64           `json:"project_id"`
		FindingIDs []int64         `json:"finding_ids"`
		Locale     string          `json:"locale"`
		Format     string          `json:"format"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	// 校验顺序与老行为逐字节一致：scope → format → 模板。demo 通道下 scope
	// 无意义（fixture 不查任务），跳过 scope 校验。
	body.Scope = strings.TrimSpace(body.Scope)
	if body.Scope == "" {
		body.Scope = db.ReportScopeTask
	}
	if !body.Demo && body.Scope != db.ReportScopeTask && body.Scope != db.ReportScopeProject {
		writeErr(w, 400, "scope 必须是 task 或 project")
		return
	}
	body.Format = strings.ToLower(strings.TrimSpace(body.Format))
	if body.Format == "" {
		body.Format = "docx"
	}
	if body.Format != "docx" && body.Format != "md" && body.Format != "html" && body.Format != "pdf" {
		writeErr(w, 400, "format 仅支持 docx|md|html|pdf")
		return
	}

	// 模板解析：inline 优先 → template_id/settings/is_default 链（老行为）。
	var inline *db.ReportTemplate
	if len(body.Template) > 0 {
		var err error
		inline, err = draftTemplateFromRaw(body.Template)
		if err != nil {
			writeErr(w, 400, "template 不是合法草稿 JSON: "+err.Error())
			return
		}
	}
	var tmpl *db.ReportTemplate
	if inline != nil {
		tmpl = inline
	} else {
		var err error
		tmpl, err = s.m.pg.ResolveTemplateIDBySettings(body.TemplateID)
		if err != nil {
			writeErr(w, 500, "读取模板失败: "+err.Error())
			return
		}
		if body.TemplateID > 0 && tmpl == nil {
			writeErr(w, 400, "模板不存在")
			return
		}
	}
	locale := strings.TrimSpace(body.Locale)
	if locale == "" && tmpl != nil {
		locale = tmpl.OutputLang
	}
	if locale == "" {
		locale = "zh-CN"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	var in *report.ReportInput
	var warning string
	if body.Demo {
		// demo 通道：fixture 数据 + 模板 meta 覆盖；不查任务表、跳过伪资产红线
		//（见函数头注释）。scope/task_id 参数在 demo 下无意义，忽略。
		in = report.DemoInput()
		in.Locale = locale
		report.DemoTouchGeneratedAt(in)
		applyTemplateMeta(in, tmpl, s.m.dir)
	} else {
		// 组一条「虚拟 job」直接喂 buildReportInput（不插 reports 表）。inline
		// draft 不在 DB，vjob 不带 TemplateID（buildReportInput 会回查库拿错
		// 的旧行），组装完成后由 applyTemplateMeta 覆盖模板段。
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
		if tmpl != nil && inline == nil {
			tid := tmpl.ID
			vjob.TemplateID = &tid
		}
		var err error
		in, warning, err = s.buildReportInput(ctx, vjob)
		if err != nil {
			writeErr(w, 400, "组装失败: "+err.Error()) // 任务/项目不存在、无 findings 等 → 400（调试语义）
			return
		}
		if inline != nil {
			applyTemplateMeta(in, inline, s.m.dir)
		}
	}
	if warning != "" {
		w.Header().Set("X-Report-Warning", url.PathEscape(warning)) // 伪资产剔除在调试端同样透传
	}

	// 文件名 = draft-<模板名>-<YYYYMMDD>.<ext>（调试语义，防与正式交付混淆）。
	tmplName := "默认模板"
	if inline != nil && strings.TrimSpace(inline.Name) != "" {
		tmplName = inline.Name
	} else if tmpl != nil && strings.TrimSpace(tmpl.Name) != "" {
		tmplName = tmpl.Name
	}
	// V9-RPT2：pdf = docx 同源渲染后 LibreOffice 转 PDF（模板页「与最终 docx
	// 一致」的预览通道）。无 soffice 时明确 502，前端回退 HTML 近似预览。
	nameExt := body.Format
	if nameExt == "pdf" {
		nameExt = "docx" // 先出 docx，再转 pdf；临时文件名沿用 docx
	}
	base := report.ReportBaseName("draft-"+tmplName, time.Now(), nameExt)

	tmpDir, err := os.MkdirTemp("", "artex-draft-")
	if err != nil {
		writeErr(w, 500, "创建临时目录失败")
		return
	}
	defer os.RemoveAll(tmpDir)
	outPath := filepath.Join(tmpDir, base)

	if data, pure := renderDraftBytes(body.Format, in, s.requestOrigin(r)); pure {
		// md/html 纯 Go 分派（renderDraftBytes 可测）；docx/pdf 走下方子进程管线。
		if err := os.WriteFile(outPath, data, 0o644); err != nil {
			writeErr(w, 500, "渲染失败: "+err.Error())
			return
		}
	} else if err := report.GenerateDocx(ctx, in, outPath); err != nil {
		writeErr(w, 502, "docx 渲染失败（无 python/python-docx？）: "+err.Error())
		return
	}
	if body.Format == "pdf" {
		if !s.previewCapability().PDF {
			reason := "未安装 LibreOffice，无法生成 PDF 预览"
			w.Header().Set("X-Preview-Error", url.PathEscape(reason))
			writeErr(w, 502, reason)
			return
		}
		pdfPath := pdfCachePath(outPath)
		res := s.convertPDF(r.Context(), outPath, pdfPath)
		if res.Err != nil {
			subj := previewSubject{TemplateID: body.TemplateID, Format: "pdf"}
			if tmpl != nil && tmpl.ID > 0 {
				subj.TemplateID = tmpl.ID
			}
			s.failPDFConversion(w, subj, res)
			return
		}
		w.Header().Set("X-Preview-Fidelity", "exact")
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", contentDispositionAttachment(strings.TrimSuffix(base, ".docx")+".pdf"))
		http.ServeFile(w, r, pdfPath)
		return
	}
	w.Header().Set("Content-Type", reportContentType(outPath))
	w.Header().Set("Content-Disposition", contentDispositionAttachment(base))
	http.ServeFile(w, r, outPath)
}

// renderChatPreview（R3）把模板对话里的「按现有数据渲染」落成 HTML 预览：
// 复用 render-draft 的数据组装（示例 fixture 或真实任务/项目）+ 纯 Go HTML
// 渲染，不落库、不进队列。失败返回错误给 handler 降级为 warning（对话不中断）。
func (s *Server) renderChatPreview(ctx context.Context, tmpl *db.ReportTemplate, p *chatPreviewInput, r *http.Request) (*chatRenderResult, error) {
	if s.m.pg == nil {
		return nil, errors.New("数据库不可用")
	}
	if p == nil {
		p = &chatPreviewInput{Demo: true}
	}
	locale := strings.TrimSpace(p.Locale)
	if locale == "" && tmpl != nil {
		locale = tmpl.OutputLang
	}
	if locale == "" {
		locale = "zh-CN"
	}
	res := &chatRenderResult{Source: "demo", Label: "示例数据"}
	var in *report.ReportInput
	var warning string
	if p.Demo || (p.TaskID <= 0 && p.ProjectID <= 0) {
		in = report.DemoInput()
		in.Locale = locale
		report.DemoTouchGeneratedAt(in)
		applyTemplateMeta(in, tmpl, s.m.dir)
	} else {
		scope := strings.TrimSpace(p.Scope)
		if scope == "" {
			scope = db.ReportScopeTask
		}
		vjob := &db.Report{
			Scope: scope, Format: "html", Locale: locale,
			FindingIDs: p.FindingIDs, CreatedAt: time.Now(),
		}
		if scope == db.ReportScopeProject {
			vjob.ProjectID = &p.ProjectID
			res.Source, res.Label = "project", fmt.Sprintf("项目#%d", p.ProjectID)
		} else {
			vjob.TaskID = &p.TaskID
			res.Source, res.Label = "task", fmt.Sprintf("任务#%d", p.TaskID)
		}
		var err error
		in, warning, err = s.buildReportInput(ctx, vjob)
		if err != nil {
			return nil, err
		}
		// inline 合并草稿覆盖模板段（vjob 不带 TemplateID，避免回查旧行）。
		applyTemplateMeta(in, tmpl, s.m.dir)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("预览渲染被取消: %w", err)
	}
	res.HTML = report.HTMLPreviewFromInput(in, s.requestOrigin(r))
	res.Warning = warning
	return res, nil
}

// renderDraftBytes 是 render-draft 的纯 Go 格式分派（T20，可测无副作用）：
// "md"→MarkdownFromInput、"html"→HTMLPreviewFromInput（证据图 src 拼 origin
// ——blob 预览下相对路径失效，见 report/html.go），pure=true；其余（docx）
// pure=false，由调用方走 report.GenerateDocx 子进程管线（本函数不碰磁盘/
// 子进程，保持纯函数测试面）。
func renderDraftBytes(format string, in *report.ReportInput, origin string) (data []byte, pure bool) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "md":
		return []byte(report.MarkdownFromInput(in)), true
	case "html":
		return []byte(report.HTMLPreviewFromInput(in, origin)), true
	default:
		return nil, false
	}
}

// draftTemplateFromRaw 把 inline 草稿 JSON 解成模板行形态（只取内容字段；
// id/is_default/时间戳等只读键忽略）。skeleton 缺省=默认全章节；非法骨架
// 直接报错（与 PATCH 入参同口径的护栏位置——渲染前的最后一次校验）。
func draftTemplateFromRaw(raw json.RawMessage) (*db.ReportTemplate, error) {
	var t db.ReportTemplate
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, err
	}
	if len(t.Skeleton) == 0 {
		t.Skeleton = db.ParseSkeletonJSON(nil)
	} else if err := db.ValidateSkeleton(t.Skeleton); err != nil {
		return nil, err
	} else {
		t.Skeleton = db.NormalizeSkeleton(t.Skeleton)
	}
	if len(t.Style) == 0 {
		t.Style = json.RawMessage("{}")
	}
	if len(t.Prompts) == 0 {
		t.Prompts = json.RawMessage("{}")
	}
	if len(t.Personnel) == 0 {
		t.Personnel = json.RawMessage("[]")
	}
	return &t, nil
}

// applyTemplateMeta 把模板的章节/元信息段覆盖进已组装的 ReportInput——与
// buildReportInput 第 5 段对 DB 模板做的事一致（logo 相对 dataDir 解析绝对
// 路径、缺文件留空），供 inline draft 与 demo 通道复用。
func applyTemplateMeta(in *report.ReportInput, tmpl *db.ReportTemplate, dataDir string) {
	if tmpl == nil {
		return
	}
	in.Chapters = tmpl.Skeleton
	in.Personnel = tmpl.Personnel
	in.Issuer = tmpl.Issuer
	in.LogoPath = tmpl.LogoPath
	in.CVSSEnabled = tmpl.CVSSEnabled
	in.Remark = tmpl.Remark
	in.Style = tmpl.Style
	in.Prompts = tmpl.Prompts
	in.TemplateDocx = report.ResolveDocxTemplatePath(dataDir, tmpl)
	in.LogoAbs = ""
	if rel := strings.TrimSpace(tmpl.LogoPath); rel != "" {
		abs := filepath.Join(dataDir, filepath.FromSlash(rel))
		if fi, err := os.Stat(abs); err == nil && !fi.IsDir() {
			in.LogoAbs = abs
		}
	}
}

// requestOrigin 推导本次请求的站点绝对前缀（证据图 src 拼 URL 用）。
// 优先 notify_public_base_url（部署方声明的对外地址，与 IM 回链同源）；
// 未配置时回退请求头（X-Forwarded-Proto > URL.Scheme；Host）。都拿不到返回
// ""（预览退相对路径，srcdoc 场景仍可用）。
func (s *Server) requestOrigin(r *http.Request) string {
	if base := strings.TrimRight(notifyPublicBaseURL(s.m.pg), "/"); base != "" {
		return base
	}
	scheme := "http"
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	} else if r.TLS != nil {
		scheme = "https"
	}
	if host := r.Host; host != "" {
		return scheme + "://" + host
	}
	return ""
}

// ---------- ReportInput 组装（DB 取数 + 纯函数合并/校验） ----------

// buildReportInput 按 job 取数组装 ReportInput：
//   - 任务级：该任务 findings（job.FindingIDs 勾子集，空=全部）→ 直接映射；
//   - 项目级：项目内多任务 findings 去重合并（MergeVulns，severity 取最高、
//     来源任务全保留）；
//   - 检测目标表：候选地址（任务 Goal/描述抽取 + 任务锚定/资产 host）经
//     FilterPseudoTargets 伪资产反向校验，剔除项写 warning（用户红线）。

// coverTitle 把报告标题收敛成模板封面的口径：「<系统名>渗透测试报告」。
//
// 背景：任务 DisplayName 通常是任务目标整句，直接印上封面会变成四五行大标题。
// 规则：优先用第一个保留目标的主机名（去掉 scheme/端口/路径），其次退回
// 传入的项目名或任务名；已有「报告」后缀的不再重复拼接。纯函数，便于单测。
func coverTitle(fallback string, targets []string) string {
	name := ""
	if len(targets) > 0 {
		raw := strings.TrimSpace(targets[0])
		if strings.Contains(raw, "://") {
			raw = hostOfURL(raw)
		} else if i := strings.IndexAny(raw, "/?#"); i > 0 {
			raw = raw[:i]
		}
		name = strings.TrimSpace(raw)
	}
	if name == "" {
		name = strings.TrimSpace(fallback)
	}
	if name == "" {
		name = "目标系统"
	}
	if r := []rune(name); len(r) > 40 {
		name = string(r[:40])
	}
	if strings.HasSuffix(name, "报告") {
		return name
	}
	if strings.HasSuffix(name, "渗透测试") {
		return name + "报告"
	}
	return name + "渗透测试报告"
}

// reportSystemName 解析 {system}。交付规范：**知道系统名就用系统名，不知道
// 就用任务 ID，禁止拿 IP 或域名占位**。当前平台没有独立的「系统名称」字段，
// 目标 host 无论 IP 还是域名都不算系统名，因此一律回退 任务<id>/项目<id>。
// （此前只跳过 IP、保留域名，重新生成时封面仍是 crm.example.com，不符合规范。）
func reportSystemName(scope string, taskID, projectID int64, targets []string) string {
	_ = targets // 保留入参：后续接入「系统名称」字段时在这里优先返回
	switch scope {
	case db.ReportScopeTask:
		if taskID > 0 {
			return fmt.Sprintf("任务%d", taskID)
		}
	case db.ReportScopeProject:
		if projectID > 0 {
			return fmt.Sprintf("项目%d", projectID)
		}
	}
	return "目标系统"
}

// hostOnly 从 URL/裸地址里取主机名：去 scheme、端口、路径、query。
func hostOnly(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "[") {
		if j := strings.Index(raw, "]"); j > 0 {
			return strings.ToLower(raw[1:j])
		}
	}
	// host:port → host（端口段必须全数字）。
	if strings.Count(raw, ":") == 1 {
		if i := strings.LastIndex(raw, ":"); i > 0 && isDigits(raw[i+1:]) {
			raw = raw[:i]
		}
	}
	return strings.ToLower(raw)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// coverTitleFromSystem 保证封面标题为「系统名+渗透测试报告」，不重复拼接。
func coverTitleFromSystem(system string) string {
	name := strings.TrimSpace(system)
	if name == "" {
		name = "目标系统"
	}
	if strings.HasSuffix(name, "报告") {
		return name
	}
	if strings.HasSuffix(name, "渗透测试") {
		return name + "报告"
	}
	return name + "渗透测试报告"
}

func firstTaskName(tasks []report.TaskMeta) string {
	if len(tasks) == 0 {
		return ""
	}
	return tasks[0].DisplayName()
}

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
		// 带上阶段前缀：job.error 只存一行，裸 SQL 错误无法区分是取数、
		// 资产解析还是模板读取失败（实测踩过一次 "parameter $3" 无从定位）。
		return nil, "", fmt.Errorf("取漏洞数据失败: %w", err)
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

	// 3.5) 证据截图注入（T16(3/3) finding_evidence_images）：按 finding_id 把
	// 各自截图挂到对应小节（step_index 相对该小节 reproduction 的步骤序）。
	// 合并小节只取「胜者 finding」的图；去重键相同=同一复现，截图通常同源，
	// 败者分散截图不并入（可接受边界，见 server 报告）。
	imagesByFinding := s.loadEvidenceImages(fs)
	// 3.4) V9-SHOT：没有截图但复现有报文的 finding，报告渲染前就地补渲一
	// 张「左请求/右响应」合成图并落库（复用 renderPacketShots，force=true）。
	// 失败只 warning（renderPacketShots 内部吞异常），报告照常出。
	if n := s.ensurePacketShots(fs, imagesByFinding); n > 0 {
		log.Printf("[reportgen] 补渲报文截图 %d 条 finding（报告 %v）", n, job.ID)
		imagesByFinding = s.loadEvidenceImages(fs)
	}
	for i := range merged {
		merged[i].Images = imagesByFinding[merged[i].FindingID]
	}

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

	// 4.5) 系统名 + 封面标题。系统名规则（V9-NAME）：能识别资产 host 用 host
	// （去 scheme/端口/路径）；否则 task 用「任务<id>」、project 用「项目<id>」。
	// 封面标题恒为「系统名+渗透测试报告」。任务 DisplayName 常是整句目标，
	// 直接当标题会整段顶到封面。
	systemName := reportSystemName(job.Scope, valueOr0(job.TaskID), valueOr0(job.ProjectID), kept)
	title = coverTitleFromSystem(systemName)

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
		SystemName:  systemName,
		TaskID:      valueOr0(job.TaskID),
		ProjectID:   valueOr0(job.ProjectID),
		TaskName:    firstTaskName(tasks),
	}
	// 名称模板：settings.name_template（空=渲染侧默认模板）。
	if st, err := s.m.pg.GetReportSettings(); err == nil && st != nil {
		in.NameTemplate = st.NameTemplate
	}
	if job.Scope == db.ReportScopeProject {
		if p, err := s.m.pg.GetProject(valueOr0(job.ProjectID)); err == nil && p != nil {
			in.ProjectName = p.Name
		}
	}
	if tmpl != nil {
		in.Issuer = tmpl.Issuer
		in.LogoPath = tmpl.LogoPath
		in.CVSSEnabled = tmpl.CVSSEnabled
		in.Remark = tmpl.Remark
		in.Style = tmpl.Style
		in.Prompts = tmpl.Prompts
		// V9-TPL：模板有可用原件 → docx 走填充渲染（保留上传件版式）。
		in.TemplateDocx = report.ResolveDocxTemplatePath(s.m.dir, tmpl)
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

// loadEvidenceImages 批量取这批 findings 的证据截图，按 finding_id 归组成
// report.EvidenceImage（Path=绝对路径，缺文件跳过——盘上文件可能已被外部清理、
// 表行残留；pybuilder 对缺文件本也容错）。无图返回空 map（调用方零特判）。
func (s *Server) loadEvidenceImages(fs []*db.DBFinding) map[int64][]report.EvidenceImage {
	out := map[int64][]report.EvidenceImage{}
	if len(fs) == 0 {
		return out
	}
	seen := map[int64]bool{}
	for _, f := range fs {
		if f.ID <= 0 || seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		list, err := s.m.pg.ListFindingEvidenceImages(f.ID)
		if err != nil {
			log.Printf("[reportgen] evidence images fid=%d: %v", f.ID, err)
			continue
		}
		for _, e := range list {
			abs := filepath.Join(s.m.dir, filepath.FromSlash(e.Filename))
			if fi, err := os.Stat(abs); err != nil || fi.IsDir() {
				continue // 表行有、盘上无 → 跳过（不留占位）
			}
			out[f.ID] = append(out[f.ID], report.EvidenceImage{
				StepIndex: e.StepIndex, Path: abs, Caption: e.Caption,
				// T20 HTML 预览的 <img> src：同源相对 API 路径（字节流端点
				// 支持 cookie/?token=，finding_evidence.go:205）。docx 通道只读
				// Path，此键 omitempty 不进旧契约。
				APIPath: fmt.Sprintf("/api/findings/%d/evidence/%d", f.ID, e.ID),
			})
		}
	}
	return out
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

// reportDownloadName 计算交付文件名：V9-NAME 名称模板渲染结果 + 产物真实后缀。
// ext 取产物文件真实后缀（本棒桩即使 format=docx 也产 .md，下载名应如实反映
// 字节内容）。系统名解析与渲染侧同一规则（host → 任务N/项目N）。
func (s *Server) reportDownloadName(job *db.Report, artifactPath string) string {
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(artifactPath)), ".")
	data := report.ReportNameData{
		TaskID:    valueOr0(job.TaskID),
		ProjectID: valueOr0(job.ProjectID),
	}
	var hosts []string
	switch job.Scope {
	case db.ReportScopeProject:
		if p, err := s.m.pg.GetProject(valueOr0(job.ProjectID)); err == nil && p != nil {
			data.ProjectName = p.Name
		}
		if tasks, err := s.m.pg.ProjectTasks(valueOr0(job.ProjectID)); err == nil {
			for _, t := range tasks {
				if hs, err := s.m.pg.Assets().HostsByTask(t.ID); err == nil {
					hosts = append(hosts, hs...)
				}
			}
		}
	default:
		if t, err := s.m.pg.GetTask(valueOr0(job.TaskID)); err == nil && t != nil {
			data.TaskName = taskMetaOf(t).DisplayName()
			if hs, err := s.m.pg.Assets().HostsByTask(t.ID); err == nil {
				hosts = append(hosts, hs...)
			}
		}
	}
	data.System = reportSystemName(job.Scope, data.TaskID, data.ProjectID, hosts)
	data.Title = coverTitleFromSystem(data.System)
	tmpl := ""
	if st, err := s.m.pg.GetReportSettings(); err == nil && st != nil {
		tmpl = st.NameTemplate
	}
	at := job.CreatedAt
	if at.IsZero() {
		at = time.Now()
	}
	return report.ReportFileName(tmpl, data, at, ext)
}

// reportContentType 按扩展名给下载 MIME（docx/md，T16 交付 zip 预留）。
func reportContentType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".md":
		return "text/markdown; charset=utf-8"
	case ".html":
		// T20 预览通道：前端 fetch→blob→iframe 直接可嵌（charset 必须给，
		// 中文标题否则按 latin1 猜）。
		return "text/html; charset=utf-8"
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
	s.removeReportFiles(job)
	writeJSON(w, 200, map[string]any{"ok": true})
}
