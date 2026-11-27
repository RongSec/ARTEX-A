package server

// R6（V9-RPT）报告中心归档页后端：
//   GET  /api/reports/tree?status=&q=        项目→任务的报告树（含数量/状态）
//   GET  /api/reports/{id}/preview           用报告数据重建 HTML 预览（回退通道）
//   GET  /api/reports/{id}/preview.pdf       docx→PDF 保真预览（见 preview_pdf.go）
//   POST /api/reports/download-batch         多选报告打包 zip（含同目录 PDF）
//   POST /api/reports/delete-batch           多选删除（行+文件）
//   POST /api/reports/regenerate-batch       多选重新生成（复用生成管道）
//
// 树分组/文件名去重都是纯函数（无 DB），单测直接覆盖。

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// maxReportBatch 是单次批量下载的报告数上限（防一次拉爆内存/磁盘）。
const maxReportBatch = 200

// reportStatusCounts 是树节点上的报告数量与状态分布。
type reportStatusCounts struct {
	Total   int `json:"total"`
	Done    int `json:"done"`
	Failed  int `json:"failed"`
	Pending int `json:"pending"`
	Running int `json:"running"`
}

func (c *reportStatusCounts) add(status string) {
	c.Total++
	switch status {
	case db.ReportDone:
		c.Done++
	case db.ReportFailed:
		c.Failed++
	case db.ReportRunning:
		c.Running++
	default:
		c.Pending++
	}
}

type reportTreeTask struct {
	ID      int64              `json:"id"`
	Name    string             `json:"name"`
	Reports []*db.Report       `json:"reports"`
	Counts  reportStatusCounts `json:"counts"`
}

type reportTreeProject struct {
	ID      int64              `json:"id"`
	Name    string             `json:"name"`
	Reports []*db.Report       `json:"reports"` // 项目级报告（scope=project）
	Tasks   []*reportTreeTask  `json:"tasks"`
	Counts  reportStatusCounts `json:"counts"`
}

type reportTree struct {
	Projects []*reportTreeProject `json:"projects"`
	// Orphans = 无项目归属（任务已删/未挂项目/项目已删）的报告，仍可预览/下载。
	Orphans []*reportTreeTask `json:"orphans"`
}

// groupReportTree 把扁平行按「项目→任务」分组；项目级报告挂项目节点，任务级
// 报告挂任务节点。行序（新→旧）保持，首见即节点创建顺序。纯函数。
func groupReportTree(rows []*db.ReportTreeRow) *reportTree {
	tree := &reportTree{Projects: []*reportTreeProject{}, Orphans: []*reportTreeTask{}}
	projIdx := map[int64]*reportTreeProject{}
	taskIdx := map[[2]int64]*reportTreeTask{}
	orphanIdx := map[int64]*reportTreeTask{}
	for _, row := range rows {
		if row == nil || row.Report == nil {
			continue
		}
		r := row.Report
		if row.ProjectID != nil && *row.ProjectID > 0 {
			pid := *row.ProjectID
			p := projIdx[pid]
			if p == nil {
				name := strings.TrimSpace(row.ProjectName)
				if name == "" {
					name = fmt.Sprintf("项目#%d", pid)
				}
				p = &reportTreeProject{ID: pid, Name: name, Reports: []*db.Report{}, Tasks: []*reportTreeTask{}}
				projIdx[pid] = p
				tree.Projects = append(tree.Projects, p)
			}
			p.Counts.add(r.Status)
			if r.Scope == db.ReportScopeProject || r.TaskID == nil {
				p.Reports = append(p.Reports, r)
				continue
			}
			key := [2]int64{pid, *r.TaskID}
			t := taskIdx[key]
			if t == nil {
				t = newReportTreeTask(*r.TaskID, row.TaskName)
				taskIdx[key] = t
				p.Tasks = append(p.Tasks, t)
			}
			t.Reports = append(t.Reports, r)
			t.Counts.add(r.Status)
			continue
		}
		// 孤儿：无项目归属。任务级按 task id 分组；项目级/无任务归「未归档」桶。
		var tid int64
		if r.TaskID != nil {
			tid = *r.TaskID
		}
		t := orphanIdx[tid]
		if t == nil {
			name := strings.TrimSpace(row.TaskName)
			if tid == 0 {
				name = "未归档（项目已删）"
			}
			t = newReportTreeTask(tid, name)
			orphanIdx[tid] = t
			tree.Orphans = append(tree.Orphans, t)
		}
		t.Reports = append(t.Reports, r)
		t.Counts.add(r.Status)
	}
	return tree
}

func newReportTreeTask(id int64, name string) *reportTreeTask {
	name = strings.TrimSpace(name)
	if name == "" {
		if id > 0 {
			name = fmt.Sprintf("任务#%d", id)
		} else {
			name = "未归档"
		}
	}
	return &reportTreeTask{ID: id, Name: name, Reports: []*db.Report{}}
}

// GET /api/reports/tree
func (s *Server) reportsTree(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	q := r.URL.Query()
	rows, err := s.m.pg.ListReportTreeRows(q.Get("status"), q.Get("q"))
	if err != nil {
		writeErr(w, 500, "读取报告树失败: "+err.Error())
		return
	}
	writeJSON(w, 200, groupReportTree(rows))
}

// GET /api/reports/{id}/preview — 用报告来源数据 + 模板重建 HTML（纯 Go）。
// 不依赖已落盘 docx，故 docx 报告也能在页面内嵌预览；渲染失败如实 400/500。
func (s *Server) reportPreview(w http.ResponseWriter, r *http.Request) {
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
	if job.Status != db.ReportDone {
		writeErr(w, 409, "报告尚未生成完成")
		return
	}
	s.writeReportHTMLPreview(w, r, job)
}

// POST /api/reports/download-batch — body {report_ids:[...]}，返回 zip 字节流。
// 只打包 done 且文件存在的报告；全部不可用 → 400。同名文件自动加「 (2)」序号。
// V9-RPT2：若报告同目录已有 PDF（保真预览缓存），一并打包。
func (s *Server) reportsDownloadBatch(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	ids, ok := readReportIDsBody(w, r)
	if !ok {
		return
	}
	if len(ids) == 0 {
		writeErr(w, 400, "report_ids 为空")
		return
	}
	if len(ids) > maxReportBatch {
		writeErr(w, 400, fmt.Sprintf("单次最多下载 %d 份报告", maxReportBatch))
		return
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	used := map[string]bool{}
	added := 0
	for _, id := range ids {
		job, err := s.m.pg.GetReport(id)
		if err != nil || job == nil || job.Status != db.ReportDone || job.FilePath == "" {
			continue
		}
		path, found := s.reportArtifactPath(job)
		if !found {
			continue
		}
		name := uniqueArchiveEntry(sanitizeArchiveName(s.reportDownloadName(job, path)), used)
		if addFileToZip(zw, path, name) {
			added++
		}
		// 同目录 PDF 一并打包（有则加，无则跳过；文件名同名换后缀）。
		pdf := pdfCachePath(path)
		if fi, err := os.Stat(pdf); err == nil && !fi.IsDir() {
			pdfName := uniqueArchiveEntry(strings.TrimSuffix(name, filepath.Ext(name))+".pdf", used)
			_ = addFileToZip(zw, pdf, pdfName)
		}
	}
	_ = zw.Close()
	if added == 0 {
		writeErr(w, 400, "所选报告没有可下载的完成文件")
		return
	}
	name := fmt.Sprintf("reports-%s.zip", time.Now().Format("20060102"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", contentDispositionAttachment(name))
	_, _ = w.Write(buf.Bytes())
}

// addFileToZip 把磁盘文件写成 zip 条目；成功返回 true。
func addFileToZip(zw *zip.Writer, path, name string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	entry, err := zw.Create(name)
	if err != nil {
		return false
	}
	_, err = io.Copy(entry, f)
	return err == nil
}

// readReportIDsBody 统一解析批量端点 body：兼容裸数组 [1,2] 与
// {report_ids:[1,2]}，去重并丢弃非正数。返回 ok=false 时已写好 400。
func readReportIDsBody(w http.ResponseWriter, r *http.Request) ([]int64, bool) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeErr(w, 400, "读取请求失败")
		return nil, false
	}
	var bodyIDs []int64
	if json.Unmarshal(raw, &bodyIDs) != nil {
		var body struct {
			ReportIDs []int64 `json:"report_ids"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			writeErr(w, 400, "请求格式错误")
			return nil, false
		}
		bodyIDs = body.ReportIDs
	}
	ids := make([]int64, 0, len(bodyIDs))
	seen := map[int64]bool{}
	for _, id := range bodyIDs {
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, true
}

// reportBatchFailure 是批量操作中单条失败的原因（前端逐条提示）。
type reportBatchFailure struct {
	ID    int64  `json:"id"`
	Error string `json:"error"`
}

// POST /api/reports/delete-batch — 删行 + 删文件（docx/pdf），逐条返回失败原因。
func (s *Server) reportsDeleteBatch(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	ids, ok := readReportIDsBody(w, r)
	if !ok {
		return
	}
	if len(ids) == 0 {
		writeErr(w, 400, "report_ids 为空")
		return
	}
	if len(ids) > maxReportBatch {
		writeErr(w, 400, fmt.Sprintf("单次最多删除 %d 份报告", maxReportBatch))
		return
	}
	deleted := 0
	failed := make([]reportBatchFailure, 0)
	for _, id := range ids {
		job, err := s.m.pg.GetReport(id)
		if err != nil {
			failed = append(failed, reportBatchFailure{ID: id, Error: err.Error()})
			continue
		}
		if job == nil {
			failed = append(failed, reportBatchFailure{ID: id, Error: "报告不存在"})
			continue
		}
		ok, err := s.m.pg.DeleteReport(id)
		if err != nil {
			failed = append(failed, reportBatchFailure{ID: id, Error: err.Error()})
			continue
		}
		if !ok {
			failed = append(failed, reportBatchFailure{ID: id, Error: "报告不存在"})
			continue
		}
		s.removeReportFiles(job)
		deleted++
	}
	writeJSON(w, 200, map[string]any{"deleted": deleted, "failed": failed})
}

// removeReportFiles 尽力删除产物与 PDF 缓存（DB 绝对路径 + dataDir 回退路径）。
func (s *Server) removeReportFiles(job *db.Report) {
	if job == nil {
		return
	}
	_ = removeReportArtifacts(s.m.dir, job.FilePath)
}

// removeReportArtifacts 删一份报告的磁盘产物：绝对路径、data/reports 下的同名
// 文件，以及 docx→PDF 预览缓存。幂等（不存在不算错），供单删、批量删与删任务
// 共用——三处若各写一份，早晚会出现「删了记录、留下文件」的漂移。
func removeReportArtifacts(dataDir, filePath string) error {
	if strings.TrimSpace(filePath) == "" {
		return nil
	}
	seen := map[string]bool{}
	var errs []error
	for _, p := range []string{filePath, filepath.Join(dataDir, "reports", filepath.Base(filePath))} {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
		if err := os.Remove(pdfCachePath(p)); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// POST /api/reports/regenerate-batch — 按原 scope/template 重建 job（复用生成
// 管道；失败报告同样允许重生成）。返回新建 job id 列表与逐条失败原因。
func (s *Server) reportsRegenerateBatch(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	ids, ok := readReportIDsBody(w, r)
	if !ok {
		return
	}
	if len(ids) == 0 {
		writeErr(w, 400, "report_ids 为空")
		return
	}
	if len(ids) > maxReportBatch {
		writeErr(w, 400, fmt.Sprintf("单次最多重新生成 %d 份报告", maxReportBatch))
		return
	}
	queued := make([]int64, 0)
	failed := make([]reportBatchFailure, 0)
	for _, id := range ids {
		job, err := s.m.pg.GetReport(id)
		if err != nil {
			failed = append(failed, reportBatchFailure{ID: id, Error: err.Error()})
			continue
		}
		if job == nil {
			failed = append(failed, reportBatchFailure{ID: id, Error: "报告不存在"})
			continue
		}
		var taskID, projectID int64
		switch job.Scope {
		case db.ReportScopeTask:
			taskID = valueOr0(job.TaskID)
			if taskID <= 0 {
				failed = append(failed, reportBatchFailure{ID: id, Error: "报告缺少来源任务"})
				continue
			}
			t, err := s.m.pg.GetTask(taskID)
			if err != nil {
				failed = append(failed, reportBatchFailure{ID: id, Error: err.Error()})
				continue
			}
			if t == nil {
				failed = append(failed, reportBatchFailure{ID: id, Error: fmt.Sprintf("来源任务 #%d 已不存在", taskID)})
				continue
			}
		case db.ReportScopeProject:
			projectID = valueOr0(job.ProjectID)
			if projectID <= 0 {
				failed = append(failed, reportBatchFailure{ID: id, Error: "报告缺少来源项目"})
				continue
			}
			p, err := s.m.pg.GetProject(projectID)
			if err != nil {
				failed = append(failed, reportBatchFailure{ID: id, Error: err.Error()})
				continue
			}
			if p == nil {
				failed = append(failed, reportBatchFailure{ID: id, Error: fmt.Sprintf("来源项目 #%d 已不存在", projectID)})
				continue
			}
		default:
			failed = append(failed, reportBatchFailure{ID: id, Error: "未知的报告 scope: " + job.Scope})
			continue
		}
		tmplID := int64(0)
		if job.TemplateID != nil {
			tmplID = *job.TemplateID
		}
		newJob, err := s.m.pg.InsertReport(job.Scope, taskID, projectID, tmplID, job.Locale, job.Format, job.FindingIDs)
		if err != nil {
			failed = append(failed, reportBatchFailure{ID: id, Error: err.Error()})
			continue
		}
		queued = append(queued, newJob.ID)
		go s.runReportJob(newJob)
	}
	writeJSON(w, 200, map[string]any{"queued": queued, "failed": failed})
}

// sanitizeArchiveName 去掉 zip 条目名里的路径分隔/保留字符（任务名可能含
// 斜杠），防止写出目录结构或穿越。纯函数。
func sanitizeArchiveName(name string) string {
	name = strings.TrimSpace(name)
	var b strings.Builder
	for _, r := range name {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			b.WriteRune('_')
		default:
			if r < 0x20 {
				b.WriteRune('_')
			} else {
				b.WriteRune(r)
			}
		}
	}
	out := strings.Trim(b.String(), ". ")
	if out == "" {
		return "report"
	}
	return out
}

// uniqueArchiveEntry 给 zip 内同名文件加序号：a.docx → a (2).docx → a (3).docx。
// used 记录已用条目名（调用方全程复用）。纯函数。
func uniqueArchiveEntry(name string, used map[string]bool) string {
	if !used[name] {
		used[name] = true
		return name
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 2; ; i++ {
		cand := fmt.Sprintf("%s (%d)%s", base, i, ext)
		if !used[cand] {
			used[cand] = true
			return cand
		}
	}
}
