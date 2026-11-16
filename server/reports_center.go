package server

// R6（V9-RPT）报告中心归档页后端：
//   GET  /api/reports/tree?status=&q=        项目→任务的报告树（含数量/状态）
//   GET  /api/reports/{id}/preview           用报告数据重建 HTML 预览（docx 也
//                                            可内嵌预览；不落盘、不改 job）
//   POST /api/reports/download-batch         多选报告打包 zip（同名自动加序号）
//
// 树分组/文件名去重都是纯函数（无 DB），单测直接覆盖。

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
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
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	in, _, err := s.buildReportInput(ctx, job)
	if err != nil {
		writeErr(w, 400, "重建报告数据失败: "+err.Error())
		return
	}
	html := report.HTMLPreviewFromInput(in, s.requestOrigin(r))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

// POST /api/reports/download-batch — body {report_ids:[...]}，返回 zip 字节流。
// 只打包 done 且文件存在的报告；全部不可用 → 400。同名文件自动加「 (2)」序号。
func (s *Server) reportsDownloadBatch(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	var body struct {
		ReportIDs []int64 `json:"report_ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	ids := make([]int64, 0, len(body.ReportIDs))
	seen := map[int64]bool{}
	for _, id := range body.ReportIDs {
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
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
		path := job.FilePath
		if _, err := os.Stat(path); err != nil {
			path = filepath.Join(s.m.dir, "reports", filepath.Base(job.FilePath))
			if _, err := os.Stat(path); err != nil {
				continue
			}
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		name := uniqueArchiveEntry(sanitizeArchiveName(s.reportDownloadName(job, path)), used)
		entry, err := zw.Create(name)
		if err == nil {
			if _, err := io.Copy(entry, f); err == nil {
				added++
			}
		}
		_ = f.Close()
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
