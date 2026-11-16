package server

// V9-RPT2（1/3）：docx 保真预览 —— 服务端用 LibreOffice 把生成的 .docx 转 PDF，
// 前端内嵌 PDF 查看（所见即最终交付）。
//
//   GET /api/preview/capability           {pdf, engine, version}
//   GET /api/reports/{id}/preview.pdf     done 报告的 PDF（缓存于 docx 同目录
//                                          <name>.pdf；支持 Range）
//
// 环境适配：soffice 在 PATH 或常见安装路径存在 → PDF；否则端点在响应头
// X-Preview-Fidelity: approximate 下回退现有 HTML 预览（不硬依赖 LibreOffice）。
//
// 转换纪律：每次转换用独占 -env:UserInstallation=file:///tmp/lo-<rand> 临时
// profile（避免并发锁），60s 超时，失败把 stderr 摘要回给调用方（502），
// 临时 profile/输出目录 defer 清理。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
)

// previewCapability 是 GET /api/preview/capability 的线格式。
type previewCapability struct {
	PDF     bool   `json:"pdf"`
	Engine  string `json:"engine"` // libreoffice | none
	Version string `json:"version"`
}

// defaultSofficeCandidates 是 PATH 之外的常见安装位置（Linux 部署机）。
var defaultSofficeCandidates = []string{
	"/usr/bin/soffice",
	"/usr/lib/libreoffice/program/soffice",
}

const (
	// previewCapabilityTTL：部署机上「进行中」的安装最多 30s 后自愈，不必重启。
	previewCapabilityTTL = 30 * time.Second
	// pdfConvertTimeout 是单次 docx→pdf 的硬上限（派工书要求 60s）。
	pdfConvertTimeout = 60 * time.Second
)

// detectSofficePath 在 PATH 与候选路径中定位 soffice。
func detectSofficePath(lookPath func(string) (string, error), candidates []string) string {
	if lookPath != nil {
		if p, err := lookPath("soffice"); err == nil && strings.TrimSpace(p) != "" {
			return p
		}
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

// detectPreviewCapability 是能力探测的纯编排（lookPath/versionOf 可注入，单测
// 覆盖「无 soffice → 回退」分支）。
func detectPreviewCapability(
	lookPath func(string) (string, error),
	candidates []string,
	versionOf func(string) string,
) previewCapability {
	path := detectSofficePath(lookPath, candidates)
	if path == "" {
		return previewCapability{PDF: false, Engine: "none"}
	}
	version := ""
	if versionOf != nil {
		version = strings.TrimSpace(versionOf(path))
	}
	return previewCapability{PDF: true, Engine: "libreoffice", Version: version}
}

// sofficeVersion 取 `soffice --version` 首行；失败留给空串（不影响 PDF 可用性）。
func sofficeVersion(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(out))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	return line
}

// previewCapability 带 30s 缓存（探测有子进程成本；装好/没装两种状态都能自愈）。
func (s *Server) previewCapability() previewCapability {
	if s.pdfProbe != nil {
		return s.pdfProbe()
	}
	s.pdfCapMu.Lock()
	defer s.pdfCapMu.Unlock()
	if !s.pdfCapAt.IsZero() && time.Since(s.pdfCapAt) < previewCapabilityTTL {
		return s.pdfCap
	}
	s.pdfCap = detectPreviewCapability(exec.LookPath, defaultSofficeCandidates, sofficeVersion)
	s.pdfCapAt = time.Now()
	return s.pdfCap
}

func (s *Server) sofficePath() string {
	return detectSofficePath(exec.LookPath, defaultSofficeCandidates)
}

// GET /api/preview/capability
func (s *Server) previewCapabilityGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.previewCapability())
}

// fileURI 把本地绝对路径转成 file:// URI（Windows 盘符补前导斜杠）。
func fileURI(abs string) string {
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return "file://" + p
}

// randomProfileDir 每次转换一个独占 profile，避免 LibreOffice 并发锁。
func randomProfileDir() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return filepath.Join(os.TempDir(), "lo-"+hex.EncodeToString(b[:]))
}

// buildSofficeArgs 是转换命令行的单一事实源（参数顺序可单测）。
func buildSofficeArgs(outDir, profileURI, docxPath string) []string {
	return []string{
		"--headless",
		"--norestore",
		"--convert-to", "pdf",
		"--outdir", outDir,
		"-env:UserInstallation=" + profileURI,
		docxPath,
	}
}

// convertDocxToPDF 执行一次转换：输出到临时目录 → 复制到 outPDF（同目录缓存）。
// 返回 stderr 摘要（失败时供 502 响应体使用）。
func convertDocxToPDF(ctx context.Context, sofficePath, docxPath, outPDF string) (string, error) {
	outDir, err := os.MkdirTemp("", "artex-pdf-")
	if err != nil {
		return "", fmt.Errorf("创建 PDF 临时目录失败: %w", err)
	}
	defer os.RemoveAll(outDir)
	profileDir := randomProfileDir()
	defer os.RemoveAll(profileDir)

	args := buildSofficeArgs(outDir, fileURI(profileDir), docxPath)
	cmd := exec.CommandContext(ctx, sofficePath, args...)
	var stderr strings.Builder
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	stderrText := truncateUTF8(strings.TrimSpace(stderr.String()), 800)
	if runErr != nil {
		if ctx.Err() != nil {
			return stderrText, fmt.Errorf("LibreOffice 转换超时或已取消: %w", ctx.Err())
		}
		return stderrText, fmt.Errorf("LibreOffice 转换失败: %v: %s", runErr, stderrText)
	}
	produced := filepath.Join(outDir, strings.TrimSuffix(filepath.Base(docxPath), filepath.Ext(docxPath))+".pdf")
	if _, err := os.Stat(produced); err != nil {
		matches, _ := filepath.Glob(filepath.Join(outDir, "*.pdf"))
		if len(matches) != 1 {
			return stderrText, fmt.Errorf("LibreOffice 未产出 PDF（stderr: %s）", stderrText)
		}
		produced = matches[0]
	}
	if err := copyFile(produced, outPDF); err != nil {
		return stderrText, fmt.Errorf("写入 PDF 缓存失败: %w", err)
	}
	return stderrText, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

// reportArtifactPath 解析报告产物路径：DB 绝对路径失效时按 base name 回退
// <dataDir>/reports/（dataDir 迁移/恢复场景）。
func (s *Server) reportArtifactPath(job *db.Report) (string, bool) {
	if job == nil || strings.TrimSpace(job.FilePath) == "" {
		return "", false
	}
	path := job.FilePath
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join(s.m.dir, "reports", filepath.Base(job.FilePath))
		if _, err := os.Stat(path); err != nil {
			return "", false
		}
	}
	return path, true
}

// pdfLock 取某份产物的转换互斥锁（同一 docx 并发预览只转一次）。
func (s *Server) pdfLock(key string) *sync.Mutex {
	if v, ok := s.pdfLocks.Load(key); ok {
		return v.(*sync.Mutex)
	}
	mu := &sync.Mutex{}
	actual, _ := s.pdfLocks.LoadOrStore(key, mu)
	return actual.(*sync.Mutex)
}

// pdfCachePath 返回 docx 同目录的 PDF 缓存路径。
func pdfCachePath(artifact string) string {
	return strings.TrimSuffix(artifact, filepath.Ext(artifact)) + ".pdf"
}

// GET /api/reports/{id}/preview.pdf
func (s *Server) reportPreviewPDF(w http.ResponseWriter, r *http.Request) {
	if !s.pgReportDBGuard(w) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "非法报告 id")
		return
	}
	job, err := s.m.pg.GetReport(id)
	if err != nil {
		writeErr(w, 500, "读取报告失败: "+err.Error())
		return
	}
	if job == nil {
		writeErr(w, 404, "报告不存在")
		return
	}
	if job.Status != db.ReportDone {
		writeErr(w, 409, "报告尚未生成完成")
		return
	}
	s.serveReportPDF(w, r, job)
}

// serveReportPDF 是端点核心（独立成函数便于单测 200/502/回退路径）。
func (s *Server) serveReportPDF(w http.ResponseWriter, r *http.Request, job *db.Report) {
	artifact, ok := s.reportArtifactPath(job)
	capability := s.previewCapability()
	if !ok || !strings.EqualFold(filepath.Ext(artifact), ".docx") || !capability.PDF {
		// 无 docx / 无 LibreOffice：回退现有 HTML 预览（版式近似）。
		w.Header().Set("X-Preview-Fidelity", "approximate")
		s.writeReportHTMLPreview(w, r, job)
		return
	}
	target := pdfCachePath(artifact)
	if _, err := os.Stat(target); err != nil {
		mu := s.pdfLock(target)
		mu.Lock()
		defer mu.Unlock()
		if _, err := os.Stat(target); err != nil {
			ctx, cancel := context.WithTimeout(r.Context(), pdfConvertTimeout)
			defer cancel()
			convert := s.pdfConvert
			if convert == nil {
				convert = convertDocxToPDF
			}
			stderr, err := convert(ctx, s.sofficePath(), artifact, target)
			if err != nil {
				msg := strings.TrimSpace(stderr)
				if msg == "" {
					msg = err.Error()
				}
				writeErr(w, 502, "PDF 转换失败: "+truncateUTF8(msg, 600))
				return
			}
		}
	}
	w.Header().Set("X-Preview-Fidelity", "exact")
	w.Header().Set("Content-Type", "application/pdf")
	http.ServeFile(w, r, target)
}

// writeReportHTMLPreview 是原「按数据重建 HTML」预览（回退路径复用）。
func (s *Server) writeReportHTMLPreview(w http.ResponseWriter, r *http.Request, job *db.Report) {
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
