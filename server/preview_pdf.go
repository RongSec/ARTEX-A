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
// profile（避免并发锁），单次 120s 超时，失败后换新 profile 重试一次，仍失败
// 才回 502；失败摘要（来源 / 格式 / 命令行 / 退出码 / stderr 前 500 字）同时写
// <dataDir>/run.log、响应体 error 与 X-Preview-Error 头，端上不再只看到状态码。
// 启动时后台预热一次 soffice（--terminate_after_init），避开首次请求冷启动。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
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
	// pdfConvertTimeout 是单次 docx→pdf 的硬上限；超时后换新 profile 重试一次。
	pdfConvertTimeout = 120 * time.Second
	// previewWarmupTimeout 给启动预热兜底（--terminate_after_init 正常 2～10s）。
	previewWarmupTimeout = 90 * time.Second
	// pdfConvertAttempts 含首次在内的总尝试次数（失败后重试 1 次）。
	pdfConvertAttempts = 2
	// pdfLogStderrLimit 是 run.log / 响应体里 stderr 的截断长度（派工书：前 500 字）。
	pdfLogStderrLimit = 500
)

// previewSubject 标识一次转换请求的来源（run.log / 响应体定位用）。
// report_id 优先；模板调试通道没有报告行时退到 template_id。
type previewSubject struct {
	ReportID   int64
	TemplateID int64
	Format     string
}

func (p previewSubject) label() string {
	if p.ReportID > 0 {
		return "report_id=" + strconv.FormatInt(p.ReportID, 10)
	}
	if p.TemplateID > 0 {
		return "template_id=" + strconv.FormatInt(p.TemplateID, 10)
	}
	return "report_id=0"
}

// convertResult 是一次转换尝试的可定位结果：命令、退出码、stderr 都留着，
// 供 run.log / 502 响应体 / X-Preview-Error 复用同一份摘要。
type convertResult struct {
	Stderr   string
	Command  string
	ExitCode int // -1 = 未拿到真实退出码（超时/启动失败/被取消）
	Attempts int
	Err      error
}

// summary 生成单行可检索摘要：{来源, format, 命令, 退出码, stderr 前 500 字}。
func (p previewSubject) summary(res convertResult) string {
	code := "n/a"
	if res.ExitCode >= 0 {
		code = strconv.Itoa(res.ExitCode)
	}
	stderr := strings.TrimSpace(res.Stderr)
	if stderr == "" {
		stderr = "(空)"
	}
	return fmt.Sprintf("%s format=%s exit=%s attempts=%d cmd=%q stderr=%q",
		p.label(), p.Format, code, res.Attempts, res.Command, truncateUTF8(stderr, pdfLogStderrLimit))
}

// appendRunLog 把一行可定位摘要追加到 <dataDir>/run.log。
// 写日志失败只打标准日志，绝不影响渲染响应本身。
func (s *Server) appendRunLog(kind, summary string) {
	dir := ""
	if s.m != nil {
		dir = s.m.dir
	}
	if dir == "" {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "run.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("[run.log] 打开失败: %v", err)
		return
	}
	defer f.Close()
	line := fmt.Sprintf("%s %s %s\n", time.Now().Format(time.RFC3339), kind, summary)
	if _, err := f.WriteString(line); err != nil {
		log.Printf("[run.log] 写入失败: %v", err)
	}
}

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
// 返回的命令/退出码/stderr 摘要供失败路径写 run.log 与响应体。
func convertDocxToPDF(ctx context.Context, sofficePath, docxPath, outPDF string) convertResult {
	res := convertResult{ExitCode: -1}
	outDir, err := os.MkdirTemp("", "artex-pdf-")
	if err != nil {
		res.Err = fmt.Errorf("创建 PDF 临时目录失败: %w", err)
		return res
	}
	defer os.RemoveAll(outDir)
	profileDir := randomProfileDir()
	defer os.RemoveAll(profileDir)

	args := buildSofficeArgs(outDir, fileURI(profileDir), docxPath)
	res.Command = strings.Join(append([]string{sofficePath}, args...), " ")
	cmd := exec.CommandContext(ctx, sofficePath, args...)
	var stderr strings.Builder
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	res.Stderr = truncateUTF8(strings.TrimSpace(stderr.String()), 800)
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
		}
		if ctx.Err() != nil {
			res.Err = fmt.Errorf("LibreOffice 转换超时或已取消: %w", ctx.Err())
			return res
		}
		res.Err = fmt.Errorf("LibreOffice 转换失败: %w: %s", runErr, res.Stderr)
		return res
	}
	produced := filepath.Join(outDir, strings.TrimSuffix(filepath.Base(docxPath), filepath.Ext(docxPath))+".pdf")
	if _, err := os.Stat(produced); err != nil {
		matches, _ := filepath.Glob(filepath.Join(outDir, "*.pdf"))
		if len(matches) != 1 {
			res.Err = fmt.Errorf("LibreOffice 未产出 PDF（stderr: %s）", res.Stderr)
			return res
		}
		produced = matches[0]
	}
	if err := copyFile(produced, outPDF); err != nil {
		res.Err = fmt.Errorf("写入 PDF 缓存失败: %w", err)
		return res
	}
	res.ExitCode = 0
	return res
}

// convertPDF 是带容错的转换入口：单次 120s 超时；失败后用**全新 profile
// 目录**重试一次（convertDocxToPDF 每次调用都随机 profile，天然换新），
// 仍失败返回最后一次结果（Err 非 nil）。请求本身已取消时不再重试。
func (s *Server) convertPDF(ctx context.Context, docxPath, outPDF string) convertResult {
	convert := s.pdfConvert
	if convert == nil {
		convert = convertDocxToPDF
	}
	sofficePath := s.sofficePath()
	var last convertResult
	for attempt := 1; attempt <= pdfConvertAttempts; attempt++ {
		actx, cancel := context.WithTimeout(ctx, pdfConvertTimeout)
		last = convert(actx, sofficePath, docxPath, outPDF)
		cancel()
		if last.Err == nil {
			last.Attempts = attempt
			return last
		}
		last.Attempts = attempt
		if ctx.Err() != nil || attempt == pdfConvertAttempts {
			return last
		}
		log.Printf("[preview] PDF 转换失败（第 %d 次，exit=%d），换新 profile 目录重试: %v (stderr=%s)",
			attempt, last.ExitCode, last.Err, truncateUTF8(last.Stderr, 200))
	}
	return last
}

// failPDFConversion 统一失败出口：run.log 落摘要 → X-Preview-Error 头 →
// 502 响应体（同一份摘要，端上可原样展示）。
func (s *Server) failPDFConversion(w http.ResponseWriter, subj previewSubject, res convertResult) {
	summary := subj.summary(res)
	s.appendRunLog("preview-convert-failed", summary)
	w.Header().Set("X-Preview-Error", url.PathEscape(summary))
	writeErr(w, http.StatusBadGateway, "PDF 转换失败："+summary)
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
		// 无 docx / 无 LibreOffice：回退现有 HTML 预览（版式近似），并把回退
		// 原因放进 X-Preview-Error，端上不再只能看到 approximate 标记。
		reason := "缺少 docx 产物，已回退 HTML 近似预览"
		switch {
		case !ok:
		case !strings.EqualFold(filepath.Ext(artifact), ".docx"):
			reason = "产物不是 docx，已回退 HTML 近似预览"
		case !capability.PDF:
			reason = "未安装 LibreOffice，已回退 HTML 近似预览"
		}
		w.Header().Set("X-Preview-Error", url.PathEscape(reason))
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
			res := s.convertPDF(r.Context(), artifact, target)
			if res.Err != nil {
				s.failPDFConversion(w, previewSubject{ReportID: job.ID, Format: "pdf"}, res)
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

// warmupSoffice 初始化一次 LibreOffice（建 profile、载入字体与转换器）。
// --terminate_after_init 只做初始化后退出，不产文件，最适合启动预热。
func warmupSoffice(ctx context.Context, sofficePath string) error {
	profileDir := randomProfileDir()
	defer os.RemoveAll(profileDir)
	cmd := exec.CommandContext(ctx, sofficePath,
		"--headless", "--norestore", "--terminate_after_init",
		"-env:UserInstallation="+fileURI(profileDir))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("预热失败: %v: %s", err, truncateUTF8(strings.TrimSpace(string(out)), 300))
	}
	return nil
}

// WarmupPreview 在启动时起后台 goroutine 预热 soffice，避免首个 PDF 请求
// 吃冷启动超时。未装 LibreOffice 时直接跳过（保留 HTML 回退通道）。
func (s *Server) WarmupPreview() {
	go s.warmupPreview()
}

// warmupPreview 是预热同步体（可单测；WarmupPreview 只是异步壳）。
func (s *Server) warmupPreview() {
	capability := s.previewCapability()
	if !capability.PDF {
		log.Printf("[preview] 未检测到 LibreOffice，跳过预热（PDF 预览回退 HTML）")
		return
	}
	warm := s.pdfWarmup
	if warm == nil {
		warm = warmupSoffice
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), previewWarmupTimeout)
	defer cancel()
	if err := warm(ctx, s.sofficePath()); err != nil {
		log.Printf("[preview] LibreOffice 预热失败（首个 PDF 请求可能更慢）: %v", err)
		s.appendRunLog("preview-warmup-failed", err.Error())
		return
	}
	log.Printf("[preview] LibreOffice 预热完成（%s，%s）", time.Since(start).Round(time.Millisecond), capability.Version)
}

