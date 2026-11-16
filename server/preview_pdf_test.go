package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
)

// newPGServer 构造仅含 PG + 临时 dataDir 的 Server（报告相关端点的最小依赖）。
// 本地/CI 无 PG 时跳过（照 finding_retests_test.go 范式）。
func newPGServer(t *testing.T) (*Server, *db.DB) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("test postgres not configured (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { pg.Close() })
	s := &Server{ctx: context.Background(), m: &Manager{pg: pg, dir: t.TempDir()}}
	return s, pg
}

func previewPDFRequest(s *Server, id int64, rangeHeader string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/api/reports/0/preview.pdf", nil)
	r.SetPathValue("id", strconv.FormatInt(id, 10))
	if rangeHeader != "" {
		r.Header.Set("Range", rangeHeader)
	}
	w := httptest.NewRecorder()
	s.reportPreviewPDF(w, r)
	return w
}

// insertFinishedReport 直接落一条 done/failed 的报告行（项目 id 无需真实存在，
// reports 表无外键）。
func insertFinishedReport(t *testing.T, pg *db.DB, projectID int64, format, filePath, errText string) *db.Report {
	t.Helper()
	job, err := pg.InsertReport(db.ReportScopeProject, 0, projectID, 0, "zh-CN", format, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.AdvanceReportStatus(job.ID, db.ReportPending, db.ReportRunning); err != nil {
		t.Fatal(err)
	}
	if errText != "" {
		if err := pg.FinishReportFailed(job.ID, errText); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := pg.FinishReportDone(job.ID, filePath, ""); err != nil {
			t.Fatal(err)
		}
	}
	got, err := pg.GetReport(job.ID)
	if err != nil || got == nil {
		t.Fatalf("reload report %d: %v", job.ID, err)
	}
	return got
}

func uniqueMissingReportID(t *testing.T, pg *db.DB) int64 {
	t.Helper()
	id := time.Now().UnixNano()
	for i := 0; i < 100; i++ {
		job, err := pg.GetReport(id)
		if err != nil {
			t.Fatal(err)
		}
		if job == nil {
			return id
		}
		id++
	}
	t.Fatal("cannot find a missing report id")
	return 0
}

// TestDetectPreviewCapabilityFallback 覆盖「无 soffice → 回退」探测分支。
func TestDetectPreviewCapabilityFallback(t *testing.T) {
	lookErr := func(string) (string, error) { return "", errors.New("not found") }
	cap := detectPreviewCapability(lookErr, []string{filepath.Join(t.TempDir(), "nope")}, nil)
	if cap.PDF || cap.Engine != "none" || cap.Version != "" {
		t.Fatalf("no soffice must fall back: %+v", cap)
	}

	// 候选路径存在 → libreoffice + 版本透传。
	bin := filepath.Join(t.TempDir(), "soffice")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cap = detectPreviewCapability(lookErr, []string{bin}, func(string) string { return "LibreOffice 7.6" })
	if !cap.PDF || cap.Engine != "libreoffice" || cap.Version != "LibreOffice 7.6" {
		t.Fatalf("candidate path must enable PDF: %+v", cap)
	}
	// PATH 命中优先于候选。
	cap = detectPreviewCapability(func(string) (string, error) { return "/opt/soffice", nil },
		[]string{bin}, func(p string) string { return "via " + p })
	if !cap.PDF || cap.Version != "via /opt/soffice" {
		t.Fatalf("PATH hit must win: %+v", cap)
	}
}

func TestBuildSofficeArgs(t *testing.T) {
	args := buildSofficeArgs("/tmp/out", "file:///tmp/lo-abc", "/data/r.docx")
	joined := strings.Join(args, "\x00")
	for _, want := range []string{
		"--headless", "--norestore", "--convert-to\x00pdf", "--outdir\x00/tmp/out",
		"-env:UserInstallation=file:///tmp/lo-abc", "/data/r.docx",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q: %v", want, args)
		}
	}
	if args[len(args)-1] != "/data/r.docx" {
		t.Errorf("input docx must be last arg: %v", args)
	}
}

// TestConvertDocxToPDFMockSoffice 用 mock soffice（真实 docx）验证调用参数与
// 产物落位。本机无 LibreOffice 时这是「转换链路」的可执行替代。
func TestConvertDocxToPDFMockSoffice(t *testing.T) {
	py, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available — skipping mock soffice conversion")
	}
	work := t.TempDir()
	docxPath := filepath.Join(work, "real.docx")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := report.GenerateDocx(ctx, report.DemoInput(), docxPath); err != nil {
		t.Skipf("python-docx unavailable (%v) — skipping real docx conversion", err)
	}
	logPath := filepath.Join(work, "args.json")
	pyPath := filepath.Join(work, "mock_soffice.py")
	pySrc := `import json, os, sys
with open(r"` + logPath + `", "w", encoding="utf-8") as f:
    json.dump(sys.argv[1:], f, ensure_ascii=False)
outdir = sys.argv[sys.argv.index("--outdir") + 1]
src = [a for a in sys.argv[1:] if a.lower().endswith(".docx")][0]
base = os.path.splitext(os.path.basename(src))[0]
with open(os.path.join(outdir, base + ".pdf"), "wb") as f:
    f.write(b"%PDF-1.4\n%mock soffice\n")
`
	if err := os.WriteFile(pyPath, []byte(pySrc), 0o644); err != nil {
		t.Fatal(err)
	}
	var mockPath string
	if runtime.GOOS == "windows" {
		mockPath = filepath.Join(work, "soffice.bat")
		body := "@echo off\r\n\"" + py + "\" \"" + pyPath + "\" %*\r\n"
		if err := os.WriteFile(mockPath, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	} else {
		mockPath = filepath.Join(work, "soffice")
		body := "#!/bin/sh\nexec \"" + py + "\" \"" + pyPath + "\" \"$@\"\n"
		if err := os.WriteFile(mockPath, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	outPDF := filepath.Join(work, "real.pdf")
	stderr, err := convertDocxToPDF(ctx, mockPath, docxPath, outPDF)
	if err != nil {
		t.Fatalf("mock conversion failed: %v (stderr=%s)", err, stderr)
	}
	data, err := os.ReadFile(outPDF)
	if err != nil || !strings.HasPrefix(string(data), "%PDF") {
		t.Fatalf("pdf cache not written: %v data=%q", err, data)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	if err := json.Unmarshal(raw, &args); err != nil {
		t.Fatal(err)
	}
	if len(args) == 0 || args[len(args)-1] != docxPath {
		t.Fatalf("input docx not last: %v", args)
	}
	var sawHeadless, sawConvert, sawProfile bool
	for _, a := range args {
		switch {
		case a == "--headless":
			sawHeadless = true
		case a == "--convert-to":
			sawConvert = true
		case strings.HasPrefix(a, "-env:UserInstallation=file:///"):
			sawProfile = strings.Contains(a, "lo-")
		}
	}
	if !sawHeadless || !sawConvert || !sawProfile {
		t.Fatalf("conversion args incomplete: %v", args)
	}
}

// TestReportPreviewPDFEndpoint 覆盖 404 / 502 / 200（含 Range）。
func TestReportPreviewPDFEndpoint(t *testing.T) {
	s, pg := newPGServer(t)
	missing := uniqueMissingReportID(t, pg)
	if w := previewPDFRequest(s, missing, ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing report: got %d body=%s", w.Code, w.Body.String())
	}

	docxPath := filepath.Join(t.TempDir(), "a.docx")
	if err := os.WriteFile(docxPath, []byte("PK fake docx"), 0o644); err != nil {
		t.Fatal(err)
	}
	job := insertFinishedReport(t, pg, 987654321, "docx", docxPath, "")
	t.Cleanup(func() { _, _ = pg.DeleteReport(job.ID) })

	s.pdfProbe = func() previewCapability {
		return previewCapability{PDF: true, Engine: "libreoffice", Version: "mock"}
	}
	s.pdfConvert = func(ctx context.Context, sofficePath, docx, outPDF string) (string, error) {
		if docx != docxPath {
			t.Errorf("convert got docx %q, want %q", docx, docxPath)
		}
		return "", os.WriteFile(outPDF, []byte("%PDF-1.4\n%fake\n"), 0o644)
	}
	w := previewPDFRequest(s, job.ID, "")
	if w.Code != http.StatusOK {
		t.Fatalf("200 path: got %d body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Fatalf("content-type=%q", ct)
	}
	if f := w.Header().Get("X-Preview-Fidelity"); f != "exact" {
		t.Fatalf("fidelity=%q", f)
	}
	if !strings.HasPrefix(w.Body.String(), "%PDF") {
		t.Fatalf("body=%q", w.Body.String())
	}
	// 第二次命中缓存（不再调用 convert）。
	calls := 0
	s.pdfConvert = func(ctx context.Context, sofficePath, docx, outPDF string) (string, error) {
		calls++
		return "", errors.New("should not convert twice")
	}
	if w := previewPDFRequest(s, job.ID, ""); w.Code != http.StatusOK || calls != 0 {
		t.Fatalf("cache miss: code=%d calls=%d", w.Code, calls)
	}
	// Range → 206。
	if w := previewPDFRequest(s, job.ID, "bytes=0-3"); w.Code != http.StatusPartialContent {
		t.Fatalf("range: got %d body=%s", w.Code, w.Body.String())
	}

	// 502：转换失败带 stderr 摘要。
	badDocx := filepath.Join(t.TempDir(), "b.docx")
	if err := os.WriteFile(badDocx, []byte("PK bad"), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := insertFinishedReport(t, pg, 987654322, "docx", badDocx, "")
	t.Cleanup(func() { _, _ = pg.DeleteReport(bad.ID) })
	s.pdfConvert = func(ctx context.Context, sofficePath, docx, outPDF string) (string, error) {
		return "Error: source file could not be loaded", errors.New("exit status 1")
	}
	w = previewPDFRequest(s, bad.ID, "")
	if w.Code != http.StatusBadGateway {
		t.Fatalf("502 path: got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "could not be loaded") {
		t.Fatalf("502 body missing stderr: %s", w.Body.String())
	}
}

// TestReportPreviewPDFFallbackHTML 覆盖无 LibreOffice 时回退 HTML + approximate。
func TestReportPreviewPDFFallbackHTML(t *testing.T) {
	s, pg := newPGServer(t)
	project, err := pg.CreateProject(db.CreateProjectInput{
		Name: "rpt2-fallback-" + strconv.FormatInt(time.Now().UnixNano(), 10),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM projects WHERE id=$1`, project.ID) })
	docxPath := filepath.Join(t.TempDir(), "c.docx")
	if err := os.WriteFile(docxPath, []byte("PK"), 0o644); err != nil {
		t.Fatal(err)
	}
	job := insertFinishedReport(t, pg, project.ID, "docx", docxPath, "")
	t.Cleanup(func() { _, _ = pg.DeleteReport(job.ID) })
	s.pdfProbe = func() previewCapability { return previewCapability{PDF: false, Engine: "none"} }
	w := previewPDFRequest(s, job.ID, "")
	if w.Code != http.StatusOK {
		t.Fatalf("fallback html code=%d body=%s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Preview-Fidelity") != "approximate" {
		t.Fatalf("fallback fidelity=%q code=%d", w.Header().Get("X-Preview-Fidelity"), w.Code)
	}
	if strings.HasPrefix(w.Header().Get("Content-Type"), "application/pdf") {
		t.Fatalf("must not serve pdf without soffice")
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("fallback must be html: %q", w.Header().Get("Content-Type"))
	}
}
