package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func postReportsHandler(t *testing.T, h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/reports/batch", strings.NewReader(body))
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

type deleteBatchResp struct {
	Deleted int                  `json:"deleted"`
	Failed  []reportBatchFailure `json:"failed"`
}

type regenerateBatchResp struct {
	Queued []int64              `json:"queued"`
	Failed []reportBatchFailure `json:"failed"`
}

// TestReportsDeleteRegenerateAndExportBatch 覆盖多选删除（含部分失败）、重新
// 生成（含部分失败）、导出 zip 携带同目录 PDF。
func TestReportsDeleteRegenerateAndExportBatch(t *testing.T) {
	s, pg := newPGServer(t)
	project, err := pg.CreateProject(db.CreateProjectInput{
		Name: fmt.Sprintf("rpt2-batch-%d", time.Now().UnixNano()),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM reports WHERE project_id=$1`, project.ID)
		_, _ = pg.Exec(`DELETE FROM projects WHERE id=$1`, project.ID)
	})
	missing := uniqueMissingReportID(t, pg)

	// 1) 删除：一条真实（docx+pdf 文件）+ 一条不存在。
	dir := t.TempDir()
	docxPath := filepath.Join(dir, "batch.docx")
	pdfPath := pdfCachePath(docxPath)
	if err := os.WriteFile(docxPath, []byte("PK docx"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pdfPath, []byte("%PDF-1.4"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := insertFinishedReport(t, pg, project.ID, "docx", docxPath, "")
	w := postReportsHandler(t, s.reportsDeleteBatch,
		fmt.Sprintf(`{"report_ids":[%d,%d]}`, done.ID, missing))
	if w.Code != http.StatusOK {
		t.Fatalf("delete-batch code=%d body=%s", w.Code, w.Body.String())
	}
	var del deleteBatchResp
	if err := json.Unmarshal(w.Body.Bytes(), &del); err != nil {
		t.Fatal(err)
	}
	if del.Deleted != 1 || len(del.Failed) != 1 || del.Failed[0].ID != missing {
		t.Fatalf("delete-batch result=%+v", del)
	}
	if _, err := os.Stat(docxPath); !os.IsNotExist(err) {
		t.Fatalf("docx must be removed, stat err=%v", err)
	}
	if _, err := os.Stat(pdfPath); !os.IsNotExist(err) {
		t.Fatalf("pdf must be removed, stat err=%v", err)
	}

	// 2) 重新生成：失败报告 + 不存在 id（部分失败）。
	failed := insertFinishedReport(t, pg, project.ID, "md", "", "previous failure")
	w = postReportsHandler(t, s.reportsRegenerateBatch,
		fmt.Sprintf(`{"report_ids":[%d,%d]}`, failed.ID, missing))
	if w.Code != http.StatusOK {
		t.Fatalf("regenerate-batch code=%d body=%s", w.Code, w.Body.String())
	}
	var regen regenerateBatchResp
	if err := json.Unmarshal(w.Body.Bytes(), &regen); err != nil {
		t.Fatal(err)
	}
	if len(regen.Queued) != 1 || len(regen.Failed) != 1 || regen.Failed[0].ID != missing {
		t.Fatalf("regenerate-batch result=%+v", regen)
	}
	newJob, err := pg.GetReport(regen.Queued[0])
	if err != nil || newJob == nil {
		t.Fatalf("new job missing: %v", err)
	}
	if newJob.Scope != failed.Scope || newJob.ProjectID == nil || *newJob.ProjectID != project.ID {
		t.Fatalf("regenerated job scope mismatch: %+v", newJob)
	}
	// 等后台 job 收尾（md 渲染走纯 Go 桩，快）。
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		j, err := pg.GetReport(newJob.ID)
		if err == nil && j != nil && (j.Status == db.ReportDone || j.Status == db.ReportFailed) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 3) 导出：完成报告的 docx + 同目录 PDF 都应进 zip。
	dir2 := t.TempDir()
	docx2 := filepath.Join(dir2, "export.docx")
	pdf2 := pdfCachePath(docx2)
	if err := os.WriteFile(docx2, []byte("PK docx"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pdf2, []byte("%PDF-1.4"), 0o644); err != nil {
		t.Fatal(err)
	}
	exp := insertFinishedReport(t, pg, project.ID, "docx", docx2, "")
	w = postReportsHandler(t, s.reportsDownloadBatch,
		fmt.Sprintf(`{"report_ids":[%d]}`, exp.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("download-batch code=%d body=%s", w.Code, w.Body.String())
	}
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	var sawDocx, sawPDF bool
	for _, n := range names {
		if strings.HasSuffix(n, ".docx") {
			sawDocx = true
		}
		if strings.HasSuffix(n, ".pdf") {
			sawPDF = true
		}
	}
	if !sawDocx || !sawPDF {
		t.Fatalf("zip entries=%v, want docx+pdf", names)
	}
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, ".pdf") {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(rc)
			_ = rc.Close()
			if !strings.HasPrefix(string(data), "%PDF") {
				t.Fatalf("pdf entry content=%q", data)
			}
		}
	}
}

func TestReportsBatchValidation(t *testing.T) {
	s, _ := newPGServer(t)
	if w := postReportsHandler(t, s.reportsDeleteBatch, `{"report_ids":[]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("empty ids: %d", w.Code)
	}
	over := make([]int64, maxReportBatch+1)
	for i := range over {
		over[i] = int64(i + 1)
	}
	body, _ := json.Marshal(over) // 裸数组形态也需被接受（但超上限 400）
	if w := postReportsHandler(t, s.reportsRegenerateBatch, string(body)); w.Code != http.StatusBadRequest {
		t.Fatalf("over limit: %d", w.Code)
	}
	if w := postReportsHandler(t, s.reportsDeleteBatch, `not-json`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad json: %d", w.Code)
	}
}
