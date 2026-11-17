package server

// V9-TPL 模板原件落盘单测（无库）：staging → <id>-<safe> 归位、路径穿越拒绝、
// 缺文件报错。渲染分支见 report/template_docx_test.go。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testServerWithDir(dir string) *Server {
	return &Server{m: &Manager{dir: dir}}
}

func TestStageAndFinalizeTemplateDocx(t *testing.T) {
	dir := t.TempDir()
	s := testServerWithDir(dir)
	rel, err := s.stageTemplateDocx(`..\evil/xx系统渗透测试报告.docx`, []byte("PK\x03\x04demo"))
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if !strings.HasPrefix(rel, "templates/.staging/import-") {
		t.Fatalf("staging 路径异常: %q", rel)
	}
	if _, err := s.resolveTemplateDocx(rel); err != nil {
		t.Fatalf("staging 路径应可解析: %v", err)
	}
	final, err := s.finalizeTemplateDocx(12, rel)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if final != "templates/12-xx系统渗透测试报告.docx" {
		t.Fatalf("归位命名不符: %q", final)
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(final))); err != nil {
		t.Fatalf("归位文件不存在: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); !os.IsNotExist(err) {
		t.Errorf("staging 文件应已移走: %v", err)
	}
	// 已是 <id>- 前缀 → 幂等返回。
	if again, err := s.finalizeTemplateDocx(12, final); err != nil || again != final {
		t.Fatalf("二次 finalize 不幂等: %q %v", again, err)
	}
}

func TestResolveTemplateDocxRejectsTraversal(t *testing.T) {
	s := testServerWithDir(t.TempDir())
	for _, bad := range []string{"", "../secret.docx", "templates/../../secret.docx", "/etc/passwd", "other/x.docx"} {
		if _, err := s.resolveTemplateDocx(bad); err == nil {
			t.Errorf("应拒绝 %q", bad)
		}
	}
}

func TestFinalizeTemplateDocxMissing(t *testing.T) {
	s := testServerWithDir(t.TempDir())
	if _, err := s.finalizeTemplateDocx(1, "templates/nope.docx"); err == nil {
		t.Fatal("缺文件应报错（调用方据此 400/回退）")
	}
}
