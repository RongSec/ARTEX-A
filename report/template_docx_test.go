package report

// V9-TPL：模板原件（docx_path）分支选择与回退测试。
// 不依赖 python：只验证路径解析与脚本分派；真实填充由
// test_template_filler.py（Go 的 TestTemplateFillerSpecSuite 拉起）断言。

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestResolveDocxTemplatePath(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "templates"), 0o755); err != nil {
		t.Fatal(err)
	}
	docx := filepath.Join(dir, "templates", "12-tpl.docx")
	if err := os.WriteFile(docx, []byte("PK\x03\x04data"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		tmpl *db.ReportTemplate
		want string
	}{
		{"有 docx_path 且文件存在", &db.ReportTemplate{DocxPath: "templates/12-tpl.docx"}, docx},
		{"无 docx_path", &db.ReportTemplate{}, ""},
		{"路径不存在", &db.ReportTemplate{DocxPath: "templates/missing.docx"}, ""},
		{"越界路径拒绝", &db.ReportTemplate{DocxPath: "../secret.docx"}, ""},
		{"nil 模板", nil, ""},
	}
	for _, c := range cases {
		if got := ResolveDocxTemplatePath(dir, c.tmpl); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestPlanDocxRender(t *testing.T) {
	dir := t.TempDir()
	tpl := filepath.Join(dir, "tpl.docx")
	if err := os.WriteFile(tpl, []byte("PK\x03\x04"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p := planDocxRender(&ReportInput{TemplateDocx: tpl}); !p.UseFill || p.ScriptName != "template_filler.py" {
		t.Fatalf("模板存在应走填充: %+v", p)
	}
	plan := planDocxRender(&ReportInput{TemplateDocx: filepath.Join(dir, "missing.docx")})
	if plan.UseFill || plan.ScriptName != "report_builder.py" {
		t.Fatalf("模板缺失应回退重建: %+v", plan)
	}
	plan = planDocxRender(&ReportInput{})
	if plan.UseFill || plan.ScriptName != "report_builder.py" {
		t.Fatalf("无模板应回退重建: %+v", plan)
	}
}

// TestGenerateDocxMissingTemplateFallsBack：TemplateDocx 指向不存在的文件时
// 必须走旧 report_builder.py 并成功产出（而非报错）。
func TestGenerateDocxMissingTemplateFallsBack(t *testing.T) {
	if !PythonAvailable() {
		t.Skip("无 python3/python 或 python-docx —— skip")
	}
	in := fixtureInput(t)
	in.TemplateDocx = filepath.Join(t.TempDir(), "nope.docx")
	out := filepath.Join(t.TempDir(), "fallback.docx")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := GenerateDocx(ctx, in, out); err != nil {
		t.Fatalf("缺失模板应回退重建成功: %v", err)
	}
	if fi, err := os.Stat(out); err != nil || fi.Size() == 0 {
		t.Fatalf("回退产物异常: %v", err)
	}
}

// TestTemplateFillerSpecSuite 直接跑 pybuilder 下的填充断言套件（样本=用户
// 真实模板 testdata/tpl_cn.docx）。无 python/python-docx 环境 skip。
func TestTemplateFillerSpecSuite(t *testing.T) {
	if !PythonAvailable() {
		t.Skip("无 python3/python 或 python-docx —— skip")
	}
	py := findPython()
	if py == "" {
		t.Skip("findPython 为空")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, py, "-m", "unittest", "test_template_filler", "-v")
	cmd.Dir = "pybuilder"
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("py 模板填充断言套件失败: %v\n%s", err, out)
	}
	t.Logf("py template filler suite:\n%s", out)
}
