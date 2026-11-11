package report

// T16(1/3) Go 侧 docx 管线测：探测 + fixture 直跑 + py 规范断言套件。
// 无 python / 无 python-docx 环境整体 skip（服务器已装）。

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func fixtureInput(t *testing.T) *ReportInput {
	t.Helper()
	rp, err := json.Marshal(Reproduction{
		EntryPoint:    "https://mall.example.com/login",
		Prerequisites: []string{"需普通账号"},
		Steps: []ReproStep{{
			Request:  "POST /login HTTP/1.1\r\nHost: mall.example.com\r\n\r\nuser=1",
			Response: "HTTP/1.1 200 OK",
			Expected: "返回200", Proves: "注入成立",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &ReportInput{
		Title: "示例门户渗透", Scope: "project", Locale: "zh-CN",
		GeneratedAt: time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC),
		Issuer:      "示例安全团队",
		Chapters:    db.ParseSkeletonJSON(nil),
		Tasks:       []TaskMeta{{ID: 7, Name: "门户外网"}},
		Targets:     []string{"mall.example.com"},
		Findings: []VulnSection{
			{FindingID: 101, Name: "SQL注入", Severity: "critical", VulnClass: "sqli",
				Asset: "mall.example.com", URLTemplate: "mall.example.com/login",
				Description: "登录处布尔盲注", Reproduction: rp, SourceTasks: []int64{7, 9},
				Harm: "可拖库", Remediation: "参数化查询"},
			{FindingID: 102, Name: "反射XSS", Severity: "low", VulnClass: "xss",
				Description: "搜索回显未转义", SourceTasks: []int64{7},
				ReportMD: "## 复现\n\n访问 /search?q=1<img>\n\n```\nGET /search?q=xss HTTP/1.1\nHost: mall.example.com\n```"},
		},
	}
}

func TestGenerateDocxWithPython(t *testing.T) {
	if !PythonAvailable() {
		t.Skip("无 python3/python 或 python-docx —— skip（服务器已装）")
	}
	out := filepath.Join(t.TempDir(), "报告-20261111.docx")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := GenerateDocx(ctx, fixtureInput(t), out); err != nil {
		t.Fatalf("GenerateDocx: %v", err)
	}
	fi, err := os.Stat(out)
	if err != nil || fi.Size() < 1000 {
		t.Fatalf("产物异常: size=%v err=%v", fi, err)
	}
	// docx=zip：头两字节 PK。
	head := make([]byte, 2)
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Read(head); err != nil || string(head) != "PK" {
		t.Fatalf("不是 zip(docx) 头: %q", head)
	}
}

// TestPyBuilderSpecSuite 直接跑嵌入的规范断言套件（写临时目录,python -m
// unittest）。断言=交付硬规范 A1–A24（详见 test_report_builder.py 头注）。
func TestPyBuilderSpecSuite(t *testing.T) {
	if !PythonAvailable() {
		t.Skip("无 python3/python 或 python-docx —— skip（服务器已装）")
	}
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	_ = write("report_builder.py", reportBuilderPy)
	_ = write("test_report_builder.py", reportBuilderTestPy)
	py := findPython()
	if py == "" {
		t.Skip("findPython 为空")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, py, "-m", "unittest", "test_report_builder", "-v")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("py 规范断言套件失败: %v\n%s", err, out)
	}
	t.Logf("py suite:\n%s", out)
}

// TestGenerateDocxNoPythonFallbackErr：模拟渲染失败路径——给一个坏 outPath
// （不存在的目录）应回 error（server 分派器据此走 Markdown 回退链）。不依赖
// python 缺失与否。
func TestGenerateDocxBadOutputErrors(t *testing.T) {
	if !PythonAvailable() {
		t.Skip("无 python 环境（分派器回退路径由 server 测覆盖）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bad := filepath.Join(t.TempDir(), "no-such-dir", "x.docx")
	if err := GenerateDocx(ctx, fixtureInput(t), bad); err == nil {
		t.Fatal("输出到不存在目录应失败")
	}
}
