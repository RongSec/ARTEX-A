package report

// T16(1/3) docx 渲染管线：go:embed 的 pybuilder 脚本 + python-docx 子进程。
//
// 流程：ReportInput → JSON → 临时目录写 <builder.py> + <input.json> →
// 子进程 python（探测 python3→python，校验 import docx）渲染 → 产物已在
// outPath（调用方直接指定最终路径）。任何一步失败返回 error，由调用方
// （server 渲染器分派器）回退 Markdown 桩交付。
//
// 渲染样式/章节规范全部在 pybuilder/report_builder.py（用户交付硬规范的单一
// 事实源）；本文件只负责进程编排，不碰样式。

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

//go:embed pybuilder/report_builder.py
var reportBuilderPy string

//go:embed pybuilder/test_report_builder.py
var reportBuilderTestPy string

// BuilderScript returns the embedded renderer source (tests write it to disk
// alongside a fixture JSON and run it directly).
func BuilderScript() string { return reportBuilderPy }

// BuilderTestScript returns the embedded spec-assertion suite source.
func BuilderTestScript() string { return reportBuilderTestPy }

// findPython prefers a project venv (which would have python-docx installed),
// then python3 / python on PATH. Returns "" when no interpreter is found.
// (Semantics reference antifox 0.1.1's report/docx.go — 行为一致：优先能
// import docx 的解释器，全都不行时返回第一个找到的，让调用方拿到真实 stderr。)
func findPython() string {
	var cands []string
	for _, rel := range []string{
		filepath.Join("venv", "bin", "python3"), filepath.Join("venv", "bin", "python"),
		filepath.Join(".venv", "bin", "python3"), filepath.Join(".venv", "bin", "python"),
	} {
		if abs, err := filepath.Abs(rel); err == nil {
			cands = append(cands, abs)
		}
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		cands = append(cands,
			filepath.Join(dir, "venv", "bin", "python3"),
			filepath.Join(dir, "venv", "bin", "python3.exe"),
		)
	}
	names := []string{"python3", "python"}
	if runtime.GOOS == "windows" {
		names = []string{"python.exe", "python3.exe", "python"}
	}
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			cands = append(cands, p)
		}
	}
	if runtime.GOOS != "windows" {
		if home, err := os.UserHomeDir(); err == nil {
			cands = append(cands, filepath.Join(home, ".pyenv", "shims", "python3"))
		}
		cands = append(cands, "/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3")
	}
	seen := map[string]bool{}
	var first string
	for _, p := range cands {
		if p == "" || seen[p] {
			continue
		}
		if fi, err := os.Stat(p); err != nil || fi.IsDir() {
			continue
		}
		seen[p] = true
		if first == "" {
			first = p
		}
		if exec.Command(p, "-c", "import docx").Run() == nil {
			return p
		}
	}
	return first
}

// PythonAvailable reports whether a python with python-docx is usable — cheap
// probe for capability endpoints / pre-flight checks (10s cap).
func PythonAvailable() bool {
	py := findPython()
	if py == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, py, "-c", "import docx").Run() == nil
}

// GenerateDocx renders in to a .docx at outPath (parent dir must exist).
// The ReportInput JSON is the data contract shared with pybuilder (contract
// v2, see input.go). ctx bounds the subprocess; a hard 3-minute fallback cap
// applies when ctx has no deadline of its own.
func GenerateDocx(ctx context.Context, in *ReportInput, outPath string) error {
	py := findPython()
	if py == "" {
		return fmt.Errorf("未找到可用的 python3（docx 渲染需要 python3 + python-docx）")
	}
	data, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("序列化报告输入失败: %w", err)
	}
	tmp, err := os.MkdirTemp("", "artex-docxgen-")
	if err != nil {
		return fmt.Errorf("创建渲染临时目录失败: %w", err)
	}
	defer os.RemoveAll(tmp)
	scriptPath := filepath.Join(tmp, "report_builder.py")
	inPath := filepath.Join(tmp, "input.json")
	if err := os.WriteFile(scriptPath, []byte(reportBuilderPy), 0o644); err != nil {
		return fmt.Errorf("写入渲染脚本失败: %w", err)
	}
	if err := os.WriteFile(inPath, data, 0o644); err != nil {
		return fmt.Errorf("写入报告 JSON 失败: %w", err)
	}
	cctx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
	}
	cmd := exec.CommandContext(cctx, py, scriptPath, inPath, outPath)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("python docx 渲染失败: %v: %s", err, tailUTF8Runes(msg, 900))
	}
	if fi, err := os.Stat(outPath); err != nil || fi.Size() == 0 {
		return fmt.Errorf("渲染完成但产物缺失或为空: %s", outPath)
	}
	return nil
}

// truncateUTF8Runes keeps at most n runes, cutting on a rune boundary.
func truncateUTF8Runes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// tailUTF8Runes 保留**尾部** n 个字符。
//
// Python traceback 的有效信息在最后：异常类型与消息。旧实现取头部，把真正
// 的 Traceback 尾巴整个截掉，线上只能看到 "... in build_vuln" 这种无用片段，
// 排查过一次就无法二次定位。尾部保留 + 前缀省略号，代价是丢掉脚本路径。
func tailUTF8Runes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return "…" + string(r[len(r)-n:])
}
