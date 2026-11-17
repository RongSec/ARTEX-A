package server

// V9-TPL 模板原件落盘：用户上传的 .docx 原封不动保存到
// <dataDir>/templates/，模板行只存相对路径 docx_path。渲染时 template_filler
// 以此为底稿填充，版式（页眉页脚/封面/表格框线）与上传件一致。
//
// 命名：导入先落到 templates/.staging/import-<nanos>-<safe>.docx（此时模板行
// 还没有 id）；CREATE/PATCH 拿到 id 后 finalize 成 <id>-<safe>.docx。
// 安全：只接受 dataDir 下 templates/ 子树的相对路径，绝对路径与 .. 一律拒绝。

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const templateDocxSubdir = "templates"

// sanitizeTemplateDocxFilename 清洗上传文件名：保留中英文/数字/._-，其余替换
// 为下划线；限长 80 rune，空回退 template。
func sanitizeTemplateDocxFilename(name string) string {
	name = strings.TrimSpace(filepath.Base(strings.ReplaceAll(name, "\\", "/")))
	var b strings.Builder
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if out == "" {
		out = "template"
	}
	if len([]rune(out)) > 80 {
		out = string([]rune(out)[:80])
	}
	if !strings.HasSuffix(strings.ToLower(out), ".docx") {
		out += ".docx"
	}
	return out
}

// resolveTemplateDocx 把相对 docx_path 解析成绝对路径，并限制在
// <dataDir>/templates 子树内（拒绝绝对路径与路径穿越）。
func (s *Server) resolveTemplateDocx(rel string) (string, error) {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return "", fmt.Errorf("docx_path 为空")
	}
	slash := filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel)))
	if filepath.IsAbs(rel) || slash == ".." || strings.HasPrefix(slash, "../") {
		return "", fmt.Errorf("docx_path 必须是 dataDir 下的相对路径")
	}
	if slash != templateDocxSubdir && !strings.HasPrefix(slash, templateDocxSubdir+"/") {
		return "", fmt.Errorf("docx_path 必须位于 %s/ 下", templateDocxSubdir)
	}
	abs := filepath.Join(s.m.dir, filepath.FromSlash(slash))
	root, err := filepath.Abs(s.m.dir)
	if err != nil {
		return "", err
	}
	target, err := filepath.Abs(abs)
	if err != nil {
		return "", err
	}
	within, err := filepath.Rel(root, target)
	if err != nil || within == ".." || strings.HasPrefix(within, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("docx_path 越出 dataDir")
	}
	return target, nil
}

// stageTemplateDocx 把导入的上传字节落到 staging 目录，返回相对路径。
func (s *Server) stageTemplateDocx(originalName string, data []byte) (string, error) {
	dir := filepath.Join(s.m.dir, filepath.FromSlash(templateDocxSubdir), ".staging")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("创建模板 staging 目录失败: %w", err)
	}
	base := fmt.Sprintf("import-%d-%s", time.Now().UnixNano(), sanitizeTemplateDocxFilename(originalName))
	abs := filepath.Join(dir, base)
	if err := os.WriteFile(abs, data, 0o644); err != nil {
		return "", fmt.Errorf("写入模板原件失败: %w", err)
	}
	return templateDocxSubdir + "/.staging/" + base, nil
}

// finalizeTemplateDocx 把 staging/任意 templates 下的原件归位为
// <id>-<safe>.docx；已是目标命名则原样返回。文件不存在返回 error（调用方
// 决定是 400 还是保留旧值）。
func (s *Server) finalizeTemplateDocx(id int64, rel string) (string, error) {
	abs, err := s.resolveTemplateDocx(rel)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(abs)
	if err != nil || fi.IsDir() || fi.Size() == 0 {
		return "", fmt.Errorf("模板原件不存在或为空: %s", rel)
	}
	base := filepath.Base(abs)
	if strings.HasPrefix(base, fmt.Sprintf("%d-", id)) {
		return filepath.ToSlash(rel), nil
	}
	name := base
	if strings.HasPrefix(name, "import-") {
		if i := strings.Index(name, "-"); i >= 0 {
			name = name[i+1:]
			if j := strings.Index(name, "-"); j >= 0 {
				name = name[j+1:]
			}
		}
	}
	name = sanitizeTemplateDocxFilename(name)
	destRel := templateDocxSubdir + "/" + fmt.Sprintf("%d-%s", id, name)
	destAbs := filepath.Join(s.m.dir, filepath.FromSlash(destRel))
	if err := os.MkdirAll(filepath.Dir(destAbs), 0o755); err != nil {
		return "", err
	}
	_ = os.Remove(destAbs) // 同 id 再次导入=替换，Windows rename 不覆盖
	if err := os.Rename(abs, destAbs); err != nil {
		if err := copyTemplateDocxFile(abs, destAbs); err != nil {
			return "", fmt.Errorf("归位模板原件失败: %w", err)
		}
		_ = os.Remove(abs)
	}
	return destRel, nil
}

func copyTemplateDocxFile(src, dst string) error {
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
		out.Close()
		return err
	}
	return out.Close()
}
