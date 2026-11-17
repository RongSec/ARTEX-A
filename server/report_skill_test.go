package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidDistillSkillName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"report-t1", true},
		{"abc", true},
		{"a1_b-c", true},
		{"Aabc", false},
		{"_abc", false},
		{"a", false},
		{"ab", true},
		{"中文名", false},
		{"a b", false},
		{"a/b", false},
		{"-ab", false},
	}
	for _, c := range cases {
		if got := validDistillSkillName(c.name); got != c.ok {
			t.Fatalf("%q: got %v want %v", c.name, got, c.ok)
		}
	}
}

func TestValidateSkillArtifact(t *testing.T) {
	valid := "---\nname: demo\ndescription: demo skill\n---\n\n# 正文\n"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	checks, err := validateSkillArtifact(dir)
	if err != nil {
		t.Fatalf("valid artifact rejected: %v", err)
	}
	if !checks.SkillMD || !checks.Meta || checks.Size == 0 {
		t.Fatalf("unexpected checks: %+v", checks)
	}

	// 失败：缺 SKILL.md
	if _, err := validateSkillArtifact(t.TempDir()); err == nil {
		t.Fatal("missing SKILL.md should fail")
	}

	// 失败：缺 frontmatter 元数据
	badDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(badDir, "SKILL.md"), []byte("---\nname: demo\n---\n\nbody\n"), 0o644)
	if _, err := validateSkillArtifact(badDir); err == nil {
		t.Fatal("missing description should fail")
	}

	// 失败：正文空且无 references/
	emptyDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(emptyDir, "SKILL.md"), []byte("---\nname: demo\ndescription: d\n---\n\n"), 0o644)
	if _, err := validateSkillArtifact(emptyDir); err == nil {
		t.Fatal("empty body without references should fail")
	}

	// 通过：正文空但 references/ 有文件
	refDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(refDir, "SKILL.md"), []byte("---\nname: demo\ndescription: d\n---\n\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(refDir, "references"), 0o755)
	_ = os.WriteFile(filepath.Join(refDir, "references", "a.md"), []byte("x"), 0o644)
	if _, err := validateSkillArtifact(refDir); err != nil {
		t.Fatalf("references fallback rejected: %v", err)
	}
}

func TestSkillNameConflictOwnership(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if id, ok := skillManifestTemplateID(path); ok || id != 0 {
		t.Fatal("missing manifest should not resolve owner")
	}
	_ = os.WriteFile(path, []byte(`{"template_id": 7}`), 0o644)
	if id, ok := skillManifestTemplateID(path); !ok || id != 7 {
		t.Fatalf("owner=%d ok=%v want 7/true", id, ok)
	}
}
