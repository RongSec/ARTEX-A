package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPostgresDSNPrecedence(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"database":{"host":"10.1.2.3","port":6000,"user":"u","password":"p","dbname":"d","sslmode":"require"}}`), 0o644)
	t.Setenv("ARTEX_CONFIG", cfgPath)

	// no env DSN → built from config file fields
	t.Setenv("ARTEX_PG_DSN", "")
	got, _, err := PostgresDSN()
	want := "postgres://u:p@10.1.2.3:6000/d?sslmode=require"
	if err != nil || got != want {
		t.Fatalf("from file: got %q err %v want %q", got, err, want)
	}

	// env wins over config file
	t.Setenv("ARTEX_PG_DSN", "postgres://envwins/x")
	if got, _, err := PostgresDSN(); err != nil || got != "postgres://envwins/x" {
		t.Fatalf("env should win, got %q err %v", got, err)
	}

	// no env, no file → error (no built-in default)
	t.Setenv("ARTEX_PG_DSN", "")
	t.Setenv("ARTEX_CONFIG", filepath.Join(dir, "nope.json"))
	if got, _, err := PostgresDSN(); err == nil {
		t.Fatalf("missing config should error, got %q", got)
	}

	// full dsn in config file is used verbatim
	os.WriteFile(cfgPath, []byte(`{"database":{"dsn":"postgres://full/dsn"}}`), 0o644)
	t.Setenv("ARTEX_CONFIG", cfgPath)
	if got, _, err := PostgresDSN(); err != nil || got != "postgres://full/dsn" {
		t.Fatalf("file dsn verbatim, got %q err %v", got, err)
	}
}

func TestEnsureFileCreatesTemplate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("ARTEX_CONFIG", path)
	t.Setenv("ARTEX_PG_DSN", "")

	got, created, err := EnsureFile()
	if err != nil {
		t.Fatalf("EnsureFile: %v", err)
	}
	if !created || got != path {
		t.Fatalf("应生成模板到 %s，实际 created=%v path=%s", path, created, got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("模板未落盘: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("模板权限应为 0600，实际 %o", perm)
	}
	c := Load()
	if c.Database.User != "artex" || c.Database.Port != 5432 {
		t.Fatalf("模板内容不可解析或默认值不对: %+v", c.Database)
	}

	// 幂等：第二次不应再写（created=false，内容不变）。
	before, _ := os.ReadFile(path)
	_, created2, _ := EnsureFile()
	after, _ := os.ReadFile(path)
	if created2 || string(before) != string(after) {
		t.Fatalf("重复调用不应覆盖已有配置")
	}
}

func TestEnsureFileSkipsWhenDSNSet(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ARTEX_CONFIG", filepath.Join(dir, "config.json"))
	t.Setenv("ARTEX_PG_DSN", "postgres://u:p@h:5432/d?sslmode=disable")
	if _, created, err := EnsureFile(); err != nil || created {
		t.Fatalf("有 ARTEX_PG_DSN 时不应生成文件: created=%v err=%v", created, err)
	}
}
