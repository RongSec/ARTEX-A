package guard

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// restoreDefaultShortCircuit 把包级配置复位成默认值，避免测试间串扰。
func restoreDefaultShortCircuit(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		dir := t.TempDir()
		if err := ReloadShortCircuit(dir); err != nil {
			t.Fatalf("恢复默认短路配置失败: %v", err)
		}
	})
}

// 合法配置文件生效：自定义 deny 名单覆盖默认值，缺省字段继续用代码默认。
func TestShortCircuitConfigFileLoaded(t *testing.T) {
	restoreDefaultShortCircuit(t)
	dir := t.TempDir()
	path := ShortCircuitConfigPath(dir)
	body := `{
	  "version": 1,
	  "tools": {"deny": ["marker_tool"]},
	  "bare_read_names": ["custom.secret"]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReloadShortCircuit(dir); err != nil {
		t.Fatalf("合法配置应加载成功: %v", err)
	}

	cfg := EffectiveShortCircuitConfig()
	if len(cfg.Tools.Deny) != 1 || cfg.Tools.Deny[0] != "marker_tool" {
		t.Fatalf("tools.deny 未生效: %+v", cfg.Tools.Deny)
	}
	// 缺省字段用默认：ask/allow 与平台正则仍在。
	if len(cfg.Tools.Ask) != len(defaultShortCircuitConfig.Tools.Ask) {
		t.Fatalf("缺省 tools.ask 应用默认值，得到 %+v", cfg.Tools.Ask)
	}
	if len(cfg.PlatformPaths) != len(defaultShortCircuitConfig.PlatformPaths) {
		t.Fatalf("缺省 platform_paths 应用默认值")
	}

	// marker_tool 被 deny；默认名单里的 create_mcp 已被覆盖，不再命中。
	if dec := shortCircuit("marker_tool", []byte(`{}`)); dec == nil || dec.Action != "deny" {
		t.Fatalf("自定义 deny 未生效: %+v", dec)
	}
	if dec := shortCircuit("create_mcp", []byte(`{}`)); dec != nil {
		t.Fatalf("tools.deny 覆盖后 create_mcp 不应再命中: %+v", dec)
	}
	// 自定义裸读名单生效，旧默认名不再命中。
	if dec := shortCircuit("Bash", []byte(`{"command":"cat custom.secret"}`)); dec == nil || dec.Action != "deny" {
		t.Fatalf("自定义 bare_read_names 未生效: %+v", dec)
	}
	if dec := shortCircuit("Bash", []byte(`{"command":"cat config.json"}`)); dec != nil {
		t.Fatalf("bare_read_names 覆盖后 config.json 不应再命中: %+v", dec)
	}
}

// 非法正则：返回错误，且不改变当前生效配置（fail-closed，不静默降级）。
func TestShortCircuitConfigInvalidRegexRejected(t *testing.T) {
	restoreDefaultShortCircuit(t)
	dir := t.TempDir()
	valid := `{"tools":{"deny":["marker_tool"]}}`
	if err := os.WriteFile(ShortCircuitConfigPath(dir), []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReloadShortCircuit(dir); err != nil {
		t.Fatal(err)
	}
	before := EffectiveShortCircuitConfig()

	invalid := `{"platform_paths":["("]}`
	if err := os.WriteFile(ShortCircuitConfigPath(dir), []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReloadShortCircuit(dir); err == nil {
		t.Fatal("非法正则应返回错误")
	}
	after := EffectiveShortCircuitConfig()
	if len(after.PlatformPaths) != len(before.PlatformPaths) {
		t.Fatalf("加载失败不得替换生效配置: before=%v after=%v", before.PlatformPaths, after.PlatformPaths)
	}
	if dec := shortCircuit("marker_tool", []byte(`{}`)); dec == nil || dec.Action != "deny" {
		t.Fatalf("加载失败后上一份配置应继续生效: %+v", dec)
	}
}

// 关键列表显式清空 → 拒绝（空列表会让整档失效）。
func TestShortCircuitConfigEmptyCriticalListRejected(t *testing.T) {
	for _, body := range []string{
		`{"platform_paths":[]}`,
		`{"platform_loose_patterns":[]}`,
		`{"bare_read_names":[]}`,
		`{"host_paths":[]}`,
		`{"ssh_host_key_patterns":[]}`,
		`{"remote_exempt_patterns":[]}`,
	} {
		if _, err := ParseShortCircuitConfig([]byte(body)); err == nil {
			t.Fatalf("空关键列表应被拒绝: %s", body)
		}
	}
}

// 缺失文件：使用默认且不自动写盘。
func TestShortCircuitConfigMissingUsesDefaultsNoWrite(t *testing.T) {
	restoreDefaultShortCircuit(t)
	dir := t.TempDir()
	path := ShortCircuitConfigPath(dir)
	if err := ReloadShortCircuit(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("缺失文件不应被自动创建，stat err=%v", err)
	}
	if got := EffectiveShortCircuitConfig(); len(got.Tools.Deny) != 3 {
		t.Fatalf("缺文件应使用默认 deny（含 delete_assets_by_host），得到 %+v", got.Tools.Deny)
	}
	if dec := shortCircuit("create_mcp", []byte(`{}`)); dec == nil || dec.Action != "deny" {
		t.Fatalf("默认规则未生效: %+v", dec)
	}
}

// dirty：写完文件但未重启 → 文件与生效配置不同 = true；恢复重启语义后才一致。
func TestShortCircuitDirty(t *testing.T) {
	restoreDefaultShortCircuit(t)
	dir := t.TempDir()
	path := ShortCircuitConfigPath(dir)
	if err := ReloadShortCircuit(dir); err != nil {
		t.Fatal(err)
	}
	if ShortCircuitDirty(path) {
		t.Fatal("文件缺失且生效默认时不应 dirty")
	}
	cfg := Defaults()
	cfg.Tools.Deny = append(cfg.Tools.Deny, "new_tool")
	if err := WriteShortCircuitConfigFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	if !ShortCircuitDirty(path) {
		t.Fatal("文件已改动但未重启，应 dirty")
	}
	if err := ReloadShortCircuit(dir); err != nil {
		t.Fatal(err)
	}
	if ShortCircuitDirty(path) {
		t.Fatal("重启（重新加载）后应不再 dirty")
	}
}

// WriteShortCircuitConfigFile 必须 0600，且内容可被重新解析。
func TestWriteShortCircuitConfigFilePerm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ShortCircuitConfigFile)
	if err := WriteShortCircuitConfigFile(path, Defaults()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows 的 Chmod 只映射只读位，权限断言仅在 POSIX 上有意义。
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("权限应为 0600，得到 %v", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseShortCircuitConfig(raw); err != nil {
		t.Fatalf("写出的配置应可重新解析: %v", err)
	}
}
