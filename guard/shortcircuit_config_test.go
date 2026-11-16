package guard

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// V9-SC：自定义条目新增 → 写盘未重启不生效 → 重载（模拟重启）后 deny →
// 删除后重载不再命中。enabled 缺省按 true 处理。
func TestShortCircuitCustomRulesLifecycle(t *testing.T) {
	restoreDefaultShortCircuit(t)
	dir := t.TempDir()
	path := ShortCircuitConfigPath(dir)
	if err := ReloadShortCircuit(dir); err != nil {
		t.Fatal(err)
	}

	body := `{
	  "version": 1,
	  "custom_rules": [
	    {"key": "block_forbidden_scan", "name": "拦截 forbidden_scan", "pattern": "forbidden_scan", "enabled": true}
	  ]
	}`
	cfg, err := ParseShortCircuitConfig([]byte(body))
	if err != nil {
		t.Fatalf("解析自定义条目失败: %v", err)
	}
	if len(cfg.CustomRules) != 1 || !cfg.CustomRules[0].Enabled {
		t.Fatalf("自定义条目解析异常: %+v", cfg.CustomRules)
	}
	if err := WriteShortCircuitConfigFile(path, cfg); err != nil {
		t.Fatal(err)
	}

	input := []byte(`{"command":"forbidden_scan --fast"}`)
	// 只写文件、未重启：运行期仍按旧配置（不热改）。
	if dec := PreviewShortCircuit("Bash", input); dec != nil {
		t.Fatalf("写盘未重启不应生效: %+v", dec)
	}
	// 模拟重启：重新读文件装入。
	if err := ReloadShortCircuit(dir); err != nil {
		t.Fatalf("重载失败: %v", err)
	}
	dec := PreviewShortCircuit("Bash", input)
	if dec == nil || dec.Action != "deny" {
		t.Fatalf("重载后自定义条目应 deny: %+v", dec)
	}
	if !strings.HasPrefix(dec.RuleName, "[代码常量]") || !strings.Contains(dec.RuleName, "拦截 forbidden_scan") {
		t.Fatalf("RuleName 应带来源前缀与条目名，得到 %q", dec.RuleName)
	}
	// 不匹配的命令不受影响。
	if dec := PreviewShortCircuit("Bash", []byte(`{"command":"ls -la"}`)); dec != nil {
		t.Fatalf("不匹配的命令不应命中: %+v", dec)
	}

	// 删除条目 → 重载后不再命中。
	cfg.CustomRules = nil
	if err := WriteShortCircuitConfigFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := ReloadShortCircuit(dir); err != nil {
		t.Fatal(err)
	}
	if dec := PreviewShortCircuit("Bash", input); dec != nil {
		t.Fatalf("删除后重载不应再命中: %+v", dec)
	}
}

// V9-SC：enabled 缺省 true；显式 false 的条目不参与匹配。
func TestShortCircuitCustomRulesEnabledDefault(t *testing.T) {
	restoreDefaultShortCircuit(t)
	body := `{"version":1,"custom_rules":[{"key":"k1","name":"默认启用","pattern":"marker_default"}]}`
	cfg, err := ParseShortCircuitConfig([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.CustomRules[0].Enabled {
		t.Fatal("enabled 缺省应为 true")
	}

	cfg.CustomRules[0].Enabled = false
	if err := ValidateShortCircuitConfig(cfg); err != nil {
		t.Fatal(err)
	}
	compiled, err := compileShortCircuitRegexes(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.customRules) != 0 {
		t.Fatalf("disabled 条目不应进入匹配切片: %+v", compiled.customRules)
	}
}

// V9-SC：重名 key（不区分大小写）、超上限、空 pattern、非法 key 全部拒绝。
func TestShortCircuitCustomRulesValidation(t *testing.T) {
	many := make([]ShortCircuitCustomRule, 0, ShortCircuitMaxCustomRules+1)
	for i := 0; i <= ShortCircuitMaxCustomRules; i++ {
		many = append(many, ShortCircuitCustomRule{
			Key:     "k" + strings.Repeat("x", i),
			Name:    "name",
			Pattern: "p",
			Enabled: true,
		})
	}
	cases := []struct {
		name  string
		rules []ShortCircuitCustomRule
		want  string
	}{
		{
			name: "重复 key",
			rules: []ShortCircuitCustomRule{
				{Key: "Dup_Key", Name: "a", Pattern: "a", Enabled: true},
				{Key: "dup_key", Name: "b", Pattern: "b", Enabled: true},
			},
			want: "重复",
		},
		{name: "超过上限", rules: many, want: "最多"},
		{
			name:  "空 pattern",
			rules: []ShortCircuitCustomRule{{Key: "empty_pattern", Name: "a", Pattern: "  ", Enabled: true}},
			want:  "pattern 不能为空",
		},
		{
			name:  "空 name",
			rules: []ShortCircuitCustomRule{{Key: "empty_name", Name: " ", Pattern: "a", Enabled: true}},
			want:  "name 不能为空",
		},
		{
			name:  "非法 key",
			rules: []ShortCircuitCustomRule{{Key: "bad-key", Name: "a", Pattern: "a", Enabled: true}},
			want:  "key",
		},
		{
			name:  "非法正则",
			rules: []ShortCircuitCustomRule{{Key: "bad_re", Name: "a", Pattern: "(", Enabled: true}},
			want:  "非法正则",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.CustomRules = c.rules
			err := ValidateShortCircuitConfig(cfg)
			if err == nil {
				t.Fatalf("应拒绝: %+v", c.rules)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("错误信息应包含 %q，得到 %v", c.want, err)
			}
		})
	}
}

// V9-SC：配置读写幂等（写→读→写字节一致），含自定义区。
func TestShortCircuitCustomRulesWriteReadIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ShortCircuitConfigFile)
	cfg := Defaults()
	cfg.CustomRules = []ShortCircuitCustomRule{
		{Key: "rule_one", Name: "规则一", Pattern: `\.secret\b`, Note: "示例说明", Enabled: true},
		{Key: "rule_two", Name: "规则二", Pattern: "plain_literal", Enabled: false},
	}
	if err := WriteShortCircuitConfigFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseShortCircuitConfig(first)
	if err != nil {
		t.Fatalf("写出的配置应可解析: %v", err)
	}
	second, err := MarshalShortCircuitConfig(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("读写不幂等:\nfirst=%s\nsecond=%s", first, second)
	}
	if err := WriteShortCircuitConfigFile(path, parsed); err != nil {
		t.Fatal(err)
	}
	third, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, third) {
		t.Fatal("重复写盘内容应完全一致")
	}
}

// V9-SC：旧配置文件（无 custom_rules）读取不报错；首次保存补出空区。
func TestShortCircuitConfigLegacyWithoutCustomRules(t *testing.T) {
	legacy := []byte(`{"version":1,"tools":{"deny":["legacy_tool"]}}`)
	cfg, err := ParseShortCircuitConfig(legacy)
	if err != nil {
		t.Fatalf("旧格式应兼容: %v", err)
	}
	if cfg.CustomRules == nil || len(cfg.CustomRules) != 0 {
		t.Fatalf("旧格式应得到空自定义区（非 nil）: %+v", cfg.CustomRules)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, ShortCircuitConfigFile)
	if err := WriteShortCircuitConfigFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"custom_rules": []`) {
		t.Fatalf("首次保存应补出 custom_rules 空区:\n%s", raw)
	}
	if _, err := ParseShortCircuitConfig(raw); err != nil {
		t.Fatalf("补区后的文件应可重新解析: %v", err)
	}
}
