package guard

// 短路表的可配置文件（V6-CFG）。
//
// 设计边界（与 shortcircuit.go 头部约束一致）：
//   - 规则仍然【不进 DB、不受 settings 热改】。唯一的热改入口是 API 写文件，
//     而写文件后必须重启服务端才生效（shortCircuit 只读启动时装入的包级变量）。
//   - 启动时读一次 <dataDir>/shortcircuit_rules.json。文件缺失 → 用 Defaults()，
//     且【不自动写盘】——首次部署不产生任何可被误改的持久文件。
//   - 文件存在但非法（正则编译失败、关键列表为空、字段类型错误）→ 明确报错，
//     由 main 拒绝启动；运行期 Reload 失败则保留上一份生效配置，不静默降级。
//   - 字段缺省 → 用代码默认；显式空数组是「用户清空」的意图，对关键列表按
//     非法处理（fail-closed），对工具/记录名单允许为空（清空 = 更严或仅取消豁免）。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/config"
)

// ShortCircuitConfigFile 是配置文件在 dataDir 下的固定名称。
const ShortCircuitConfigFile = "shortcircuit_rules.json"

// ShortCircuitTools 是三类工具名单。判定顺序 deny → ask → allow，与
// shortCircuit 的既有语义一致（deny 无人工放行路径，ask 有 60s 超时兜底）。
type ShortCircuitTools struct {
	Deny  []string `json:"deny"`
	Ask   []string `json:"ask"`
	Allow []string `json:"allow"`
}

// ShortCircuitConfig 是配置文件的稳定 JSON 形状，也是 GET API 回给前端的结构。
type ShortCircuitConfig struct {
	Version               int               `json:"version"`
	Tools                 ShortCircuitTools `json:"tools"`
	PlatformPaths         []string          `json:"platform_paths"`
	PlatformLoosePatterns []string          `json:"platform_loose_patterns"`
	BareReadNames         []string          `json:"bare_read_names"`
	HostPaths             []string          `json:"host_paths"`
	SSHHostKeyPatterns    []string          `json:"ssh_host_key_patterns"`
	RemoteExemptPatterns  []string          `json:"remote_exempt_patterns"`
	RecordOnlyTools       []string          `json:"record_only_tools"`
}

// Defaults 返回代码内置的默认配置。API 的「恢复默认」和文件缺字段的兜底都用它。
// 返回深拷贝：调用方修改切片不会污染包级默认值。
func Defaults() ShortCircuitConfig {
	return cloneShortCircuitConfig(defaultShortCircuitConfig)
}

var defaultShortCircuitConfig = ShortCircuitConfig{
	Version: 1,
	Tools: ShortCircuitTools{
		Deny: []string{"create_mcp", "update_mcp"},
		Ask: []string{
			"create_custom_tool", "update_custom_tool",
			"update_skill_file", "delete_assets_by_host",
		},
		Allow: []string{"create_skill"},
	},
	PlatformPaths: []string{
		// 平台签名密钥（现行 + 旧版遗留两处位置）
		`/app/(?:data/)?jwt\.key`,
		`/app/\.env\b`,
		// MITM CA 私钥/证书
		`/app/data/traffic/_ca/[^\s"']*\.(?:pem|key|crt)`,
		// 相对路径回溯到平台密钥（cwd 为 /app/data/sessions/<key>）
		`(?:\.\./){2,}jwt\.key`,
		// /proc 族：环境块 / 命令行 / 内存
		`/proc/[^\s"']*envi[^\s"']*`,
		`/proc/\d+/cmdline`,
		`/proc/\d+/mem`,
	},
	PlatformLoosePatterns: []string{
		// 宽字符类补充：覆盖 jwt.key 被插入空白/分隔符的变形
		`/app/(?:data/)?j[\s._-]*w[\s._-]*t[\s._-]*\.?[\s._-]*k[\s._-]*e[\s._-]*y`,
	},
	BareReadNames: []string{"config.json", ".jwt", "jwt.key"},
	HostPaths: []string{
		// /etc/shadow / /etc/gshadow
		`/etc/s[\s._-]*h[\s._-]*a[\s._-]*d[\s._-]*o[\s._-]*w`,
		`/etc/gshadow`,
		// /etc/sudoers, /etc/sudoers.d/
		`/etc/s[\s._-]*u[\s._-]*d[\s._-]*o[\s._-]*e[\s._-]*r[\s._-]*s(?:\.d)?`,
		// /root/.ssh 下具体文件（目录本体不拦）
		`/root/\.ssh/[^\s"'` + "`" + `]+`,
	},
	SSHHostKeyPatterns: []string{
		`/etc/ssh/ssh_host_[^\s"'` + "`" + `]*key`,
	},
	RemoteExemptPatterns: []string{
		`(?:^|[\s"'` + "`" + `;&|(<>$])(?:ssh|scp|sftp|rsync|proxychains(?:4|chain)?[0-9]*|netcat|ncat|nc|winrm|ansible)\b`,
		`(?:^|[\s"'` + "`" + `;&|(<>$])(?:mysql|psql|mariadb)\b[^\n]*?\s-{1,2}h(?:ost)?[=\s]`,
		`@(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9][a-z0-9._-]*[a-z0-9])(?:[:/'"\s)|,;-]|$)`,
		`https?://\S`,
		`(?:^|[\s"'` + "`" + `;&|(<>$])(?:docker|podman|kubectl)\b[^\n]*?\bexec\b`,
	},
	RecordOnlyTools: []string{
		"record_fact", "report_finding", "update_finding_report",
		"add_hint", "add_task_hint", "add_intent", "prove_goal",
		"goal_met", "set_goals", "set_constraints", "insert_assets",
		"bind_finding_traffic",
	},
}

// shortCircuitConfigJSON 用指针字段区分「缺省」与「显式空数组」。
type shortCircuitConfigJSON struct {
	Version *int `json:"version"`
	Tools   *struct {
		Deny  *[]string `json:"deny"`
		Ask   *[]string `json:"ask"`
		Allow *[]string `json:"allow"`
	} `json:"tools"`
	PlatformPaths         *[]string `json:"platform_paths"`
	PlatformLoosePatterns *[]string `json:"platform_loose_patterns"`
	BareReadNames         *[]string `json:"bare_read_names"`
	HostPaths             *[]string `json:"host_paths"`
	SSHHostKeyPatterns    *[]string `json:"ssh_host_key_patterns"`
	RemoteExemptPatterns  *[]string `json:"remote_exempt_patterns"`
	RecordOnlyTools       *[]string `json:"record_only_tools"`
}

// ParseShortCircuitConfig 把 JSON 字节解析成配置：缺省字段填默认值，再做校验。
// 不修改任何包级状态 —— PUT 校验失败时调用方据此返回 400，内存配置保持不变。
func ParseShortCircuitConfig(raw []byte) (ShortCircuitConfig, error) {
	var in shortCircuitConfigJSON
	if err := json.Unmarshal(raw, &in); err != nil {
		return ShortCircuitConfig{}, fmt.Errorf("配置 JSON 解析失败: %w", err)
	}
	cfg := Defaults()
	if in.Version != nil {
		cfg.Version = *in.Version
	}
	if in.Tools != nil {
		if in.Tools.Deny != nil {
			cfg.Tools.Deny = *in.Tools.Deny
		}
		if in.Tools.Ask != nil {
			cfg.Tools.Ask = *in.Tools.Ask
		}
		if in.Tools.Allow != nil {
			cfg.Tools.Allow = *in.Tools.Allow
		}
	}
	if in.PlatformPaths != nil {
		cfg.PlatformPaths = *in.PlatformPaths
	}
	if in.PlatformLoosePatterns != nil {
		cfg.PlatformLoosePatterns = *in.PlatformLoosePatterns
	}
	if in.BareReadNames != nil {
		cfg.BareReadNames = *in.BareReadNames
	}
	if in.HostPaths != nil {
		cfg.HostPaths = *in.HostPaths
	}
	if in.SSHHostKeyPatterns != nil {
		cfg.SSHHostKeyPatterns = *in.SSHHostKeyPatterns
	}
	if in.RemoteExemptPatterns != nil {
		cfg.RemoteExemptPatterns = *in.RemoteExemptPatterns
	}
	if in.RecordOnlyTools != nil {
		cfg.RecordOnlyTools = *in.RecordOnlyTools
	}
	cfg = normalizeShortCircuitConfig(cfg)
	if err := ValidateShortCircuitConfig(cfg); err != nil {
		return ShortCircuitConfig{}, err
	}
	return cfg, nil
}

// ValidateShortCircuitConfig 编译全部正则并检查关键列表非空。
// 空列表语义：正则类关键列表为空 = 整档失效，必须拒绝（fail-closed）；
// 工具名单/记录名单为空是合法收紧，放行。
func ValidateShortCircuitConfig(cfg ShortCircuitConfig) error {
	if cfg.Version <= 0 {
		return fmt.Errorf("version 必须为正整数")
	}
	critical := []struct {
		field string
		list  []string
	}{
		{"platform_paths", cfg.PlatformPaths},
		{"platform_loose_patterns", cfg.PlatformLoosePatterns},
		{"bare_read_names", cfg.BareReadNames},
		{"host_paths", cfg.HostPaths},
		{"ssh_host_key_patterns", cfg.SSHHostKeyPatterns},
		{"remote_exempt_patterns", cfg.RemoteExemptPatterns},
	}
	for _, c := range critical {
		if len(c.list) == 0 {
			return fmt.Errorf("%s 不能为空（空列表会让整档防线失效）", c.field)
		}
	}
	if _, err := compileShortCircuitRegexes(cfg); err != nil {
		return err
	}
	return nil
}

// compiledShortCircuit 是配置编译后的全部匹配器。shortCircuit 只读这些
// 包级变量（见 shortcircuit.go），不感知文件。
type compiledShortCircuit struct {
	platformDeny  map[string]bool
	platformAsk   map[string]bool
	platformAllow map[string]bool
	platform      *regexp.Regexp
	platformLoose *regexp.Regexp
	bareRead      *regexp.Regexp
	host          *regexp.Regexp
	sshHostKey    *regexp.Regexp
	remote        *regexp.Regexp
	recordOnly    map[string]bool
}

func compileShortCircuitRegexes(cfg ShortCircuitConfig) (compiledShortCircuit, error) {
	var out compiledShortCircuit
	var err error

	if out.platform, err = compileAlternation("platform_paths", cfg.PlatformPaths, "", ""); err != nil {
		return out, err
	}
	if out.platformLoose, err = compileAlternation("platform_loose_patterns", cfg.PlatformLoosePatterns, "", ""); err != nil {
		return out, err
	}
	if out.bareRead, err = compileBareReadNames(cfg.BareReadNames); err != nil {
		return out, err
	}
	if out.host, err = compileAlternation("host_paths", cfg.HostPaths, hostPathStart, hostPathEnd); err != nil {
		return out, err
	}
	if out.sshHostKey, err = compileAlternation("ssh_host_key_patterns", cfg.SSHHostKeyPatterns, hostPathStart, ""); err != nil {
		return out, err
	}
	if out.remote, err = compileAlternation("remote_exempt_patterns", cfg.RemoteExemptPatterns, "", ""); err != nil {
		return out, err
	}
	out.platformDeny = toNameSet("tools.deny", cfg.Tools.Deny)
	out.platformAsk = toNameSet("tools.ask", cfg.Tools.Ask)
	out.platformAllow = toNameSet("tools.allow", cfg.Tools.Allow)
	out.recordOnly = toNameSet("record_only_tools", cfg.RecordOnlyTools)
	return out, nil
}

// compileAlternation 逐条校验正则语法，再拼成一条 alternation。
// prefix/suffix 用于 host 档的路径词首/词尾边界（RE2 无环视）。
func compileAlternation(field string, patterns []string, prefix, suffix string) (*regexp.Regexp, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("%s 不能为空", field)
	}
	for i, p := range patterns {
		if strings.TrimSpace(p) == "" {
			return nil, fmt.Errorf("%s[%d] 为空", field, i)
		}
		if _, err := regexp.Compile("(?i)(?:" + prefix + p + suffix + ")"); err != nil {
			return nil, fmt.Errorf("%s[%d] 非法正则 %q: %w", field, i, p, err)
		}
	}
	wrapped := make([]string, 0, len(patterns))
	for _, p := range patterns {
		// prefix/suffix 必须逐条包裹：host 档每个分支都要自带路径词首/词尾
		// 边界，只包在 alternation 外层会让 p1 吃到 p2 的尾巴。
		wrapped = append(wrapped, prefix+p+suffix)
	}
	expr := "(?i)(?:" + strings.Join(wrapped, "|") + ")"
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("%s 组合正则非法: %w", field, err)
	}
	return re, nil
}

// compileBareReadNames 用固定骨架 + QuoteMeta 后的裸文件名拼装裸读档。
// 文件名按字面量处理：用户写 jwt.key，不应被当成正则 `jwt.key`。
func compileBareReadNames(names []string) (*regexp.Regexp, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("bare_read_names 不能为空")
	}
	quoted := make([]string, 0, len(names))
	for i, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			return nil, fmt.Errorf("bare_read_names[%d] 为空", i)
		}
		quoted = append(quoted, regexp.QuoteMeta(n))
	}
	expr := `(?i)(?:^|[\s"'` + "`" + `;&|(])` +
		`(?:cat|head|tail|less|more|cp|mv|sed|awk|strings)[\s"'` + "`" + `]+` +
		`["']?(?:` + strings.Join(quoted, "|") + `)` +
		`(?:$|[\s"'` + "`" + `;|&)<>{[=,)])`
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("bare_read_names 组合正则非法: %w", err)
	}
	return re, nil
}

func toNameSet(field string, names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n != "" {
			m[n] = true
		}
	}
	return m
}

func normalizeShortCircuitConfig(cfg ShortCircuitConfig) ShortCircuitConfig {
	trim := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, s := range in {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	cfg.Tools.Deny = trim(cfg.Tools.Deny)
	cfg.Tools.Ask = trim(cfg.Tools.Ask)
	cfg.Tools.Allow = trim(cfg.Tools.Allow)
	cfg.PlatformPaths = trim(cfg.PlatformPaths)
	cfg.PlatformLoosePatterns = trim(cfg.PlatformLoosePatterns)
	cfg.BareReadNames = trim(cfg.BareReadNames)
	cfg.HostPaths = trim(cfg.HostPaths)
	cfg.SSHHostKeyPatterns = trim(cfg.SSHHostKeyPatterns)
	cfg.RemoteExemptPatterns = trim(cfg.RemoteExemptPatterns)
	cfg.RecordOnlyTools = trim(cfg.RecordOnlyTools)
	return cfg
}

func cloneShortCircuitConfig(cfg ShortCircuitConfig) ShortCircuitConfig {
	cp := func(in []string) []string {
		if in == nil {
			return nil
		}
		out := make([]string, len(in))
		copy(out, in)
		return out
	}
	cfg.Tools.Deny = cp(cfg.Tools.Deny)
	cfg.Tools.Ask = cp(cfg.Tools.Ask)
	cfg.Tools.Allow = cp(cfg.Tools.Allow)
	cfg.PlatformPaths = cp(cfg.PlatformPaths)
	cfg.PlatformLoosePatterns = cp(cfg.PlatformLoosePatterns)
	cfg.BareReadNames = cp(cfg.BareReadNames)
	cfg.HostPaths = cp(cfg.HostPaths)
	cfg.SSHHostKeyPatterns = cp(cfg.SSHHostKeyPatterns)
	cfg.RemoteExemptPatterns = cp(cfg.RemoteExemptPatterns)
	cfg.RecordOnlyTools = cp(cfg.RecordOnlyTools)
	return cfg
}

// --- 包级状态：启动时装入一次，运行期只由 Reload 显式替换 ---

var (
	shortCircuitStateMu sync.RWMutex
	shortCircuitActive  = Defaults()
	shortCircuitPath    string
	shortCircuitLoaded  time.Time
	shortCircuitLoadErr error
)

// 求值依据是 shortcircuit.go 中声明的包级变量（map / *regexp.Regexp）；
// 声明处保持零值，由 init 或 ReloadShortCircuit 装入默认/文件配置。

// guardDataDir 是默认 dataDir；main 在启动时可 SetShortCircuitDataDir 覆盖。
var guardDataDir = func() string {
	return filepath.Join(config.BaseDir(), "data")
}()

// SetShortCircuitDataDir 设置后续 InitShortCircuit 读取的 dataDir。
// 必须在任何 Guard 构造前调用（main 在 NewManager 之前调用）。
func SetShortCircuitDataDir(dir string) {
	if strings.TrimSpace(dir) != "" {
		guardDataDir = dir
	}
}

// ShortCircuitConfigPath 返回 dataDir 下配置文件的绝对路径。
func ShortCircuitConfigPath(dataDir string) string {
	if abs, err := filepath.Abs(filepath.Join(dataDir, ShortCircuitConfigFile)); err == nil {
		return abs
	}
	return filepath.Join(dataDir, ShortCircuitConfigFile)
}

func init() {
	// 先装入代码默认，保证任何测试/调用在 Init 之前也得到完整规则。
	if err := applyShortCircuitConfig(Defaults()); err != nil {
		panic("guard: 内置短路默认配置非法: " + err.Error())
	}
	shortCircuitPath = ShortCircuitConfigPath(guardDataDir)
	shortCircuitLoaded = time.Now()
}

var shortCircuitInitOnce sync.Once

// InitShortCircuit 在首次 Guard 初始化时读一次配置文件。返回错误时进程应拒绝
// 启动（main 已按此处理）；同时运行期 shortCircuit 会 fail-closed 全拒。
func InitShortCircuit() error {
	shortCircuitInitOnce.Do(func() {
		shortCircuitLoadErr = ReloadShortCircuit(guardDataDir)
	})
	return shortCircuitLoadErr
}

// ReloadShortCircuit 从 dataDir 读取并启用配置。文件缺失 → 默认配置（不写盘）。
// 解析/校验失败 → 返回错误，且【不改变】当前生效配置。
func ReloadShortCircuit(dataDir string) error {
	path := ShortCircuitConfigPath(dataDir)
	cfg, err := readShortCircuitConfig(path)
	if err != nil {
		return err
	}
	if err := applyShortCircuitConfig(cfg); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	shortCircuitStateMu.Lock()
	shortCircuitActive = cfg
	shortCircuitPath = path
	shortCircuitLoaded = time.Now()
	shortCircuitLoadErr = nil
	shortCircuitStateMu.Unlock()
	return nil
}

func readShortCircuitConfig(path string) (ShortCircuitConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Defaults(), nil
		}
		return ShortCircuitConfig{}, fmt.Errorf("读取 %s 失败: %w", path, err)
	}
	cfg, err := ParseShortCircuitConfig(raw)
	if err != nil {
		return ShortCircuitConfig{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func applyShortCircuitConfig(cfg ShortCircuitConfig) error {
	c, err := compileShortCircuitRegexes(cfg)
	if err != nil {
		return err
	}
	platformDenyTools = c.platformDeny
	platformAskTools = c.platformAsk
	platformAllowTools = c.platformAllow
	recordOnlyTools = c.recordOnly
	platformCredentialRe = c.platform
	platformCredentialLooseRe = c.platformLoose
	platformConfigBareReadRe = c.bareRead
	hostSystemCredentialRe = c.host
	sshHostKeyRe = c.sshHostKey
	remoteRefRe = c.remote
	return nil
}

// EffectiveShortCircuitConfig 返回当前生效配置的深拷贝。
func EffectiveShortCircuitConfig() ShortCircuitConfig {
	shortCircuitStateMu.RLock()
	defer shortCircuitStateMu.RUnlock()
	return cloneShortCircuitConfig(shortCircuitActive)
}

// ShortCircuitLoadedAt 返回当前生效配置的装入时间。
func ShortCircuitLoadedAt() time.Time {
	shortCircuitStateMu.RLock()
	defer shortCircuitStateMu.RUnlock()
	return shortCircuitLoaded
}

// ShortCircuitConfiguredPath 返回当前生效配置的来源路径。
func ShortCircuitConfiguredPath() string {
	shortCircuitStateMu.RLock()
	defer shortCircuitStateMu.RUnlock()
	return shortCircuitPath
}

// ShortCircuitDirty 判断 path 下的文件内容与当前生效配置是否不同。
// 文件缺失时：生效配置等于默认 → 不脏（本次启动用的就是默认）；
// 否则脏（用户曾保存过非默认配置，但文件被删/未部署）。读取/解析失败按脏处理，
// 提示用户重启前先修复文件。
func ShortCircuitDirty(path string) bool {
	shortCircuitStateMu.RLock()
	active := cloneShortCircuitConfig(shortCircuitActive)
	loadedPath := shortCircuitPath
	shortCircuitStateMu.RUnlock()
	if strings.TrimSpace(path) == "" {
		path = loadedPath
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return !reflect.DeepEqual(active, defaultShortCircuitConfig)
		}
		return true
	}
	onDisk, err := ParseShortCircuitConfig(raw)
	if err != nil {
		return true
	}
	return !reflect.DeepEqual(active, onDisk)
}

// MarshalShortCircuitConfig 把配置序列化为写盘/展示用的缩进 JSON（带尾换行）。
func MarshalShortCircuitConfig(cfg ShortCircuitConfig) ([]byte, error) {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// WriteShortCircuitConfigFile 校验后以 0600 写入配置文件。只落盘，不热改内存。
func WriteShortCircuitConfigFile(path string, cfg ShortCircuitConfig) error {
	cfg = normalizeShortCircuitConfig(cfg)
	if err := ValidateShortCircuitConfig(cfg); err != nil {
		return err
	}
	data, err := MarshalShortCircuitConfig(cfg)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("创建目录 %s 失败: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", path, err)
	}
	// WriteFile 不会修正已存在文件的权限，显式收紧一次。
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("设置 %s 权限失败: %w", path, err)
	}
	return nil
}

// shortCircuitConfigError 返回启动时配置加载错误（nil 表示正常）。
func shortCircuitConfigError() error {
	shortCircuitStateMu.RLock()
	defer shortCircuitStateMu.RUnlock()
	return shortCircuitLoadErr
}
