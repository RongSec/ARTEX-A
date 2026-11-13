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
// shortCircuit 的既有语义一致（deny 无人工放行路径，ask 有 15s 超时兜底）。
// V6-AUTO 起内置默认不再有 ask 工具：自主优先，破坏业务数据直接 deny，
// 平台配置/新建能力直接 allow。
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
	ControlPlanePatterns  []string          `json:"control_plane_patterns"`
	// PlatformAbsDir 是 V6-CP 的运行时字段：启动时由 EffectiveShortCircuitConfig
	// 填入 dataDir 的绝对路径，供 UI 只读展示；【不落盘、不参与解析】。
	// 选择「新增字段」而不是「追加到 platform_paths」的理由：追加会随 UI 保存
	// 把机器相关的绝对路径写死进配置文件（换部署路径后旧前缀继续生效、
	// 新前缀失效），且无法区分「用户手写模式」与「运行时生成模式」。
	PlatformAbsDir string `json:"platform_abs_dir"`
}

// Defaults 返回代码内置的默认配置。API 的「恢复默认」和文件缺字段的兜底都用它。
// 返回深拷贝：调用方修改切片不会污染包级默认值。
func Defaults() ShortCircuitConfig {
	return cloneShortCircuitConfig(defaultShortCircuitConfig)
}

var defaultShortCircuitConfig = ShortCircuitConfig{
	Version: 1,
	// 工具名单分档原则（V6-AUTO：自主优先，不再有 ask）：
	//   破坏业务数据 → deny（无人工放行路径，硬拦）；
	//   平台配置/新建能力 → allow（显式判定放行，不打断自主任务）。
	//
	// create_mcp / update_mcp：MCP 注册是凭据汇（stdio 以容器 root 拉起任意
	// 二进制、http/sse 把 env 当 header 回放），等价于让平台对任意地址带任意
	// header 发请求，agent 不得自行开通。
	// delete_assets_by_host：批量删除业务资产直接销毁测评成果，属不可逆的
	// 业务破坏，与 MCP 同档硬拦 —— 以前放 ask，人不在线时会超时 deny，
	// 语义上本就是 deny，只是多空等一轮，现改为直接 deny。
	// create_custom_tool / update_custom_tool / update_skill_file：平台配置类，
	// 不直接破坏业务数据；其后果仍由动作层护栏兜住（护栏拦行为不拦内容）。
	// 注：update_skill_file 能改 agent prompt，但改完的 prompt 仍要在动作层
	// 过 guard/规则/判官，故接受这一取舍 —— 自主任务的价值大于「prompt
	// 可能被 agent 自己改」的风险。create_skill 同理，且新建不覆盖既有行为。
	Tools: ShortCircuitTools{
		Deny: []string{"create_mcp", "update_mcp", "delete_assets_by_host"},
		Ask:  []string{},
		Allow: []string{
			"create_skill", "create_custom_tool",
			"update_custom_tool", "update_skill_file",
		},
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
	// V6-CP：平台控制面 API。威胁模型是 agent 自己（而非持 JWT 的人）：
	// 先读绝对路径的 jwt.key 拿到 token，再调 /api/intercept/**、/api/settings
	// 关规则——热加载规则被自主绕过。这里按「平台自身监听地址 + 管理路径」
	// 拦死；实际 -addr 的 host/port 由启动时追加生成的同形模式覆盖（见
	// control_plane.go 的 controlPlaneAddrAlt）。
	//
	// 只列平台管理面：/api/health、/api/facts、/function/facts 是只读业务面，
	// 刻意不拦（agent 自查健康是合法动作）。
	ControlPlanePatterns: []string{
		`(?:https?://)?(?:127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0):(?:8801|8787)/api/(?:intercept|settings|system|agents|mcp|tools)(?:[/?#\s"'` + "`" + `;&|)>},.]|$)`,
		`(?:https?://)?(?:127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0):(?:8801|8787)/api/tasks/[^/\s"'` + "`" + `;&|]+/control(?:[/?#\s"'` + "`" + `;&|)>},.]|$)`,
		`(?:https?://)?(?:127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0):(?:8801|8787)/api/tasks/control(?:/batch)?(?:[/?#\s"'` + "`" + `;&|)>},.]|$)`,
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
	ControlPlanePatterns  *[]string `json:"control_plane_patterns"`
	// platform_abs_dir 刻意不在此结构里：它是运行时派生值，PUT 传回来也
	// 必须忽略（否则前端原样回传会把旧机器的绝对路径固化进配置）。
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
	if in.ControlPlanePatterns != nil {
		cfg.ControlPlanePatterns = *in.ControlPlanePatterns
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
		{"control_plane_patterns", cfg.ControlPlanePatterns},
	}
	for _, c := range critical {
		if len(c.list) == 0 {
			return fmt.Errorf("%s 不能为空（空列表会让整档防线失效）", c.field)
		}
	}
	if _, err := compileShortCircuitRegexes(cfg, ""); err != nil {
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
	// V6-CP：平台 dataDir 绝对路径（按运行时 dataDir 生成）与控制面 API。
	platformAbs  *regexp.Regexp
	controlPlane controlPlaneMatcher
}

// compileShortCircuitRegexes 编译配置。dataDir 用于生成平台绝对路径档；
// 传空串表示不生成（校验/无 dataDir 的嵌入场景），其余档不受影响。
func compileShortCircuitRegexes(cfg ShortCircuitConfig, dataDir string) (compiledShortCircuit, error) {
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
	if out.controlPlane, err = buildControlPlaneMatcher(cfg.ControlPlanePatterns); err != nil {
		return out, err
	}
	if out.platformAbs, err = buildPlatformAbsRegexp(dataDir); err != nil {
		return out, fmt.Errorf("platform_abs_dir %q 生成失败: %w", dataDir, err)
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
	cfg.ControlPlanePatterns = trim(cfg.ControlPlanePatterns)
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
	cfg.ControlPlanePatterns = cp(cfg.ControlPlanePatterns)
	return cfg
}

// --- 包级状态：启动时装入一次，运行期只由 Reload 显式替换 ---

var (
	shortCircuitStateMu sync.RWMutex
	shortCircuitActive  = Defaults()
	shortCircuitPath    string
	shortCircuitLoaded  time.Time
	shortCircuitLoadErr error
	// shortCircuitLoadedDir 是生效配置对应的 dataDir。platform_abs_dir 的
	// 展示值必须与短路表实际编译时用的目录一致（Reload 的入参），不能读
	// 包级 guardDataDir——试判/测试会用临时 dataDir 重载。
	shortCircuitLoadedDir string
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
	if err := applyShortCircuitConfig(Defaults(), guardDataDir); err != nil {
		panic("guard: 内置短路默认配置非法: " + err.Error())
	}
	shortCircuitPath = ShortCircuitConfigPath(guardDataDir)
	shortCircuitLoaded = time.Now()
	shortCircuitLoadedDir = guardDataDir
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
	if err := applyShortCircuitConfig(cfg, dataDir); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	shortCircuitStateMu.Lock()
	shortCircuitActive = cfg
	shortCircuitPath = path
	shortCircuitLoaded = time.Now()
	shortCircuitLoadedDir = dataDir
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

func applyShortCircuitConfig(cfg ShortCircuitConfig, dataDir string) error {
	c, err := compileShortCircuitRegexes(cfg, dataDir)
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
	platformAbsRe = c.platformAbs
	controlPlaneDetector = c.controlPlane
	return nil
}

// EffectiveShortCircuitConfig 返回当前生效配置的深拷贝。PlatformAbsDir 在此
// 填入运行时 dataDir 的绝对路径——只用于 UI 只读展示，不写入配置文件
// （写盘走 Parse/Defaults 的结果，见 PlatformAbsDir 字段注释）。
func EffectiveShortCircuitConfig() ShortCircuitConfig {
	shortCircuitStateMu.RLock()
	cfg := cloneShortCircuitConfig(shortCircuitActive)
	dataDir := shortCircuitLoadedDir
	shortCircuitStateMu.RUnlock()
	if dataDir == "" {
		dataDir = guardDataDir
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		abs = dataDir
	}
	cfg.PlatformAbsDir = filepath.ToSlash(filepath.Clean(abs))
	return cfg
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
