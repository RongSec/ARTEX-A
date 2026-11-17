package server

// V6-CFG：短路规则的文件配置 API + 重启端点。
//
// 为什么必须「写文件 + 重启」而不是像 /api/settings 那样热改：短路表是平台
// 唯一不受 DB/settings 热改面影响的红线。持 JWT 者能 PUT settings、DELETE
// DB 规则，但改不了已编译进进程的包级变量——除非他能写文件并重启进程，
// 而那两步都会留下文件 mtime 与审计链记录。这里刻意不提供 reload 接口。

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
)

// ShortCircuitRule 是 V9-RULE 统一规则行：内置工具策略 + 平台路径 + 自定义
// 条目合并后的展示/编辑形态。priority 升序（数值小的先命中）。
type ShortCircuitRule struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"` // builtin | custom
	Priority    int    `json:"priority"`
	Name        string `json:"name"`
	Action      string `json:"action"` // allow | deny | ask
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Readonly    bool   `json:"readonly"`
}

const (
	shortCircuitMaxBody = 1 << 20 // 1 MiB，足够容纳全量正则；防止超大 body 打爆内存
	// restartDelay 是「响应 200 → 旧进程退出」的窗口。给 HTTP 响应与审计写入
	// 留出落盘时间，同时让旧进程先释放 8801，2s 后 exec 的新进程才能重新绑定。
	defaultRestartDelay = 2 * time.Second
)

func (s *Server) shortCircuitPath() string {
	if s.m == nil {
		return guard.ShortCircuitConfigPath("data")
	}
	return guard.ShortCircuitConfigPath(s.m.dir)
}

// GET /api/system/shortcircuit
// 返回当前【生效】配置（不是文件内容）、内置默认、文件路径、装入时间、是否脏。
func (s *Server) shortCircuitGet(w http.ResponseWriter, r *http.Request) {
	path := s.shortCircuitPath()
	loaded := guard.ShortCircuitLoadedAt()
	cfg := guard.EffectiveShortCircuitConfig()
	writeJSON(w, 200, map[string]any{
		"config":    cfg,
		"defaults":  guard.Defaults(),
		"rules":     buildShortCircuitRules(cfg),
		"file_path": path,
		"loaded_at": loaded.Format(time.RFC3339),
		"dirty":     guard.ShortCircuitDirty(path),
		// 旧字段（一版兼容）：老前端/脚本仍可从顶层读取原配置结构。
		"tools":          cfg.Tools,
		"platform_paths": cfg.PlatformPaths,
		"custom_rules":   cfg.CustomRules,
	})
}

// PUT /api/system/shortcircuit
// body 既接受 {"config": {...}}，也接受裸配置对象。校验通过后写文件（0600），
// 不触碰内存中的生效配置——必须重启才生效。
func (s *Server) shortCircuitPut(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, shortCircuitMaxBody+1))
	if err != nil {
		writeErr(w, 400, "读取请求体失败: "+err.Error())
		return
	}
	if len(body) > shortCircuitMaxBody {
		writeErr(w, 400, "配置过大（上限 1 MiB）")
		return
	}
	raw := body
	var wrapper struct {
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		writeErr(w, 400, "请求格式错误: "+err.Error())
		return
	}
	if len(wrapper.Config) > 0 && string(wrapper.Config) != "null" {
		raw = wrapper.Config
	}
	cfg, err := guard.ParseShortCircuitConfig(raw)
	if err != nil {
		writeErr(w, 400, "短路规则校验失败: "+err.Error())
		return
	}
	path := s.shortCircuitPath()
	if err := guard.WriteShortCircuitConfigFile(path, cfg); err != nil {
		writeErr(w, 500, "写入短路规则文件失败: "+err.Error())
		return
	}
	s.auditSystem("shortcircuit_config_put", "修改短路规则文件（需重启生效）", map[string]any{
		"file_path": path,
		"config":    cfg,
	})
	writeJSON(w, 200, map[string]any{
		"ok":           true,
		"need_restart": true,
		"file_path":    path,
	})
}

// POST /api/system/shortcircuit/reset
func (s *Server) shortCircuitReset(w http.ResponseWriter, r *http.Request) {
	cfg := guard.Defaults()
	path := s.shortCircuitPath()
	if err := guard.WriteShortCircuitConfigFile(path, cfg); err != nil {
		writeErr(w, 500, "写入默认短路规则失败: "+err.Error())
		return
	}
	s.auditSystem("shortcircuit_config_reset", "恢复短路规则默认值（需重启生效）", map[string]any{
		"file_path": path,
	})
	writeJSON(w, 200, map[string]any{
		"ok":           true,
		"need_restart": true,
		"file_path":    path,
	})
}

// POST /api/system/restart
//
// 顺序不可颠倒：先写审计（谁/何时/参数）→ 回 200 → 延迟 2s → sh 启动替代进程
// → os.Exit(0)。旧进程退出后新进程（sleep 2 后 exec）才绑定端口，避免
// "address already in use"。审计放在退出前，因为 os.Exit 不会等待异步写。
func (s *Server) systemRestart(w http.ResponseWriter, r *http.Request) {
	exe, err := os.Executable()
	if err != nil {
		writeErr(w, 500, "无法定位当前可执行文件: "+err.Error())
		return
	}
	logPath := filepath.Join(s.shortCircuitDataDir(), "restart.log")
	s.auditSystem("system_restart", "手动重启服务端（短路规则生效）", map[string]any{
		"executable": exe,
		"args":       os.Args[1:],
		"log_file":   logPath,
		"remote":     r.RemoteAddr,
	})

	delay := s.restartDelay
	if delay <= 0 {
		delay = defaultRestartDelay
	}
	restart := s.restartFunc
	if restart == nil {
		restart = func() error { return s.spawnRestart(exe, logPath) }
	}
	exit := s.exitFunc
	if exit == nil {
		exit = os.Exit
	}

	writeJSON(w, 200, map[string]any{
		"ok":            true,
		"scheduled":     true,
		"delay_seconds": int(delay / time.Second),
		"log_file":      logPath,
	})
	go func() {
		time.Sleep(delay)
		if err := restart(); err != nil {
			// 关键失败回退：替代进程没起来就绝不退出旧进程，服务继续可用。
			log.Printf("[restart] 排程失败，旧进程继续运行: %v", err)
			return
		}
		exit(0)
	}()
}

// spawnRestart 用 `sh -c 'sleep 2; exec <exe> <argv> >> <log> 2>&1'` 拉起自身。
// 返回 nil 表示子进程已成功创建；随即由调用方 os.Exit(0) 释放端口。
func (s *Server) spawnRestart(exe, logPath string) error {
	script := restartScript(exe, os.Args[1:], logPath)
	cmd, err := restartCommand(script)
	if err != nil {
		return err
	}
	// 子进程的输出已在 shell 脚本里重定向；这里保持 nil（/dev/null），
	// 避免与父进程的日志 sink 纠缠。
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动重启子进程失败: %w", err)
	}
	log.Printf("[restart] 已排程替代进程 pid=%d，2s 后 exec %s", cmd.Process.Pid, exe)
	return nil
}

// restartScript 拼出 POSIX sh 命令。参数逐个单引号转义，防止 argv 里的空格/
// 引号/元字符破坏命令（例如 -addr :8801 或包含空格的 data 路径）。
func restartScript(exe string, args []string, logPath string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, shellQuote(exe))
	for _, a := range args {
		parts = append(parts, shellQuote(a))
	}
	return "sleep 2; exec " + strings.Join(parts, " ") + " >> " + shellQuote(logPath) + " 2>&1"
}

// shellQuote 见 customtool.go（单引号包裹，单引号自身用 '\'' 拼接）。

func (s *Server) shortCircuitDataDir() string {
	if s.m == nil || s.m.dir == "" {
		return "data"
	}
	return s.m.dir
}

// ---------- V9-RULE：统一规则表 ----------

// builtinID 用「字段 + 模式/工具名」的短哈希做稳定 id：禁用条目仍可回显
// （GET 用 Defaults ∪ 当前配置），重新启用时不依赖易漂移的数组下标。
func builtinID(scope, value string) string {
	sum := sha1.Sum([]byte(scope + "\x00" + value))
	return "builtin:" + scope + ":" + hex.EncodeToString(sum[:6])
}

func customRuleID(key string) string { return "custom:" + key }

// pathRuleFields 是内置正则档的展示元数据（顺序=优先级排序依据）。
var pathRuleFields = []struct {
	field string
	name  string
	desc  string
}{
	{"platform_paths", "平台凭据路径", "命中即 deny：平台 jwt.key/.env/MITM CA 等凭据路径"},
	{"platform_loose_patterns", "平台凭据宽松变形", "覆盖 jwt.key 被插入空白/分隔符的变形"},
	{"bare_read_names", "裸读文件名", "读命令第一参数为裸相对名（config.json/.jwt/jwt.key）时 deny"},
	{"host_paths", "本机系统凭据", "命中且命令无远程指代时 deny（/etc/shadow、sudoers、/root/.ssh）"},
	{"ssh_host_key_patterns", "本机 SSH 主机私钥", "命中 /etc/ssh/ssh_host_*key 时 deny（.pub 放行）"},
	{"control_plane_patterns", "平台控制面 API", "请求平台自身管理接口（/api/intercept|settings|system/...）时 deny"},
}

// buildShortCircuitRules 把配置文件合并成统一规则表（按 priority 升序）。
// 内置行来自 Defaults ∪ 当前配置：被禁用的内置项仍回显（enabled=false），
// 保证开关可逆；不在 Defaults 里的额外模式视为内置只读（只可停用）。
func buildShortCircuitRules(cfg guard.ShortCircuitConfig) []ShortCircuitRule {
	def := guard.Defaults()
	out := make([]ShortCircuitRule, 0, 64)
	addTools := func(action string, base int, cur, defaults []string) {
		seen := map[string]bool{}
		ordered := make([]string, 0, len(defaults)+len(cur))
		for _, n := range append(append([]string{}, defaults...), cur...) {
			n = strings.TrimSpace(n)
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			ordered = append(ordered, n)
		}
		for i, n := range ordered {
			out = append(out, ShortCircuitRule{
				ID:          builtinID("tools."+action, n),
				Kind:        "builtin",
				Priority:    base + i,
				Name:        n,
				Action:      action,
				Pattern:     n,
				Description: "内置工具策略 " + action + "：" + n,
				Enabled:     containsString(cur, n),
				Readonly:    true,
			})
		}
	}
	addTools("deny", 10, cfg.Tools.Deny, def.Tools.Deny)
	// 自定义条目优先级起点 100，按配置文件顺序（即运行时匹配顺序）。
	for i, r := range cfg.CustomRules {
		action := strings.TrimSpace(r.Action)
		if action == "" {
			action = "deny"
		}
		out = append(out, ShortCircuitRule{
			ID:          customRuleID(r.Key),
			Kind:        "custom",
			Priority:    100 + i,
			Name:        r.Name,
			Action:      action,
			Pattern:     r.Pattern,
			Description: r.Note,
			Enabled:     r.Enabled,
			Readonly:    false,
		})
	}
	addTools("ask", 200, cfg.Tools.Ask, def.Tools.Ask)
	addTools("allow", 300, cfg.Tools.Allow, def.Tools.Allow)

	base := 400
	for _, f := range pathRuleFields {
		cur := pathList(cfg, f.field)
		defs := pathList(def, f.field)
		seen := map[string]bool{}
		ordered := make([]string, 0, len(defs)+len(cur))
		for _, p := range append(append([]string{}, defs...), cur...) {
			p = strings.TrimSpace(p)
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			ordered = append(ordered, p)
		}
		for i, p := range ordered {
			out = append(out, ShortCircuitRule{
				ID:          builtinID(f.field, p),
				Kind:        "builtin",
				Priority:    base + i,
				Name:        fmt.Sprintf("%s #%d", f.name, i+1),
				Action:      "deny",
				Pattern:     p,
				Description: f.desc,
				Enabled:     containsString(cur, p),
				Readonly:    true,
			})
		}
		base += 100
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

func pathList(cfg guard.ShortCircuitConfig, field string) []string {
	switch field {
	case "platform_paths":
		return cfg.PlatformPaths
	case "platform_loose_patterns":
		return cfg.PlatformLoosePatterns
	case "bare_read_names":
		return cfg.BareReadNames
	case "host_paths":
		return cfg.HostPaths
	case "ssh_host_key_patterns":
		return cfg.SSHHostKeyPatterns
	case "control_plane_patterns":
		return cfg.ControlPlanePatterns
	}
	return nil
}

func setPathList(cfg *guard.ShortCircuitConfig, field string, v []string) {
	switch field {
	case "platform_paths":
		cfg.PlatformPaths = v
	case "platform_loose_patterns":
		cfg.PlatformLoosePatterns = v
	case "bare_read_names":
		cfg.BareReadNames = v
	case "host_paths":
		cfg.HostPaths = v
	case "ssh_host_key_patterns":
		cfg.SSHHostKeyPatterns = v
	case "control_plane_patterns":
		cfg.ControlPlanePatterns = v
	}
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func toggleString(list []string, value string, enabled bool) []string {
	has := containsString(list, value)
	if enabled && !has {
		return append(append([]string{}, list...), value)
	}
	if !enabled && has {
		out := make([]string, 0, len(list))
		for _, s := range list {
			if s != value {
				out = append(out, s)
			}
		}
		return out
	}
	return list
}

// applyShortCircuitRules 把统一规则表拆回原配置文件结构。内置项只读取
// enabled（其余字段忽略）；自定义项全字段生效，按 priority 排序写回
// custom_rules（数组顺序即运行时匹配顺序）。
func applyShortCircuitRules(cfg guard.ShortCircuitConfig, rules []ShortCircuitRule) (guard.ShortCircuitConfig, error) {
	// 建立 id → 内置项映射（用当前配置 ∪ 默认值，与 GET 一致）。
	known := map[string]struct {
		scope string
		value string
	}{}
	collect := func(scope string, lists ...[]string) {
		for _, l := range lists {
			for _, v := range l {
				v = strings.TrimSpace(v)
				if v != "" {
					known[builtinID(scope, v)] = struct{ scope, value string }{scope, v}
				}
			}
		}
	}
	def := guard.Defaults()
	collect("tools.deny", cfg.Tools.Deny, def.Tools.Deny)
	collect("tools.ask", cfg.Tools.Ask, def.Tools.Ask)
	collect("tools.allow", cfg.Tools.Allow, def.Tools.Allow)
	for _, f := range pathRuleFields {
		collect(f.field, pathList(cfg, f.field), pathList(def, f.field))
	}

	customs := make([]guard.ShortCircuitCustomRule, 0)
	type customWithPriority struct {
		p int
		r guard.ShortCircuitCustomRule
	}
	var customList []customWithPriority

	for _, rule := range rules {
		if rule.Kind == "custom" {
			key := strings.TrimPrefix(rule.ID, "custom:")
			if key == rule.ID || strings.TrimSpace(key) == "" {
				return cfg, fmt.Errorf("自定义规则 id 必须以 custom: 开头并带 key")
			}
			action := strings.ToLower(strings.TrimSpace(rule.Action))
			if action == "" {
				action = "deny"
			}
			if action != "deny" && action != "ask" && action != "allow" {
				return cfg, fmt.Errorf("自定义规则 %s 的 action %q 非法", key, rule.Action)
			}
			customList = append(customList, customWithPriority{p: rule.Priority, r: guard.ShortCircuitCustomRule{
				Key: key, Name: rule.Name, Action: action, Pattern: rule.Pattern,
				Note: rule.Description, Enabled: rule.Enabled,
			}})
			continue
		}
		item, ok := known[rule.ID]
		if !ok {
			return cfg, fmt.Errorf("未知内置规则 id：%s", rule.ID)
		}
		switch item.scope {
		case "tools.deny":
			cfg.Tools.Deny = toggleString(cfg.Tools.Deny, item.value, rule.Enabled)
		case "tools.ask":
			cfg.Tools.Ask = toggleString(cfg.Tools.Ask, item.value, rule.Enabled)
		case "tools.allow":
			cfg.Tools.Allow = toggleString(cfg.Tools.Allow, item.value, rule.Enabled)
		default:
			list := toggleString(pathList(cfg, item.scope), item.value, rule.Enabled)
			setPathList(&cfg, item.scope, list)
		}
	}
	sort.SliceStable(customList, func(i, j int) bool { return customList[i].p < customList[j].p })
	for _, c := range customList {
		customs = append(customs, c.r)
	}
	cfg.CustomRules = customs
	return cfg, nil
}

// shortCircuitRulesPut PUT /api/system/shortcircuit/rules
// body {rules:[...]}：整表保存，内置项只应用 enabled，自定义项全字段。
func (s *Server) shortCircuitRulesPut(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, shortCircuitMaxBody+1))
	if err != nil {
		writeErr(w, 400, "读取请求体失败: "+err.Error())
		return
	}
	if len(body) > shortCircuitMaxBody {
		writeErr(w, 400, "配置过大（上限 1 MiB）")
		return
	}
	var in struct {
		Rules []ShortCircuitRule `json:"rules"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		writeErr(w, 400, "请求格式错误: "+err.Error())
		return
	}
	if in.Rules == nil {
		writeErr(w, 400, "缺少 rules 数组")
		return
	}
	path := s.shortCircuitPath()
	base, err := readShortCircuitConfigForUpdate(path)
	if err != nil {
		writeErr(w, 500, "读取当前配置失败: "+err.Error())
		return
	}
	cfg, err := applyShortCircuitRules(base, in.Rules)
	if err != nil {
		writeErr(w, 400, "规则校验失败: "+err.Error())
		return
	}
	if err := guard.WriteShortCircuitConfigFile(path, cfg); err != nil {
		writeErr(w, 400, "写入短路规则文件失败: "+err.Error())
		return
	}
	s.auditSystem("shortcircuit_rules_put", "保存统一短路规则表（需重启生效）", map[string]any{
		"file_path": path,
		"rules":     in.Rules,
	})
	writeJSON(w, 200, map[string]any{
		"ok":           true,
		"need_restart": true,
		"file_path":    path,
		"rules":        buildShortCircuitRules(cfg),
	})
}

// readShortCircuitConfigForUpdate 优先读盘上文件（保留尚未重启的改动），
// 文件缺失回退默认配置。
func readShortCircuitConfigForUpdate(path string) (guard.ShortCircuitConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return guard.Defaults(), nil
		}
		return guard.ShortCircuitConfig{}, err
	}
	return guard.ParseShortCircuitConfig(raw)
}

// auditSystem 复用 audit_events 哈希链（db.AppendAuditEvent）。DB 不可用时
// 退回进程日志（server logs 会进 /api/logs 的环形缓冲），不阻断配置写入。
func (s *Server) auditSystem(action, reason string, payload map[string]any) {
	if s.m == nil || s.m.pg == nil {
		log.Printf("[audit] %s: %s payload=%v（数据库不可用，仅写进程日志）", action, reason, payload)
		return
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[audit] %s payload 序列化失败: %v", action, err)
		return
	}
	if _, err := s.m.pg.AppendAuditEvent(db.AuditEvent{
		Actor:    "ARTEX",
		ToolName: "system",
		Action:   action,
		Reason:   reason,
		Payload:  raw,
	}); err != nil {
		log.Printf("[audit] %s 写入审计链失败: %v", action, err)
	}
}
