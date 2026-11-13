package server

// V6-CFG：短路规则的文件配置 API + 重启端点。
//
// 为什么必须「写文件 + 重启」而不是像 /api/settings 那样热改：短路表是平台
// 唯一不受 DB/settings 热改面影响的红线。持 JWT 者能 PUT settings、DELETE
// DB 规则，但改不了已编译进进程的包级变量——除非他能写文件并重启进程，
// 而那两步都会留下文件 mtime 与审计链记录。这里刻意不提供 reload 接口。

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
)

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
	writeJSON(w, 200, map[string]any{
		"config":    guard.EffectiveShortCircuitConfig(),
		"defaults":  guard.Defaults(),
		"file_path": path,
		"loaded_at": loaded.Format(time.RFC3339),
		"dirty":     guard.ShortCircuitDirty(path),
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
