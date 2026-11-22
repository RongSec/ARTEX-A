package server

// 手动重启服务端（POST /api/system/restart）。
//
// 原本跟「短路规则文件」放在一个文件里，因为它是「改文件后让配置生效」的
// 最后一步。V12-RULES 删掉短路规则文件后，这个端点本身还有用（改了环境变量
// /二进制升级等场景需要进程重启），所以单独留下，逻辑不变。

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// defaultRestartDelay 是「响应 200 → 旧进程退出」的窗口。给 HTTP 响应与审计
// 写入留出落盘时间，同时让旧进程先释放监听端口，2s 后 exec 的新进程才能重新
// 绑定，避免 "address already in use"。
const defaultRestartDelay = 2 * time.Second

func (s *Server) dataDirPath() string {
	if s.m == nil || s.m.dir == "" {
		return "data"
	}
	return s.m.dir
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
	logPath := filepath.Join(s.dataDirPath(), "restart.log")
	s.auditSystem("system_restart", "手动重启服务端", map[string]any{
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

// auditSystem 把一次系统级动作写进审计链（重启、配置变更等）。
// 与工具调用同一个 audit_events 表，action 用 system_* 前缀区分。
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
