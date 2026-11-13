//go:build windows

package server

import (
	"fmt"
	"os/exec"
)

// restartCommand 在 Windows 上没有可移植的 /bin/sh。生产部署（Linux/Docker）
// 走 restart_unix.go 的 sh -c 机制；Windows 本地开发请用 start.bat 重启。
func restartCommand(_ string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("Windows 不支持 sh -c 自重启，请用 start.bat 手动重启")
}
