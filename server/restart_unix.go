//go:build !windows

package server

import (
	"os/exec"
	"syscall"
)

// restartCommand 用 /bin/sh 执行自重启脚本。Setsid 让替代进程脱离当前
// 进程组：即使旧进程退出、终端挂断，sleep+exec 的新进程也能独立存活。
func restartCommand(script string) (*exec.Cmd, error) {
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd, nil
}
