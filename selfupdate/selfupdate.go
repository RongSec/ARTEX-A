// Package selfupdate 只负责一件事：**查询** GitHub 上有没有新版本。
//
// 它曾经实现过完整的页面一键更新（下载 → SHA256 → 冒烟 → 暂存 → 下次启动
// 原子换装 → 起不来自动回滚），从 v0.3.16-hs.7 起那套逻辑整体删除，理由写在
// server/update.go 顶部：容器部署下它换的只是容器可写层里的一个文件，
// `docker compose up -d` 就退回镜像版本，且换不掉基础镜像里的 LibreOffice /
// 工具层 / Playwright——「版本号变了、能力没变」比不升级更难查。
//
// 现在升级统一由仓库根目录的 update.sh 完成（拉完整镜像、更新前 pg_dump、
// 健康检查失败自动回滚、离线 tar 导入）。本包只剩版本号比较与环境判断，
// 供 GET /api/update/check 使用。
package selfupdate

import (
	"os"
	"strconv"
	"strings"
)

// CompareVersions 比较两个版本号，返回 -1/0/1（a<b / a==b / a>b）。
// ok=false 表示至少一边不是可比较的版本号（例如本地开发构建的 "dev" 或
// git describe 产出的 "0.3.7-2-gabc1234-dirty"），此时调用方应跳过版本比较，
// 否则会把开发中的构建误判成"有新版本"。
func CompareVersions(a, b string) (int, bool) {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	if !aok || !bok {
		return 0, false
	}
	for i := range 3 {
		if av[i] != bv[i] {
			if av[i] < bv[i] {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

// parseVersion 解析 "v0.3.7" / "0.3.7" 形式的版本号为 [3]int。
//
// 只接受纯净的三段式：build.sh 在非 tag 构建时用 git describe 产出
// "0.3.7-2-gabc1234" 这类带后缀的版本，它们必须被判为不可比较，而不是被当成
// 0.3.7 —— 否则开发构建会被误判为"已是最新"。
func parseVersion(s string) ([3]int, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return [3]int{}, false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// InDocker 报告进程是否跑在容器里。
//
// 只用于让 /api/update/check 如实告诉前端"你这份是镜像部署"，页面据此显示
// 不同的升级命令（镜像部署走 update.sh 拉镜像；源码部署走 update.sh local）。
func InDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	b, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, "docker") || strings.Contains(s, "containerd")
}
