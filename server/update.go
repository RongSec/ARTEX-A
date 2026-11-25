package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/Autumn-27/artex/selfupdate"
)

// 「版本检查」的 HTTP 面。
//
// 从 v0.3.16-hs.7 起，程序内**不再执行**任何更新动作：下载、换装、
// 自举回滚（原来的 /api/update/apply、/rollback、/stream 与 selfupdate.Stage）
// 全部删除，只保留「有没有新版本」这一个查询。原因不是偷懒，是那套机制
// 在容器部署下有三处硬伤：
//
//	① 假成功：换装写的是容器可写层，`docker compose up -d` 重建容器就退回
//	   镜像自带的版本。用户看到版本号变了、过两天又变回去，还查不出原因。
//	② 换不干净：它只替换 /app/artex 一个文件。基础镜像里的 LibreOffice、
//	   apt 工具层、Playwright 浏览器、python-docx 都不会跟着更新。版本号上去了、
//	   能力没上去，比不升级更难排查（docx 静默降级就是这么来的）。
//	③ 退不回去：回滚要旧镜像 tag + 数据库快照，进程内既没有前者，也不该
//	   在业务进程里做后者。
//
// 这些事现在由仓库根目录的 update.sh 负责：拉完整镜像、更新前 pg_dump、
// 健康检查失败自动回滚、离线镜像导入。页面只负责告诉用户「有新版本，去跑
// 那条命令」。查询仍然走服务端而不是浏览器直连，因为只有服务端能访问
// GitHub 才谈得上升级（服务器在内网、代理只配在浏览器上时，前端能查、后端
// 拉不动，那还不如在检查这一步就如实报错）。

// updateCmd 是页面上展示的升级命令。写死一份，避免前后端各说各的。
const updateCmd = "./update.sh"

// releaseCache 缓存 GitHub 的最新版本查询结果。
//
// 顶栏的"有新版本"提示会在每次整页加载时查一次，而未认证的 GitHub API 是
// 每 IP 每小时 60 次——不缓存的话，多开几个标签页或刷几次页面就把配额耗光了，
// 之后真想查时反而查不动。用户显式点"检查更新"时可以 force 绕过缓存。
type releaseCache struct {
	mu  sync.Mutex
	rel *selfupdate.Release
	err error
	at  time.Time
	// fetch 是取数函数，仅为测试留的注入点；为 nil 时走真正的 GitHub 查询。
	fetch func(context.Context, *http.Client) (*selfupdate.Release, error)
}

const (
	releaseTTL = 30 * time.Minute
	// 失败结果也缓存一小会儿，否则 GitHub 不可达时每次页面加载都要干等一次超时；
	// 但 TTL 要短，网络恢复后很快就能自己好。
	releaseErrTTL = 2 * time.Minute
	// 查询用的超时。NewClient 的 30 分钟超时是给下载整包用的，查版本不能等那么久。
	releaseTimeout = 20 * time.Second
)

var relCache = &releaseCache{}

// get 返回最新 Release，命中缓存则不访问网络。
//
// 取数期间一直持有锁：并发请求会排队等同一次查询的结果，而不是各自去打 GitHub
// （页面刚加载时多个标签页同时来查，正是最容易触发限流的时刻）。
func (c *releaseCache) get(ctx context.Context, client *http.Client, force bool) (*selfupdate.Release, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !force {
		ttl := releaseTTL
		if c.err != nil {
			ttl = releaseErrTTL
		}
		if !c.at.IsZero() && time.Since(c.at) < ttl {
			return c.rel, c.err
		}
	}

	fetch := c.fetch
	if fetch == nil {
		fetch = selfupdate.FetchLatest
	}
	ctx, cancel := context.WithTimeout(ctx, releaseTimeout)
	defer cancel()
	rel, err := fetch(ctx, client)
	// 请求被取消（用户关了标签页）不代表 GitHub 有问题，别把它写进缓存，
	// 否则下一个访客会拿到一条莫名其妙的"已取消"错误。
	if err != nil && ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled) {
		return c.rel, err
	}
	c.rel, c.err, c.at = rel, err, time.Now()
	return rel, err
}

// updateCheck 查询 GitHub 上的最新正式版并与当前版本比较。
//
// 它只回答两个问题：有没有新版本、该跑什么命令。不带任何副作用。
func (s *Server) updateCheck(w http.ResponseWriter, r *http.Request) {
	current := BuildVersion
	mode := "binary"
	if selfupdate.InDocker() {
		mode = "docker"
	}
	out := map[string]any{
		"current":    current,
		"mode":       mode,
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"repo":       selfupdate.Repo,
		"update_cmd": updateCmd,
	}

	// 顶栏提示走缓存（默认）；用户点"检查更新"时带 force=1 强制回源。
	force := r.URL.Query().Get("force") != ""
	client := selfupdate.NewClient(s.m.OutboundProxy())
	rel, err := relCache.get(r.Context(), client, force)
	if err != nil {
		out["error"] = err.Error()
		writeJSON(w, 200, out)
		return
	}

	latest := rel.TagName
	out["latest"] = latest
	out["notes"] = rel.Body
	out["html_url"] = rel.HTMLURL
	if !rel.PublishedAt.IsZero() {
		out["published_at"] = rel.PublishedAt.Format(time.RFC3339)
	}

	cmp, comparable := selfupdate.CompareVersions(current, latest)
	out["comparable"] = comparable
	out["has_update"] = comparable && cmp < 0
	if !comparable {
		// 开发构建（dev / git describe 带后缀）没有可比较的版本号，不提示升级。
		out["reason"] = fmt.Sprintf("当前版本 %q 不是正式发布版本，已跳过版本比较", current)
	}
	writeJSON(w, 200, out)
}
