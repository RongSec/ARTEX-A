package server

// 漏洞情报的运行时：定时循环、手动触发、并发闸门、阶段上报。
//
// 一条 pass 的顺序：
//   KEV（廉价、信号最强）→ NVD 主同步（lastModified 窗口）→ PoC 聚合（可选）
//   → 资产指纹联动（命中即给任务挂 hint）→ nuclei 模板树更新
//
// 与快通道的关系：快通道按 publishedDate 拉「刚披露的高危」，独立锁、独立游标，
// 主同步跑 30 分钟期间它照常进库（见 FastLaneConfig）。两者共用 vuln_cves。
//
// 并发控制：主同步与手动「立即同步」共用一个锁，同一时刻只有一轮；快通道自己
// 一个锁。所有出网请求走「上网代理」（OutboundProxy），与渗透流量分离。

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/artex/vulnintel"
)

// 情报配置项（settings 键）。凭据类只存键名，值由 settings 表保存。
const (
	settingVulnIntelOn             = "vulnintel_enabled"
	settingNvdApiKey               = "nvd_api_key"
	settingVulnIntelGitHubToken    = "vulnintel_github_token"
	settingVulnIntelPocEnabled     = "vulnintel_poc_enabled"
	settingVulnIntelBackfillDays   = "vulnintel_backfill_days"
	settingVulnIntelMaxRuntimeMin  = "vulnintel_max_runtime_minutes"
	settingVulnIntelFastLaneOn     = "vulnintel_fast_lane_enabled"
	settingVulnIntelFastLaneMin    = "vulnintel_fast_lane_interval_minutes"
	settingVulnIntelFastLaneDays   = "vulnintel_fast_lane_window_days"
	settingVulnIntelGhsaCursor     = "vulnintel_ghsa_cursor"
	settingVulnIntelLegacyMigrated = "vulnintel_legacy_migrated"
)

const (
	defaultVulnIntelMaxRuntimeMin = 30
	defaultVulnIntelInterval      = 6 * time.Hour
	// 首轮延迟：先让服务对外可用，再开始跑重 IO 的同步。
	defaultVulnIntelFirstDelay = 90 * time.Second
)

// vulnIntelRuntime 把「同步器 + 运行状态」收成一个字段挂在 Server 上，
// 避免在 Server 结构里摊开七八个互不相干的字段。
type vulnIntelRuntime struct {
	store     *vulnintel.Store
	nucleiDir string

	mu     sync.Mutex // 主同步 / 手动同步
	fastMu sync.Mutex // 快通道

	running   atomic.Bool
	startedAt atomic.Int64
	cancel    atomic.Value // context.CancelFunc
	phase     atomic.Value // string
}

// intSetting 读整数设置，缺失或格式错用默认值。
func intSetting(pg interface {
	GetSetting(string) (string, bool, error)
}, key string, def int) int {
	v, ok, err := pg.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

// settingString 读字符串设置（读失败按空串）。
func settingString(pg interface {
	GetSetting(string) (string, bool, error)
}, key string) string {
	v, _, _ := pg.GetSetting(key)
	return strings.TrimSpace(v)
}

// vulnIntelEnabled 是总开关。默认开：只读公开数据，无副作用。
func (s *Server) vulnIntelEnabled() bool {
	if s == nil || s.vuln == nil || s.m == nil || s.m.pg == nil {
		return false
	}
	return s.m.pg.GetBool(settingVulnIntelOn, true)
}

// VulnIntelProxy 是情报同步的出口：复用「上网代理」。
//
// 不再单独设一个 vulnintel_proxy 键：同一个出口在两个地方配，用户改了一个
// 另一个不生效，是典型的「配了但没用」故障。
func (s *Server) VulnIntelProxy() string {
	if s == nil || s.m == nil {
		return ""
	}
	return s.m.OutboundProxy()
}

// vulnIntelConfig 组装一轮主同步的配置。每次读库：页面改完下一轮即生效。
func (s *Server) vulnIntelConfig() vulnintel.Config {
	cfg := vulnintel.Config{
		ProxyURL:     s.VulnIntelProxy(),
		PocEnabled:   s.m.pg.GetBool(settingVulnIntelPocEnabled, false),
		BackfillDays: intSetting(s.m.pg, settingVulnIntelBackfillDays, 0),
		NvdAPIKey:    settingString(s.m.pg, settingNvdApiKey),
		GitHubToken:  settingString(s.m.pg, settingVulnIntelGitHubToken),
	}
	// 环境变量兜底：容器化部署更习惯把凭据放 env，而不是进数据库。
	if cfg.NvdAPIKey == "" {
		cfg.NvdAPIKey = strings.TrimSpace(os.Getenv("NVD_API_KEY"))
	}
	if cfg.GitHubToken == "" {
		cfg.GitHubToken = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}
	if mins := intSetting(s.m.pg, settingVulnIntelMaxRuntimeMin, defaultVulnIntelMaxRuntimeMin); mins > 0 {
		cfg.MaxRuntime = time.Duration(mins) * time.Minute
	}
	return cfg
}

// startVulnIntelLoops 起两条循环：主同步（6 小时）+ 快通道（30 分钟）。
func (s *Server) startVulnIntelLoops(ctx context.Context) {
	if s.vuln == nil {
		return
	}
	// 启动期先做一次旧库迁移（幂等，settings 标记避免重复扫）。
	go func() {
		if !s.m.pg.GetBool(settingVulnIntelLegacyMigrated, false) {
			res, err := s.vuln.store.MigrateLegacy(ctx)
			if err != nil {
				log.Printf("[vulnintel] 旧库迁移失败: %v", err)
				return
			}
			_ = s.m.pg.SetBool(settingVulnIntelLegacyMigrated, true)
			if res.CVEs > 0 || res.Pocs > 0 {
				log.Printf("[vulnintel] 旧库迁移: 读 CVE %d(新增 %d) / PoC %d(新增 %d)",
					res.CVEs, res.NewCV, res.Pocs, res.NewPo)
			}
		}
	}()

	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(defaultVulnIntelFirstDelay):
		}
		for {
			if s.vulnIntelEnabled() {
				if err := s.runVulnIntelPass(ctx); err != nil && err != errVulnSyncRunning {
					log.Printf("[vulnintel] 定时同步未完整完成: %v（游标已保留，下轮续跑）", err)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(defaultVulnIntelInterval):
			}
		}
	}()

	go s.runFastLaneLoop(ctx)
}

// errVulnSyncRunning 表示已有一轮在跑。
var errVulnSyncRunning = fmt.Errorf("vulnintel sync already running")

// SyncVulnIntelNow 是页面「立即同步」：忽略 enabled 开关（点了就是要跑）。
func (s *Server) SyncVulnIntelNow() bool {
	if s == nil || s.vuln == nil {
		return false
	}
	if !s.vuln.mu.TryLock() {
		return false
	}
	s.vuln.running.Store(true)
	s.vuln.startedAt.Store(time.Now().Unix())
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	s.vuln.cancel.Store(context.CancelFunc(cancel))
	go func() {
		defer s.vuln.mu.Unlock()
		defer s.vuln.running.Store(false)
		defer s.vuln.cancel.Store(context.CancelFunc(func() {}))
		defer cancel()
		if err := s.vulnIntelPassLocked(ctx); err != nil {
			log.Printf("[vulnintel] 手动同步未完整完成: %v", err)
		}
	}()
	return true
}

// CancelVulnIntelSync 协作式中断：ctx 传到 NVD/GHSA 请求与 git 子进程，
// 子进程被杀、本轮带着「已取消」退出，锁由 defer 复位。
func (s *Server) CancelVulnIntelSync() bool {
	if s == nil || s.vuln == nil || !s.vuln.running.Load() {
		return false
	}
	if c, ok := s.vuln.cancel.Load().(context.CancelFunc); ok {
		c()
		log.Printf("[vulnintel] 收到中断请求")
		return true
	}
	return false
}

// VulnIntelSyncState 返回是否在跑与开始时间（unix 秒，0=从未）。
func (s *Server) VulnIntelSyncState() (bool, int64) {
	if s == nil || s.vuln == nil {
		return false, 0
	}
	return s.vuln.running.Load(), s.vuln.startedAt.Load()
}

// SetVulnSyncPhase 更新阶段描述（状态页展示）。
func (s *Server) SetVulnSyncPhase(p string) {
	if s == nil || s.vuln == nil {
		return
	}
	s.vuln.phase.Store(p)
}

// SyncPhase 返回当前阶段（空=未跑）。
func (s *Server) SyncPhase() string {
	if s == nil || s.vuln == nil {
		return ""
	}
	if v, ok := s.vuln.phase.Load().(string); ok {
		return v
	}
	return ""
}

// runVulnIntelPass 是定时循环入口，与手动触发共用同一把锁。
func (s *Server) runVulnIntelPass(ctx context.Context) error {
	if s.vuln == nil {
		return nil
	}
	if !s.vuln.mu.TryLock() {
		return errVulnSyncRunning
	}
	defer s.vuln.mu.Unlock()
	s.vuln.running.Store(true)
	s.vuln.startedAt.Store(time.Now().Unix())
	runCtx, cancel := context.WithCancel(ctx)
	s.vuln.cancel.Store(context.CancelFunc(cancel))
	defer s.vuln.running.Store(false)
	defer s.vuln.cancel.Store(context.CancelFunc(func() {}))
	defer cancel()
	return s.vulnIntelPassLocked(runCtx)
}

// vulnIntelPassLocked 是一轮完整 pass。调用方持锁。
func (s *Server) vulnIntelPassLocked(ctx context.Context) error {
	cfg := s.vulnIntelConfig()
	s.SetVulnSyncPhase("同步 CVE / KEV / GHSA / PoC")
	err := vulnintel.Run(ctx, s.vuln.store, cfg)
	if ctx.Err() != nil {
		s.SetVulnSyncPhase("已中断")
		log.Printf("[vulnintel] 本轮被中断（进度保留）")
		return ctx.Err()
	}
	if err != nil {
		log.Printf("[vulnintel] 本轮未完整完成: %v", err)
	}
	// 同步没完整完成也照跑联动：已 upsert 的记录已经可查。
	s.SetVulnSyncPhase("资产指纹联动")
	s.linkVulnIntelAssets()
	s.SetVulnSyncPhase("nuclei 模板树更新")
	s.refreshNucleiTemplates(cfg.ProxyURL)
	s.SetVulnSyncPhase("")
	return nil
}

// refreshNucleiTemplates 维护本地模板树。刻意放在 enabled 闸门之外：
// scan_with_nuclei 是独立功能，情报同步关了模板也不该烂掉。
func (s *Server) refreshNucleiTemplates(proxyURL string) {
	if s.vuln == nil || s.vuln.nucleiDir == "" {
		return
	}
	// 15 分钟：depth-1 clone 约 100-200MB，慢代理 5 分钟必超时；超时杀掉的
	// clone 会留半成品目录，正是「0 个模板」事故的根因。
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := vulnintel.EnsureTemplates(ctx, s.vuln.nucleiDir, proxyURL); err != nil {
		log.Printf("[vulnintel] nuclei 模板树更新失败: %v", err)
	}
}

// ── 近期高危快通道 ─────────────────────────────────────────────────────

func (s *Server) fastLaneEnabled() bool {
	if !s.vulnIntelEnabled() {
		return false
	}
	return s.m.pg.GetBool(settingVulnIntelFastLaneOn, true)
}

func (s *Server) fastLaneConfig() vulnintel.FastLaneConfig {
	cfg := vulnintel.FastLaneConfig{
		ProxyURL:   s.VulnIntelProxy(),
		NvdAPIKey:  settingString(s.m.pg, settingNvdApiKey),
		WindowDays: intSetting(s.m.pg, settingVulnIntelFastLaneDays, 7),
		MaxRuntime: 5 * time.Minute,
	}
	if cfg.NvdAPIKey == "" {
		cfg.NvdAPIKey = strings.TrimSpace(os.Getenv("NVD_API_KEY"))
	}
	// 页间隔必须按 key 推导：匿名 5 次/30s ≈ 6.5s/次，有 key 0.7s/次。
	// 硬编码 1 秒在匿名下第一页就 429（Pojun 实测记录）。
	cfg.PageDelay = vulnintel.PageDelayFor(cfg.NvdAPIKey)
	return cfg
}

// runFastLaneLoop 起跑延迟 7 分钟，刻意与主同步的 90 秒大幅错开：
// 两者都打 NVD 匿名额度（5 次/30 秒共享），挨着起跑必然互相挤成 429。
func (s *Server) runFastLaneLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(7 * time.Minute):
	}
	for {
		if s.fastLaneEnabled() {
			s.fastLaneOnce(ctx)
		}
		interval := 30 * time.Minute
		if mins := intSetting(s.m.pg, settingVulnIntelFastLaneMin, 0); mins > 0 {
			interval = time.Duration(mins) * time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// fastLaneOnce 跑一轮快通道：拉取 → 入库 → 资产联动 → GHSA 补区间。
func (s *Server) fastLaneOnce(parent context.Context) {
	if s.vuln == nil || !s.vuln.fastMu.TryLock() {
		return
	}
	defer s.vuln.fastMu.Unlock()

	ctx, cancel := context.WithTimeout(parent, 6*time.Minute)
	defer cancel()

	res, err := vulnintel.RunFastLane(ctx, s.vuln.store, s.fastLaneConfig())
	if err != nil {
		log.Printf("[vulnintel] 快通道本轮失败: %v", err)
		return
	}
	if res.Stored > 0 {
		log.Printf("[vulnintel] 快通道: 扫 %d 条，入库 %d 条（版本待定 %d），游标 %s",
			res.Scanned, res.Stored, res.VersionUndetermined, res.Cursor)
		s.linkVulnIntelAssets()
	}
	s.syncGhsaVersions(ctx)
}

// syncGhsaVersions 补版本区间。失败不影响主流程：GHSA 是补充源。
func (s *Server) syncGhsaVersions(ctx context.Context) {
	if s.vuln == nil {
		return
	}
	token := settingString(s.m.pg, settingVulnIntelGitHubToken)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}
	client, err := vulnintel.NewGhsaClient(token, s.VulnIntelProxy())
	if err != nil {
		log.Printf("[vulnintel] GHSA 客户端初始化失败: %v", err)
		return
	}
	since := time.Now().Add(-7 * 24 * time.Hour)
	if v := settingString(s.m.pg, settingVulnIntelGhsaCursor); v != "" {
		if t, perr := time.Parse(time.RFC3339, v); perr == nil {
			since = t
		}
	}
	res, err := s.vuln.store.SyncGhsa(ctx, client, since, 3)
	if err != nil {
		log.Printf("[vulnintel] GHSA 同步失败: %v", err)
		s.recordGhsaState(ctx, since, 0, err)
		return
	}
	if res.Upserted > 0 || res.Merged > 0 {
		log.Printf("[vulnintel] GHSA: 拉 %d 条，新增 %d，补区间 %d", res.Fetched, res.Upserted, res.Merged)
	}
	if latest := s.latestGhsaUpdated(ctx); latest.After(since) {
		_ = s.m.pg.SetSetting(settingVulnIntelGhsaCursor, latest.UTC().Format(time.RFC3339))
		since = latest
	}
	s.recordGhsaState(ctx, since, int64(res.Upserted+res.Merged), nil)
}

func (s *Server) recordGhsaState(ctx context.Context, cursor time.Time, total int64, syncErr error) {
	if s.vuln == nil {
		return
	}
	st, err := s.vuln.store.GetSyncState(ctx, "ghsa")
	if err != nil {
		return
	}
	st.Source = "ghsa"
	st.Enabled = true
	st.Cursor = cursor.UTC().Format(time.RFC3339)
	st.TotalSynced += total
	if syncErr != nil {
		st.LastError = syncErr.Error()
	} else {
		st.LastError = ""
	}
	_ = s.vuln.store.SaveSyncState(ctx, st)
}

func (s *Server) latestGhsaUpdated(ctx context.Context) time.Time {
	var v string
	err := s.m.pg.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(modified_at)::text,'') FROM vuln_cves WHERE source='ghsa'`).Scan(&v)
	if err != nil || v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}
