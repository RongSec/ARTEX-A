package server

// 漏洞情报的 HTTP 面（V2 组件倒排结构）。
//
// 页面能力：看（库状态 / 库配置 / 情报库 / 命中我的资产）、筛（KEV/CVSS/时间/
// 关键词）、触发同步、中断、连通性诊断。
//
// 数据全部来自公开源；PoC 只存元数据，不克隆不执行。

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/vulnintel"
)

func (s *Server) intelReady(w http.ResponseWriter) bool {
	if s == nil || s.vuln == nil {
		writeErr(w, http.StatusServiceUnavailable, "漏洞情报未启用（数据库未就绪）")
		return false
	}
	return true
}

// GET /api/intel/status
//
// 一次返回：库配置（含每源运行时状态与条数）、计数、脱敏凭据、同步运行态、
// nuclei 模板树现状。前端不需要拼多次请求。
func (s *Server) intelStatus(w http.ResponseWriter, r *http.Request) {
	if !s.intelReady(w) {
		return
	}
	ctx := r.Context()
	sources, err := s.listVulnSources(ctx)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	counts := s.vuln.store.Counts(ctx)
	running, startedAt := s.VulnIntelSyncState()

	cfg := map[string]any{
		"nvd_api_key":         maskSecret(settingString(s.m.pg, settingNvdApiKey)),
		"nvd_key_set":         settingString(s.m.pg, settingNvdApiKey) != "",
		"github_token":        maskSecret(settingString(s.m.pg, settingVulnIntelGitHubToken)),
		"github_token_set":    settingString(s.m.pg, settingVulnIntelGitHubToken) != "",
		"proxy":               s.VulnIntelProxy(),
		"poc_enabled":         s.m.pg.GetBool(settingVulnIntelPocEnabled, false),
		"backfill_days":       intSetting(s.m.pg, settingVulnIntelBackfillDays, 0),
		"max_runtime_minutes": intSetting(s.m.pg, settingVulnIntelMaxRuntimeMin, defaultVulnIntelMaxRuntimeMin),
		"fast_lane_enabled":   s.m.pg.GetBool(settingVulnIntelFastLaneOn, true),
		"fast_lane_minutes":   intSetting(s.m.pg, settingVulnIntelFastLaneMin, 30),
		"fast_lane_days":      intSetting(s.m.pg, settingVulnIntelFastLaneDays, 7),
	}
	writeJSON(w, 200, map[string]any{
		"enabled":         s.vulnIntelEnabled(),
		"sources":         sources,
		"counts":          counts,
		"config":          cfg,
		"sync_running":    running,
		"sync_started_at": startedAt,
		"sync_phase":      s.SyncPhase(),
		"nuclei":          nucleiTemplatesStatus(s.vuln.nucleiDir),
		"next_tick_hint":  "定时同步每 6 小时一轮（启动后约 90 秒跑第一轮）；快通道 7 分钟后起跑，之后 30 分钟一轮",
	})
}

// GET /api/intel/search?q=&kev=1&min_cvss=&severity=&since=&limit=&offset=
func (s *Server) intelSearch(w http.ResponseWriter, r *http.Request) {
	if !s.intelReady(w) {
		return
	}
	q := r.URL.Query()
	minCVSS, _ := strconv.ParseFloat(q.Get("min_cvss"), 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	items, total, err := s.vuln.store.SearchCVEs(r.Context(), vulnintel.SearchFilter{
		Query:    q.Get("q"),
		KEVOnly:  q.Get("kev") == "1" || q.Get("kev") == "true",
		MinCVSS:  minCVSS,
		Severity: q.Get("severity"),
		Since:    q.Get("since"),
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total})
}

// GET /api/intel/asset-hits?min_cvss=&kev=&limit=
func (s *Server) intelAssetHits(w http.ResponseWriter, r *http.Request) {
	if !s.intelReady(w) {
		return
	}
	q := r.URL.Query()
	minCVSS, _ := strconv.ParseFloat(q.Get("min_cvss"), 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	hits, err := s.vuln.store.AssetHits(r.Context(), minCVSS, q.Get("kev") == "1", limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": hits})
}

// POST /api/intel/sync {mode: "all"|"kev"|"recent"|"full"|"poc"|"ghsa"|"templates", days?, since?, until?}
func (s *Server) intelSync(w http.ResponseWriter, r *http.Request) {
	if !s.intelReady(w) {
		return
	}
	var req struct {
		Mode  string `json:"mode"`
		Days  int    `json:"days"`
		Since string `json:"since"`
		Until string `json:"until"`
	}
	_ = decode(r, &req)
	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		mode = "all"
	}
	switch mode {
	case "all":
		if !s.SyncVulnIntelNow() {
			writeErr(w, 409, "已有一轮同步在进行中（可先中断）")
			return
		}
	case "kev":
		go func() {
			if err := s.vuln.store.SyncKEVOnly(s.ctx, s.vulnIntelConfig()); err != nil {
				log.Printf("[vulnintel] 手动 KEV 同步失败: %v", err)
			}
		}()
	case "recent":
		go func() {
			if err := s.vuln.store.SyncNVDWindow(s.ctx, s.vulnIntelConfig(), time.Now().AddDate(0, 0, -7), time.Now()); err != nil {
				log.Printf("[vulnintel] 手动增量同步失败: %v", err)
			}
		}()
	case "full":
		days := req.Days
		go func() {
			if err := s.vuln.store.BackfillNVD(s.ctx, s.vulnIntelConfig(), days); err != nil {
				log.Printf("[vulnintel] 手动全量同步失败: %v", err)
			}
		}()
	case "range":
		since, err := time.Parse("2006-01-02", strings.TrimSpace(req.Since))
		if err != nil {
			writeErr(w, 400, "since 需要 YYYY-MM-DD")
			return
		}
		until := since.AddDate(0, 0, 100)
		if v := strings.TrimSpace(req.Until); v != "" {
			until, err = time.Parse("2006-01-02", v)
			if err != nil {
				writeErr(w, 400, "until 需要 YYYY-MM-DD")
				return
			}
		}
		if !until.After(since) {
			writeErr(w, 400, "until 必须晚于 since")
			return
		}
		go func(a, b time.Time) {
			if err := s.vuln.store.SyncNVDWindow(s.ctx, s.vulnIntelConfig(), a, b); err != nil {
				log.Printf("[vulnintel] 手动区间同步失败: %v", err)
			}
		}(since, until)
	case "poc":
		go func() {
			cfg := s.vulnIntelConfig()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			if err := s.vuln.store.SyncPoCOnly(ctx, cfg); err != nil {
				log.Printf("[vulnintel] 手动 PoC 聚合失败: %v", err)
			}
		}()
	case "ghsa":
		go s.syncGhsaVersions(s.ctx)
	case "templates":
		go func() {
			s.SetVulnSyncPhase("nuclei 模板树更新")
			s.refreshNucleiTemplates(s.VulnIntelProxy())
			s.SetVulnSyncPhase("")
		}()
	default:
		writeErr(w, 400, "mode 只能是 all / kev / recent / full / range / poc / ghsa / templates")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true, "mode": mode})
}

// POST /api/intel/sync/cancel
func (s *Server) intelSyncCancel(w http.ResponseWriter, r *http.Request) {
	if !s.intelReady(w) {
		return
	}
	if !s.CancelVulnIntelSync() {
		writeErr(w, 409, "当前没有在跑的同步轮")
		return
	}
	writeJSON(w, 200, map[string]any{"cancelling": true})
}

// ── 库配置 ─────────────────────────────────────────────────────────────

// GET /api/intel/sources
func (s *Server) intelSources(w http.ResponseWriter, r *http.Request) {
	if !s.intelReady(w) {
		return
	}
	items, err := s.listVulnSources(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

// PATCH /api/intel/sources/{id}
func (s *Server) intelSourceUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.intelReady(w) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, 400, "缺少库 id")
		return
	}
	var p patchVulnSource
	if err := decode(r, &p); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if err := s.updateVulnSource(r.Context(), id, p); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	items, err := s.listVulnSources(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "items": items})
}

// POST /api/intel/config { enabled?, nvd_api_key?, github_token?, poc_enabled?,
//
//	backfill_days?, max_runtime_minutes?, fast_lane_*? }
//
// 凭据语义：省略字段 = 不改；传 "-" = 清除；空串 = 保持不变。
func (s *Server) intelConfigSave(w http.ResponseWriter, r *http.Request) {
	if !s.intelReady(w) {
		return
	}
	var req struct {
		Enabled       *bool   `json:"enabled"`
		NvdAPIKey     *string `json:"nvd_api_key"`
		GitHubToken   *string `json:"github_token"`
		PocEnabled    *bool   `json:"poc_enabled"`
		BackfillDays  *int    `json:"backfill_days"`
		MaxRuntimeMin *int    `json:"max_runtime_minutes"`
		FastLaneOn    *bool   `json:"fast_lane_enabled"`
		FastLaneMin   *int    `json:"fast_lane_minutes"`
		FastLaneDays  *int    `json:"fast_lane_days"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	setSecret := func(key string, val *string) error {
		if val == nil {
			return nil
		}
		v := strings.TrimSpace(*val)
		if v == "-" {
			return s.m.pg.SetSetting(key, "")
		}
		if v == "" {
			return nil // 留空 = 保持，避免前端清空输入框就丢凭据
		}
		return s.m.pg.SetSetting(key, v)
	}
	if req.Enabled != nil {
		_ = s.m.pg.SetBool(settingVulnIntelOn, *req.Enabled)
	}
	if err := setSecret(settingNvdApiKey, req.NvdAPIKey); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := setSecret(settingVulnIntelGitHubToken, req.GitHubToken); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if req.PocEnabled != nil {
		_ = s.m.pg.SetBool(settingVulnIntelPocEnabled, *req.PocEnabled)
	}
	if req.BackfillDays != nil {
		d := *req.BackfillDays
		if d < 0 {
			d = 0
		}
		_ = s.m.pg.SetSetting(settingVulnIntelBackfillDays, strconv.Itoa(d))
	}
	if req.MaxRuntimeMin != nil {
		m := *req.MaxRuntimeMin
		if m < 5 {
			m = 5
		}
		_ = s.m.pg.SetSetting(settingVulnIntelMaxRuntimeMin, strconv.Itoa(m))
	}
	if req.FastLaneOn != nil {
		_ = s.m.pg.SetBool(settingVulnIntelFastLaneOn, *req.FastLaneOn)
	}
	if req.FastLaneMin != nil {
		m := *req.FastLaneMin
		if m < 5 {
			m = 5
		}
		_ = s.m.pg.SetSetting(settingVulnIntelFastLaneMin, strconv.Itoa(m))
	}
	if req.FastLaneDays != nil {
		d := *req.FastLaneDays
		if d < 7 {
			d = 7
		}
		_ = s.m.pg.SetSetting(settingVulnIntelFastLaneDays, strconv.Itoa(d))
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ── 连通性诊断 ─────────────────────────────────────────────────────────

type probeResult struct {
	Source    string `json:"source"`
	Target    string `json:"target"`
	OK        bool   `json:"ok"`
	Status    int    `json:"status"`
	LatencyMS int64  `json:"latency_ms"`
	Auth      string `json:"auth,omitempty"`
	Error     string `json:"error,omitempty"`
	Hint      string `json:"hint,omitempty"`
	ProxyUsed string `json:"proxy_used,omitempty"`
}

// POST /api/intel/probe {proxy?}
//
// 逐源真实探测：区分「源挂了 / 代理挂了 / 网络不通」。
//
// 两条硬要求：
//   - 探的必须是**真正会请求的地址**（库配置改过就用改过的），否则诊断通过、
//     同步失败会互相打脸；
//   - 必须带**与同步相同的凭据**。此前探测按匿名发请求，明明配了 token 仍报
//     403；PoC 那行探的是 /rate_limit——该端点不消耗额度、必然 200，等于假通过。
func (s *Server) intelProbe(w http.ResponseWriter, r *http.Request) {
	if !s.intelReady(w) {
		return
	}
	var req struct {
		Proxy *string `json:"proxy"`
	}
	_ = decode(r, &req)
	proxy := s.VulnIntelProxy()
	if req.Proxy != nil && strings.TrimSpace(*req.Proxy) != "" {
		proxy = strings.TrimSpace(*req.Proxy)
	}
	client, err := vulnintel.NewNvdClient("", proxy)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// 探测目标来自库配置（用户可能已换成镜像）：探的必须是实际会请求的地址，
	// 否则「诊断通过、同步失败」会互相打脸。
	eps := s.vulnSourceEndpoints(r.Context())
	pick := func(id, def string) string {
		if v := eps[id]; v != "" {
			return v
		}
		return def
	}

	// 凭据与同步共用同一份设置：探测显示「通」就必须代表同步也能通。
	nvdHeaders := map[string]string{}
	nvdAuth := "匿名"
	if key := settingString(s.m.pg, settingNvdApiKey); key != "" {
		nvdHeaders["apiKey"] = key
		nvdAuth = "已认证"
	}
	ghHeaders := map[string]string{"Accept": "application/vnd.github+json"}
	ghAuth := "匿名"
	if tok := settingString(s.m.pg, settingVulnIntelGitHubToken); tok != "" {
		ghHeaders["Authorization"] = "Bearer " + tok
		ghAuth = "已认证"
	}

	repo := strings.TrimRight(pick("nuclei_templates", vulnintel.DefaultNucleiRepo), "/")
	checks := []struct {
		source  string
		target  string
		headers map[string]string
		auth    string
	}{
		{"nvd", pick("nvd", "https://services.nvd.nist.gov") + "/rest/json/cves/2.0?resultsPerPage=1", nvdHeaders, nvdAuth},
		{"kev", pick("kev", "https://www.cisa.gov") + "/sites/default/files/feeds/known_exploited_vulnerabilities.json", nil, "公开"},
		// PoC 同步走 search/repositories，探针必须打同一个端点。
		{"github_poc", pick("github_poc", "https://api.github.com") + "/search/repositories?q=CVE-2021-41773&per_page=1", ghHeaders, ghAuth},
		{"ghsa", pick("ghsa", "https://api.github.com") + "/advisories?per_page=1", ghHeaders, ghAuth},
		{"nuclei_templates", strings.TrimSuffix(repo, ".git") + ".git/info/refs?service=git-upload-pack", nil, "公开"},
	}
	results := make([]probeResult, 0, len(checks))
	for _, c := range checks {
		results = append(results, probeURL(r.Context(), client.HTTP, c.source, c.target, c.headers, c.auth, proxy))
	}
	writeJSON(w, 200, map[string]any{
		"proxy":     proxy,
		"effective": proxy == "",
		"results":   results,
	})
}

func probeURL(ctx context.Context, hc *http.Client, source, target string, headers map[string]string, auth, proxy string) probeResult {
	res := probeResult{Source: source, Target: target, ProxyUsed: proxy, Auth: auth}
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(qctx, http.MethodGet, target, nil)
	if err != nil {
		res.Error = err.Error()
		res.Hint = vulnIntelErrorHint(res.Error)
		return res
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := hc.Do(req)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		res.Hint = vulnIntelErrorHint(res.Error)
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	res.Status = resp.StatusCode
	res.OK = resp.StatusCode == http.StatusOK
	if !res.OK {
		res.Error = "HTTP " + strconv.Itoa(resp.StatusCode)
		if resp.StatusCode == http.StatusForbidden && auth == "匿名" {
			// 匿名额度用尽是最常见的 403：明确说清是「没带凭据」而不是权限问题。
			res.Hint = "403：匿名额度已用尽（GitHub 60 次/小时，NVD 5 次/30 秒）。在「同步配置」填 Token / Key 后重试。"
		} else if resp.StatusCode == http.StatusForbidden && strings.Contains(strings.ToLower(string(body)), "rate limit") {
			res.Hint = "403：当前 Token 额度已用尽，等下一小时窗口或换 Token。"
		} else {
			res.Hint = vulnIntelErrorHint(res.Error + " " + string(body))
		}
	}
	return res
}

// maskSecret 遮掉凭据：空串原样返回，有值只留尾四位。
func maskSecret(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if len(v) <= 4 {
		return "****"
	}
	return "••••••••" + v[len(v)-4:]
}

// vulnIntelErrorHint 把底层错误翻成能照着修的中文建议。
func vulnIntelErrorHint(err string) string {
	e := strings.ToLower(err)
	switch {
	case err == "":
		return ""
	case strings.Contains(e, "proxyconnect") || strings.Contains(e, "socks") ||
		strings.Contains(e, "proxy is unreachable"):
		return "代理连不上：检查「上网代理」地址/端口，或清空改直连。"
	case strings.Contains(e, "failed to connect to") || strings.Contains(e, "couldn't connect to server") ||
		strings.Contains(e, "connection timed out"):
		return "连不上目标：让「上网代理」指向能出网的节点；git 拉模板还要求代理支持远端域名解析（socks5h）。"
	case strings.Contains(e, "no such host") || strings.Contains(e, "dial tcp: lookup"):
		return "DNS 解析失败：填一个能出网的代理。"
	case strings.Contains(e, "context deadline") || strings.Contains(e, "client.timeout"):
		return "请求超时：网络慢或代理节点不可用。换代理或增大单轮上限。"
	case strings.Contains(e, "status 401"):
		return "401 未授权：API Key / Token 无效或过期。"
	case strings.Contains(e, "status 403"):
		return "403 被拒：多为触发限速（NVD 匿名仅 5 次/30 秒）。填 Key 或换代理。"
	case strings.Contains(e, "status 404"):
		return "404：数据源路径变了，或代理返回了拦截页。"
	case strings.Contains(e, "429") || strings.Contains(e, "rate limit"):
		return "被限速：游标会续跑，或配置 NVD Key / GitHub Token 提升配额。"
	case strings.Contains(e, "was not closed cleanly") || strings.Contains(e, "unexpected eof") ||
		strings.Contains(e, "handshake") || strings.Contains(e, "connection reset"):
		// GitHub 主站在不少企业网/校园网是被策略阻断的（api.github.com 通、
		// github.com 不通是常见组合）——模板 clone 正好走 github.com。
		return "连接被重置：多为网络策略阻断。给模板库配镜像端点，或让「上网代理」能到 github.com。"
	case strings.Contains(e, "x509") || strings.Contains(e, "tls"):
		return "TLS 校验失败：多半是代理做了 MITM，换普通 http 代理。"
	default:
		return "看完整错误；先点「测试连通性」区分网络/代理/数据源问题。"
	}
}

// ── nuclei 模板树状态 ─────────────────────────────────────────────────

type nucleiTemplatesDTO struct {
	Dir       string `json:"dir"`
	Exists    bool   `json:"exists"`
	IsGit     bool   `json:"is_git"`
	Templates int    `json:"templates"`
	UpdatedAt string `json:"updated_at,omitempty"`
	Hint      string `json:"hint"`
}

func nucleiTemplatesStatus(dir string) nucleiTemplatesDTO {
	out := nucleiTemplatesDTO{Dir: dir}
	if dir == "" {
		out.Hint = "模板目录未配置"
		return out
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		out.Hint = "模板树尚未克隆：点「立即同步」或单点「更新模板」拉取"
		return out
	}
	out.Exists = true
	_, err = os.Stat(filepath.Join(dir, ".git"))
	out.IsGit = err == nil
	out.Templates = vulnintel.CountTemplates(dir)
	if out.IsGit {
		if fi, err := os.Stat(filepath.Join(dir, ".git", "FETCH_HEAD")); err == nil {
			out.UpdatedAt = fi.ModTime().Format(time.RFC3339)
		} else if fi, err := os.Stat(filepath.Join(dir, ".git", "index")); err == nil {
			out.UpdatedAt = fi.ModTime().Format(time.RFC3339)
		}
	}
	if out.Templates == 0 {
		out.Hint = "目录存在但没有 yaml 模板——克隆未完成，删除该目录后重新拉取"
	} else {
		out.Hint = "已就绪：" + strconv.Itoa(out.Templates) + " 个模板"
	}
	return out
}

// GET /api/intel/pocs?cve=CVE-2024-3094
func (s *Server) intelPocs(w http.ResponseWriter, r *http.Request) {
	if !s.intelReady(w) {
		return
	}
	cve := strings.TrimSpace(r.URL.Query().Get("cve"))
	if cve == "" {
		writeErr(w, 400, "cve 必填")
		return
	}
	items, err := s.vuln.store.GetPoCs(r.Context(), cve)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"cve_id": strings.ToUpper(cve), "items": items})
}

// GET /api/intel/vuln?cve=... —— 单条详情（含结构化版本区间）
func (s *Server) intelVuln(w http.ResponseWriter, r *http.Request) {
	if !s.intelReady(w) {
		return
	}
	cve := strings.TrimSpace(r.URL.Query().Get("cve"))
	if cve == "" {
		writeErr(w, 400, "cve 必填")
		return
	}
	d, err := s.vuln.store.GetVuln(r.Context(), cve)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if d == nil {
		writeErr(w, 404, "库里没有这条 CVE")
		return
	}
	writeJSON(w, 200, d)
}
