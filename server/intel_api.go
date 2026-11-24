package server

// 漏洞情报的 HTTP 面（V10-INTEL）。数据来自 NVD + CISA KEV 两个公开源，
// 页面只做「看 / 筛 / 触发同步」，不提供任何 PoC 托管。

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

func (s *Server) intelReady(w http.ResponseWriter) bool {
	if s.intel == nil {
		writeErr(w, http.StatusServiceUnavailable, "漏洞情报未启用（数据库未就绪）")
		return false
	}
	return true
}

// GET /api/intel/status
func (s *Server) intelStatus(w http.ResponseWriter, r *http.Request) {
	if !s.intelReady(w) {
		return
	}
	writeJSON(w, 200, s.intel.Status(r.Context()))
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
	entries, total, err := s.m.PG().SearchVulnIntel(r.Context(), db.VulnIntelSearch{
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
	writeJSON(w, 200, map[string]any{"items": entries, "total": total})
}

// GET /api/intel/asset-hits?limit=
func (s *Server) intelAssetHits(w http.ResponseWriter, r *http.Request) {
	if !s.intelReady(w) {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	hits, err := s.m.PG().VulnIntelAssetHits(r.Context(), limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": hits})
}

// POST /api/intel/sync {mode: "kev"|"recent"|"full", days?: number}
//
// 同步是长任务（全量回填几分钟），接口立即返回 202，进度靠 /status 的 running 字段轮询。
func (s *Server) intelSync(w http.ResponseWriter, r *http.Request) {
	if !s.intelReady(w) {
		return
	}
	var req struct {
		Mode  string `json:"mode"`
		Days  int    `json:"days"`
		Since string `json:"since"` // mode=range 时必填，YYYY-MM-DD
		Until string `json:"until"` // mode=range 时可选，默认 Since+100 天
	}
	_ = decode(r, &req)
	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		mode = "recent"
	}
	// 先跑起来再返回：begin 冲突检测是同步的，能立刻告诉调用方「已经在跑了」。
	ctx := s.ctx
	switch mode {
	case "kev":
		go func() {
			if _, err := s.intel.SyncKEV(ctx); err != nil {
				log.Printf("[vulnintel] 手动 KEV 同步失败: %v", err)
			}
		}()
	case "recent":
		go func() {
			if _, err := s.intel.SyncNVD(ctx, time.Now().AddDate(0, 0, -7), time.Now()); err != nil {
				log.Printf("[vulnintel] 手动增量同步失败: %v", err)
			}
		}()
	case "full":
		days := req.Days
		if days <= 0 {
			days = 120
		}
		go func() {
			if _, err := s.intel.Backfill(ctx, days); err != nil {
				log.Printf("[vulnintel] 手动全量同步失败: %v", err)
			}
		}()
	case "range":
		// 按时间段回填（测试/补历史用）：NVD 单查询窗口 ≤120 天，SyncNVD 内部
		// 会按 100 天切窗，所以这里允许给任意跨度。
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
			if _, err := s.intel.SyncNVD(ctx, a, b); err != nil {
				log.Printf("[vulnintel] 手动区间同步失败: %v", err)
			}
		}(since, until)
	case "poc":
		// PoC 聚合：一次最多 200 个 CVE（认证 25/轮，靠多轮补齐）；前端点一次
		// 「聚合 PoC」就把这一轮跑满，比等后台快很多。
		n := 200
		if s.intel.GitHubConfig().TokenSet == false {
			n = 40 // 匿名 10 次/分钟，200 个要跑 20 分钟，别让用户以为点坏了
		}
		go func() {
			checked, added, err := s.intel.SyncPoc(ctx, n)
			if err != nil {
				log.Printf("[vulnintel] 手动 PoC 聚合失败: %v", err)
				return
			}
			log.Printf("[vulnintel] 手动 PoC 聚合完成：查 %d，命中 %d", checked, added)
		}()
	default:
		writeErr(w, 400, "mode 只能是 kev / recent / range / full / poc")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true, "mode": mode})
}

// GET /api/intel/config —— GitHub 配置回显（token 只给末四位）
func (s *Server) intelConfig(w http.ResponseWriter, r *http.Request) {
	if !s.intelReady(w) {
		return
	}
	writeJSON(w, 200, s.intel.GitHubConfig())
}

// POST /api/intel/config {enabled?: bool, token?: string}
// token 省略 = 不改；空串 = 清空。保存后下一轮同步即生效，无需重启。
func (s *Server) intelConfigSave(w http.ResponseWriter, r *http.Request) {
	if !s.intelReady(w) {
		return
	}
	var req struct {
		Enabled *bool   `json:"enabled"`
		Token   *string `json:"token"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.Token != nil {
		tok := strings.TrimSpace(*req.Token)
		// 只做最基本的形状校验：GitHub token 有 ghp_/github_pat_ 前缀，但用户也可能
		// 粘贴 fine-grained token（github_pat_）。长度过短多半是误粘贴。
		if tok != "" && len(tok) < 20 {
			writeErr(w, 400, "token 看起来不完整（长度 < 20）")
			return
		}
		req.Token = &tok
	}
	if err := s.intel.SetGitHubConfig(req.Enabled, req.Token); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, s.intel.GitHubConfig())
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
	items, err := s.m.PG().ListVulnPocs(r.Context(), strings.ToUpper(cve))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"cve_id": strings.ToUpper(cve), "items": items})
}
