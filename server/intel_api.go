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
		Mode string `json:"mode"`
		Days int    `json:"days"`
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
	default:
		writeErr(w, 400, "mode 只能是 kev / recent / full")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true, "mode": mode})
}
