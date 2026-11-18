package server

// 给 agent 用的漏洞情报工具（V10-INTEL）。
//
// 两个只读工具，数据全部来自公开源（NVD + CISA KEV）：
//   search_vulns          按组件/关键词/CVSS/在野利用筛情报库
//   list_asset_vuln_hits  拿当前资产的技术指纹反查候选 CVE（命中我的资产）
//
// 语义红线：这两件只产出「候选」。命中不等于可利用——组件名匹配不带版本，
// 版本区间一律 unknown，必须由 worker 在授权目标上实测确认后才能 report_finding。

import (
	"context"
	"encoding/json"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func (s *Server) intelTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolSearchVulns(), s.toolListAssetVulnHits()}
}

func (s *Server) toolSearchVulns() actool.CoreTool {
	return roTool("search_vulns",
		"查漏洞情报库（公开源：NVD 全量 + CISA KEV 在野利用）。用于「这个组件/产品最近爆了什么洞」「EXP 是否在野被用」。\n"+
			"返回 cve_id/severity/cvss/kev/published/描述摘要。注意：情报库只有组件名维度，没有你目标的版本；"+
			"命中的条目一律是【候选】，必须用实际请求验证后才能 report_finding。",
		objSchema(map[string]any{
			"query":    strParam("关键词：组件名/产品名/CVE 编号，如 nginx、Next.js、CVE-2024-3094"),
			"kev_only": map[string]any{"type": "boolean", "description": "只看 CISA KEV（确认在野被利用）"},
			"min_cvss": map[string]any{"type": "number", "description": "CVSS 下限，如 9 只看严重"},
			"since":    strParam("发布时间下限 YYYY-MM-DD；查「最近爆的洞」时用"),
			"limit":    map[string]any{"type": "integer", "description": "返回条数，默认 20，上限 100"},
		}, "query"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Query   string  `json:"query"`
				KEVOnly bool    `json:"kev_only"`
				MinCVSS float64 `json:"min_cvss"`
				Since   string  `json:"since"`
				Limit   int     `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 || limit > 100 {
				limit = 20
			}
			items, total, err := s.m.PG().SearchVulnIntel(ctx, db.VulnIntelSearch{
				Query: a.Query, KEVOnly: a.KEVOnly, MinCVSS: a.MinCVSS, Since: a.Since, Limit: limit,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out := make([]map[string]any, 0, len(items))
			ids := make([]string, 0, len(items))
			for _, e := range items {
				ids = append(ids, e.CVEID)
			}
			// PoC 线索一次批量取（每 CVE 最多 2 条）：全量查询会给 planner 塞几百行，
			// 它只想知道「有没有现成 EXP」，具体仓库让它自己按 url 看。
			pocs, _ := s.m.PG().PoCByCVE(ctx, ids, 2)
			for _, e := range items {
				row := map[string]any{
					"cve_id": e.CVEID, "severity": e.Severity, "cvss": e.CVSS,
					"kev": e.KEV, "title": e.Title,
				}
				if !e.PublishedAt.IsZero() {
					row["published"] = e.PublishedAt.Format("2006-01-02")
				}
				if len(e.Refs) > 0 {
					row["refs"] = e.Refs[:min(3, len(e.Refs))]
				}
				if e.PocCount > 0 {
					row["poc_count"] = e.PocCount
					top := make([]map[string]any, 0, 2)
					for _, p := range pocs[e.CVEID] {
						top = append(top, map[string]any{"repo": p.Repo, "url": p.URL, "stars": p.Stars})
					}
					row["poc_top"] = top
				}
				out = append(out, row)
			}
			return jsonResult(map[string]any{
				"total": total, "returned": len(out), "items": out,
				"note": "候选不等于可利用：情报库无你的目标版本，必须实测确认后再 report_finding。" +
					" poc_count/poc_top 是 GitHub 公开仓库线索（别人写的 EXP），只作参考，不要直接跑陌生代码。",
			})
		})
}

func (s *Server) toolListAssetVulnHits() actool.CoreTool {
	return roTool("list_asset_vuln_hits",
		"把当前资产台账里的技术指纹（technologies）反查情报库，列出「命中我的资产」的高危/在野利用候选 CVE。\n"+
			"只读、只看 CVSS>=7 或在 KEV 的条目；version_in_range 恒为 unknown（我们没采到版本），"+
			"所以这是【排查线索】，不是漏洞结论。",
		objSchema(map[string]any{
			"limit": map[string]any{"type": "integer", "description": "返回条数，默认 50，上限 200"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Limit int `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 || limit > 200 {
				limit = 50
			}
			hits, err := s.m.PG().VulnIntelAssetHits(ctx, limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"returned": len(hits), "items": hits,
				"note": "技术指纹只到组件名，没有版本；命中只代表「这个组件有已知高危洞」，需要实测版本与利用条件。",
			})
		})
}
