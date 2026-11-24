package server

// 给 agent 用的漏洞情报工具（V2 组件倒排结构）。
//
// 四件只读工具：
//   search_vulns           按组件（vendor/product）+ 目标版本查已知漏洞，返回三态版本判定
//   get_vuln               单条详情：完整描述、CVSS 向量、结构化版本区间、参考链接
//   get_poc                该 CVE 的公开 PoC 仓库（只给链接，不下载不执行）
//   list_asset_vuln_hits   资产台账技术指纹反查情报库（命中我的资产）
//
// 语义红线：命中不等于可利用。search_vulns 的 version_in_range 才是「该打」的
// 硬信号；字段缺失（无结构化区间）必须由 worker 用实际请求验证后才能 report_finding。

import (
	"context"
	"encoding/json"

	actool "github.com/Autumn-27/norma/tool"
)

func (s *Server) intelTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolSearchVulns(),
		s.toolGetVuln(),
		s.toolGetPoc(),
		s.toolListAssetVulnHits(),
	}
}

func (s *Server) toolSearchVulns() actool.CoreTool {
	return roTool("search_vulns",
		"按组件名检索【公开已知漏洞】库（NVD + GitHub Advisory + CISA KEV 在野利用清单）。\n"+
			"识别出目标组件（Web 中间件/框架/服务/固件等）后先查这里：有 KEV 标记=已在野利用、优先考虑。\n"+
			"给 version 参数可做版本判定：\n"+
			"  - version_in_range=true → 目标版本落在受影响区间内（该打）\n"+
			"  - version_in_range=false → 不在区间（通常不用打）\n"+
			"  - 字段缺失 → 无结构化区间，需用 get_vuln 看 cpe_criteria 自行判断\n"+
			"**false 不等于绝对安全**：部分库的区间填错或缺失，拿不准时用 get_vuln 复核。\n"+
			"source 字段标明来自 nvd 还是 ghsa：GHSA 的版本区间必填（可信度更高），NVD 对新披露 CVE 常留空。\n"+
			"product 用 CPE 命名（http_server / nginx / tomcat），不是自然语言；命中为空时换常见写法再试。",
		objSchema(map[string]any{
			"product": strParam("组件名（CPE product 段），如 http_server / nginx / thinkphp / tomcat / weblogic；支持 % 通配"),
			"vendor":  strParam("厂商名过滤（可选），如 apache / oracle，用于区分同名组件"),
			"version": strParam("目标版本号（可选），如 2.4.49；给了才做区间判定"),
			"limit":   map[string]any{"type": "integer", "description": "返回条数上限（默认 20，最大 50）"},
		}, "product"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.vuln == nil {
				return actool.Errorf("search_vulns 未启用: 漏洞情报库未初始化"), nil
			}
			var a struct {
				Product string `json:"product"`
				Vendor  string `json:"vendor"`
				Version string `json:"version"`
				Limit   int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			hits, err := s.vuln.store.SearchVulns(ctx, a.Vendor, a.Product, a.Version, a.Limit)
			if err != nil {
				return actool.Errorf("检索漏洞失败: " + err.Error()), nil
			}
			if len(hits) == 0 {
				return jsonResult(map[string]any{
					"count": 0,
					"note": "该组件名在情报库无命中：可能拼写与 CPE 命名不符（试 http_server / httpd / IIS / tomcat），" +
						"或该组件近期无已知漏洞。",
				})
			}
			kev := 0
			for _, h := range hits {
				if h.KEV {
					kev++
				}
			}
			return jsonResult(map[string]any{
				"count":           len(hits),
				"kev_count":       kev,
				"vulnerabilities": hits,
				"note": "kev=true 表示 CISA 已确认在野利用，价值最高；下一步用 get_vuln 看影响区间、" +
					"get_poc 找现成利用，再决定是否值得派意图验证。",
			})
		})
}

func (s *Server) toolGetVuln() actool.CoreTool {
	return roTool("get_vuln",
		"取一条 CVE 的完整详情：描述、CVSS 向量、**结构化受影响版本区间**、参考链接、CWE。\n"+
			"search_vulns 的 version_in_range 缺失或你怀疑区间不对时用它复核；"+
			"version_ranges 里 source=nvd/ghsa 标明区间来自哪个源（两源可能不一致）。",
		objSchema(map[string]any{
			"cve_id": strParam("CVE 编号，如 CVE-2021-41773"),
		}, "cve_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.vuln == nil {
				return actool.Errorf("get_vuln 未启用: 漏洞情报库未初始化"), nil
			}
			var a struct {
				CVEID string `json:"cve_id"`
			}
			_ = json.Unmarshal(in, &a)
			d, err := s.vuln.store.GetVuln(ctx, a.CVEID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if d == nil {
				return jsonResult(map[string]any{"found": false, "note": "库里没有这条 CVE（可能尚未同步）"})
			}
			return jsonResult(d)
		})
}

func (s *Server) toolGetPoc() actool.CoreTool {
	return roTool("get_poc",
		"查该 CVE 的公开 PoC / Exploit 线索（GitHub 仓库元数据，按 star 排序）。\n"+
			"返回的是链接与说明，**不下载、不执行代码**。先 search_vulns 确认漏洞成立，再取弹药。\n"+
			"注意：陌生仓库的代码不要直接跑；优先用 nuclei 模板做无损验证。",
		objSchema(map[string]any{
			"cve_id": strParam("CVE 编号，如 CVE-2021-41773"),
		}, "cve_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.vuln == nil {
				return actool.Errorf("get_poc 未启用: 漏洞情报库未初始化"), nil
			}
			var a struct {
				CVEID string `json:"cve_id"`
			}
			_ = json.Unmarshal(in, &a)
			items, err := s.vuln.store.GetPoCs(ctx, a.CVEID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"cve_id": a.CVEID,
				"count":  len(items),
				"items":  items,
				"note":   "只作参考线索，不代表可利用；不要直接执行陌生 PoC。",
			})
		})
}

func (s *Server) toolListAssetVulnHits() actool.CoreTool {
	return roTool("list_asset_vuln_hits",
		"把当前资产台账的技术指纹（technologies）反查情报库，列出「命中我的资产」的候选 CVE。\n"+
			"默认只看 CVSS>=7 或在 KEV 的条目。技术指纹只有组件名、版本不保证可靠，"+
			"所以这是【排查线索】，不是漏洞结论——必须实测确认。",
		objSchema(map[string]any{
			"limit":    map[string]any{"type": "integer", "description": "返回条数，默认 50，上限 200"},
			"min_cvss": map[string]any{"type": "number", "description": "CVSS 下限，默认 7"},
			"kev_only": map[string]any{"type": "boolean", "description": "只看 CISA KEV"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.vuln == nil {
				return actool.Errorf("list_asset_vuln_hits 未启用: 漏洞情报库未初始化"), nil
			}
			var a struct {
				Limit   int     `json:"limit"`
				MinCVSS float64 `json:"min_cvss"`
				KEVOnly bool    `json:"kev_only"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 || limit > 200 {
				limit = 50
			}
			minScore := a.MinCVSS
			if minScore <= 0 {
				minScore = 7
			}
			hits, err := s.vuln.store.AssetHits(ctx, minScore, a.KEVOnly, limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"returned": len(hits),
				"items":    hits,
				"note":     "命中只代表「这个组件有已知高危洞」，版本与利用条件必须在授权目标上实测。",
			})
		})
}
