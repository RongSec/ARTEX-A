package agent

// 阅读者下钻代理（V10-READER）：规划者看不到被采纳任务的整张图，只能向阅读者
// 发一次「下钻请求」，拿到脱敏后的【测试方法】。
//
// 为什么不让规划者直接 node_detail：
//   - 对方节点 payload 里带 target/evidence/asset，一行 URL 就把 host 暴露了；
//     规划者拿到 host 就可能绕过 scope 去打别人的资产。
//   - 两个任务可能同时在跑：直接读对方正在进行的意图会互相干扰，也会让规划者
//     去"等"另一个任务。
//
// 所以这里是唯一入口，口径是「只保留测试方法」：
//   - 保留：HTTP 方法 + 路径、参数名、payload 形态、工具与命令、结论/状态码、
//     组件与版本、漏洞类型与用法要点。
//   - 脱敏：URL 只留路径、IP/域名换占位符、凭据值一律 <redacted>。
//   - 不给：host、资产 id、对方 scope、对方正在跑的意图（仅终态意图可取过程）。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/redact"
	actool "github.com/Autumn-27/norma/tool"
)

// 脱敏统一走 redact 包（与 db 层暴露索引同一套规则）。
func redactTestMethod(s string) string { return redact.TestMethod(s) }

func requestsIn(s string) []string { return redact.RequestsIn(s) }

// readerDrillNode 是一个节点脱敏后的可读视图。
type readerDrillNode struct {
	ID       int64    `json:"id"`
	Kind     string   `json:"kind"`
	State    string   `json:"state,omitempty"`
	Summary  string   `json:"summary,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Vuln     string   `json:"vulnclass,omitempty"`
	Requests []string `json:"requests,omitempty"`
	Steps    []string `json:"steps,omitempty"` // intent 专用：执行过程（工具 + 摘要）
	Detail   string   `json:"method_detail,omitempty"`
}

func (t *ToolSet) askReader() actool.CoreTool {
	return t.readExpTool("ask_reader",
		"向阅读者下钻被采纳任务的细节（只回【测试方法】，不含 host/IP/凭据）。\n"+
			"什么时候用：graph_overview.reader_refs 里某个参考任务的接口/漏洞看着和当前目标同构，需要看它当时怎么测的（请求方法+路径、参数、payload 形态、工具、结论）。\n"+
			"不给 node_ids 时按 query 在对方 finding/fact 摘要里检索；给 node_ids 就按 id 取（id 来自 reader_refs.drillable，或本次返回的检索结果）。\n"+
			"边界：只能读被采纳（adopted）的任务；返回内容已脱敏，host 一律是占位符，别拿它当目标去打。",
		obj(map[string]any{
			"related_task_id": str("参考任务 id（reader_refs[].related_task_id）"),
			"node_ids": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "integer"},
				"description": "要下钻的节点 id（finding/fact/intent）。留空则按 query 检索",
			},
			"query": str("关键词：接口路径/漏洞类型/组件名，如 /api/user、越权、shiro"),
			"limit": map[string]any{"type": "integer", "description": "返回条数，默认 5，上限 10"},
		}, "related_task_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				RelatedTaskID json.RawMessage   `json:"related_task_id"`
				NodeIDs       []json.RawMessage `json:"node_ids"`
				Query         string            `json:"query"`
				Limit         int               `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			relatedID := pid(a.RelatedTaskID)
			if relatedID <= 0 {
				return actool.Errorf("related_task_id 必填（取 reader_refs[].related_task_id）"), nil
			}
			limit := a.Limit
			if limit <= 0 || limit > 10 {
				limit = 5
			}
			ids := make([]int64, 0, len(a.NodeIDs))
			for _, raw := range a.NodeIDs {
				if id := pid(raw); id > 0 {
					ids = append(ids, id)
				}
			}
			// 没给 id 就检索；检索也空时给一份可下钻索引，避免规划者反复猜。
			if len(ids) == 0 {
				q := strings.TrimSpace(a.Query)
				if q != "" {
					nodes, err := t.ts.ReaderSearchNodes(relatedID, q, limit)
					if err != nil {
						return actool.Errorf(err.Error()), nil
					}
					for _, n := range nodes {
						ids = append(ids, n.ID)
					}
					if len(ids) == 0 {
						return actool.Errorf(fmt.Sprintf("任务#%d 里没有匹配 %q 的 finding/fact；换关键词，或直接用 reader_refs.drillable 里的 id", relatedID, q)), nil
					}
				} else {
					refs, err := t.ts.ReaderRefs(8)
					if err != nil {
						return actool.Errorf(err.Error()), nil
					}
					var target *db.ReaderTaskRef
					for i := range refs {
						if refs[i].TaskID == relatedID {
							target = &refs[i]
							break
						}
					}
					if target == nil {
						return actool.Errorf(fmt.Sprintf("任务#%d 不在本任务的采纳列表里（只有 adopted 的参考任务可下钻）", relatedID)), nil
					}
					out := make([]map[string]any, 0, len(target.Nodes))
					for _, n := range target.Nodes {
						out = append(out, map[string]any{"id": n.ID, "kind": n.Kind, "summary": n.Summary})
					}
					return jsonResult(map[string]any{
						"related_task_id": relatedID,
						"drillable":       out,
						"note":            "这些是可下钻的 id。带 node_ids 再调一次拿测试方法；intent 类 id 会返回执行过程。",
					})
				}
			}
			items := make([]readerDrillNode, 0, len(ids))
			for _, id := range ids {
				n, err := t.ts.ReaderTaskNode(relatedID, id)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if n == nil {
					continue
				}
				item := readerDrillNode{ID: n.ID, Kind: n.Kind, State: n.State}
				var p map[string]any
				_ = json.Unmarshal(n.Payload, &p)
				str := func(k string) string {
					if v, ok := p[k].(string); ok {
						return v
					}
					return ""
				}
				item.Summary = redactTestMethod(str("summary"))
				switch n.Kind {
				case db.KindFinding:
					item.Severity = str("severity")
					item.Vuln = str("vulnclass")
					body := strings.Join([]string{str("detail"), str("evidence"), str("repro")}, "\n")
					item.Requests = requestsIn(body)
					item.Detail = truncateRunes(redactTestMethod(body), 900)
				case db.KindFact:
					body := strings.Join([]string{str("detail"), str("evidence")}, "\n")
					item.Requests = requestsIn(body)
					item.Detail = truncateRunes(redactTestMethod(body), 900)
				case db.KindIntent:
					steps, err := t.ts.ReaderTaskTrace(relatedID, n.ID, 30)
					if err == nil {
						for _, act := range steps {
							line := strings.TrimSpace(act.Tool)
							if act.Summary != "" {
								if line != "" {
									line += " · "
								}
								line += redactTestMethod(act.Summary)
							}
							if strings.TrimSpace(line) == "" {
								continue
							}
							if len(item.Steps) >= 12 {
								break
							}
							item.Steps = append(item.Steps, truncateRunes(line, 220))
						}
					}
				}
				items = append(items, item)
				if len(items) >= limit {
					break
				}
			}
			return jsonResult(map[string]any{
				"related_task_id": relatedID,
				"items":           items,
				"note":            "只保留测试方法：host/IP 已替换为占位符，凭据值已抹除。把这些方法套到当前任务的授权目标上，不要直接打占位符。",
			})
		})
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
