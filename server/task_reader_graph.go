package server

// 阅读者读图工具（V10-READER-2）：给阅读者一双「能读完两边整张图」的眼睛。
//
// 为什么需要它：判「两个任务是否相关」不能只看投影摘要。用户的口径是——
// 阅读者要能读双方的完整图（节点 payload、意图执行过程、情报表接口），
// 才能判断「接口重合度高 / 同一组件 / 同一利用链」，而不是靠键名相同就采纳。
//
// 边界：
//   - 只读：注册成 roTool，绑 reader（tool_base='none'，无执行类工具）。
//   - 只回给阅读者：规划者拿不到这个工具；它对规划者的暴露走 reader_refs
//     与 ask_reader（脱敏后）。
//   - 不脱敏：阅读者需要 host/版本才能判断相关性，这里给原文；脱敏发生在
//     「写给规划者」的那一侧（reader_refs / ask_reader / hint），单点收口。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// readerGraphMaxRunes 是一次读图返回正文的总预算。阅读者一轮要读两三张图，
// 单张给到 24k runes 已经能覆盖绝大多数任务的 finding/fact；超出按节点截断
// 并在返回体里标注 truncated，让模型知道「还有但没给」而不是以为读全了。
const readerGraphMaxRunes = 24000

func (s *Server) toolReadTaskGraph() actool.CoreTool {
	return roTool("read_task_graph",
		"阅读者专用：读指定任务的【完整探索图】——目标/意图/事实/发现/提示节点的正文，意图的执行过程（工具+摘要），以及该任务的情报表（接口 method+path+用途、凭据、组件、资产、漏洞）。"+
			"判相关性时必须对【发起方】与【候选】各读一次：比接口重合、组件版本、凭据复用、漏洞类型，再决定 adopt/dismiss。"+
			"与 get_task_graph_digest 的区别：digest 是给规划者看的摘要；这个是给阅读者判案用的全文（含 host，只对阅读者可见）。",
		objSchema(map[string]any{
			"task_id": strParam("任务 id"),
			"kinds": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "节点类型过滤，默认 [goal,intent,fact,finding,hint]；可选 begin/digest/all",
			},
			"limit":        map[string]any{"type": "integer", "description": "节点条数上限，默认 60，最大 150（按 id 倒序，最近的优先）"},
			"detail_chars": map[string]any{"type": "integer", "description": "单个节点正文截断长度，默认 700，最大 2000"},
			"with_trace":   map[string]any{"type": "boolean", "description": "是否附带意图的执行过程（activity：工具+摘要，最多 3 个意图 × 10 步）"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID      json.RawMessage `json:"task_id"`
				Kinds       []string        `json:"kinds"`
				Limit       int             `json:"limit"`
				DetailChars int             `json:"detail_chars"`
				WithTrace   bool            `json:"with_trace"`
			}
			_ = json.Unmarshal(in, &a)
			taskID := parseProfileID(a.TaskID)
			if taskID <= 0 {
				return actool.Errorf("task_id 必填"), nil
			}
			limit := a.Limit
			if limit <= 0 || limit > 150 {
				limit = 60
			}
			detail := a.DetailChars
			if detail <= 0 || detail > 2000 {
				detail = 700
			}
			kinds := a.Kinds
			all := len(kinds) == 1 && strings.EqualFold(strings.TrimSpace(kinds[0]), "all")
			if len(kinds) == 0 {
				kinds = []string{db.KindGoal, db.KindIntent, db.KindFact, db.KindFinding, db.KindHint}
			}
			for i := range kinds {
				kinds[i] = strings.TrimSpace(kinds[i])
			}

			var name, goal, status string
			var expID int64
			var projectID int64
			if err := s.m.pg.QueryRow(`
SELECT COALESCE(name,''), COALESCE(goal,''), COALESCE(status,''), exploration_id, COALESCE(project_id,0)
FROM tasks WHERE id=$1 AND deleted_at IS NULL`, taskID).Scan(&name, &goal, &status, &expID, &projectID); err != nil || expID <= 0 {
				return actool.Errorf(fmt.Sprintf("任务#%d 不存在或没有探索图", taskID)), nil
			}

			// 节点：默认只看「有判案价值」的五类；digest/begin 需要显式点名。
			filter := ""
			args := []any{expID}
			if !all {
				filter = " AND kind = ANY($2)"
				args = append(args, kinds)
			}
			args = append(args, limit)
			rows, err := s.m.pg.Query(`
SELECT id, kind, state, priority, payload::text
FROM exploration_nodes
WHERE exploration_id=$1`+filter+`
ORDER BY id DESC LIMIT $`+fmt.Sprint(len(args)), args...)
			if err != nil {
				return actool.Errorf("读探索图失败: " + err.Error()), nil
			}
			defer rows.Close()

			budget := readerGraphMaxRunes
			nodeOut := make([]map[string]any, 0, limit)
			intentIDs := make([]int64, 0, 3)
			truncated := false
			for rows.Next() {
				var id int64
				var kind, state, payload string
				var priority int
				if rows.Scan(&id, &kind, &state, &priority, &payload) != nil {
					continue
				}
				if budget <= 0 {
					truncated = true
					break
				}
				var p map[string]any
				_ = json.Unmarshal([]byte(payload), &p)
				str := func(keys ...string) string {
					for _, k := range keys {
						if v, ok := p[k].(string); ok && strings.TrimSpace(v) != "" {
							return v
						}
					}
					return ""
				}
				item := map[string]any{
					"id": id, "kind": kind, "state": state, "priority": priority,
					"summary": clipRunes(str("summary", "title", "text", "goal", "reason"), detail),
				}
				if sev := str("severity"); sev != "" {
					item["severity"] = sev
				}
				if vc := str("vulnclass"); vc != "" {
					item["vulnclass"] = vc
				}
				if tg := str("target", "host", "url"); tg != "" {
					item["target"] = clipRunes(tg, 200)
				}
				if body := str("detail", "evidence", "repro"); body != "" {
					item["detail"] = clipRunes(body, detail)
				}
				if kind == db.KindIntent && len(intentIDs) < 3 {
					intentIDs = append(intentIDs, id)
				}
				// 预算扣减：把本条实际字符量从总额里减掉（JSON 会再放大，按 1.6 估）。
				budget -= int(float64(len(payload)) * 1.6)
				nodeOut = append(nodeOut, item)
			}
			if err := rows.Err(); err != nil {
				return actool.Errorf("读探索图失败: " + err.Error()), nil
			}

			// 意图执行过程：判「它当时是怎么测的」最直接的证据。
			if a.WithTrace {
				for i := range nodeOut {
					if len(intentIDs) == 0 {
						break
					}
					id, _ := nodeOut[i]["id"].(int64)
					if id != intentIDs[0] {
						continue
					}
					steps := s.readerIntentSteps(id, 10)
					if len(steps) > 0 {
						nodeOut[i]["steps"] = steps
					}
					intentIDs = intentIDs[1:]
				}
			}

			// 情报表：接口是「重合度」的主证据；其余四类给 key，供阅读者比对。
			intel := s.readerIntelFull(taskID)
			// 边：判案时要能看出对方「哪条链走通了、哪条断了」。采纳时写的
			// chains（entry→steps→outcome）就是从这张边表整理出来的——只看
			// 节点列表看不出先后与产出关系。
			edges := s.readerGraphEdges(expID, 400)
			out := map[string]any{
				"task_id": taskID, "project_id": projectID,
				"name": name, "goal": clipRunes(goal, 400), "status": status,
				"nodes": nodeOut, "intel": intel, "edges": edges,
			}
			if truncated || budget <= 0 {
				out["truncated"] = true
				out["note"] = "节点较多，已按最近优先截断；可用 kinds/limit 分次读，或直接看 intel.endpoints 比对接口面。"
			}
			return jsonResult(out)
		})
}

// readerGraphEdges 读探索图的边（src/rel/dst），给阅读者判「哪条链走通了」。
// 只给 id 三元组 + 两端节点的一句话摘要：摘要让模型不用再猜 id 是什么，
// 又不会把正文重复灌一遍（正文已经在 nodes 里）。
func (s *Server) readerGraphEdges(expID int64, limit int) []map[string]any {
	if expID <= 0 {
		return nil
	}
	if limit <= 0 || limit > 800 {
		limit = 400
	}
	rows, err := s.m.pg.Query(`
SELECT e.src_id, e.rel, e.dst_id,
       COALESCE(sn.kind,''), COALESCE(sn.payload->>'summary',''),
       COALESCE(dn.kind,''), COALESCE(dn.payload->>'summary','')
FROM exploration_edges e
LEFT JOIN exploration_nodes sn ON sn.id = e.src_id
LEFT JOIN exploration_nodes dn ON dn.id = e.dst_id
WHERE e.exploration_id=$1
ORDER BY e.src_id, e.dst_id LIMIT $2`, expID, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var src, dst int64
		var rel, srcKind, srcSum, dstKind, dstSum string
		if rows.Scan(&src, &rel, &dst, &srcKind, &srcSum, &dstKind, &dstSum) != nil {
			continue
		}
		out = append(out, map[string]any{
			"from": src, "rel": rel, "to": dst,
			"from_kind": srcKind, "from_summary": clipRunes(srcSum, 80),
			"to_kind": dstKind, "to_summary": clipRunes(dstSum, 80),
		})
	}
	return out
}

// readerIntentSteps 读一个意图的 activity（工具 + 摘要），过滤思考/用量行。
func (s *Server) readerIntentSteps(intentID int64, limit int) []string {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.m.pg.Query(`
SELECT COALESCE(tool,''), COALESCE(summary,'')
FROM activity
WHERE node_id=$1 AND COALESCE(kind,'') NOT IN ('thinking','usage')
ORDER BY id ASC LIMIT $2`, intentID, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var tool, summary string
		if rows.Scan(&tool, &summary) != nil {
			continue
		}
		line := strings.TrimSpace(tool)
		if summary != "" {
			if line != "" {
				line += " · "
			}
			line += summary
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, clipRunes(line, 200))
	}
	return out
}

// readerIntelFull 把情报表按类展开：接口单独给 method/path/purpose/status，
// 其余类给原始 key（组件 product@ver、资产 host:port、漏洞 title|asset）。
func (s *Server) readerIntelFull(taskID int64) map[string]any {
	out := map[string]any{"counts": map[string]int{}}
	rows, err := s.m.pg.Query(`
SELECT kind, key, COALESCE(detail::text,'{}')
FROM task_intel WHERE task_id=$1 ORDER BY kind, key LIMIT 200`, taskID)
	if err != nil {
		return out
	}
	defer rows.Close()
	counts := map[string]int{}
	endpoints := []map[string]any{}
	other := map[string][]string{}
	for rows.Next() {
		var kind, key, detail string
		if rows.Scan(&kind, &key, &detail) != nil {
			continue
		}
		counts[kind]++
		if kind == db.IntelKindEndpoint {
			m, p := splitEndpointKey(key)
			ep := map[string]any{"method": strings.ToUpper(m), "path": p}
			var d struct {
				Purpose     string `json:"purpose"`
				StatusCodes []int  `json:"status_codes"`
			}
			_ = json.Unmarshal([]byte(detail), &d)
			if d.Purpose != "" {
				ep["purpose"] = clipRunes(d.Purpose, 60)
			}
			if len(d.StatusCodes) > 0 {
				ep["status"] = d.StatusCodes
			}
			if len(endpoints) < 80 {
				endpoints = append(endpoints, ep)
			}
			continue
		}
		if len(other[kind]) < 40 {
			other[kind] = append(other[kind], clipRunes(key, 120))
		}
	}
	out["counts"] = counts
	out["endpoints"] = endpoints
	for k, v := range other {
		out[k] = v
	}
	return out
}
