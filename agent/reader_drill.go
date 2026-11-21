package agent

// 阅读者下钻代理（V10-READER）：规划者看不到被采纳任务的整张图，只能向阅读者
// 发一次「下钻请求」，拿到阅读者总结后的【测试方法】。
//
// 为什么不让规划者直接 node_detail：
//   - 对方节点 payload 里带 target/evidence/asset，一行 URL 就把 host 暴露了；
//     规划者拿到 host 就可能绕过 scope 去打别人的资产。
//   - 两个任务可能同时在跑：直接读对方正在进行的意图会互相干扰，也会让规划者
//     去"等"另一个任务。
//
// 流程（用户口径）：
//   1. 服务端按 id 取节点、抽请求行、做确定性脱敏 —— 这一步只是「取证」；
//   2. 阅读者（LLM）看这批证据，总结成接口测试方法论（怎么测、验什么、判据）；
//   3. 规划者拿到方法论 + 少量证据索引，不是对方的原始图。
// 第 2 步由 ToolSet.readerAnswer 注入（server 用任务 LLM 链实现）；未注入时
// 退回第 1 步的脱敏证据并明确标注「未总结」，绝不假装有方法论。

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/redact"
	actool "github.com/Autumn-27/norma/tool"
)

// reReaderHostRef 挡住 worker 在 query 里夹带 host/IP/URL：worker 只允许按路径、
// 参数名或漏洞类型下钻，地址一律由本任务的授权资产决定，不能从参考任务“借”。
var reReaderHostRef = regexp.MustCompile(`(?i)https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[a-z0-9][a-z0-9\-]*\.(?:com|cn|net|org|io|co|cc|top|xyz|info|biz|edu|gov|mil|local|lan|corp|internal|intra|test|dev|cloud|site|online)\b`)

// readerTwoPartContract 是 worker 下钻后的硬要求（V11-READER4，用户口径）：
// 只复现对方的结论不算完成——那正是「下钻完只做简单复现就回报」的退化形态。
// 每次下钻都要在本任务资产上补一条自己设计的验证，用来发现借鉴经验没覆盖的
// 部分（或证伪它）。
const readerTwoPartContract = "两段都要做：① 借鉴复现——按 items 里的请求形态在本任务资产上重放，拿到与对方一致的基线；② 自主验证——至少一条本任务独立设计的验证（变体参数/负控/低权账号/兄弟实例/边界遍历）。只复现对方结论就回报 = 未完成意图；fact/finding 的 evidence 必须分「借鉴复现」「自主验证」两节，写清各自请求与结果。"

// readerCredentialNote 是 worker 下钻时凭据的定性（用户口径）：凭据不隐藏，
// 因为密码复用本身就是一条要测的攻击路径；但它是参考任务环境里的原值，可能
// 过期/不通用，只能当低置信假设，不能直接写进本任务报告。
const readerCredentialNote = "items 里的凭据（口令/token/Cookie）是参考任务环境中的原值，**仅作低置信参考**：可能已过期、可能只在那台机器有效。只用于在本任务目标上试密码复用/默认口令；本任务资产上验证成功后才算数，不要当成本任务已确认的凭据写进 finding。"

// readerRefIDs 把已采纳参考任务转成「#134、#136」这样的短清单，
// 用于 ask_reader 的报错信息（执行者据此改 related_task_id，不用再试错）。
func readerRefIDs(refs []db.ReaderTaskRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, "#"+strconv.FormatInt(r.TaskID, 10))
	}
	return out
}

// 脱敏统一走 redact 包（与 db 层暴露索引同一套规则）。
func redactTestMethod(s string) string { return redact.TestMethod(s) }

func requestsIn(s string) []string { return redact.RequestsIn(s) }

// ReaderDrillNode 是一个节点脱敏后的可读视图（导出：server 侧要把它喂给模型）。
type ReaderDrillNode struct {
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

// ReaderDrillRequest 是「交给阅读者总结」的输入：一次下钻取到的全部证据。
type ReaderDrillRequest struct {
	RelatedTaskID int64             `json:"related_task_id"`
	Query         string            `json:"query,omitempty"`
	Items         []ReaderDrillNode `json:"items"`
	// Audience 区分调用方：planner=要方法论（规划用），worker=要可执行的测试细节
	// （执行用）。阅读者的总结口径不同，但两者都只给脱敏后的“怎么测”。
	Audience string `json:"audience,omitempty"`
	// CurrentGoal/CurrentIntent 让阅读者知道“当前任务在测什么”，从而裁剪经验，
	// 而不是把参考任务的所有细节平铺。worker 传入自己领到的意图。
	CurrentGoal   string `json:"current_goal,omitempty"`
	CurrentIntent string `json:"current_intent,omitempty"`
}

// recordReaderDrill 落一条审计记录（V11）。审计是旁路：上下文已取消/库写失败
// 都不能让下钻本身失败——用户看到的是「这次下钻拿了什么」，不是「记录成功没」。
func (t *ToolSet) recordReaderDrill(ctx context.Context, relatedID int64, ids []int64, query, mode string, items int) {
	if t == nil || t.ts == nil || t.taskID <= 0 {
		return
	}
	modeName := "planner"
	if t.readerDetailMode {
		modeName = "detail"
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	_ = t.ts.RecordReaderDrill(rctx, db.ReaderDrill{
		TaskID: t.taskID, RelatedTaskID: relatedID, IntentID: t.readerIntentID,
		NodeIDs: ids, Query: query, Mode: modeName, ItemCount: items,
	})
}

func (t *ToolSet) askReader() actool.CoreTool {
	desc := "向阅读者下钻被采纳任务的细节，拿回【接口测试方法论】（不含 host/IP/凭据）。\n" +
		"什么时候用：graph_overview.reader_refs 里某个参考任务的接口/漏洞看着和当前目标同构，需要知道它当时怎么测的、验什么、判据是什么。\n" +
		"不给 node_ids 时按 query 在对方 finding/fact/intent 摘要与执行步骤里检索；给 node_ids 就按 id 取（id 来自 reader_refs.drillable/intents，或本次返回的检索结果）。\n" +
		"返回的 methodology 是阅读者读完证据后的总结；evidence 只是脱敏后的证据索引。方法论要套到当前任务的授权目标上验证，别照抄对方的目标。"
	if t.readerDetailMode {
		desc = "向阅读者下钻被采纳任务的【脱敏测试细节/步骤】（不含 host/IP/域名/凭据）。\n" +
			"什么时候用：本条意图要测的接口/组件在 graph_overview.reader_refs 里出现过，需要知道参考任务当时发了什么请求、用了什么参数/payload、怎么判断命中。\n" +
			"node_ids 取自 reader_refs.drillable/intents；留空则按 query 检索 finding/fact/intent 摘要与 intent 执行步骤。\n" +
			"query 只写路径、参数名、漏洞类型或组件名（如 /api/user、越权、shiro）；**不要写 URL、host、IP、域名**，写了会被拒绝。\n" +
			"返回的 items 是逐条脱敏后的证据（请求行/步骤/说明），并带 required_next：**下钻不是让你照抄一遍**——必须①在本任务资产上复现基线，②再做至少一条本任务独立设计的验证（变体参数/负控/兄弟实例/边界遍历），两段都写进 fact/finding。只复现=未完成意图。不要直接打参考任务的地址。"
	}
	return t.readExpTool("ask_reader", desc,
		obj(map[string]any{
			"related_task_id": str("参考任务 id（reader_refs[].related_task_id）"),
			"node_ids": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "integer"},
				"description": "要下钻的节点 id（finding/fact/intent）。留空则按 query 检索",
			},
			"query": str("关键词：接口路径/漏洞类型/组件名，如 /api/user、越权、shiro；worker 禁止写 host/IP/URL"),
			"limit": map[string]any{"type": "integer", "description": "返回条数，默认 5（worker 默认 8），上限 10"},
		}, "related_task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
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
			if t.readerDetailMode {
				if t.readerCallLimit > 0 && t.readerCalls >= t.readerCallLimit {
					return actool.Errorf(fmt.Sprintf("本意图的 ask_reader 调用已达上限（%d 次）：用已拿到的细节继续测，或把缺口写进 fact 交规划者", t.readerCallLimit)), nil
				}
				if q := strings.TrimSpace(a.Query); q != "" && reReaderHostRef.MatchString(q) {
					return actool.Errorf(fmt.Sprintf("query 只允许路径/参数名/漏洞类型，不能包含 URL、host 或 IP：%q。请改成 /api/... 这类路径再试", q)), nil
				}
				t.readerCalls++
			}
			limit := a.Limit
			if limit <= 0 {
				if t.readerDetailMode {
					limit = 8
				} else {
					limit = 5
				}
			}
			if limit > 10 {
				limit = 10
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
					// 多词查询按空白拆词、逐个检索去重：中文短语（"登录 user_token 会话"）
					// 整串 LIKE 基本不可能命中，实测第一次调用就踩了这个坑。
					seen := map[int64]bool{}
					for _, term := range strings.Fields(q) {
						if len([]rune(term)) < 2 {
							continue
						}
						nodes, err := t.ts.ReaderSearchNodes(relatedID, term, limit)
						if err != nil {
							return actool.Errorf(err.Error()), nil
						}
						for _, n := range nodes {
							if !seen[n.ID] {
								seen[n.ID] = true
								ids = append(ids, n.ID)
							}
							if len(ids) >= limit {
								break
							}
						}
						if len(ids) >= limit {
							break
						}
					}
				}
				if len(ids) == 0 {
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
						// 下钻前不知道「本任务到底采纳了谁」会让执行者反复试错
						// （实测 3 次调用全打在不同任务上、全被拒）。错误里直接
						// 给已采纳清单，下一次就能命中。
						msg := fmt.Sprintf("任务#%d 不在本任务的采纳列表里（只有 adopted 的参考任务可下钻）", relatedID)
						if ids := readerRefIDs(refs); len(ids) > 0 {
							msg += "；当前已采纳：" + strings.Join(ids, "、") + "。只能从这些任务里选 related_task_id"
						}
						// candidate ≠ 永久拒绝：阅读者还在读图，adopt 完成后同一调用
						// 立刻可用（adopt 会唤醒规划者并 steer 正在跑的 worker）。
						if d, derr := t.ts.ReaderLinkDecision(relatedID); derr == nil && d == "candidate" {
							msg += "；该任务是候选（candidate），阅读者尚未判完——adopt 后立刻可用，届时你会收到规划者注入的指令，稍后重试即可"
						}
						return actool.Errorf(msg), nil
					}
					// 检索为空也走这里：给可下钻索引（id+摘要），不要只回一句「没命中」
					// ——规划者拿不到索引就只能放弃或瞎猜。
					out := make([]map[string]any, 0, len(target.Nodes))
					for _, n := range target.Nodes {
						out = append(out, map[string]any{"id": n.ID, "kind": n.Kind, "summary": n.Summary})
					}
					t.recordReaderDrill(ctx, relatedID, nil, strings.TrimSpace(a.Query), "index", 0)
					return jsonResult(map[string]any{
						"related_task_id": relatedID,
						"drillable":       out,
						"intents":         target.Intents,
						"note":            "这些是可下钻的 id。带 node_ids 再调一次拿测试方法论；intent 类 id 会返回执行过程。",
					})
				}
			}
			items := make([]ReaderDrillNode, 0, len(ids))
			for _, id := range ids {
				n, err := t.ts.ReaderTaskNode(relatedID, id)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if n == nil {
					continue
				}
				item := ReaderDrillNode{ID: n.ID, Kind: n.Kind, State: n.State}
				var p map[string]any
				_ = json.Unmarshal(n.Payload, &p)
				str := func(k string) string {
					if v, ok := p[k].(string); ok {
						return v
					}
					return ""
				}
				// worker 要拿凭据试密码复用 → 保留凭据值；planner 只要方法论 → 抹掉。
				// host/IP 两者都脱敏（参考任务的资产不在本任务授权范围）。
				redactBody := redactTestMethod
				if t.readerDetailMode {
					redactBody = redact.TestMethodKeepSecrets
				}
				item.Summary = redactBody(str("summary"))
				detailCap := 1200
				if t.readerDetailMode {
					detailCap = 2200
				}
				switch n.Kind {
				case db.KindFinding:
					item.Severity = str("severity")
					item.Vuln = str("vulnclass")
					body := strings.Join([]string{str("detail"), str("evidence"), str("repro")}, "\n")
					item.Requests = requestsIn(body)
					item.Detail = truncateRunes(redactBody(body), detailCap)
				case db.KindFact:
					body := strings.Join([]string{str("detail"), str("evidence")}, "\n")
					item.Requests = requestsIn(body)
					item.Detail = truncateRunes(redactBody(body), detailCap)
				case db.KindIntent:
					item.Steps = t.readerIntentSteps(relatedID, n.ID, 12, 220)
				}
				items = append(items, item)
				if len(items) >= limit {
					break
				}
			}

			// worker 模式：核心交付是「脱敏后的细节」，不是方法论。细节不足时
			// 才把参考任务最近意图的执行步骤补进来，再请阅读者补一段经验总结。
			if t.readerDetailMode {
				if !hasConcreteReaderEvidence(items) && t.readerAnswer != nil {
					items = t.readerWidenEvidence(relatedID, items, 3)
				}
				out := map[string]any{
					"related_task_id": relatedID,
					"mode":            "detail",
					"items":           items,
					"required_next":   readerTwoPartContract,
					"credential_note": readerCredentialNote,
					"note":            "items 是参考任务里的测试细节（请求行/步骤/说明）：host/IP 已换成占位符；凭据按原值给出，只作低置信参考。套到本意图的授权资产上验证，不要直接打占位符。",
				}
				if t.readerAnswer != nil && len(items) > 0 && !hasConcreteReaderEvidence(items) {
					exp, err := t.readerAnswer(ctx, ReaderDrillRequest{
						RelatedTaskID: relatedID, Query: strings.TrimSpace(a.Query), Items: items,
						Audience: "worker", CurrentGoal: t.readerGoal, CurrentIntent: t.readerIntent,
					})
					if err != nil {
						out["reader_error"] = err.Error()
					} else if strings.TrimSpace(exp) != "" {
						out["experience"] = exp
					}
				}
				t.recordReaderDrill(ctx, relatedID, ids, strings.TrimSpace(a.Query), "detail", len(items))
				return jsonResult(out)
			}

			// 规划者模式：阅读者总结：把「证据」变成「怎么测」。未注入（测试/无 LLM）时如实退回证据。
			if t.readerAnswer != nil && len(items) > 0 {
				method, err := t.readerAnswer(ctx, ReaderDrillRequest{
					RelatedTaskID: relatedID, Query: strings.TrimSpace(a.Query), Items: items,
					Audience: "planner", CurrentGoal: t.readerGoal, CurrentIntent: t.readerIntent,
				})
				if err != nil {
					t.recordReaderDrill(ctx, relatedID, ids, strings.TrimSpace(a.Query), "planner", len(items))
					return jsonResult(map[string]any{
						"related_task_id": relatedID,
						"items":           items,
						"note":            "阅读者总结失败（" + err.Error() + "）：以下为脱敏后的原始证据，自行归纳；host/IP 仍是占位符。",
					})
				}
				// 证据只留索引：正文已经进了方法论，重复给会白占规划者上下文。
				evidence := make([]map[string]any, 0, len(items))
				for _, it := range items {
					e := map[string]any{"id": it.ID, "kind": it.Kind, "summary": it.Summary}
					if len(it.Requests) > 0 {
						e["requests"] = it.Requests
					}
					if it.Vuln != "" {
						e["vulnclass"] = it.Vuln
					}
					evidence = append(evidence, e)
				}
				t.recordReaderDrill(ctx, relatedID, ids, strings.TrimSpace(a.Query), "planner", len(items))
				return jsonResult(map[string]any{
					"related_task_id": relatedID,
					"methodology":     method,
					"evidence":        evidence,
					"note":            "methodology 是阅读者读完对方证据后总结的测试方法（已脱敏）。套到当前任务的授权目标上验证；evidence 只是出处索引。",
				})
			}
			t.recordReaderDrill(ctx, relatedID, ids, strings.TrimSpace(a.Query), "planner", len(items))
			return jsonResult(map[string]any{
				"related_task_id": relatedID,
				"items":           items,
				"note":            "只保留测试方法：host/IP 已替换为占位符，凭据值已抹除。把这些方法套到当前任务的授权目标上，不要直接打占位符。",
			})
		})
}

// readerIntentSteps 把一个意图的 activity 压成「工具 · 脱敏摘要」的短行。
// worker 下钻时它就是「参考任务当时怎么打的」最直接的证据。
func (t *ToolSet) readerIntentSteps(relatedID, intentID int64, maxSteps, maxRunes int) []string {
	steps, err := t.ts.ReaderTaskTrace(relatedID, intentID, maxSteps*3)
	if err != nil {
		return nil
	}
	out := make([]string, 0, maxSteps)
	// worker 要看到「当时用的口令/token」才能试复用；planner 只要方法，抹掉。
	redactStep := redactTestMethod
	if t.readerDetailMode {
		redactStep = redact.TestMethodKeepSecrets
	}
	for _, act := range steps {
		line := strings.TrimSpace(act.Tool)
		if act.Summary != "" {
			if line != "" {
				line += " · "
			}
			line += redactStep(act.Summary)
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, truncateRunes(line, maxRunes))
		if len(out) >= maxSteps {
			break
		}
	}
	return out
}

// hasConcreteReaderEvidence 判断这批证据是否已经能让执行者直接构造请求：
// 有请求行、有执行步骤，或有正文说明，都算「够用」；只有摘要才算不足。
func hasConcreteReaderEvidence(items []ReaderDrillNode) bool {
	for _, it := range items {
		if len(it.Requests) > 0 || len(it.Steps) > 0 || strings.TrimSpace(it.Detail) != "" {
			return true
		}
	}
	return false
}

// readerWidenEvidence 在按 id 取到的证据不足时，补参考任务最近结束意图的执行步骤。
// 这是「阅读者去 B 的上下文里找经验」的确定性版本：不猜、不读 host，只把已脱敏的
// 步骤补进来；补完仍不足才走 LLM 总结。
func (t *ToolSet) readerWidenEvidence(relatedID int64, items []ReaderDrillNode, max int) []ReaderDrillNode {
	if max <= 0 {
		return items
	}
	seen := map[int64]bool{}
	for _, it := range items {
		seen[it.ID] = true
	}
	intents, err := t.ts.ReaderTaskLastIntents(relatedID, 8)
	if err != nil {
		return items
	}
	added := 0
	for _, in := range intents {
		if seen[in.ID] {
			continue
		}
		steps := t.readerIntentSteps(relatedID, in.ID, 12, 220)
		if len(steps) == 0 {
			continue
		}
		items = append(items, ReaderDrillNode{
			ID: in.ID, Kind: db.KindIntent, State: in.State, Summary: in.Summary, Steps: steps,
		})
		seen[in.ID] = true
		added++
		if added >= max {
			break
		}
	}
	return items
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
