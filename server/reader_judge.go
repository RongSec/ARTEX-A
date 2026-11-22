package server

// V11-READER7：每个候选一个独立上下文的判官。
//
// 背景（用户口径）：阅读者一轮里顺序读 N 个候选，把【发起方图】重复读 N 次，
// 且前一个候选的整张图会留在上下文里——但那些内容对后一个候选的判断没有帮助。
// 实测任务 #140 的阅读者会话 8 次调用、上下文从 6.6k 涨到 29.3k、累计 13.7 万
// 输入 token，墙上时间 113 秒。
//
// 这里把「读图」从 agent 会话里拿出来：judge_related_tasks 对每个候选各跑一次
// 独立 LLM 调用（上下文 = 发起方摘要 + 该候选摘要），并发 3，判完即弃。阅读者
// 主会话只拿到 N 条简短判定结果，不再累积图。adopt/dismiss 仍由阅读者调用，
// 审计口径（decided_by=reader、llm_records.worker=reader）不变。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/artex/redact"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

// readerJudgeConcurrency 是单次 judge_related_tasks 的并发判定数。
// 3 是「不把本地模型打满」与「N=6 时两轮判完」的折中。
const readerJudgeConcurrency = 3

// readerJudgePrompt 是判官的系统提示。它只判「测法能不能迁移」，不写洞察、
// 不做总结——那些是阅读者主会话的职责。
const readerJudgePrompt = `你是渗透测试平台的【阅读者·判官】。输入是同一项目内两个任务图的摘要：发起方任务 A（正在测）与参考任务 B（历史任务）。
只做一件事：判断 B 里已验证的测试方法能否迁移到 A 的目标上，并给出 0-100 的相关性评分。

评分口径：
- ≥60：同一利用链（B 前一步的产出正好是 A 后一步的输入），或 ≥2 条接口 method+path 同构且测法可迁移，或同一已验证组件/凭据可直接复用；
- 40-59：同一攻击面、只有部分可迁移（例如接口相同但认证体系不同）；
- <40：只是键相同、或仅组件同名。

输出要求：
1. 只输出一个 JSON 对象，不要 markdown 代码块，不要解释文字。
2. 字段：
   {"score": 0-100,
    "reason": "在两边读到了什么（点名重合接口/组件/利用链），不能只写键相同",
    "overlap": ["GET /api/x", "POST /api/y"],
    "chains": [{"entry":"GET /api/x","steps":["..."],"outcome":"...","verified":true,"node_ids":[123]}]}
3. overlap 只写 method+path，不写 host/IP/端口；chains 最多 4 条，node_ids 只填摘要里真实出现过的节点 id。
4. 证据不足以下结论时给低分（<40），并在 reason 里写「缺少什么证据」，不要猜。`

// readerJudgeVerdict 是单个候选的判定结果。
type readerJudgeVerdict struct {
	CandidateTaskID int64            `json:"candidate_task_id"`
	CandidateName   string           `json:"candidate_name,omitempty"`
	Score           int              `json:"score"`
	Reason          string           `json:"reason"`
	Overlap         []string         `json:"overlap,omitempty"`
	Chains          []db.ReaderChain `json:"chains,omitempty"`
	Error           string           `json:"error,omitempty"`
}

// readerJudgeOutput 是判官模型的 JSON 输出。
type readerJudgeOutput struct {
	Score   int              `json:"score"`
	Reason  string           `json:"reason"`
	Overlap []string         `json:"overlap"`
	Chains  []db.ReaderChain `json:"chains"`
}

// readerTaskDigest 把一张任务图压成判官能读的紧凑文本（目标 + 节点 + 边 + 情报）。
// 与 get_task_graph_digest 的区别：面向「一次性判官」而不是「可继续下钻的 agent」，
// 所以不带 id 跳转说明、不带工具指引，只留判相关性需要的语义。
func (s *Server) readerTaskDigest(ctx context.Context, taskID int64, maxNodes int) string {
	pg := s.m.pg
	if pg == nil || taskID <= 0 {
		return ""
	}
	if maxNodes <= 0 || maxNodes > 60 {
		maxNodes = 36
	}
	t, err := pg.GetTask(taskID)
	if err != nil || t == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "任务#%d「%s」状态=%s\n目标：%s\n", t.ID, strings.TrimSpace(t.Name), t.Status, clipText(t.Goal, 300))
	if d := strings.TrimSpace(t.Description); d != "" {
		fmt.Fprintf(&b, "描述：%s\n", clipText(d, 200))
	}

	// 节点：goal/finding/fact/intent 优先（判相关性靠结论与测法），其余按 id 补足。
	rows, qerr := pg.QueryContext(ctx, `
SELECT id, kind, COALESCE(state,''), COALESCE(payload->>'summary', payload->>'text', '')
FROM exploration_nodes WHERE exploration_id=$1
ORDER BY CASE kind WHEN 'goal' THEN 0 WHEN 'finding' THEN 1 WHEN 'fact' THEN 2 WHEN 'intent' THEN 3 WHEN 'hint' THEN 4 ELSE 5 END, id
LIMIT $2`, t.ExplorationID, maxNodes)
	if qerr == nil {
		defer rows.Close()
		b.WriteString("节点：\n")
		for rows.Next() {
			var id int64
			var kind, state, body string
			if err := rows.Scan(&id, &kind, &state, &body); err != nil {
				continue
			}
			fmt.Fprintf(&b, "- [%s#%d%s] %s\n", kind, id, stateSuffix(state), clipText(body, 180))
		}
	}

	edges, eerr := pg.QueryContext(ctx, `
SELECT e.src_id, e.rel, e.dst_id FROM exploration_edges e
WHERE e.exploration_id=$1 ORDER BY e.created_at, e.src_id LIMIT 60`, t.ExplorationID)
	if eerr == nil {
		defer edges.Close()
		lines := make([]string, 0, 24)
		for edges.Next() {
			var src, dst int64
			var rel string
			if err := edges.Scan(&src, &rel, &dst); err != nil {
				continue
			}
			lines = append(lines, fmt.Sprintf("- %d -%s-> %d", src, rel, dst))
		}
		if len(lines) > 0 {
			b.WriteString("边：\n")
			b.WriteString(strings.Join(lines, "\n"))
			b.WriteString("\n")
		}
	}

	if intels, ierr := pg.TaskIntelForTask(ctx, taskID); ierr == nil && len(intels) > 0 {
		b.WriteString("情报：\n")
		n := 0
		for _, it := range intels {
			if n >= 30 {
				break
			}
			if it.Kind == db.IntelKindAsset {
				continue // 资产只作定位，判相关性用接口/凭据/组件/漏洞
			}
			fmt.Fprintf(&b, "- %s %s %s\n", it.Kind, it.Key, clipText(intelDetailText(it), 120))
			n++
		}
	}
	// 判官只需要语义，不需要 host/凭据明文。
	return redact.TestMethod(b.String())
}

// stateSuffix 让节点状态进摘要但保持紧凑（unresolved 之类不必显示）。
func stateSuffix(state string) string {
	switch state {
	case "", "open", "done", "resolved":
		return ""
	}
	return "/" + state
}

// intelDetailText 从情报表 detail 里取一句人类可读的补充（purpose/title 等）。
func intelDetailText(it db.TaskIntel) string {
	if len(it.Detail) == 0 {
		return strings.TrimSpace(it.Value)
	}
	var d map[string]any
	if err := json.Unmarshal(it.Detail, &d); err != nil {
		return strings.TrimSpace(it.Value)
	}
	for _, k := range []string{"purpose", "title", "evidence", "note"} {
		if v, ok := d[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return strings.TrimSpace(it.Value)
}

// clipText 按 rune 截断并压掉换行（摘要必须单行，否则判官上下文会膨胀）。
func clipText(s string, max int) string {
	s = strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// judgeCandidateIsolated 对单个候选做一次独立 LLM 判定。
// 每次调用只带「发起方摘要 + 该候选摘要」，与其它候选完全隔离。
func (s *Server) judgeCandidateIsolated(ctx context.Context, taskID, candID int64) readerJudgeVerdict {
	out := readerJudgeVerdict{CandidateTaskID: candID}
	rt := &taskLLMRuntime{s: s, taskID: strconv.FormatInt(taskID, 10), agentKey: "reader"}
	a := s.readerTaskDigest(ctx, taskID, 30)
	bb := s.readerTaskDigest(ctx, candID, 36)
	if a == "" || bb == "" {
		out.Error = "任务图摘要为空（任务不存在或已删除）"
		return out
	}
	if t, err := s.m.pg.GetTask(candID); err == nil && t != nil {
		out.CandidateName = t.Name
	}
	user := "【发起方任务 A】\n" + a + "\n\n【参考任务 B】\n" + bb + "\n\n只输出 JSON。"
	callCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	callCtx = llmrec.WithWorker(callCtx, "reader")
	msg, _, _, err := rt.Complete(callCtx, llm.CompletionRequest{
		System:    []string{readerJudgePrompt},
		Messages:  []llm.Message{llm.UserText(user)},
		MaxTokens: 1200,
		Thinking:  "disabled",
	})
	if err != nil {
		out.Error = "判官模型调用失败：" + err.Error()
		return out
	}
	parsed, perr := parseReaderJudgeJSON(msg.Text())
	if perr != nil {
		out.Error = perr.Error()
		return out
	}
	out.Score = parsed.Score
	if out.Score < 0 {
		out.Score = 0
	}
	if out.Score > 100 {
		out.Score = 100
	}
	out.Reason = strings.TrimSpace(parsed.Reason)
	// 输出侧再脱敏一次：判官可能把摘要里的占位符"还原"。
	out.Overlap = normalizeJudgeOverlap(parsed.Overlap, 6)
	out.Chains = normalizeJudgeChains(parsed.Chains, 4)
	return out
}

// parseReaderJudgeJSON 容忍 ```json 围栏与前后缀文字，取第一个完整 JSON 对象。
func parseReaderJudgeJSON(s string) (readerJudgeOutput, error) {
	var out readerJudgeOutput
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "{"); i >= 0 {
		if j := strings.LastIndex(s, "}"); j > i {
			s = s[i : j+1]
		}
	}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return out, fmt.Errorf("判官输出不是合法 JSON：%v", err)
	}
	if strings.TrimSpace(out.Reason) == "" {
		return out, fmt.Errorf("判官输出缺少 reason")
	}
	return out, nil
}

// normalizeJudgeOverlap 只保留 method+path 形态、去重、截断。
func normalizeJudgeOverlap(in []string, n int) []string {
	out := make([]string, 0, n)
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(redact.TestMethod(s))
		if s == "" || len(s) > 120 {
			continue
		}
		k := strings.ToLower(s)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
		if len(out) >= n {
			break
		}
	}
	return out
}

// normalizeJudgeChains 清洗判官给的链摘要：脱敏、限条数、丢掉没有 entry 的。
func normalizeJudgeChains(in []db.ReaderChain, n int) []db.ReaderChain {
	out := make([]db.ReaderChain, 0, n)
	for _, c := range in {
		c.Entry = strings.TrimSpace(redact.TestMethod(c.Entry))
		if c.Entry == "" {
			continue
		}
		c.Outcome = strings.TrimSpace(redact.TestMethod(c.Outcome))
		if len(c.Steps) > 4 {
			c.Steps = c.Steps[:4]
		}
		for i := range c.Steps {
			c.Steps[i] = strings.TrimSpace(redact.TestMethod(c.Steps[i]))
		}
		out = append(out, c)
		if len(out) >= n {
			break
		}
	}
	return out
}

// toolJudgeRelatedTasks 是阅读者的批量判定入口：每个候选一个独立上下文，
// 并发 readerJudgeConcurrency。它不落库——adopt/dismiss 仍由阅读者决定并调用，
// 保证审计链（decided_by / reason / chains）只有一个写入点。
func (s *Server) toolJudgeRelatedTasks() actool.CoreTool {
	return wrTool("judge_related_tasks",
		"阅读者专用：一次判定多个候选，每个候选一个【独立上下文】（发起方摘要 + 该候选摘要），互不影响。"+
			"返回每个候选的 score(0-100)/reason/overlap/chains；score≥40 的用 adopt_related_task 采纳（把 chains/overlap 原样带上），<40 用 dismiss_related_task。"+
			"这比逐个 read_task_graph 省很多上下文：不要再用 read_task_graph 读全部候选；只有某个候选判官说「证据不足」、且你确实需要补证时，才单独读那一张图。",
		objSchema(map[string]any{
			"task_id":       strParam("发起方任务 id（本轮图变更消息里的 task_id）"),
			"candidate_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "候选任务 id 数组（request_reader_links 返回的 candidates[].task_id），最多 8 个"},
		}, "task_id", "candidate_ids"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID       json.RawMessage `json:"task_id"`
				CandidateIDs []int64         `json:"candidate_ids"`
			}
			_ = json.Unmarshal(in, &a)
			taskID, _, err := s.taskIntelLinkTarget(ctx, a.TaskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			ids := make([]int64, 0, len(a.CandidateIDs))
			seen := map[int64]bool{}
			for _, id := range a.CandidateIDs {
				if id <= 0 || id == taskID || seen[id] {
					continue
				}
				seen[id] = true
				ids = append(ids, id)
			}
			if len(ids) == 0 {
				return actool.Errorf("candidate_ids 不能为空（用 request_reader_links 返回的 task_id）"), nil
			}
			if len(ids) > 8 {
				ids = ids[:8]
			}
			verdicts := make([]readerJudgeVerdict, len(ids))
			sem := make(chan struct{}, readerJudgeConcurrency)
			var wg sync.WaitGroup
			for i, cand := range ids {
				wg.Add(1)
				go func(i int, cand int64) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					verdicts[i] = s.judgeCandidateIsolated(ctx, taskID, cand)
					if verdicts[i].Error != "" {
						log.Printf("[reader-judge] 候选#%d 判定失败: %s", cand, verdicts[i].Error)
					}
				}(i, cand)
			}
			wg.Wait()
			// 按分数降序返回，阅读者先处理高分候选。
			sort.SliceStable(verdicts, func(i, j int) bool { return verdicts[i].Score > verdicts[j].Score })
			ok := 0
			for _, v := range verdicts {
				if v.Error == "" {
					ok++
				}
			}
			return jsonResult(map[string]any{
				"task_id":  taskID,
				"verdicts": verdicts,
				"note": fmt.Sprintf("每个候选独立判定（%d/%d 成功）。score≥40 → adopt_related_task 并带上 chains/overlap；<40 → dismiss_related_task；error 项可单独 read_task_graph 补证。",
					ok, len(verdicts)),
			})
		})
}
