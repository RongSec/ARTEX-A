package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/intercept"
)

// ============================================================================
// POST /api/intercept/judge/test —— 试判（只计算，不落地）
//
// 用途：评估「短路表 + DB 规则 + 判官」这条链子的拦截能力，也是后续调整
// 红线时的观测工具 —— 改完规则/正则，直接贴一条真实形态的工具入参就能看到
// 三层分别怎么判、最终落到哪一层，不需要真跑一次会被拦下的任务。
//
// 【硬约束：无副作用】
//   - 不执行任何命令、不阻塞、不建 intercept_pending；
//   - 不调 Interceptor.Log / AppendDecisionEvent / HandleAsk —— 审计链与审批
//     历史不能被"试判"污染（否则每次观测都在链上留一条假记录，链的取证
//     价值就没了）；
//   - Match 只读内存缓存（首次未加载时从 DB 读规则，仍是读），Judge 只在
//     调用方明确请求时跑一次模型。
//
// 三层顺序与真实路径一致（guard.applyIntercept）：
//
//	shortCircuit → Match → Judge
//
// 唯一差别是短路表的 allow/ask 同样作为终局返回而不继续下探 —— 真实路径
// 里 shortCircuit 一旦返回非 nil 就直接 return，DB 规则与判官都不会再跑。
// 试判要回答的是"线上这条命令会被怎么处理"，因此照抄终局语义，而不是
// 按"前两层都没 deny"的字面意思继续跑（那会给出线上并不存在的判定）。
//
// 【测量模式：skip_short_circuit / skip_rules】
// 两个可选布尔只用于能力测量（如评估"删掉短路表后判官能否独挡"），默认
// false 时与上面的线上语义逐字段一致：
//
//   - skip_short_circuit=true：跳过短路表，从 DB 规则开始；规则仍可 deny/ask；
//   - skip_rules=true：跳过 DB 规则匹配，直接进判官；
//   - 两者都 true：纯判官判定（前提 use_judge=true）。
//
// 跳过本身会改变结论，不加标记极易被误读成线上真实行为，所以返回体带
// bypassed（本次跳过了哪几层），且最终由判官定论时 message 加
// 「[仅判官·已跳过前两层]」前缀。这些参数不改变"不执行、不写审计"的约束。
// ============================================================================

// 试判限流：同一 token 每分钟 30 次。判官调用要烧 token，若无上限，一个
// 脚本循环就能把额度打空；试判是人工观测工具，30/min 足够。
const (
	judgeTestRateLimit  = 30
	judgeTestRateWindow = time.Minute
)

// judgeTestCostHint 是返回里的 token 用量提示（判官单次约 2-3k）。
const judgeTestCostHint = "本次调用约 2-3k tokens"

// judgeTestRequest 是试判入参。
//
// Input 用 json.RawMessage 原样保留：与真实 hook 事件同形（Bash 的
// {"command":...}、Write 的 {"file_path":...}），三层判定吃到的字节必须
// 与线上完全一致，否则转义/padding 类用例的结论会失真。
type judgeTestRequest struct {
	Tool     string          `json:"tool"`
	Input    json.RawMessage `json:"input"`
	UseJudge *bool           `json:"use_judge"` // 缺省 true；false 时跳过判官（省钱）

	// 测量用开关：默认 false，生产语义不变。见文件头「测量模式」。
	// V12-RULES：短路层已删除（规则只有 intercept_rules 一套），故测量开关
	// 只剩「跳过规则表」一个。
	SkipRules bool `json:"skip_rules"`
}

// judgeTestLayer 是短路表/规则两层的观测结果。hit=false 时其余字段省略。
// 规则层带 rule_id（短路表是代码常量，无 DB 行号）。
type judgeTestLayer struct {
	Hit      bool   `json:"hit"`
	RuleID   int64  `json:"rule_id,omitempty"`
	RuleName string `json:"rule_name,omitempty"`
	Action   string `json:"action,omitempty"`
	Message  string `json:"message,omitempty"`
}

// judgeTestJudge 是判官层的观测结果。
//
// called=false 有两种原因，分别写在 Reason 里：调用方没请求（use_judge=false）
// 或判官未启用/未接线。ModelFallback=true 表示模型报错、超时或输出不可解析，
// 此时 Action 是 llm_judge_fail_action 的回退值。
type judgeTestJudge struct {
	Called        bool   `json:"called"`
	Action        string `json:"action,omitempty"`
	Reason        string `json:"reason,omitempty"`
	ModelFallback bool   `json:"model_fallback"`
}

// judgeTestFinal 是最终结论：动作 + 由哪一层定的。
// Layer ∈ rule|judge|none（none = 规则与判官都没拦，按放行处理）。
type judgeTestFinal struct {
	Action  string `json:"action"`
	Layer   string `json:"layer"`
	Message string `json:"message"`
}

// judgeTestResponse 是试判返回体。
//
// Bypassed 只在测量模式（skip_*）下出现：[]string{"rules"} 的
// 子集，明示本次哪些层根本没参与判定。默认参数下省略，返回体与上线语义版
// 逐字段一致，避免把测量结果误读成线上真实行为。
type judgeTestResponse struct {
	Rule          judgeTestLayer `json:"rule"`
	Judge         judgeTestJudge `json:"judge"`
	Final         judgeTestFinal `json:"final"`
	JudgeCostHint string         `json:"judge_cost_hint,omitempty"`
	Bypassed      []string       `json:"bypassed,omitempty"`
}

// judgeTestSkipPrefix 标记"跳过前两层后由判官单独定论"的结果。
const judgeTestSkipPrefix = "[仅判官·已跳过前两层] "

// judgeTestJudgeMessage 给测量模式下判官定论的 message 加前缀，防止把
// "删掉前两层后的结论"当成线上行为。
func judgeTestJudgeMessage(msg string, bypassed []string) string {
	if len(bypassed) == 0 {
		return msg
	}
	return judgeTestSkipPrefix + msg
}

// judgeTestDeps 把三层判定以函数注入，使试判编排可以脱离 DB/模型测试。
//
// 生产路径由 s.judgeTestDeps() 接上真实的 guard/interceptor；单测注入假
// 判定即可覆盖"短路命中不调判官""规则命中"等分支，无需起库。
type judgeTestDeps struct {
	match func(tool string, input []byte) (intercept.Decision, bool)
	judge        func(ctx context.Context, tool string, input json.RawMessage) (intercept.Decision, bool)
}

// evaluateJudgeTest 是试判的纯编排核：只做判定与分层，不写库、不记审计。
func evaluateJudgeTest(ctx context.Context, req judgeTestRequest, deps judgeTestDeps) judgeTestResponse {
	tool := strings.TrimSpace(req.Tool)
	useJudge := req.UseJudge == nil || *req.UseJudge
	var resp judgeTestResponse
	// 测量模式：记录本次主动跳过了哪几层（默认两个 false → 空，返回体省略）。
	if req.SkipRules {
		resp.Bypassed = append(resp.Bypassed, "rules")
	}

	// 第一层：DB 规则（priority DESC，首条命中）。V12-RULES 后这是唯一一层规则。
	var ruleDec intercept.Decision
	ruleMatched := false
	if !req.SkipRules && deps.match != nil {
		ruleDec, ruleMatched = deps.match(tool, req.Input)
	}
	if ruleMatched {
		resp.Rule = judgeTestLayer{
			Hit: true, RuleID: ruleDec.RuleID, RuleName: ruleDec.RuleName,
			Action: ruleDec.Action, Message: ruleDec.Message,
		}
		// deny 硬拦、allow 显式放行：两者在真实路径上都不再问判官。
		// ask 继续下探（V4-D 修复1：ask 规则命中先交模型裁决，人工只兜底）。
		if ruleDec.Action != "ask" {
			resp.Final = judgeTestFinal{Action: ruleDec.Action, Layer: "rule", Message: ruleDec.Message}
			return resp
		}
	}

	// 第二层：判官（仅当规则表未给终局、且调用方请求时）。
	if !useJudge {
		resp.Judge = judgeTestJudge{Called: false, Reason: "未请求判官（use_judge=false）"}
		noneMsg := "未命中拦截规则，且未请求判官，按放行处理"
		if len(resp.Bypassed) > 0 {
			noneMsg = "规则表已按 skip 参数跳过，且未请求判官，按放行处理"
		}
		resp.Final = judgeTestFinal{Action: "allow", Layer: "none", Message: noneMsg}
		if ruleMatched {
			// ask 规则命中但没请求判官：真实路径进人工审批。
			resp.Final = judgeTestFinal{Action: "ask", Layer: "rule", Message: ruleDec.Message}
		}
		return resp
	}

	var judgeDec intercept.Decision
	judged := false
	if deps.judge != nil {
		judgeDec, judged = deps.judge(ctx, tool, req.Input)
	}
	if !judged {
		resp.Judge = judgeTestJudge{Called: false, Reason: "判官未启用"}
		noneMsg := "未命中拦截规则，判官未启用，按放行处理"
		if len(resp.Bypassed) > 0 {
			noneMsg = "规则表已按 skip 参数跳过，判官未启用，按放行处理"
		}
		resp.Final = judgeTestFinal{Action: "allow", Layer: "none", Message: noneMsg}
		if ruleMatched {
			resp.Final = judgeTestFinal{Action: "ask", Layer: "rule", Message: ruleDec.Message}
		}
		return resp
	}

	resp.Judge = judgeTestJudge{
		Called: true, Action: judgeDec.Action, Reason: judgeDec.Message,
		ModelFallback: judgeDec.ModelFallback,
	}
	resp.JudgeCostHint = judgeTestCostHint

	if ruleMatched {
		// ask 规则交裁：只有模型真实给出的 allow/deny 能终结（与
		// intercept.judgeAskOverridesHuman 同语义）；模型失败或给 ask 时
		// 回落规则自带的 ask 语义。
		if !judgeDec.ModelFallback && (judgeDec.Action == "allow" || judgeDec.Action == "deny") {
			resp.Final = judgeTestFinal{
				Action: judgeDec.Action, Layer: "judge",
				Message: judgeTestJudgeMessage(judgeDec.Message, resp.Bypassed),
			}
		} else {
			resp.Final = judgeTestFinal{Action: "ask", Layer: "rule", Message: ruleDec.Message}
		}
		return resp
	}

	resp.Final = judgeTestFinal{
		Action: judgeDec.Action, Layer: "judge",
		Message: judgeTestJudgeMessage(judgeDec.Message, resp.Bypassed),
	}
	return resp
}

// judgeTestDeps 接上生产实现。interceptor 未初始化（无库/单测直构 Server）
// 时规则与判官两层按"不存在"处理 —— 与 Guard 在 interceptor==nil 时的放行
// 语义一致。
func (s *Server) judgeTestDeps() judgeTestDeps {
	deps := judgeTestDeps{}
	if s.m == nil || s.m.interceptor == nil {
		return deps
	}
	ic := s.m.interceptor
	deps.match = ic.Match
	deps.judge = ic.Judge
	return deps
}

// interceptJudgeTest 是 POST /api/intercept/judge/test 的 handler。
//
// 鉴权由外层 requireAuth 完成（与其它 /api/intercept/* 管理端点一致）；
// 这里再做一次 per-token 限流，防止判官被脚本刷爆 token。
func (s *Server) interceptJudgeTest(w http.ResponseWriter, r *http.Request) {
	tok := extractToken(r)
	if tok == "" {
		writeErr(w, http.StatusUnauthorized, "未授权")
		return
	}
	if !s.judgeTestLimiter().allow(judgeTestTokenKey(tok)) {
		writeErr(w, http.StatusTooManyRequests, "试判请求过于频繁：同一 token 每分钟最多 30 次")
		return
	}
	var req judgeTestRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Tool) == "" {
		writeErr(w, http.StatusBadRequest, "tool 不能为空")
		return
	}
	// input 必须与真实 hook 事件同形（JSON 对象）。缺省/非法会让判官的
	// BuildReviewInput 返回「审查上下文不完整」，试判结果就没有观测价值。
	if len(req.Input) == 0 || !json.Valid(req.Input) {
		writeErr(w, http.StatusBadRequest, "input 必须是有效的 JSON 工具入参")
		return
	}
	writeJSON(w, http.StatusOK, evaluateJudgeTest(r.Context(), req, s.judgeTestDeps()))
}

// judgeTestTokenKey 用 token 摘要做限流键：进程内存里不留原始 JWT。
func judgeTestTokenKey(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:8])
}

// judgeTestLimiter 返回本 Server 的限流器，惰性初始化。
// 用 sync.Once 是为了兼容测试里直接 &Server{} 构造（字段零值可用）。
func (s *Server) judgeTestLimiter() *judgeTestRateLimiter {
	s.judgeTestOnce.Do(func() {
		s.judgeTestRate = newJudgeTestRateLimiter(judgeTestRateLimit, judgeTestRateWindow, time.Now)
	})
	return s.judgeTestRate
}

// judgeTestRateLimiter 是固定窗口计数的 per-key 限流（进程内存，重启清零）。
//
// 只用于试判这一条观测端点：多实例部署时各进程独立计数，属可接受偏差
// （限流的目的不是精确配额，而是防止单进程被脚本打满模型额度）。
type judgeTestRateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	now    func() time.Time
	hits   map[string][]time.Time
}

func newJudgeTestRateLimiter(limit int, window time.Duration, now func() time.Time) *judgeTestRateLimiter {
	return &judgeTestRateLimiter{limit: limit, window: window, now: now, hits: map[string][]time.Time{}}
}

// allow 记录一次请求并返回是否放行。窗口外的旧计数在每次调用时顺带丢弃。
func (l *judgeTestRateLimiter) allow(key string) bool {
	now := l.now()
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()

	q := l.hits[key]
	drop := 0
	for drop < len(q) && !q[drop].After(cutoff) {
		drop++
	}
	q = q[drop:]
	if len(q) >= l.limit {
		l.hits[key] = q
		return false
	}
	l.hits[key] = append(q, now)

	// 防止 key 无界增长：键过多时清掉已过窗口的 key（正常使用下只有管理员
	// 那一个 token，这段只在异常场景兜底）。
	if len(l.hits) > 1024 {
		for k, v := range l.hits {
			if len(v) == 0 || !v[len(v)-1].After(cutoff) {
				delete(l.hits, k)
			}
		}
	}
	return true
}
