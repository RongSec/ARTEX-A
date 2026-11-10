package traffic

// 步骤↔流量自动关联（artex-hs T14(2/2)，架构 §4.2 / b4-spec §T14）。语义移植
// antifox（0.1.1 血统）的 ResolveSteps：把 report_finding 结构化复现的每一步
// （逐字 request/response 原文）映射回【本任务时间窗内】真实录制的 exchange，
// 供证据回链/截图穿插。0.3.15 的差异适配：
//   - 表结构同名（exchanges/ts/url 等），时间窗谓词直接进 WHERE（原版 PageQuery
//     无时间窗字段，这里不扩它——关联走自有窄查询，别污染 UI 分页路径）；
//   - 全文索引是 contentless 的 ex_fts(rowid)，与 exchanges 经 rowid 关联
//     （antifox 是独立 bodies 表按 id，谓词形态不同、语义相同）；
//   - 候选排序取【最早】（antifox resolveStepInWindow 同）：步骤按时间顺序列举，
//     同名端点的重复请求里 step1=最早、step2=其后第一个（cursor 链式推进），
//     比 antifox 单步版 pickBest 的「最新优先」更贴「有序步骤」的语义。
//
// 铁律=宁缺毋滥：只有候选唯一（或被判别词/状态收窄到唯一）才绑；仅端点命中而
// 候选仍多=弃权；零命中=弃权——绑错一条流量比不绑更糟（污染报告证据）。

import (
	"regexp"
	"strconv"
	"strings"
)

// StepRef 是一步复现的逐字请求/响应原文（不依赖 report 包类型，防 traffic→report
// 反向耦合；server 层负责把 report.ReproStep 映射过来）。
type StepRef struct {
	Request  string
	Response string
}

// ResolveSteps maps an ORDERED list of reproduction steps to real recorded
// exchanges, constrained to the task's traffic time window [sinceUnix,
// untilUnix] (Unix seconds, closed bounds). Steps resolve in order — each
// step's exchange must come at-or-after the previous step's (agents list
// steps chronologically), which disambiguates repeated identical requests:
// of many identical requests to one endpoint, step 1 is the earliest, step 2
// the next after it, and so on. Per step: narrow method+path to the window,
// then refine by body/query/response discriminators (each applied only while
// ≥1 candidate remains — an over-specific or paraphrased field never drops
// the match to zero), then pick the EARLIEST candidate at-or-after the
// previous step's timestamp; when several survive narrowing, only a UNIQUE
// status match (the step's stated status, else the sole 2xx) resolves it,
// otherwise abstain. Returns one exchange id per step ("" when unresolved).
func (t *Traffic) ResolveSteps(sinceUnix, untilUnix int64, steps []StepRef) []string {
	out := make([]string, len(steps))
	cursor := int64(0) // previous step's exchange ts (chronological lower bound)
	for i, st := range steps {
		method, path, query, bodyToken := parseStepRequest(st.Request)
		if method == "" || path == "" {
			continue // 请求原文里既无报文明细也无 URL——不猜，abstain
		}
		if id, ts, ok := t.resolveStepInWindow(sinceUnix, untilUnix, cursor, method, path, query, bodyToken, st.Response); ok {
			out[i] = id
			cursor = ts
		}
	}
	return out
}

// resolveStepInWindow finds the earliest exchange matching one step, at-or-after
// cursor, inside the task's time window. Returns (id, ts, ok); ok=false on
// zero candidates or unresolvable ambiguity (see pickBest semantics folded
// into the earliest-first pick below).
func (t *Traffic) resolveStepInWindow(sinceUnix, untilUnix, cursor int64, method, path, query, bodyToken, respText string) (string, int64, bool) {
	where := `method=? AND url LIKE ? ESCAPE '\' AND ts BETWEEN ? AND ? AND ts >= ?`
	args := []any{strings.ToUpper(method), likeContains(path), sinceUnix, untilUnix, cursor}
	// tryNarrow applies a discriminator only if it still leaves ≥1 candidate,
	// so a paraphrased/over-specific field can't zero out a match that should
	// succeed. narrowed 记录「至少一次内容级收窄生效」——它是最终消歧的资格证明：
	// 只有端级匹配（narrowed=false）而候选仍多时绝不猜。
	narrowed := false
	tryNarrow := func(cond string, arg any) {
		w, a := where+" AND "+cond, append(append([]any{}, args...), arg)
		if len(t.queryIDs(w, a)) >= 1 {
			where, args, narrowed = w, a, true
		}
	}
	if t.fts && bodyToken != "" {
		tryNarrow(`rowid IN (SELECT rowid FROM ex_fts WHERE ex_fts MATCH ?)`, ftsQuote(bodyToken))
	}
	if query != "" {
		// URL-encoded payloads are full of %27/%20 — escape LIKE metacharacters.
		tryNarrow(`url LIKE ? ESCAPE '\'`, likeContains(query))
	}
	if t.fts {
		for _, disc := range respDiscriminators(respText) {
			if len(t.queryIDs(where, args)) <= 1 {
				break // 已唯一，不必再收窄
			}
			tryNarrow(`rowid IN (SELECT rowid FROM ex_fts WHERE ex_fts MATCH ?)`, ftsQuote(disc))
		}
	}
	// 有序语义：取 cursor 之后最早者。先数候选：
	//   0 个 → abstain。
	//   1 个 → 直接绑。
	//   ≥2 个：若从未发生内容级收窄（只有端点匹配）→ 多义 abstain；
	//          若收窄后仍多个（同一步请求被重放），用状态再消歧：步骤文本自述
	//          状态唯一命中 → 绑它；否则唯一 2xx → 绑它；再否则 abstain。
	//          全过不了关才退化为「最早者」是【不允许】的——宁缺毋滥。
	type cand struct {
		id     string
		ts     int64
		status int
	}
	rows, err := t.db.Query(`SELECT id, ts, status FROM exchanges WHERE `+where+` ORDER BY ts ASC, id ASC LIMIT 50`, args...)
	if err != nil {
		return "", 0, false
	}
	defer rows.Close()
	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.id, &c.ts, &c.status); err == nil {
			cands = append(cands, c)
		}
	}
	if len(cands) == 0 {
		return "", 0, false
	}
	if len(cands) == 1 {
		return cands[0].id, cands[0].ts, true
	}
	if !narrowed {
		return "", 0, false // 仅端点命中、候选仍多 → 真多义，不猜
	}
	uniq := func(pred func(int) bool) (string, int64, bool) {
		var hit string
		var hts int64
		n := 0
		for _, c := range cands {
			if pred(c.status) {
				hit, hts, n = c.id, c.ts, n+1
			}
		}
		return hit, hts, n == 1
	}
	if want := expectedStatus(respText); want > 0 {
		if id, ts, ok := uniq(func(s int) bool { return s == want }); ok {
			return id, ts, true
		}
	}
	return uniq(func(s int) bool { return s >= 200 && s < 300 })
}

// Reproduction-step request parsing: a step's "request" is either a verbatim
// HTTP packet or the command the agent ran (curl/shell). Both forms resolve to
// the real recorded exchange via these patterns.
var (
	reHTTPReqLine = regexp.MustCompile(`^([A-Z]+)\s+(\S+)\s+HTTP/\S+\s*$`)
	reURLInText   = regexp.MustCompile("https?://[^\\s\"'`;)<>]+")
	reCurlMethod  = regexp.MustCompile(`(?:-X|--request)\s+([A-Za-z]+)`)
	reBodyFlag    = regexp.MustCompile(`(?:^|\s)(?:-F|--form|-d|--data|--data-raw|--data-binary)(?:\s|=)`)
	reUploadName  = regexp.MustCompile(`filename=["']?([^"'\s;,]+)`)
	reCurlData    = regexp.MustCompile(`(?:-d|--data(?:-raw|-binary)?)[ =]\s*["']?([^"'\n]+)`)
	reStatusLine  = regexp.MustCompile(`(?i)HTTP[/0-9.]*\s+([1-5]\d\d)\b`)
	reLongToken   = regexp.MustCompile(`[A-Za-z0-9]{8,}`)
)

// parseStepRequest extracts method, url PATH (query stripped), the url QUERY,
// and a body discriminator token from a step's request text — whether it's a
// raw HTTP request packet ("METHOD /path?q PROTO\n…\n\n<body>") or a curl/shell
// command citing a target URL. query (GET-style) and the body token (upload
// filename / POST data / leading body slice) disambiguate same-endpoint
// requests; both may be empty when nothing distinctive is present.
func parseStepRequest(text string) (method, path, query, bodyToken string) {
	// 1) Raw HTTP request packet.
	if m := reHTTPReqLine.FindStringSubmatch(firstNonEmptyLine(text)); m != nil {
		method = strings.ToUpper(m[1])
		path, query = splitQuery(m[2])
		if i := strings.Index(text, "\n\n"); i >= 0 {
			body := text[i+2:]
			// Prefer the upload filename (strongest discriminator, and avoids
			// a whole-body FTS miss when the agent paraphrased the multipart
			// boundary as a placeholder).
			if m := reUploadName.FindStringSubmatch(body); m != nil {
				bodyToken = m[1]
			} else {
				bodyToken = bodyPhrase(body)
			}
		}
		return
	}
	// 2) curl / shell command citing a target URL.
	u := reURLInText.FindString(text)
	if u == "" {
		return "", "", "", ""
	}
	path, query = splitQuery(u)
	if m := reCurlMethod.FindStringSubmatch(text); m != nil {
		method = strings.ToUpper(m[1])
	} else if reBodyFlag.MatchString(text) {
		method = "POST"
	} else {
		method = "GET"
	}
	// Body discriminator only for body-bearing methods (GET/HEAD have none indexed).
	if method != "GET" && method != "HEAD" {
		if m := reUploadName.FindStringSubmatch(text); m != nil {
			bodyToken = m[1]
		} else if m := reCurlData.FindStringSubmatch(text); m != nil {
			bodyToken = bodyPhrase(m[1])
		}
	}
	return
}

// expectedStatus extracts the HTTP status a step's response states (e.g.
// "HTTP/1.1 200 OK" / "HTTP 200"), or 0 when none is given.
func expectedStatus(respText string) int {
	if m := reStatusLine.FindStringSubmatch(respText); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// respDiscriminators returns candidate strings from a step's response, in
// priority order, to disambiguate same-request exchanges: distinctive long
// tokens first (they survive "…" paraphrasing), then the verbatim leading slice.
func respDiscriminators(resp string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range reLongToken.FindAllString(resp, -1) {
		if len(out) >= 5 {
			break
		}
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	if p := bodyPhrase(resp); p != "" {
		out = append(out, p)
	}
	return out
}

// queryIDs returns up to 10 exchange ids matching where (newest first).
func (t *Traffic) queryIDs(where string, args []any) []string {
	rows, err := t.db.Query(`SELECT id FROM exchanges WHERE `+where+` ORDER BY ts DESC LIMIT 10`, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// likeContains builds a `%…%` LIKE pattern with the inner value's LIKE
// metacharacters (\ % _) escaped — use with `ESCAPE '\'` so URL-encoded
// payloads match literally.
func likeContains(s string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s) + "%"
}

func splitQuery(target string) (path, query string) {
	if i := strings.IndexByte(target, '?'); i >= 0 {
		return target[:i], target[i+1:]
	}
	return target, ""
}

// bodyPhrase returns a matchable leading slice of a body/response text:
// trimmed, ≥minTrigram runes (shorter cannot hit the trigram index at all),
// capped so a huge body doesn't turn into a huge MATCH term.
func bodyPhrase(body string) string {
	b := strings.TrimSpace(body)
	r := []rune(b)
	if len(r) < minTrigram {
		return ""
	}
	if len(r) > 400 {
		r = r[:400]
	}
	return string(r)
}

func firstNonEmptyLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(ln); t != "" {
			return t
		}
	}
	return ""
}
