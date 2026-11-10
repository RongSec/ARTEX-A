package traffic

// 步骤↔流量自动关联（artex-hs T14(2/2)，架构 §4.2 / b4-spec §T14）。语义移植
// antifox（0.1.1 血统）的 ResolveSteps：把 report_finding 结构化复现的每一步
// （逐字 request/response 原文）映射回【本任务时间窗内】真实录制的 exchange，
// 供证据回链/报告穿插。与 antifox 的取舍差异：
//   - antifox 把全部收窄谓词（method/path/body FTS/响应判别词）写进 SQLite
//     查询，无法脱离数据库测试；这里把收窄核心抽成纯函数 ResolveReproSteps
//     （输入=步骤列表+候选摘要，输出=每步 exchange id 或 abstain），DB 侧只
//     留一个最小的「时间窗候选拉取」WindowCandidates——可无 PG/无 SQLite 单测；
//   - 原版候选排序取【最早】（步骤按时间顺序列举，cursor 链式推进：step1=最
//     早、step2=其后第一个），比 antifox 单步版「最新优先」更贴「有序步骤」；
//   - 宁缺毋滥铁律同 antifox 的「唯一才绑」精神并更严：仅端点命中（软收窄全
//     部未生效）而候选仍多 = 弃权；多候选只有状态唯一（步骤自述状态命中、或
//     唯一 2xx）才放行——绑错一条流量比不绑更糟（污染报告证据）。
//   - Host 头缺失时【不限 host】继续收窄（antifox 语义：path substring 同样
//     不带 host 谓词）；裸报文 request-line 为绝对 URI 时也从 URI 取 host。

import (
	"net/url"
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

// Cand 是一个候选 exchange 的最小摘要（WindowCandidates 从索引库拉出，喂给纯
// 函数）。ReqSnip/RespSnip 是截断的正文开头（candSnip 字节）——够做特征匹配，
// 又不会把整库正文搬进内存。
type Cand struct {
	ID       string
	TS       int64
	Host     string
	Method   string
	URL      string
	Status   int
	ReqHead  string
	ReqSnip  string
	RespHead string
	RespSnip string
}

// candSnip caps one body snippet pulled for step resolution. 512B already
// carries any distinctive payload opening; larger windows only bloat memory.
const candSnip = 512

// ResolveSteps is the DB-side orchestration: pull the task window's recorded
// exchanges, then hand them to the pure resolver. Returns one exchange id per
// step ("" = abstain). On query failure it degrades to all-abstain (logged by
// the caller chain; this is a best-effort enrichment, never fatal).
func (t *Traffic) ResolveSteps(sinceUnix, untilUnix int64, steps []StepRef) []string {
	cands, err := t.WindowCandidates(sinceUnix, untilUnix, 0)
	if err != nil {
		ids := make([]string, len(steps))
		return ids
	}
	return ResolveReproSteps(sinceUnix, untilUnix, steps, cands)
}

// WindowCandidates is the minimal host+time-window retrieval the task spec
// asks for（现有 Search/Page 均无时间窗谓词，且不该为旁路关联扩 UI 分页面）：
// [since,until] 闭窗口内的 exchange 元数据 + 截断正文摘要，ts 升序。
func (t *Traffic) WindowCandidates(sinceUnix, untilUnix int64, limit int) ([]Cand, error) {
	const maxWindow = 5000
	if limit <= 0 || limit > maxWindow {
		limit = maxWindow
	}
	rows, err := t.db.Query(`SELECT e.id,e.ts,e.host,e.method,e.url,e.status,
  COALESCE(b.req_head,''), COALESCE(CAST(substr(b.req_body,1,?) AS TEXT),''),
  COALESCE(b.resp_head,''), COALESCE(CAST(substr(b.resp_body,1,?) AS TEXT),'')
FROM exchanges e LEFT JOIN exchange_bodies b ON b.id=e.id
WHERE e.ts BETWEEN ? AND ? ORDER BY e.ts ASC, e.id ASC LIMIT ?`, candSnip, candSnip, sinceUnix, untilUnix, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Cand
	for rows.Next() {
		var c Cand
		if err := rows.Scan(&c.ID, &c.TS, &c.Host, &c.Method, &c.URL, &c.Status,
			&c.ReqHead, &c.ReqSnip, &c.RespHead, &c.RespSnip); err == nil {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

// ResolveReproSteps is the PURE narrowing core: no I/O, fully unit-testable.
// It maps an ORDERED list of reproduction steps to candidate exchanges inside
// the task's time window [sinceUnix, untilUnix] (Unix seconds, closed bounds).
//
// Steps resolve in order — each step's exchange must come at-or-after the
// previous step's resolved timestamp (agents list steps chronologically),
// which disambiguates repeated identical requests: of many identical requests
// to one endpoint, step 1 is the earliest, step 2 the next after it, etc.
//
// Per step:
//  1. hard filters: time window + order cursor; method; Host (only when the
//     step's request names one — verbatim packets carry `Host:`; a bare
//     `GET /path HTTP/1.1` line does not, and then host is NOT constrained);
//     url path (endpoint predicate, substring or token-set containment).
//     An unparseable request (no method+path) abstains outright — never guess.
//  2. soft narrowing (content-level), each applied only if ≥1 candidate
//     survives (an over-specific or paraphrased field must never zero out a
//     match that should succeed): url query → request-body discriminator →
//     response discriminators (stop once unique).
//  3. verdict: 0 candidates → abstain; 1 → bind; >1 → bind only if some soft
//     narrowing actually fired AND the step's stated status matches exactly
//     one candidate (else the sole 2xx); otherwise abstain.
//
// Returns one exchange id per step ("" = unresolved/abstained).
func ResolveReproSteps(sinceUnix, untilUnix int64, steps []StepRef, cands []Cand) []string {
	out := make([]string, len(steps))
	cursor := sinceUnix // previous step's exchange ts (chronological lower bound)
	for i, st := range steps {
		method, path, query, bodyToken := parseStepRequest(st.Request)
		if method == "" || path == "" {
			continue // 请求原文里既无报文明细也无 URL——不猜，abstain
		}
		host := parseStepHost(st.Request)

		// ── 硬过滤（窗口+顺序+method+host+path 端点谓词，同 antifox 的 WHERE）──
		pool := make([]Cand, 0, len(cands))
		for _, c := range cands {
			if c.TS < cursor || c.TS > untilUnix {
				continue
			}
			if !strings.EqualFold(c.Method, method) {
				continue
			}
			if host != "" && !strings.EqualFold(c.Host, host) {
				continue
			}
			if !pathMatch(path, c.URL) {
				continue
			}
			pool = append(pool, c)
		}
		if len(pool) == 0 {
			continue
		}

		// ── 软收窄（内容级特征）：每级只在「收窄后仍 ≥1 候选」时生效 ──
		narrowed := false
		tryNarrow := func(keep func(Cand) bool) {
			if len(pool) <= 1 {
				return // 已唯一，不再收窄
			}
			var next []Cand
			for _, c := range pool {
				if keep(c) {
					next = append(next, c)
				}
			}
			if len(next) >= 1 {
				pool, narrowed = next, true
			}
		}
		if query != "" {
			q := strings.ToLower(query)
			tryNarrow(func(c Cand) bool { return strings.Contains(strings.ToLower(c.URL), q) })
		}
		if bodyToken != "" {
			b := strings.ToLower(bodyToken)
			tryNarrow(func(c Cand) bool {
				return strings.Contains(strings.ToLower(c.ReqSnip), b) || strings.Contains(strings.ToLower(c.ReqHead), b)
			})
		}
		for _, disc := range respDiscriminators(st.Response) {
			if len(pool) <= 1 {
				break
			}
			d := strings.ToLower(disc)
			tryNarrow(func(c Cand) bool {
				return strings.Contains(strings.ToLower(c.RespSnip), d) || strings.Contains(strings.ToLower(c.RespHead), d)
			})
		}

		// ── 裁决：唯一才绑，宁缺毋滥 ──
		if len(pool) == 1 {
			out[i] = pool[0].ID
			cursor = pool[0].TS
			continue
		}
		if !narrowed {
			continue // 仅端点级（method/host/窗口）命中而候选仍多 → 真多义，不猜
		}
		uniq := func(pred func(Cand) bool) (Cand, bool) {
			var hit Cand
			n := 0
			for _, c := range pool {
				if pred(c) {
					hit, n = c, n+1
				}
			}
			return hit, n == 1
		}
		if want := expectedStatus(st.Response); want > 0 {
			if c, ok := uniq(func(c Cand) bool { return c.Status == want }); ok {
				out[i] = c.ID
				cursor = c.TS
				continue
			}
		}
		if c, ok := uniq(func(c Cand) bool { return c.Status >= 200 && c.Status < 300 }); ok {
			out[i] = c.ID
			cursor = c.TS
		}
		// 仍无法唯一 → abstain（cursor 不推进，后续步骤从同一时刻起找）
	}
	return out
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
	reHostHeader  = regexp.MustCompile(`(?im)^host:\s*([^\s]+)`)
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
		target := m[2]
		// An absolute-form request line ("GET http://host/path HTTP/1.1")
		// leaks the host into the target — reduce it to path?query so the
		// recorded url (also absolute-or-path forms) still aligns.
		if strings.Contains(target, "://") {
			if rest := target[strings.Index(target, "://")+3:]; strings.Contains(rest, "/") {
				target = rest[strings.Index(rest, "/"):]
			} else {
				target = "/"
			}
		}
		path, query = splitQuery(target)
		if i := strings.Index(text, "\n\n"); i >= 0 {
			body := text[i+2:]
			// Prefer the upload filename (strongest discriminator, and avoids
			// a whole-body miss when the agent paraphrased the multipart
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
	// url.Parse owns percent-encoding/fragment; splitQuery is the fallback
	// for values Parse rejects (bare IPv6 without brackets, control chars).
	if parsed, err := url.Parse(u); err == nil && parsed.Path != "" {
		path, query = parsed.EscapedPath(), parsed.RawQuery
	} else {
		path, query = splitQuery(u)
	}
	if m := reCurlMethod.FindStringSubmatch(text); m != nil {
		method = strings.ToUpper(m[1])
	} else if reBodyFlag.MatchString(text) {
		method = "POST"
	} else {
		method = "GET"
	}
	// Body discriminator only for body-bearing methods (GET/HEAD have none).
	if method != "GET" && method != "HEAD" {
		if m := reUploadName.FindStringSubmatch(text); m != nil {
			bodyToken = m[1]
		} else if m := reCurlData.FindStringSubmatch(text); m != nil {
			bodyToken = bodyPhrase(m[1])
		}
	}
	return
}

// parseStepHost extracts the target host a step's request names, or "" when
// the step gives none (a bare `GET /path HTTP/1.1` with no Host header, or a
// relative-URL command). "" means "do not constrain host" — matching antifox,
// whose step query never had a host predicate at all.
func parseStepHost(text string) string {
	if m := reHostHeader.FindStringSubmatch(text); m != nil {
		return hostOnly(strings.ToLower(m[1]))
	}
	if m := reHTTPReqLine.FindStringSubmatch(firstNonEmptyLine(text)); m != nil && strings.Contains(m[2], "://") {
		if u, err := url.Parse(m[2]); err == nil {
			return strings.ToLower(u.Hostname())
		}
	}
	if u := reURLInText.FindString(text); u != "" {
		if pu, err := url.Parse(u); err == nil {
			return strings.ToLower(pu.Hostname())
		}
	}
	return ""
}

// pathMatch reports whether a recorded URL matches a step's path: verbatim
// substring either way (handles agent-side prefix loss or extra suffix), or
// every non-numeric path token of the step present in the recorded path
// (tolerates /api/v1/ prefixes and ID-segment drift).
func pathMatch(stepPath, candURL string) bool {
	candPath := candURL
	if i := strings.IndexByte(candPath, '?'); i >= 0 {
		candPath = candPath[:i]
	}
	if i := strings.Index(candPath, "://"); i >= 0 {
		rest := candPath[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			candPath = rest[j:]
		} else {
			candPath = "/"
		}
	}
	sp, cp := strings.ToLower(stepPath), strings.ToLower(candPath)
	if sp == "" || sp == "/" {
		return true // 步骤没给出有效 path，端点级不收窄
	}
	if strings.Contains(cp, sp) || strings.Contains(sp, cp) {
		return true
	}
	toks := pathTokens(sp)
	if len(toks) == 0 {
		return false
	}
	ctoks := pathTokens(cp)
	for _, t := range toks {
		found := false
		for _, c := range ctoks {
			if c == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// pathTokens splits a url path into its meaningful segments, dropping the
// template placeholders (db.TemplatePath turns ids into {n}/{s}) so a
// templated step and a concrete recording still align.
func pathTokens(p string) []string {
	var out []string
	for _, seg := range strings.Split(p, "/") {
		seg = strings.TrimSpace(seg)
		if seg == "" || strings.HasPrefix(seg, "{") {
			continue
		}
		out = append(out, seg)
	}
	return out
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
// tokens first (they survive "…" paraphrasing), then the verbatim leading
// slice.
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

// splitQuery separates a target's path from its query string.
func splitQuery(target string) (path, query string) {
	if i := strings.IndexByte(target, '?'); i >= 0 {
		return target[:i], target[i+1:]
	}
	return target, ""
}

// bodyPhrase returns a matchable leading slice of a body/response text:
// trimmed to its FIRST LINE (multi-line phrases never match a substring hunt),
// ≥minTrigram runes (shorter is too generic to discriminate), capped at 200
// runes so a huge body doesn't dominate matching.
func bodyPhrase(body string) string {
	b := strings.TrimSpace(body)
	if i := strings.IndexByte(b, '\n'); i >= 0 {
		b = strings.TrimSpace(b[:i])
	}
	r := []rune(b)
	if len(r) < minTrigram {
		return ""
	}
	if len(r) > 200 {
		r = r[:200]
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
