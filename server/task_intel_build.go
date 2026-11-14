package server

// 任务情报表生成（V7-INTEL 第一层）：任务进入终态时，把 findings / facts /
// 资产抽成结构化、可直接比对的 (kind,key) 行，落 task_intel；新增行即发一条
// project_graph_events 信号（复用现有事件表，唤醒 reader）。
//
// 抽取口径（与任务书一致）：
//   endpoint   finding 的 URL / 证据里的请求行 / 资产 URL；方法缺失记 GET；
//              同 key 合并出现次数、来源 finding id、host 集合。
//   credential fact/finding 正文命中凭据模式（password= / passwd: / pwd= /
//              user:pass / Authorization: Bearer / Cookie: / 32/40 位 hex /
//              ssh-rsa 私钥标记）。**value 只写脱敏描述**（"password for
//              admin@10.0.0.5"），明文只以 detail.secret_masked（前 2 后 2）
//              出现——情报表会被 reader/planner 直接读，不能变成明文口令仓库。
//   component  资产指纹/响应头/banner 的 Server: / X-Powered-By / 常见产品版本；
//              归一化到 product@major.minor。
//   asset      资产 host:port。
//   vuln       finding 标题 + 严重度，key=title|asset（小写），供后续同类打法比对。
//
// 挂点：Manager.SetTaskStatus / SetTaskStatusGuarded 的终态收口 →
// emitTaskTerminal → installTerminalHooks 串联到 onTaskTerminalBuildIntel。
// 异步（钩子已在 goroutine 里）+ 失败只 log：情报表是旁路增强，绝不影响任务
// 状态写入。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// taskIntelBuildTimeout 是终态钩子里生成情报表的预算：只读本任务数据 +
// 一两百行 upsert，30s 对慢查询也宽裕；超时即放弃（本轮缺失可由手动 rebuild
// 或下次任务重跑补上）。
const taskIntelBuildTimeout = 30 * time.Second

// intelBuildInput 是一次抽取的全部原料（纯数据，便于无库单测）。
type intelBuildInput struct {
	TaskID   int64
	Findings []db.IntelFinding
	Facts    []db.IntelFact
	Assets   []*db.Asset
}

// intelBuildStats 是一次生成的统计（接口回显 + 事件摘要来源）。
type intelBuildStats struct {
	TaskID   int64          `json:"task_id"`
	Rows     int            `json:"rows"`
	Inserted int            `json:"inserted"`
	Updated  int            `json:"updated"`
	ByKind   map[string]int `json:"by_kind"`
	Skipped  string         `json:"skipped,omitempty"` // 无项目等跳过原因
}

// onTaskTerminalBuildIntel 是终态钩子的一段：按任务书口径只对 done/timeout
// 生成（failed 不在本期范围：失败任务可能被人工复活重跑，半程情报会污染比对面；
// 需要时用 POST /api/tasks/{id}/intel/rebuild 显式补）。失败只记日志——终态早已
// 提交，这里是"之后尽力把情报补齐"。
func (s *Server) onTaskTerminalBuildIntel(taskID int64, status string) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	if status != "done" && status != "timeout" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), taskIntelBuildTimeout)
	defer cancel()
	st, err := s.buildTaskIntel(ctx, taskID)
	if err != nil {
		log.Printf("[task-intel] task %d 情报表生成失败（不影响任务状态）: %v", taskID, err)
		return
	}
	if st.Skipped != "" {
		return
	}
	log.Printf("[task-intel] task %d 情报表完成：%d 行（新增 %d / 更新 %d）", taskID, st.Rows, st.Inserted, st.Updated)
}

// buildTaskIntel 读任务 → 抽取 → upsert → 有新增则发图变更信号。幂等：同一
// 任务重复调用行数不变（UNIQUE + upsert 覆盖），重复调用不重复发信号。
func (s *Server) buildTaskIntel(ctx context.Context, taskID int64) (intelBuildStats, error) {
	st := intelBuildStats{TaskID: taskID, ByKind: map[string]int{}}
	pg := s.m.pg
	t, err := pg.GetTask(taskID)
	if err != nil {
		return st, err
	}
	if t == nil {
		st.Skipped = "任务不存在"
		return st, nil
	}
	if t.ProjectID == nil || *t.ProjectID <= 0 {
		// 无项目任务=原版路径：情报表是项目内/跨项目勾连的底座，没有项目不落行。
		st.Skipped = "任务未挂项目"
		return st, nil
	}
	pid := *t.ProjectID

	findings, err := pg.TaskFindingsForIntel(ctx, taskID)
	if err != nil {
		return st, fmt.Errorf("读 findings: %w", err)
	}
	facts, err := pg.TaskFactsForIntel(ctx, taskID)
	if err != nil {
		return st, fmt.Errorf("读 facts: %w", err)
	}
	assets, err := pg.Assets().QueryByTask(taskID, "", 0, 0)
	if err != nil {
		return st, fmt.Errorf("读资产: %w", err)
	}

	rows := extractTaskIntel(intelBuildInput{TaskID: taskID, Findings: findings, Facts: facts, Assets: assets})
	st.Rows = len(rows)
	res, err := pg.UpsertTaskIntel(ctx, pid, taskID, rows)
	if err != nil {
		return st, fmt.Errorf("写情报表: %w", err)
	}
	st.Inserted, st.Updated, st.ByKind = res.Inserted, res.Updated, res.ByKind

	// 信号：只报「新增」——重复生成没有新攻击面，不该反复唤醒 reader。
	if summary := db.IntelDeltaSummary(taskID, res.ByKind); summary != "" {
		if err := pg.InsertGraphEvent(ctx, pid, taskID, 0, "intel", summary); err != nil {
			log.Printf("[task-intel] task %d 图变更事件写入失败: %v", taskID, err)
		}
	}
	return st, nil
}

// ---------------------------------------------------------------------------
// 抽取（纯函数，无库）
// ---------------------------------------------------------------------------

var (
	// 请求行：GET /api/x HTTP/1.1
	reIntelReqLine = regexp.MustCompile(`(?im)^[ \t]*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+(\S+)`)
	// 裸绝对 URL（正文/证据里散落的接口地址）。
	reIntelAbsURL = regexp.MustCompile(`(?i)https?://[^\s"'<>\)\]\}]+`)
	// 响应头。
	reIntelServerHdr = regexp.MustCompile(`(?im)^[ \t]*server[ \t]*:[ \t]*([^\r\n]+)`)
	reIntelPoweredBy = regexp.MustCompile(`(?im)^[ \t]*x-powered-by[ \t]*:[ \t]*([^\r\n]+)`)
	// 常见产品 + 版本（自由文本里要求带版本，避免 "mysql -u root" 之类噪音）。
	reIntelProductVer = regexp.MustCompile(`(?i)\b(apache(?:\s+httpd)?|nginx|php|tomcat|redis|mysql|docker|jenkins|dvwa|iis|openssh|wordpress|spring(?:boot)?|jquery|vue\.js|react)\b[^\r\n]{0,12}?\bv?(\d+(?:\.\d+){0,3})\b`)
	// 已知产品（无版本也收，仅用于资产 technologies 这种显式指纹列表）。
	reIntelKnownProduct = regexp.MustCompile(`(?i)^\s*(apache(?:\s+httpd)?|nginx|php|tomcat|redis|mysql|docker|jenkins|dvwa|iis|openssh|wordpress)\s*$`)
	// 产品名/版本拆分：nginx/1.18.0、PHP:7.4.33、Apache Tomcat 9.0.65。
	reIntelProdWithVer = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9 ._+\-]*?)\s*(?:[/:]|\s)\s*[vV]?(\d[\w.\-]*)\s*$`)
	reIntelProdOnly    = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9 ._+\-]*)\s*$`)
	reIntelHdrProdVer  = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9._+\-]*)\s*[/ ]\s*[vV]?(\d[\w.\-]*)`)

	// 凭据模式（顺序即优先级）。
	reIntelPwdAssign = regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[=:]\s*["']?([^\s"'&;,\r\n]+)`)
	reIntelUserHint  = regexp.MustCompile(`(?i)(?:user(?:name)?|login|account|账号|用户名)\s*[=:]\s*["']?([^\s"'&;,\r\n]+)`)
	reIntelCommonUsr = regexp.MustCompile(`(?i)\b(root|admin|administrator|sa|guest|test|operator)\b`)
	reIntelUserPass  = regexp.MustCompile(`(?:^|[\s"'\[(,])([A-Za-z][A-Za-z0-9._-]{1,31})\s*:\s*([^\s"'/:<>]{3,64})(?:$|[\s"'\]),;])`)
	reIntelBearer    = regexp.MustCompile(`(?i)authorization\s*:\s*bearer\s+([A-Za-z0-9\-._~+/=]{8,})`)
	reIntelCookie    = regexp.MustCompile(`(?i)cookie\s*:\s*([^\r\n]{6,300})`)
	reIntelHash      = regexp.MustCompile(`\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40})\b`)
	reIntelPrivKey   = regexp.MustCompile(`(?i)-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----`)
	reIntelSSHRSA    = regexp.MustCompile(`(?i)ssh-rsa\s+(AAAA[A-Za-z0-9+/=]{20,})`)

	// 主机（IPv4 或域名，可带端口）。
	reIntelHost = regexp.MustCompile(`(?i)\b((?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(?::(\d{1,5}))?\b`)
)

// intelUserPassNoise 是 user:pass 模式的假阳性黑名单：报文头名、URL scheme
// 与日期词。真实证据里到处都是 "Host: x" / "Date: Mon, 01 Jan…"，不加这层
// 会把报文头当成账号口令（用户名 "Date"、口令 "Mon,"）。
var intelUserPassNoise = map[string]bool{
	"http": true, "https": true, "ftp": true, "ws": true, "wss": true,
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"server": true, "host": true, "content-type": true, "content-length": true,
	"user-agent": true, "referer": true, "location": true, "date": true,
	"accept": true, "accept-encoding": true, "accept-language": true,
	"connection": true, "cache-control": true, "pragma": true, "expires": true,
	"etag": true, "vary": true, "age": true, "via": true, "allow": true,
	"upgrade": true, "te": true, "trailer": true, "warning": true,
	"last-modified": true, "transfer-encoding": true, "content-encoding": true,
	"strict-transport-security": true, "x-frame-options": true,
	"x-content-type-options": true, "x-xss-protection": true,
	"bearer": true, "basic": true,
}

// intelEntry 是聚合中的一行（同 kind+key 合并）。
type intelEntry struct {
	kind     string
	key      string
	value    string
	source   string
	sourceID *int64

	count      int
	methods    map[string]bool
	hosts      map[string]bool
	findingIDs map[int64]bool
	assetIDs   map[int64]bool
	factIDs    map[int64]bool
	versions   map[string]bool
	patterns   map[string]bool

	secretMasked string
	assetType    string
	assetURL     string
	severity     string
	vulnClass    string
}

type intelAcc struct {
	byKey map[string]*intelEntry
	order []string
}

func newIntelAcc() *intelAcc {
	return &intelAcc{byKey: map[string]*intelEntry{}}
}

func (a *intelAcc) get(kind, key, value, source string, sourceID int64) *intelEntry {
	if key == "" {
		return nil
	}
	id := kind + "\x00" + key
	if e, ok := a.byKey[id]; ok {
		if e.value == "" && value != "" {
			e.value = value
		}
		return e
	}
	e := &intelEntry{
		kind: kind, key: key, value: value, source: source,
		methods: map[string]bool{}, hosts: map[string]bool{},
		findingIDs: map[int64]bool{}, assetIDs: map[int64]bool{}, factIDs: map[int64]bool{},
		versions: map[string]bool{}, patterns: map[string]bool{},
	}
	if sourceID > 0 {
		sid := sourceID
		e.sourceID = &sid
		switch source {
		case "finding":
			e.findingIDs[sourceID] = true
		case "asset":
			e.assetIDs[sourceID] = true
		case "fact":
			e.factIDs[sourceID] = true
		}
	}
	a.byKey[id] = e
	a.order = append(a.order, id)
	return e
}

func (a *intelAcc) rows(taskID int64) []db.TaskIntel {
	out := make([]db.TaskIntel, 0, len(a.order))
	for _, id := range a.order {
		e := a.byKey[id]
		detail := e.detail()
		raw, err := json.Marshal(detail)
		if err != nil {
			raw = []byte(`{}`)
		}
		out = append(out, db.TaskIntel{
			TaskID: taskID, Kind: e.kind, Key: e.key, Value: e.value,
			Detail: json.RawMessage(raw), Source: e.source, SourceID: e.sourceID,
		})
	}
	return out
}

// detail 按 kind 组装合并明细（数组全部排序，保证重复生成字节级稳定）。
func (e *intelEntry) detail() map[string]any {
	d := map[string]any{"count": e.count}
	switch e.kind {
	case db.IntelKindEndpoint:
		d["methods"] = sortedKeys(e.methods)
		d["hosts"] = sortedKeys(e.hosts)
		if ids := sortedIntKeys(e.findingIDs); len(ids) > 0 {
			d["finding_ids"] = ids
		}
		if ids := sortedIntKeys(e.assetIDs); len(ids) > 0 {
			d["asset_ids"] = ids
		}
		if ids := sortedIntKeys(e.factIDs); len(ids) > 0 {
			d["fact_node_ids"] = ids
		}
	case db.IntelKindCredential:
		d["secret_masked"] = e.secretMasked
		if p := sortedKeys(e.patterns); len(p) > 0 {
			d["patterns"] = p
		}
	case db.IntelKindComponent:
		if v := sortedKeys(e.versions); len(v) > 0 {
			d["versions"] = v
		}
		if ids := sortedIntKeys(e.assetIDs); len(ids) > 0 {
			d["asset_ids"] = ids
		}
		if ids := sortedIntKeys(e.findingIDs); len(ids) > 0 {
			d["finding_ids"] = ids
		}
		if ids := sortedIntKeys(e.factIDs); len(ids) > 0 {
			d["fact_node_ids"] = ids
		}
	case db.IntelKindAsset:
		d["asset_type"] = e.assetType
		if e.assetURL != "" {
			d["url"] = e.assetURL
		}
	case db.IntelKindVuln:
		d["severity"] = e.severity
		d["vulnclass"] = e.vulnClass
		if ids := sortedIntKeys(e.findingIDs); len(ids) > 0 {
			d["finding_ids"] = ids
		}
	}
	return d
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedIntKeys(m map[int64]bool) []int64 {
	if len(m) == 0 {
		return nil
	}
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// extractTaskIntel 纯函数：原料 → 情报表行。同 kind+key 合并，输出顺序=首见
// 顺序（资产→finding→fact，各自 id 升序），重复调用结果完全一致。
func extractTaskIntel(in intelBuildInput) []db.TaskIntel {
	acc := newIntelAcc()
	assetKeyByID := map[int64]string{}
	var firstAssetKey string

	for _, a := range in.Assets {
		ak := intelAssetKey(a)
		if ak == "" {
			continue
		}
		if _, seen := assetKeyByID[a.ID]; !seen {
			assetKeyByID[a.ID] = ak
		}
		if firstAssetKey == "" {
			firstAssetKey = ak
		}
		if e := acc.get(db.IntelKindAsset, ak, ak, "asset", a.ID); e != nil {
			e.count++
			e.assetType = a.Type
			e.assetURL = redactURLForValue(a.URL)
		}
		if strings.TrimSpace(a.URL) != "" {
			method := a.Method
			if strings.TrimSpace(method) == "" {
				method = "GET"
			}
			acc.addEndpoint(method, a.URL, "asset", a.ID)
		}
		for _, tech := range a.Technologies {
			acc.addComponentRaw(tech, "asset", a.ID)
		}
		acc.addComponentsFromText(intelExtraText(a.Extra), "asset", a.ID)
	}

	for _, f := range in.Findings {
		text := strings.Join([]string{f.Summary, f.Evidence}, "\n")
		acc.addEndpointsFromText(text, "finding", f.ID)
		acc.addCredentialsFromText(text, "finding", f.ID)
		acc.addComponentsFromText(text, "finding", f.ID)
		acc.addVuln(f, assetKeyByID, firstAssetKey)
	}
	for _, fact := range in.Facts {
		text := strings.Join([]string{fact.Summary, fact.Detail, fact.Evidence}, "\n")
		acc.addEndpointsFromText(text, "fact", fact.NodeID)
		acc.addCredentialsFromText(text, "fact", fact.NodeID)
		acc.addComponentsFromText(text, "fact", fact.NodeID)
	}
	return acc.rows(in.TaskID)
}

// ---------------------------------------------------------------------------
// endpoint
// ---------------------------------------------------------------------------

func (a *intelAcc) addEndpoint(method, rawurl, source string, sourceID int64) {
	key, value := db.NormalizeEndpoint(method, rawurl)
	if key == "" {
		return
	}
	e := a.get(db.IntelKindEndpoint, key, redactURLForValue(value), source, sourceID)
	if e == nil {
		return
	}
	m := strings.ToLower(strings.TrimSpace(method))
	if m == "" {
		m = "get"
	}
	e.count++
	e.methods[m] = true
	if host := hostOfURL(rawurl); host != "" {
		e.hosts[host] = true
	}
}

// addEndpointsFromText 从正文里抽请求行与裸 URL：请求行带方法，裸 URL 记 GET。
func (a *intelAcc) addEndpointsFromText(text, source string, sourceID int64) {
	if strings.TrimSpace(text) == "" {
		return
	}
	for _, m := range reIntelReqLine.FindAllStringSubmatch(text, -1) {
		a.addEndpoint(m[1], m[2], source, sourceID)
	}
	for _, raw := range reIntelAbsURL.FindAllString(text, -1) {
		a.addEndpoint("", raw, source, sourceID)
	}
}

// hostOfURL 取 URL 的 host[:port]（解析失败返回空）。
func hostOfURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host)
}

// redactURLForValue 是 value 侧的保密处理：URL 里内嵌的 userinfo 与敏感 query
// 值（token/password/...）一律替换成 ***。value 要"人类可读原文"，但情报表
// 会被 reader/planner 直接读，原文不能顺带把凭据带出去。
func redactURLForValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	changed := false
	if u.User != nil {
		u.User = url.User("REDACTED")
		changed = true
	}
	if u.RawQuery != "" {
		q := u.Query()
		for k := range q {
			if intelSensitiveQueryKey(k) {
				q.Set(k, "REDACTED")
				changed = true
			}
		}
		if changed {
			u.RawQuery = q.Encode()
		}
	}
	if !changed {
		return raw
	}
	return u.String()
}

func intelSensitiveQueryKey(k string) bool {
	switch strings.ToLower(k) {
	case "password", "passwd", "pwd", "pass", "token", "access_token", "refresh_token",
		"secret", "key", "apikey", "api_key", "auth", "authorization", "session",
		"sessionid", "cookie", "sig", "signature":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// credential
// ---------------------------------------------------------------------------

// addCredentialsFromText 抽凭据。value 恒为脱敏描述；密文只以
// detail.secret_masked（前 2 后 2）落库。
func (a *intelAcc) addCredentialsFromText(text, source string, sourceID int64) {
	if strings.TrimSpace(text) == "" {
		return
	}
	user := intelUsernameHint(text)
	service := intelServiceHint(text)

	for _, m := range reIntelPwdAssign.FindAllStringSubmatch(text, -1) {
		a.addCredential("password", user, service, m[1], "password=", source, sourceID)
	}
	for _, m := range reIntelBearer.FindAllStringSubmatch(text, -1) {
		a.addCredential("token", user, service, m[1], "authorization:bearer", source, sourceID)
	}
	for _, m := range reIntelCookie.FindAllStringSubmatch(text, -1) {
		a.addCredential("cookie", user, service, m[1], "cookie:", source, sourceID)
	}
	hostSpans := reIntelHost.FindAllStringIndex(text, -1)
	for _, m := range reIntelUserPass.FindAllStringSubmatchIndex(text, -1) {
		u := strings.ToLower(text[m[2]:m[3]])
		secret := text[m[4]:m[5]]
		// 报文头/日期形态过滤：`Date: Mon, 01 Jan` 这类以逗号/分号结尾的"口令"
		// 一律丢弃，宁可漏报也不把头部误记成凭据。
		if intelUserPassNoise[u] || strings.ContainsAny(strings.TrimRight(secret, " "), ",;") {
			continue
		}
		// host:port 过滤：`app.example.com:8080` 会被本模式误读成 user:pass，
		// 命中区间完全落在某个 host[:port] 里的一律跳过。
		if intelSpanInsideHost(m[2], m[5], hostSpans) {
			continue
		}
		a.addCredential("password", text[m[2]:m[3]], service, secret, "user:pass", source, sourceID)
	}
	for _, m := range reIntelHash.FindAllStringSubmatch(text, -1) {
		a.addCredential("hash", user, service, m[1], "hex32/40", source, sourceID)
	}
	if reIntelPrivKey.MatchString(text) {
		a.addCredential("key", user, service, "PRIVATE KEY", "pem-private-key", source, sourceID)
	}
	for _, m := range reIntelSSHRSA.FindAllStringSubmatch(text, -1) {
		a.addCredential("key", user, service, m[1], "ssh-rsa", source, sourceID)
	}
}

// intelSpanInsideHost 报告 [start,end) 是否完全落在某个 host[:port] 匹配区间内
// （用于排除 "app.example.com:8080" 这类被 user:pass 正则误命中的字符串）。
func intelSpanInsideHost(start, end int, spans [][]int) bool {
	for _, sp := range spans {
		if start >= sp[0] && end <= sp[1] {
			return true
		}
	}
	return false
}

func (a *intelAcc) addCredential(kind, username, service, secret, pattern, source string, sourceID int64) {
	secret = strings.TrimSpace(strings.Trim(secret, `"'`))
	key, value := db.NormalizeCredential(kind, username, service)
	if key == "" || secret == "" {
		return
	}
	e := a.get(db.IntelKindCredential, key, value, source, sourceID)
	if e == nil {
		return
	}
	e.count++
	e.patterns[pattern] = true
	if e.secretMasked == "" {
		e.secretMasked = maskIntelSecret(secret)
	}
}

// maskIntelSecret 只留前 2 后 2 字符（≤4 字符全遮），返回值本身不含可用明文。
func maskIntelSecret(s string) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= 4 {
		return "****"
	}
	return string(r[:2]) + "****" + string(r[len(r)-2:])
}

// intelUsernameHint 从正文猜账号：显式 user=/login= 优先，其次常见特权账号词。
func intelUsernameHint(text string) string {
	if m := reIntelUserHint.FindStringSubmatch(text); m != nil {
		return strings.Trim(m[1], `"'`)
	}
	if m := reIntelCommonUsr.FindStringSubmatch(text); m != nil {
		return strings.ToLower(m[1])
	}
	return ""
}

// intelServiceHint 取正文里第一个 host[:port] 作为凭据归属服务。
func intelServiceHint(text string) string {
	if m := reIntelHost.FindStringSubmatch(text); m != nil {
		if m[2] != "" {
			return m[1] + ":" + m[2]
		}
		return m[1]
	}
	return ""
}

// ---------------------------------------------------------------------------
// component
// ---------------------------------------------------------------------------

// addComponentRaw 处理一条显式指纹（资产 technologies 项）：允许无版本
// （product@*），因为它在指纹列表里就是"确认存在该组件"。
func (a *intelAcc) addComponentRaw(raw, source string, sourceID int64) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	product, version := "", ""
	if m := reIntelProdWithVer.FindStringSubmatch(raw); m != nil {
		product, version = m[1], m[2]
	} else if m := reIntelProdOnly.FindStringSubmatch(raw); m != nil {
		if !reIntelKnownProduct.MatchString(m[1]) {
			return // 不认识的产品名不硬塞（防 "HTTP" 这类泛词入库）
		}
		product = m[1]
	} else {
		return
	}
	a.addComponent(product, version, source, sourceID)
}

func (a *intelAcc) addComponent(product, version, source string, sourceID int64) {
	key, value := db.NormalizeComponent(product, version)
	if key == "" {
		return
	}
	e := a.get(db.IntelKindComponent, key, value, source, sourceID)
	if e == nil {
		return
	}
	e.count++
	if v := strings.TrimSpace(version); v != "" {
		e.versions[v] = true
	}
}

// addComponentsFromText 从响应头/正文抽组件：Server: / X-Powered-By 头优先，
// 其次是"产品 + 版本"的裸文本（要求带版本，避免泛词噪音）。
func (a *intelAcc) addComponentsFromText(text, source string, sourceID int64) {
	if strings.TrimSpace(text) == "" {
		return
	}
	for _, m := range reIntelServerHdr.FindAllStringSubmatch(text, -1) {
		if p, v, ok := parseIntelHeaderProduct(m[1]); ok {
			a.addComponent(p, v, source, sourceID)
		}
	}
	for _, m := range reIntelPoweredBy.FindAllStringSubmatch(text, -1) {
		if p, v, ok := parseIntelHeaderProduct(m[1]); ok {
			a.addComponent(p, v, source, sourceID)
		}
	}
	for _, m := range reIntelProductVer.FindAllStringSubmatch(text, -1) {
		a.addComponent(m[1], m[2], source, sourceID)
	}
}

func parseIntelHeaderProduct(v string) (product, version string, ok bool) {
	if m := reIntelHdrProdVer.FindStringSubmatch(v); m != nil {
		return m[1], m[2], true
	}
	v = strings.TrimSpace(v)
	if v != "" && reIntelKnownProduct.MatchString(v) {
		return v, "", true
	}
	return "", "", false
}

// intelExtraText 把资产 extra（响应头/banner 等）摊平成可扫描文本。
func intelExtraText(extra map[string]any) string {
	if len(extra) == 0 {
		return ""
	}
	var b strings.Builder
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch v := extra[k].(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				fmt.Fprintf(&b, "%s: %s\n", k, v)
			}
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
					fmt.Fprintf(&b, "%s: %s\n", k, s)
				}
			}
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// asset / vuln
// ---------------------------------------------------------------------------

// intelAssetKey 取资产的 host:port 键（URL 优先，其次 ip/domain + port）。
// 端口未知时退化为纯 host：有端口比 host 更精确，但没有端口也不该丢掉资产。
func intelAssetKey(a *db.Asset) string {
	if a == nil {
		return ""
	}
	if u, err := url.Parse(strings.TrimSpace(a.URL)); err == nil && u.Host != "" {
		host := strings.ToLower(u.Hostname())
		if host == "" {
			return ""
		}
		if p := u.Port(); p != "" {
			return host + ":" + p
		}
		switch strings.ToLower(u.Scheme) {
		case "https", "wss":
			return host + ":443"
		case "http", "ws":
			return host + ":80"
		}
		return host
	}
	host := strings.ToLower(strings.TrimSpace(a.Domain))
	if host == "" {
		host = strings.TrimSpace(a.IP)
	}
	if host == "" {
		return ""
	}
	if a.Port != nil && *a.Port > 0 {
		return host + ":" + strconv.Itoa(*a.Port)
	}
	return host
}

// addVuln 落一条漏洞情报：key=title|asset（小写），供后续"同类打法"比对。
func (a *intelAcc) addVuln(f db.IntelFinding, assetKeyByID map[int64]string, fallbackAsset string) {
	title := strings.TrimSpace(f.Name)
	if title == "" {
		title = strings.TrimSpace(f.VulnClass)
	}
	if title == "" {
		return
	}
	asset := ""
	for _, aid := range f.AssetIDs {
		if k := assetKeyByID[aid]; k != "" {
			asset = k
			break
		}
	}
	if asset == "" {
		asset = fallbackAsset
	}
	if asset == "" {
		asset = "-"
	}
	key := strings.ToLower(title + "|" + asset)
	sev := strings.ToLower(strings.TrimSpace(f.Severity))
	value := title
	if sev != "" {
		value += " [" + sev + "]"
	}
	e := a.get(db.IntelKindVuln, key, value, "finding", f.ID)
	if e == nil {
		return
	}
	e.count++
	e.severity = sev
	e.vulnClass = f.VulnClass
	e.findingIDs[f.ID] = true
}
