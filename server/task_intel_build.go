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
	return s.buildTaskIntelMode(ctx, taskID, false)
}

// rebuildTaskIntel 是 rebuild 接口的实现：先删掉本任务由抽取生成的旧行
// （source=finding/fact/asset），再按当前原料整表重建；source=manual 的行
// 原样保留。这样历史上抽错的噪声行不会继续留在比对面（删除+写入同一事务）。
func (s *Server) rebuildTaskIntel(ctx context.Context, taskID int64) (intelBuildStats, error) {
	return s.buildTaskIntelMode(ctx, taskID, true)
}

func (s *Server) buildTaskIntelMode(ctx context.Context, taskID int64, replace bool) (intelBuildStats, error) {
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

	// 重建前记下已有 key：删除后重新插入的"老行"不算新增攻击面，不发信号。
	var before map[string]bool
	if replace {
		old, err := pg.TaskIntelForTask(ctx, taskID)
		if err != nil {
			return st, fmt.Errorf("读旧情报表: %w", err)
		}
		before = make(map[string]bool, len(old))
		for _, r := range old {
			before[r.Kind+"\x00"+r.Key] = true
		}
	}

	var res db.UpsertIntelResult
	if replace {
		res, err = pg.ReplaceTaskIntel(ctx, pid, taskID, rows)
	} else {
		res, err = pg.UpsertTaskIntel(ctx, pid, taskID, rows)
	}
	if err != nil {
		return st, fmt.Errorf("写情报表: %w", err)
	}
	st.Inserted, st.Updated, st.ByKind = res.Inserted, res.Updated, res.ByKind

	delta := res.ByKind
	if replace {
		delta = map[string]int{}
		for _, r := range rows {
			if !before[r.Kind+"\x00"+r.Key] {
				delta[r.Kind]++
			}
		}
	}
	// 信号：只报「新增」——重复生成没有新攻击面，不该反复唤醒 reader。
	if summary := db.IntelDeltaSummary(taskID, delta); summary != "" {
		if err := pg.InsertGraphEvent(ctx, pid, taskID, 0, "intel", summary); err != nil {
			log.Printf("[task-intel] task %d 图变更事件写入失败: %v", taskID, err)
		}
	}
	return st, nil
}

// ---------------------------------------------------------------------------
// 抽取（纯函数，无库）
// ---------------------------------------------------------------------------

// intelProductAlternation 是受控产品表的正则选择支（长名在前，避免前缀抢先）。
// 只有这张表里的产品才会进 component：自由文本里的 "HTTP"/"OK" 这类泛词不入表，
// 也就不可能变成一条"组件"。
const intelProductAlternation = `apache|httpd|nginx|php|tomcat|redis|mariadb|postgresql|postgres|pgsql|mysql|docker|jenkins|dvwa|openssh|openssl|iis|expressjs|express|jquery|bootstrap|spring[ \t]+boot|spring`

// intelProductAliases 把同一产品的别名归一到 canonical 名（apache/httpd 同族、
// apache tomcat 归 tomcat）：跨任务比对要的是"同一个产品"，不是同一个写法。
var intelProductAliases = map[string]string{
	"apache": "apache", "apache httpd": "apache", "apache http server": "apache", "httpd": "apache",
	"apache tomcat": "tomcat", "tomcat": "tomcat",
	"nginx": "nginx", "php": "php", "redis": "redis",
	"mysql": "mysql", "mariadb": "mariadb",
	"postgresql": "postgresql", "postgres": "postgresql", "pgsql": "postgresql",
	"docker": "docker", "jenkins": "jenkins", "dvwa": "dvwa",
	"openssh": "openssh", "open ssh": "openssh", "openssl": "openssl",
	"iis": "iis", "microsoft-iis": "iis", "microsoft iis": "iis",
	"express": "express", "expressjs": "express", "express.js": "express",
	"jquery": "jquery", "bootstrap": "bootstrap",
	"spring": "spring", "spring boot": "spring", "springboot": "spring",
}

var (
	// 请求行：GET /api/x HTTP/1.1。单独识别——目标只做"路径/绝对 URL"校验，
	// 绝不把整行（或带中文标点的残句）丢给 URL 解析。
	reIntelReqLine = regexp.MustCompile(`(?im)^[ \t]*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)[ \t]+(\S+)`)
	// 裸绝对 URL：必须以 http(s):// 开头；遇到空白/引号/括号/中文标点即结束。
	reIntelAbsURL = regexp.MustCompile("(?i)https?://[^\\s\"'<>()\\[\\]{}`，。；、！？（）【】《》「」]+")
	// 响应头。
	reIntelServerHdr = regexp.MustCompile(`(?im)^[ \t]*server[ \t]*:[ \t]*([^\r\n]+)`)
	reIntelPoweredBy = regexp.MustCompile(`(?im)^[ \t]*x-powered-by[ \t]*:[ \t]*([^\r\n]+)`)
	// 受控产品名 + 版本：产品名与版本之间只允许 ≤3 个分隔字符（紧邻判据），
	// 版本至少两段（"php 200" 这种状态码不成立）。
	reIntelProductVer = regexp.MustCompile(`(?i)\b(` + intelProductAlternation + `)\b[ \t/:]{0,3}[vV]?(\d+(?:\.\d+){1,3})\b`)
	// 产品名/版本拆分：nginx/1.18.0、PHP:7.4.33、Apache Tomcat 9.0.65。
	reIntelProdWithVer = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9 ._+\-]*?)\s*(?:[/:]|\s)\s*[vV]?(\d[\w.\-]*)\s*$`)
	reIntelProdOnly    = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9 ._+\-]*)\s*$`)
	reIntelHdrProdVer  = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9._+\-]*)\s*[/ ]\s*[vV]?(\d[\w.\-]*)`)

	// 版本合格线：至少 major.minor 两段，杜绝 "200"/"404" 被当版本。
	reIntelVersionOK = regexp.MustCompile(`^[vV]?\d+(?:\.\d+){1,3}\b`)
	// 用户名形态（2-32 位账号字符）。
	reIntelUsername = regexp.MustCompile(`^[A-Za-z0-9_.@$-]{2,32}$`)
	// 域名/IP 形态（服务归属必须是 host 或 host:port，路径不算）。
	reIntelIPv4   = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)
	reIntelDomain = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
	// 文件名式伪域名后缀：login.php / index.html 是路径，不是服务。
	reIntelFileTLD = regexp.MustCompile(`(?i)\.(php\d?|phtml|html?|shtml|asp|aspx|jsp|do|action|js|mjs|css|json|xml|txt|md|png|jpe?g|gif|svg|ico|pdf|zip|tar|gz|bz2|rar|exe|dll|sh|bash|py|pl|rb|log|bak|sql|ya?ml|ini|conf|env)$`)

	// 凭据模式（顺序即优先级；只认显式结构）。
	reIntelPwdAssign = regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[=:]\s*["']?([^\s"'&;,\r\n]+)`)
	reIntelUserHint  = regexp.MustCompile(`(?i)(?:user(?:name)?|account|账号|用户名)\s*[=:]\s*["']?([^\s"'&;,\r\n]+)`)
	reIntelCommonUsr = regexp.MustCompile(`(?i)\b(root|admin|administrator|sa|guest|test|operator)\b`)
	reIntelUserPass  = regexp.MustCompile(`(?:^|[\s"'\[(,])([A-Za-z0-9_.@$-]{2,32})\s*:\s*([^\s"'/:<>]{3,64})(?:$|[\s"'\]),;])`)
	reIntelBearer    = regexp.MustCompile(`(?i)authorization\s*:\s*bearer\s+([A-Za-z0-9\-._~+/=]{8,})`)
	reIntelCookie    = regexp.MustCompile(`(?i)cookie\s*:\s*([^\r\n]{6,300})`)
	reIntelHash      = regexp.MustCompile(`\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40})\b`)
	reIntelPrivKey   = regexp.MustCompile(`(?i)-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----`)
	reIntelSSHRSA    = regexp.MustCompile(`(?i)ssh-rsa\s+(AAAA[A-Za-z0-9+/=]{20,})`)

	// 主机（IPv4 或域名，可带端口）。
	reIntelHost = regexp.MustCompile(`(?i)\b((?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(?::(\d{1,5}))?\b`)
)

// intelUsernameStopwords 是"字段名/页面词"而不是账号：它们会以 `xxx: value`
// 的形态出现在证据里，落成凭据就是纯噪声。admin 不在此列（那是真账号）。
var intelUsernameStopwords = map[string]bool{
	"name": true, "username": true, "user": true, "password": true, "passwd": true,
	"pwd": true, "level": true, "currently": true, "surname": true, "phpids": true,
	"login": true, "submit": true, "security": true, "low": true, "high": true,
	"medium": true, "impossible": true, "account": true,
}

// intelURLTrailing 是 URL 结束处允许出现的尾随标点（抽取时剥掉）。
const intelURLTrailing = " \t\r\n\"'<>()[]{}，。；、,.;:!?！？）】》」』"

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

// get 取/建一行聚合。同 key 合并时**不改已有 value**（value 语义只由首条决定），
// 但 count 与来源 id 在调用方逐条累加——合并行必须能反查到全部来源。
func (a *intelAcc) get(kind, key, value, source string, sourceID int64) *intelEntry {
	if key == "" {
		return nil
	}
	id := kind + "\x00" + key
	if e, ok := a.byKey[id]; ok {
		if e.value == "" && value != "" {
			e.value = value
		}
		if sourceID > 0 {
			switch source {
			case "finding":
				e.findingIDs[sourceID] = true
			case "asset":
				e.assetIDs[sourceID] = true
			case "fact":
				e.factIDs[sourceID] = true
			}
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
			TaskID: taskID, Kind: e.kind, Key: e.key,
			MatchKey: db.IntelMatchKey(e.kind, e.key),
			Value:    e.value,
			Detail:   json.RawMessage(raw), Source: e.source, SourceID: e.sourceID,
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
		// 凭据的 service 若在正文里只剩路径（login.php），退回该 finding 的资产
		// host——凭据必须挂在主机上，不能挂在路径上。
		acc.addCredentialsFromText(text, intelFindingService(f, assetKeyByID), "finding", f.ID)
		acc.addComponentsFromText(text, "finding", f.ID)
		acc.addVuln(f, assetKeyByID, firstAssetKey)
	}
	for _, fact := range in.Facts {
		text := strings.Join([]string{fact.Summary, fact.Detail, fact.Evidence}, "\n")
		acc.addEndpointsFromText(text, "fact", fact.NodeID)
		acc.addCredentialsFromText(text, "", "fact", fact.NodeID)
		acc.addComponentsFromText(text, "fact", fact.NodeID)
	}
	return acc.rows(in.TaskID)
}

// intelFindingService 取 finding 关联资产的 host:port（凭据 service 的兜底归属）。
// 资产键本身就是 host[:port]，可直接作为凭据归属。
func intelFindingService(f db.IntelFinding, assetKeyByID map[int64]string) string {
	for _, aid := range f.AssetIDs {
		if k := assetKeyByID[aid]; k != "" {
			return k
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// endpoint
// ---------------------------------------------------------------------------

// addEndpoint 落一条绝对 URL 接口。只接受 http(s):// 开头、可被 url.Parse 解析、
// 路径以 "/" 开头且不含中文/全角字符的 URL；任何一项不满足就整条丢弃（宁可漏报，
// 也不让 "//127.0.0.1:9081，Apache/2.4.25" 这种残句进比对面）。
func (a *intelAcc) addEndpoint(method, rawurl, source string, sourceID int64) {
	u, ok := intelAbsoluteURL(rawurl)
	if !ok {
		return
	}
	a.addEndpointTarget(method, u, u, source, sourceID)
}

// addEndpointTarget 是 endpoint 的落库口：target 已通过形态校验，display 是
// value 侧原文（请求行只记路径，不记整行）。
func (a *intelAcc) addEndpointTarget(method, target, display, source string, sourceID int64) {
	key, value := db.NormalizeEndpoint(method, target)
	if key == "" {
		return
	}
	if strings.TrimSpace(display) == "" {
		display = value
	}
	e := a.get(db.IntelKindEndpoint, key, redactURLForValue(display), source, sourceID)
	if e == nil {
		return
	}
	m := strings.ToLower(strings.TrimSpace(method))
	if m == "" {
		m = "get"
	}
	e.count++
	e.methods[m] = true
	if host := hostOfURL(target); host != "" {
		e.hosts[host] = true
	}
}

// intelAbsoluteURL 校验并规范化一条绝对 URL；不合格返回 ("", false)。
func intelAbsoluteURL(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	low := strings.ToLower(s)
	if !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://") {
		return "", false
	}
	s = strings.TrimRight(s, intelURLTrailing)
	if s == "" {
		return "", false
	}
	for _, r := range s {
		// 中文标点/全角字符/控制符/空格：整条 URL 判为无效（不做截断猜测）。
		if r < 0x21 || r > 0x7e {
			return "", false
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return "", false
	}
	if u.Path != "" && !strings.HasPrefix(u.Path, "/") {
		return "", false
	}
	return s, true
}

// intelRequestTarget 校验请求行里的 origin-form 目标：必须以单个 "/" 开头、
// 无空白、纯 ASCII（"//host，中文" 这类协议相对残句直接否掉）。
func intelRequestTarget(p string) (string, bool) {
	p = strings.TrimSpace(p)
	if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return "", false
	}
	for _, r := range p {
		if r <= 0x20 || r > 0x7e {
			return "", false
		}
	}
	return p, true
}

// addEndpointsFromText 从正文里抽请求行与裸 URL：请求行带方法，裸 URL 记 GET。
func (a *intelAcc) addEndpointsFromText(text, source string, sourceID int64) {
	if strings.TrimSpace(text) == "" {
		return
	}
	for _, m := range reIntelReqLine.FindAllStringSubmatch(text, -1) {
		a.addRequestLine(m[1], m[2], source, sourceID)
	}
	for _, raw := range reIntelAbsURL.FindAllString(text, -1) {
		a.addEndpoint("", raw, source, sourceID)
	}
}

// addRequestLine 处理 "METHOD target"：target 是绝对 URL 时按 URL 走，否则只做
// 路径校验——请求行从不整行参与 URL 解析。
func (a *intelAcc) addRequestLine(method, target, source string, sourceID int64) {
	low := strings.ToLower(target)
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		a.addEndpoint(method, target, source, sourceID)
		return
	}
	p, ok := intelRequestTarget(target)
	if !ok {
		return
	}
	a.addEndpointTarget(method, p, p, source, sourceID)
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
//
// fallbackService 是调用方给的归属主机（finding 的资产 host）：正文里只剩
// "login.php" 这种路径时，凭据挂到主机上，而不是挂到路径上。
func (a *intelAcc) addCredentialsFromText(text, fallbackService, source string, sourceID int64) {
	if strings.TrimSpace(text) == "" {
		return
	}
	user := intelUsernameHint(text)
	service := intelServiceHint(text)
	if service == "" {
		if s, ok := intelValidService(fallbackService); ok {
			service = s
		}
	}
	if service == "" {
		// 没有可归属的主机：这条凭据无法参与"同账号同服务"的比对，不入表。
		return
	}

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
		rawUser := text[m[2]:m[3]]
		u := strings.ToLower(rawUser)
		secret := text[m[4]:m[5]]
		// 报文头/日期形态过滤：`Date: Mon, 01 Jan` 这类以逗号/分号结尾的"口令"
		// 一律丢弃，宁可漏报也不把头部误记成凭据。
		if intelUserPassNoise[u] || strings.ContainsAny(strings.TrimRight(secret, " "), ",;") {
			continue
		}
		// 用户名必须是账号形态且不是字段名（Surname/name/currently/level…）。
		if _, ok := intelValidUsername(rawUser); !ok {
			continue
		}
		// host:port 过滤：`app.example.com:8080` 会被本模式误读成 user:pass，
		// 命中区间完全落在某个 host[:port] 里的一律跳过。
		if intelSpanInsideHost(m[2], m[5], hostSpans) {
			continue
		}
		a.addCredential("password", rawUser, service, secret, "user:pass", source, sourceID)
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
	if username != "" {
		u, ok := intelValidUsername(username)
		if !ok {
			return
		}
		username = u
	}
	svc, ok := intelValidService(service)
	if !ok {
		// service 为空/是路径（login.php）：这条凭据没有可比对的主机归属。
		return
	}
	key, value := db.NormalizeCredential(kind, username, svc)
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

// intelValidUsername 校验账号形态：2-32 位账号字符 + 非字段停用词。
func intelValidUsername(s string) (string, bool) {
	s = strings.Trim(strings.TrimSpace(s), `"'`)
	if !reIntelUsername.MatchString(s) {
		return "", false
	}
	if intelUsernameStopwords[strings.ToLower(s)] {
		return "", false
	}
	return s, true
}

// intelValidService 校验凭据归属：必须是 host 或 host:port（IP/域名），
// 不能是登录页路径（login.php / /login）。
func intelValidService(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || strings.ContainsAny(s, "/\\ \t\r\n") {
		return "", false
	}
	host, port := s, ""
	if i := strings.LastIndex(s, ":"); i > 0 {
		host, port = s[:i], s[i+1:]
		n, err := strconv.Atoi(port)
		if port == "" || err != nil || n < 1 || n > 65535 {
			return "", false
		}
	}
	if reIntelIPv4.MatchString(host) {
		for _, part := range strings.Split(host, ".") {
			n, err := strconv.Atoi(part)
			if err != nil || n > 255 {
				return "", false
			}
		}
		return s, true
	}
	if host == "localhost" {
		return s, true
	}
	if !reIntelDomain.MatchString(host) || reIntelFileTLD.MatchString(host) {
		return "", false
	}
	return s, true
}

// intelUsernameHint 从正文猜账号：显式 user=/account= 优先，其次常见特权账号词。
// 两种来源都要过 intelValidUsername（字段名不是账号）。
func intelUsernameHint(text string) string {
	if m := reIntelUserHint.FindStringSubmatch(text); m != nil {
		if u, ok := intelValidUsername(m[1]); ok {
			return u
		}
	}
	if m := reIntelCommonUsr.FindStringSubmatch(text); m != nil {
		if u, ok := intelValidUsername(m[1]); ok {
			return u
		}
	}
	return ""
}

// intelServiceHint 取正文里第一个"合法主机"作为凭据归属服务；login.php 这类
// 被域名正则撞上的文件名一律跳过（它不是服务，是路径）。
func intelServiceHint(text string) string {
	for _, m := range reIntelHost.FindAllStringSubmatch(text, -1) {
		cand := m[1]
		if m[2] != "" {
			cand += ":" + m[2]
		}
		if s, ok := intelValidService(cand); ok {
			return s
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// component
// ---------------------------------------------------------------------------

// addComponentRaw 处理一条显式指纹（资产 technologies 项）：允许无版本
// （product@*），因为它在指纹列表里就是"确认存在该组件"；但产品名仍必须在
// 受控表内，版本也必须达到 major.minor。
func (a *intelAcc) addComponentRaw(raw, source string, sourceID int64) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	product, version := "", ""
	if m := reIntelProdWithVer.FindStringSubmatch(raw); m != nil {
		product, version = m[1], m[2]
	} else if m := reIntelProdOnly.FindStringSubmatch(raw); m != nil {
		product = m[1]
	} else {
		return
	}
	a.addComponent(product, version, source, sourceID)
}

// addComponent 落一条组件情报。产品名先归一到受控表的 canonical 名（value 仍
// 保留原文），版本必须匹配 \d+(?:\.\d+){1,3}——"200"/"404" 这种单段数字不是
// 版本，直接丢弃，而不是记成 product@200。
func (a *intelAcc) addComponent(product, version, source string, sourceID int64) {
	canonical, ok := intelCanonicalProduct(product)
	if !ok {
		return
	}
	ver := strings.TrimSpace(version)
	if len(ver) > 1 && (ver[0] == 'v' || ver[0] == 'V') && ver[1] >= '0' && ver[1] <= '9' {
		ver = ver[1:]
	}
	if ver != "" && !reIntelVersionOK.MatchString(ver) {
		return
	}
	key, _ := db.NormalizeComponent(canonical, ver)
	if key == "" {
		return
	}
	_, value := db.NormalizeComponent(strings.TrimSpace(product), ver)
	if value == "" {
		value = key
	}
	e := a.get(db.IntelKindComponent, key, value, source, sourceID)
	if e == nil {
		return
	}
	e.count++
	if ver != "" {
		e.versions[ver] = true
	}
}

// intelCanonicalProduct 把产品名/别名归一到受控表的 canonical 名。
func intelCanonicalProduct(name string) (string, bool) {
	k := strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(name)), " "))
	if k == "" {
		return "", false
	}
	c, ok := intelProductAliases[k]
	return c, ok
}

// addComponentsFromText 只从紧邻形态抽组件：Server: / X-Powered-By 头，
// 以及正文里"产品名 + ≤3 字符分隔 + 版本"的裸文本。产品归属严格按产品名，
// 绝不把 MariaDB 的版本套到 PHP 头上。
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
		if _, known := intelCanonicalProduct(m[1]); known {
			return m[1], m[2], true
		}
		return "", "", false
	}
	v = strings.TrimSpace(v)
	if _, known := intelCanonicalProduct(v); known {
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
