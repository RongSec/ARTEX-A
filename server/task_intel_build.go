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
// 一两百行 upsert，30s 对慢查询也宽裕。V9-PURPOSE 起还要容纳接口用途的模型
// 补充（单次 30s、解析失败重试 1 次），因此把总预算放宽到 90s；钩子本身在
// 后台 goroutine 里跑，放宽不会阻塞任务状态写入。超时即放弃（本轮缺失可由
// 手动 rebuild 或下次任务重跑补上）。
const taskIntelBuildTimeout = 90 * time.Second

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
	return s.buildTaskIntelMode(ctx, taskID, false, false)
}

// rebuildTaskIntel 是 rebuild 接口的实现：先删掉本任务由抽取生成的旧行
// （source=finding/fact/asset），再按当前原料整表重建；source=manual 的行
// 原样保留。这样历史上抽错的噪声行不会继续留在比对面（删除+写入同一事务）。
// forcePurpose=false：已经由模型生成的接口用途沿用到新表，不重复请求模型。
func (s *Server) rebuildTaskIntel(ctx context.Context, taskID int64) (intelBuildStats, error) {
	return s.buildTaskIntelMode(ctx, taskID, true, false)
}

// rebuildTaskIntelForcePurpose 是 rebuild 的显式强制模式（?force_purpose=1）：
// 忽略已有 purpose_source=model，重新请求模型。普通 rebuild 默认不强制，保证
// 重复点击「重建」不会反复烧模型调用。
func (s *Server) rebuildTaskIntelForcePurpose(ctx context.Context, taskID int64) (intelBuildStats, error) {
	return s.buildTaskIntelMode(ctx, taskID, true, true)
}

func (s *Server) buildTaskIntelMode(ctx context.Context, taskID int64, replace, forcePurpose bool) (intelBuildStats, error) {
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
	// 接口用途：规则值先落 purpose_rule/purpose_source=rule，再由一次批量模型
	// 调用覆盖成抽象用途（见 task_intel_purpose.go）。模型是旁路增强：无配置/
	// 失败/超时都保留规则值，绝不让情报表生成失败。
	annotateIntelPurposeRules(rows)
	old, err := pg.TaskIntelForTask(ctx, taskID)
	if err != nil {
		return st, fmt.Errorf("读旧情报表: %w", err)
	}
	s.fillIntelEndpointPurposes(ctx, t, findings, old, rows, forcePurpose)
	st.Rows = len(rows)

	// 重建前记下已有 key：删除后重新插入的"老行"不算新增攻击面，不发信号。
	var before map[string]bool
	if replace {
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
	// 水位：运行中的增量构建（V10-INTEL-LIVE）按它判「5 分钟到了没」。
	s.markIntelBuilt(ctx, taskID)
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
const intelProductAlternation = `apache[ \t]+shiro|apache|httpd|nginx|php|tomcat|redis|mariadb|postgresql|postgres|pgsql|mysql|docker|jenkins|dvwa|openssh|openssl|iis|expressjs|express|jquery|bootstrap|` +
	`spring[ \t]+cloud[ \t]+gateway|spring[ \t]+boot|spring|` +
	`shiro|weblogic|struts2|struts|fastjson|log4j2|log4j|` +
	`nacos|consul|grafana|zabbix|kibana|elasticsearch|rabbitmq|mongodb|jboss|wildfly|thinkphp|laravel|django|flask`

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
	"spring cloud gateway": "spring cloud gateway",
	// 实战高频、CVE 密集的组件：不在表里就永远比不到跨任务同组件，
	// 而「同组件版本且有在野利用」是阅读者的强信号之一。
	"apache shiro": "shiro", "shiro": "shiro",
	"weblogic": "weblogic", "oracle weblogic": "weblogic",
	"struts2": "struts2", "struts": "struts2",
	"fastjson": "fastjson", "log4j2": "log4j", "log4j": "log4j",
	"nacos": "nacos", "consul": "consul", "grafana": "grafana", "zabbix": "zabbix",
	"kibana": "kibana", "elasticsearch": "elasticsearch", "rabbitmq": "rabbitmq",
	"mongodb": "mongodb", "jboss": "jboss", "wildfly": "wildfly",
	"thinkphp": "thinkphp", "laravel": "laravel", "django": "django", "flask": "flask",
}

var (
	// 请求行：GET /api/x HTTP/1.1。行首或空白/引号之后都算——事实正文里大量
	// 请求是写在句子中间的（"…，GET /login.php 无 Cookie 返回 200"），只认行首
	// 会把真实接口漏掉。目标串仍只做"路径/绝对 URL"校验，绝不把整行交给 URL 解析。
	reIntelReqLine = regexp.MustCompile(`(?i)(?:^|[\s"'(\[（【])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)[ \t]+(\S+)`)
	// 裸绝对 URL：必须以 http(s):// 开头；遇到空白/引号/括号/中文标点即结束。
	reIntelAbsURL = regexp.MustCompile("(?i)https?://[^\\s\"'<>()\\[\\]{}`，。；、！？（）【】《》「」]+")
	// 反引号/引号包裹的裸路径：`/config.php`、"admin/login.php"。只认片段本身，
	// 是否算接口由 intelQuotedPathOK 二次判定（/tmp 这类目录不当接口）。
	reIntelQuotedPath = regexp.MustCompile("[`\"'](/[^\\s`\"'<>，。；、！？（）【】《》「」]*)[`\"']")
	// 状态码：HTTP/1.1 302 / 返回 200 / 状态码：403 / status: 404。
	reIntelHTTPStatus = regexp.MustCompile(`(?i)(?:HTTP/\d(?:\.\d)?[ \t]+|返回[ \t]*|状态码[ \t]*[:：]?[ \t]*|status(?:[ \t]*code)?[ \t]*[:=][ \t]*)([1-5]\d{2})\b`)
	// 鉴权线索：401/403 或"未登录/需要登录/无 Cookie"——同段落出现即认为该段
	// 描述的接口需要登录态。
	reIntelAuthHint = regexp.MustCompile(`(?i)(?:\b401\b|\b403\b|未登录|需要登录|需登录|未授权|需要认证|无[ \t]*cookie)`)
	// 参数名：query/表单形态 name=value（只取名，不取值）；小写开头，避开
	// PHPSESSID 这类大写常量与报文头。
	reIntelParamAssign = regexp.MustCompile(`(?:^|[\s&?;,(\[{'"])([a-z_][a-z0-9_\-]{0,30})[ \t]*=`)
	// Host 头：段落里没有 URL 时，接口的主机归属只能从这里来。
	reIntelHostHeader = regexp.MustCompile(`(?im)^[ \t]*host[ \t]*:[ \t]*([^\r\n]+)`)

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
	// 实测误报：这些是 JS 变量名 / JSON 字段名 / HTTP 头名 / nmap 输出词，
	// 被 `xxx: yyy` 模式当成「账号: 口令」写进了凭据表（任务 216 一次 20+ 条）。
	"shown": true, "cmd": true, "clusterid": true, "payload123": true, "exponent": true,
	"status": true, "isok": true, "newpage": true, "origin": true, "je": true,
	"real-chromium": true, "enterprisedomains": true, "alg": true, "hostname": true,
	"env": true, "domain": true, "imageid": true, "qrcode": true, "deviceid": true,
	"csrf": true, "xsrf": true, "captcha": true, "verifycode": true, "rememberme": true,
	"token": true, "secret": true, "authorization": true,
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

	// 接口层的"能不能用/怎么用"信息：用途、参数名、状态码、是否需登录。
	// 这些字段只从证据正文里取，取不到就留空，绝不编。
	purpose     string
	params      map[string]bool
	statusCodes map[int]bool
	authNeeded  bool

	// 凭据在哪些接口上用过（同段落里出现的 path）。
	whereUsed map[string]bool

	secretMasked string
	assetType    string
	assetURL     string
	severity     string
	vulnClass    string
	vulnTitle    string
}

type intelAcc struct {
	byKey map[string]*intelEntry
	order []string
	// hostPorts 是全文（finding/fact/资产 URL）出现过的 host → 端口集合。
	// 只用于把"裸主机"补成 host:port：正文里 127.0.0.1 与 URL 里的
	// 127.0.0.1:9081 是同一台机器，情报表不该留一个没有端口的键。
	hostPorts map[string][]string
}

func newIntelAcc() *intelAcc {
	return &intelAcc{byKey: map[string]*intelEntry{}, hostPorts: map[string][]string{}}
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
		params: map[string]bool{}, statusCodes: map[int]bool{}, whereUsed: map[string]bool{},
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
		if e.purpose != "" {
			d["purpose"] = e.purpose
		}
		if p := sortedKeys(e.params); len(p) > 0 {
			d["params"] = p
		}
		if s := sortedIntVals(e.statusCodes); len(s) > 0 {
			d["status_codes"] = s
		}
		// auth_required 恒出现（false 也是结论："正文没要求登录"），前端不用判空。
		d["auth_required"] = e.authNeeded
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
		if w := sortedKeys(e.whereUsed); len(w) > 0 {
			d["where_used"] = w
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
		if e.vulnTitle != "" {
			d["title"] = e.vulnTitle
		}
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

func sortedIntVals(m map[int]bool) []int {
	if len(m) == 0 {
		return nil
	}
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// extractTaskIntel 纯函数：原料 → 情报表行。同 kind+key 合并，输出顺序=首见
// 顺序（资产→finding→fact，各自 id 升序），重复调用结果完全一致。
func extractTaskIntel(in intelBuildInput) []db.TaskIntel {
	acc := newIntelAcc()
	acc.hostPorts = intelHostPortIndex(in)
	assetKeyByID := map[int64]string{}
	var firstAssetKey string

	for _, a := range in.Assets {
		ak := intelAssetKey(a, acc.hostPorts)
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
			acc.addEndpoint(method, a.URL, "", "asset", a.ID)
		}
		for _, tech := range a.Technologies {
			acc.addComponentRaw(tech, "asset", a.ID)
		}
		acc.addComponentsFromText(intelExtraText(a.Extra), "asset", a.ID)
	}

	for _, f := range in.Findings {
		text := strings.Join([]string{f.Summary, f.Evidence}, "\n")
		acc.addEndpointsFromText(text, intelFindingPurpose(f), "finding", f.ID)
		// 凭据的 service 若在正文里只剩路径（login.php），退回该 finding 的资产
		// host——凭据必须挂在主机上，不能挂在路径上。
		// 凭据不再从 finding 正文正则猜：agent 发现可用凭据时调 record_credential。
		// 正则版本把字段名/头名/扫描输出都写成凭据（shown: 65532 等），噪声不可控。
		_ = text
		acc.addComponentsFromText(text, "finding", f.ID)
		acc.addVuln(f, assetKeyByID, firstAssetKey)
	}
	for _, fact := range in.Facts {
		text := strings.Join([]string{fact.Summary, fact.Detail, fact.Evidence}, "\n")
		acc.addEndpointsFromText(text, intelClipRunes(fact.Summary, 60), "fact", fact.NodeID)
		// 同上：fact 正文也不再自动抽凭据。
		acc.addComponentsFromText(text, "fact", fact.NodeID)
	}
	return acc.rows(in.TaskID)
}

// intelFindingPurpose 取 finding 的"一句用途"：标题优先（缩写到 60 字），
// 标题为空才退回漏洞分类。取不到就返回空——情报表不编用途。
func intelFindingPurpose(f db.IntelFinding) string {
	s := strings.TrimSpace(f.Name)
	if s == "" {
		s = strings.TrimSpace(f.VulnClass)
	}
	return intelClipRunes(s, 60)
}

// intelClipRunes 按字符（不是字节）截断，避免把中文从中间切开。
func intelClipRunes(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n]))
}

// intelHostPortIndex 汇总全文出现过的 host → 端口（去重升序）。资产/凭据正文
// 常常只写主机名，而同任务的 URL 里带着端口；索引用于把裸主机补成 host:port。
func intelHostPortIndex(in intelBuildInput) map[string][]string {
	set := map[string]map[string]bool{}
	addHost := func(raw string) {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" {
			return
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			return
		}
		// 只记显式端口：这是"该主机在本任务用过哪个端口"的证据集，
		// 补默认端口会让唯一性判定失效（80 与 9081 并存 → 放弃补全）。
		port := u.Port()
		if port == "" {
			return
		}
		if set[host] == nil {
			set[host] = map[string]bool{}
		}
		set[host][port] = true
	}
	scan := func(text string) {
		for _, raw := range reIntelAbsURL.FindAllString(text, -1) {
			addHost(raw)
		}
		for _, m := range reIntelHostHeader.FindAllStringSubmatch(text, -1) {
			if s, ok := intelValidService(strings.TrimSpace(m[1])); ok {
				// 只采信显式端口：Host 头没写端口时补 80 是假设，不能当作
				// "该主机就是这个端口"的证据去改写资产键。
				if i := strings.LastIndex(s, ":"); i > 0 {
					if set[s[:i]] == nil {
						set[s[:i]] = map[string]bool{}
					}
					set[s[:i]][s[i+1:]] = true
				}
			}
		}
	}
	for _, a := range in.Assets {
		if a == nil {
			continue
		}
		addHost(a.URL)
		if a.Port != nil && *a.Port > 0 {
			host := strings.ToLower(strings.TrimSpace(a.Domain))
			if host == "" {
				host = strings.ToLower(strings.TrimSpace(a.IP))
			}
			if host != "" {
				if set[host] == nil {
					set[host] = map[string]bool{}
				}
				set[host][strconv.Itoa(*a.Port)] = true
			}
		}
	}
	for _, f := range in.Findings {
		scan(f.Summary + "\n" + f.Evidence)
	}
	for _, fact := range in.Facts {
		scan(fact.Summary + "\n" + fact.Detail + "\n" + fact.Evidence)
	}
	out := make(map[string][]string, len(set))
	for host, ports := range set {
		list := make([]string, 0, len(ports))
		for p := range ports {
			list = append(list, p)
		}
		sort.Strings(list)
		out[host] = list
	}
	return out
}

// intelDefaultPort 按 scheme 取默认端口（未知按 http/80：情报面里的服务几乎
// 都是 HTTP 系）。
func intelDefaultPort(scheme string) int {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "https", "wss":
		return 443
	default:
		return 80
	}
}

// intelPortForHost 取某主机在全文里唯一的端口；没有或多于一个都不猜。
func intelPortForHost(hostPorts map[string][]string, host string) string {
	ports := hostPorts[strings.ToLower(strings.TrimSpace(host))]
	if len(ports) != 1 {
		return ""
	}
	return ports[0]
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

// intelEndpointCtx 是一段正文里与接口同现的附加信息。按"段"（空行分隔）统计：
// auth_required 只在同段落出现鉴权线索时成立，避免一句 401 污染整篇。
type intelEndpointCtx struct {
	params      []string
	statusCodes []int
	auth        bool
	hosts       []string
}

// intelEndpointHit 是一条"正文里见过的接口"。抽取与覆盖率审计共用同一个
// 扫描函数（intelScanParagraph），保证两边规则永远一致。
type intelEndpointHit struct {
	method string
	target string // 绝对 URL 或 origin-form 路径，均已过形态校验
}

// addEndpoint 落一条绝对 URL 接口。只接受 http(s):// 开头、可被 url.Parse 解析、
// 路径以 "/" 开头且不含中文/全角字符的 URL；任何一项不满足就整条丢弃（宁可漏报，
// 也不让 "//127.0.0.1:9081，Apache/2.4.25" 这种残句进比对面）。
func (a *intelAcc) addEndpoint(method, rawurl, purpose, source string, sourceID int64) {
	u, ok := intelAbsoluteURL(rawurl)
	if !ok {
		return
	}
	a.addEndpointTarget(method, u, u, purpose, intelEndpointCtx{}, source, sourceID)
}

// addEndpointTarget 是 endpoint 的落库口：target 已通过形态校验，display 是
// value 侧原文（请求行只记路径，不记整行）。
func (a *intelAcc) addEndpointTarget(method, target, display, purpose string, ctx intelEndpointCtx, source string, sourceID int64) {
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
	if purpose != "" && e.purpose == "" {
		e.purpose = purpose
	}
	// 主机归属：绝对 URL 自带 host:port；相对路径用同段落/同文档里出现过的
	// URL/Host 头补（正文写过的归属，不是凭空补）。
	if host := hostOfURL(target); host != "" {
		e.hosts[host] = true
	} else {
		for _, h := range ctx.hosts {
			e.hosts[h] = true
		}
	}
	for _, p := range ctx.params {
		if len(e.params) >= intelMaxParams {
			break
		}
		e.params[p] = true
	}
	// URL 自带的 query 参数名也是该接口的参数。
	if u, err := url.Parse(strings.TrimSpace(target)); err == nil && u.RawQuery != "" {
		for k := range u.Query() {
			if len(e.params) >= intelMaxParams {
				break
			}
			if k = strings.TrimSpace(k); k != "" {
				e.params[k] = true
			}
		}
	}
	for _, sc := range ctx.statusCodes {
		e.statusCodes[sc] = true
	}
	if ctx.auth {
		e.authNeeded = true
	}
}

// intelMaxParams 是一条接口最多保留的参数名个数（情报表是"接口形状"摘要，
// 不是参数表；超过 12 个的多半是噪声或大表单）。
const intelMaxParams = 12

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

// addEndpointsFromText 从正文里抽接口。正文按空行切段，每段独立判定参数/
// 状态码/鉴权线索，再把结果附着到该段抽出的接口上；段落里没有 URL/Host 时
// 退回整篇的 host 集合（同一个 fact 的 Host 头可能写在下一行）。
func (a *intelAcc) addEndpointsFromText(text, purpose, source string, sourceID int64) {
	if strings.TrimSpace(text) == "" {
		return
	}
	docHosts := intelTextHosts(text)
	for _, para := range intelTextParagraphs(text) {
		if strings.TrimSpace(para) == "" {
			continue
		}
		ctx := intelEndpointCtx{
			params:      intelTextParamNames(para),
			statusCodes: intelTextStatusCodes(para),
			auth:        reIntelAuthHint.MatchString(para),
			hosts:       intelTextHosts(para),
		}
		// 段内没有 URL/Host 时，只有全文唯一主机才敢回填：多主机文档里回填
		// 等于给接口乱挂主机。
		if len(ctx.hosts) == 0 && len(docHosts) == 1 {
			ctx.hosts = docHosts
		}
		for _, hit := range intelScanParagraph(para) {
			a.addEndpointTarget(hit.method, hit.target, hit.target, purpose, ctx, source, sourceID)
		}
	}
}

// intelTextParagraphs 按空行切段（连续多个空行也算分隔）：鉴权/状态码的
// "同段落"判据就落在这里。
func intelTextParagraphs(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	parts := strings.Split(text, "\n\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

// intelScanParagraph 是一段正文 → 接口清单的唯一实现：抽取与覆盖率审计都走
// 这里，规则只有一份。命中按 (method,target) 段内去重，避免同一行既被请求行
// 又被裸 URL 命中而把 hit_count 翻倍。
func intelScanParagraph(para string) []intelEndpointHit {
	seen := map[string]bool{}
	out := make([]intelEndpointHit, 0, 4)
	appendHit := func(method, target string) {
		// 去重键按"缺省 GET"算：同一目标既被请求行命中又被引号路径命中时只记一次。
		m := strings.ToLower(strings.TrimSpace(method))
		if m == "" {
			m = "get"
		}
		id := m + "\x00" + target
		if target == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, intelEndpointHit{method: method, target: target})
	}
	for _, m := range reIntelReqLine.FindAllStringSubmatch(para, -1) {
		target := strings.TrimRight(m[2], intelURLTrailing)
		low := strings.ToLower(target)
		if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
			if s, ok := intelAbsoluteURL(target); ok {
				appendHit(m[1], s)
			}
			continue
		}
		if p, ok := intelRequestTarget(target); ok {
			appendHit(m[1], p)
		}
	}
	for _, m := range reIntelQuotedPath.FindAllStringSubmatch(para, -1) {
		if p, ok := intelQuotedPathTarget(m[1]); ok {
			appendHit("", p)
		}
	}
	for _, raw := range reIntelAbsURL.FindAllString(para, -1) {
		if s, ok := intelAbsoluteURL(raw); ok {
			appendHit("", s)
		}
	}
	return out
}

// intelQuotedPathTarget 判定反引号/引号里的裸路径算不算接口。只放行两类：
//  1. 带服务端脚本/动作后缀（.php/.jsp/.do/.action）；
//  2. 两段及以上的路径（/vulnerabilities/exec/）。
//
// 单段目录（/tmp、/etc）一律不算——那是文件系统路径，不是接口。
func intelQuotedPathTarget(p string) (string, bool) {
	p = strings.TrimSpace(strings.TrimRight(p, intelURLTrailing))
	if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return "", false
	}
	for _, r := range p {
		if r <= 0x20 || r > 0x7e {
			return "", false
		}
	}
	path := p
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	low := strings.ToLower(path)
	for _, ext := range []string{".php", ".jsp", ".do", ".action"} {
		if strings.HasSuffix(low, ext) {
			return p, true
		}
	}
	segs := 0
	for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
		if strings.TrimSpace(seg) != "" {
			segs++
		}
	}
	if segs >= 2 {
		return p, true
	}
	return "", false
}

// intelTextParamNames 取一段正文里的参数名（query/表单 name=value，只留名）。
func intelTextParamNames(text string) []string {
	set := map[string]bool{}
	for _, m := range reIntelParamAssign.FindAllStringSubmatch(text, -1) {
		name := strings.TrimSpace(m[1])
		if name == "" || len(set) >= intelMaxParams {
			continue
		}
		set[name] = true
	}
	return sortedKeys(set)
}

// intelTextStatusCodes 取一段正文里的 HTTP 状态码（"返回 200" / "HTTP/1.1 302"）。
func intelTextStatusCodes(text string) []int {
	set := map[int]bool{}
	for _, m := range reIntelHTTPStatus.FindAllStringSubmatch(text, -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil || n < 100 || n > 599 {
			continue
		}
		set[n] = true
	}
	return sortedIntVals(set)
}

// intelTextHosts 取一段正文里出现的主机（URL 的 host:port + Host 头），
// 归一化为 host:port；缺端口时按 scheme 补 80/443。
func intelTextHosts(text string) []string {
	set := map[string]bool{}
	add := func(raw string) {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" {
			return
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			return
		}
		port := u.Port()
		if port == "" {
			port = strconv.Itoa(intelDefaultPort(u.Scheme))
		}
		set[host+":"+port] = true
	}
	for _, raw := range reIntelAbsURL.FindAllString(text, -1) {
		add(raw)
	}
	for _, m := range reIntelHostHeader.FindAllStringSubmatch(text, -1) {
		if s, ok := intelValidService(strings.TrimSpace(m[1])); ok {
			// Host 头没写端口时按 http/80 补：明文 HTTP 证据里 Host 与端口同义。
			if !strings.Contains(s, ":") {
				s += ":80"
			}
			set[s] = true
		}
	}
	return sortedKeys(set)
}

// intelTextPaths 取一段正文里"提到过的接口路径"（请求行/引号路径/URL 路径），
// 用作凭据的 where_used：凭据和接口写在同一段里，就说明它在该接口用过。
func intelTextPaths(text string) []string {
	set := map[string]bool{}
	for _, hit := range intelScanParagraph(text) {
		p := intelPathOfTarget(hit.target)
		if p != "" {
			set[p] = true
		}
	}
	return sortedKeys(set)
}

// intelPathOfTarget 取接口目标里的路径部分（绝对 URL 取 Path，否则去掉 query）。
func intelPathOfTarget(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	if u, err := url.Parse(t); err == nil && u.Host != "" {
		if u.Path == "" {
			return "/"
		}
		return u.Path
	}
	if i := strings.IndexByte(t, '?'); i >= 0 {
		t = t[:i]
	}
	return t
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
	// 主机没带端口时，用同任务正文里出现过的唯一端口补齐（正文只写 127.0.0.1、
	// URL 里写的是 127.0.0.1:9081，同一台机器不该出现两个键）。
	if !strings.Contains(service, ":") {
		if p := intelPortForHost(a.hostPorts, service); p != "" {
			service += ":" + p
		}
	}
	// 同段落里出现的接口路径 = 该凭据的使用位置。
	used := intelTextPaths(text)

	for _, m := range reIntelPwdAssign.FindAllStringSubmatch(text, -1) {
		if !intelPasswordShape(m[1]) {
			continue
		}
		a.addCredential("password", user, service, m[1], "password=", used, source, sourceID)
	}
	for _, m := range reIntelBearer.FindAllStringSubmatch(text, -1) {
		a.addCredential("token", user, service, m[1], "authorization:bearer", used, source, sourceID)
	}
	for _, m := range reIntelCookie.FindAllStringSubmatch(text, -1) {
		a.addCredential("cookie", user, service, m[1], "cookie:", used, source, sourceID)
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
		// 高精度门槛：只接受「与显式 user=/account= 提示一致」或「常见特权账号」
		// 的 user:pass。纯 `xxx: yyy` 文本里字段名/头名/输出词太多（shown: 65532、
		// X-Forwarded-Host: evil.com、cmd: com.bokesoft…），不设门槛就会把整张
		// 页面的 JS 变量都写成凭据。
		if user == "" || !strings.EqualFold(rawUser, user) {
			if !reIntelCommonUsr.MatchString(rawUser) {
				continue
			}
		}
		// 口令形态：至少 6 位、不是数字/占位词/散文。`shown: 65532` 这类纯数字
		// 端口/计数一律丢弃。
		if !intelPasswordShape(secret) {
			continue
		}
		// host:port 过滤：`app.example.com:8080` 会被本模式误读成 user:pass，
		// 命中区间完全落在某个 host[:port] 里的一律跳过。
		if intelSpanInsideHost(m[2], m[5], hostSpans) {
			continue
		}
		a.addCredential("password", rawUser, service, secret, "user:pass", used, source, sourceID)
	}
	for _, m := range reIntelHash.FindAllStringSubmatch(text, -1) {
		a.addCredential("hash", user, service, m[1], "hex32/40", used, source, sourceID)
	}
	if reIntelPrivKey.MatchString(text) {
		a.addCredential("key", user, service, "PRIVATE KEY", "pem-private-key", used, source, sourceID)
	}
	for _, m := range reIntelSSHRSA.FindAllStringSubmatch(text, -1) {
		a.addCredential("key", user, service, m[1], "ssh-rsa", used, source, sourceID)
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

func (a *intelAcc) addCredential(kind, username, service, secret, pattern string, whereUsed []string, source string, sourceID int64) {
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
		masked := maskIntelSecret(secret)
		if masked == "" {
			if kind != "key" {
				return // 不像密文（散文/头部碎片）：不入凭据表
			}
			masked = "****"
		}
		e.secretMasked = masked
	}
	for _, p := range whereUsed {
		if len(e.whereUsed) >= intelMaxWhereUsed {
			break
		}
		if p != "" {
			e.whereUsed[p] = true
		}
	}
}

// intelMaxWhereUsed 是一条凭据最多记多少个使用位置。
const intelMaxWhereUsed = 8

// reIntelSecretShape 判定「像密文」的字符集（token/JWT/base64/hex/口令）。
// Cookie 正则抓的是整行，遇到散文（中文、空格、引号、括号）时会截进正文碎片；
// 这类字符串不展示掩码——前 2 后 2 的截断反而把正文带进详情页（实测出现
// 「re****估。」「us****]}」）。
var reIntelSecretShape = regexp.MustCompile(`^[A-Za-z0-9._~+/=:@\-]+$`)

// intelPasswordShape 判断一个「口令」是否像真的秘密：至少 6 位、不是纯数字
// （端口/计数/验证码）、不是 null/true/**** 之类的占位。宁可漏报，也不把
// nmap 输出或 JS 配置写成凭据。
func intelPasswordShape(s string) bool {
	s = strings.TrimSpace(strings.Trim(s, `"'`))
	if len([]rune(s)) < 6 {
		return false
	}
	lower := strings.ToLower(s)
	switch lower {
	case "null", "undefined", "true", "false", "password", "passwd", "pwd",
		"changeme", "notshown", "filtered", "open", "closed":
		return false
	}
	allDigit, allStar := true, true
	for _, r := range s {
		if r < '0' || r > '9' {
			allDigit = false
		}
		if r != '*' && r != '.' {
			allStar = false
		}
	}
	return !allDigit && !allStar
}

// maskIntelSecret 只留前 2 后 2 字符（≤4 字符全遮），返回值本身不含可用明文。
// 形如 "user_token=eyJ..." 的 cookie 只掩 = 后面的值部分。
func maskIntelSecret(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "="); i >= 0 && i < len(s)-1 {
		s = strings.TrimSpace(s[i+1:])
	}
	r := []rune(s)
	if len(r) <= 4 {
		return "****"
	}
	if len(r) > 128 || !reIntelSecretShape.MatchString(s) {
		return "" // 不是密文形态：宁可不展示，也不把正文碎片当掩码
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

// intelAssetKey 取资产的 host:port 键。口径（本单修正）：
//   - 有 URL：显式端口优先，无端口按 scheme 补 80/443；
//   - 无 URL：资产自带 port 优先；否则用同任务正文里该主机的唯一端口补齐；
//   - 都没有才退回裸 host（没有证据就绝不编端口）。
//
// 现有缺陷是 URL 缺端口时直接退化到裸 host（127.0.0.1），使资产键与接口/
// 凭据的 host:port 对不上，跨任务比对断链。
func intelAssetKey(a *db.Asset, hostPorts map[string][]string) string {
	if a == nil {
		return ""
	}
	if raw := strings.TrimSpace(a.URL); raw != "" {
		if u, ok := intelParseLooseURL(raw); ok {
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
			default:
				return host + ":80"
			}
		}
	}
	host := strings.ToLower(strings.TrimSpace(a.Domain))
	if host == "" {
		host = strings.ToLower(strings.TrimSpace(a.IP))
	}
	if host == "" {
		return ""
	}
	if a.Port != nil && *a.Port > 0 {
		return host + ":" + strconv.Itoa(*a.Port)
	}
	if p := intelPortForHost(hostPorts, host); p != "" {
		return host + ":" + p
	}
	return host
}

// intelParseLooseURL 解析"可能省略 scheme"的资产 URL：http://h:1/x、
// //h:1/x、h:1/x 都能解出 Host。
func intelParseLooseURL(raw string) (*url.URL, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false
	}
	if strings.HasPrefix(raw, "//") {
		raw = strings.TrimPrefix(raw, "//")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, false
	}
	return u, true
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
	e.vulnTitle = title
	e.findingIDs[f.ID] = true
}
