package db

// 任务情报表（V7-INTEL 第一层）：每个任务一份可直接比对的表（接口/凭据/
// 组件/资产/漏洞）。本文件负责三件事：
//
//  1. 归一化纯函数（NormalizeEndpoint / NormalizeComponent / NormalizeCredential）
//     ——跨任务能"比对"的前提是 key 稳定：数字/UUID 段折叠、版本截到
//     major.minor、query 只留参数名、凭据键小写定长。全部无副作用，单测直断言。
//  2. 落库/读取（UpsertTaskIntel / TaskIntelForTask / IntelSince）+ 跨任务勾连
//     结果表读写（SaveTaskIntelLink / ListTaskIntelLinks，供下一单）。
//  3. 抽取原料查询（TaskFindingsForIntel / TaskFactsForIntel）——抽取规则本身
//     在 server/task_intel_build.go（依赖 server 的拼装，db 不 import server）。
//
// 信号复用 project_graph_events（InsertGraphEvent），不新增事件表：本包只提供
// IntelDeltaSummary 纯函数拼摘要，写事件的动作由调用方（server）在 upsert 后做。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// TaskIntel 是 task_intel 的一行（任务情报表的可比对单元）。
type TaskIntel struct {
	ID        int64           `json:"id"`
	ProjectID int64           `json:"project_id"`
	TaskID    int64           `json:"task_id"`
	Kind      string          `json:"kind"`
	Key       string          `json:"key"`
	MatchKey  string          `json:"match_key"`
	Value     string          `json:"value"`
	Detail    json.RawMessage `json:"detail"`
	Source    string          `json:"source"`
	SourceID  *int64          `json:"source_id,omitempty"`
	// Rev 是全局变更序列（task_intel_rev_seq）：新增和内容变更都 bump。
	// 阅读者的增量读按它而不是 id —— id 只增不改，接口细节变丰富时读不到。
	Rev       int64     `json:"rev"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// 情报 kind 枚举（与 schema 的 CHECK 一致）。
const (
	IntelKindEndpoint   = "endpoint"
	IntelKindCredential = "credential"
	IntelKindComponent  = "component"
	IntelKindAsset      = "asset"
	IntelKindVuln       = "vuln"
)

// IntelKindLabel 是 kind 的中文短名（事件摘要"新增接口情报 3 条"用）。
func IntelKindLabel(kind string) string {
	switch kind {
	case IntelKindEndpoint:
		return "接口情报"
	case IntelKindCredential:
		return "凭据"
	case IntelKindComponent:
		return "组件"
	case IntelKindAsset:
		return "资产"
	case IntelKindVuln:
		return "漏洞"
	}
	return kind
}

// IntelDeltaSummary 纯函数：拼一条图变更摘要，形如
// `task#12 新增接口情报 3 条 / 凭据 1 条`。顺序固定（接口/凭据/组件/资产/
// 漏洞），只列数量 >0 的 kind；全 0 返回 ""（调用方跳过发事件）。
func IntelDeltaSummary(taskID int64, byKind map[string]int) string {
	order := []string{IntelKindEndpoint, IntelKindCredential, IntelKindComponent, IntelKindAsset, IntelKindVuln}
	parts := make([]string, 0, len(order))
	for _, k := range order {
		if n := byKind[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d 条", IntelKindLabel(k), n))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return fmt.Sprintf("task#%d 新增%s", taskID, strings.Join(parts, " / "))
}

// ---------------------------------------------------------------------------
// 归一化纯函数
// ---------------------------------------------------------------------------

// reNumeric / reUUID 复用 db/nkey.go 的同名包级变量（TemplatePath 也用它）；
// 本层把 UUID 也折叠成 {id}（而非 {uuid}）：跨任务比对只要"这是一个实例 id"，
// 不区分数字还是 UUID。
var reVersionLead = regexp.MustCompile(`^[vV]?(\d+)(?:\.(\d+))?`)

// NormalizeEndpoint 归一化一个接口：key = 小写 method + 路径（数字/UUID 段
// 折叠为 {id}，query 只保留参数名并按名字排序去值），value = 原始 URL。
//
// 例：POST https://h/api/user/123/profile?id=1&x=2
//
//	→ key "post /api/user/{id}/profile?id&x"，value 原串。
//
// 空 URL 返回空 key（调用方跳过）。method 为空按 GET 计。路径大小写保持原样
// （HTTP 路径大小写敏感），只有 method 小写。query 参数名排序是为了让
// "?a=1&b=2" 与 "?b=2&a=1" 视为同一接口——比对要的是接口形状，不是取值顺序。
func NormalizeEndpoint(method, rawurl string) (key, value string) {
	raw := strings.TrimSpace(rawurl)
	if raw == "" {
		return "", ""
	}
	m := strings.ToLower(strings.TrimSpace(method))
	target := raw
	u, err := url.Parse(target)
	if err != nil || (u.Scheme == "" && u.Host == "" && strings.Contains(target, " ")) {
		// 整行请求行（"POST /api/x HTTP/1.1"）或非法串：取 method + 目标两段重解析。
		fields := strings.Fields(target)
		if len(fields) >= 2 && isHTTPMethod(fields[0]) {
			if m == "" {
				m = strings.ToLower(fields[0])
			}
			target = fields[1]
			u, err = url.Parse(target)
		}
		if err != nil {
			u = &url.URL{Path: target}
			err = nil
		}
	}
	if m == "" {
		m = "get"
	}
	// "example.com/api/x"（省略 scheme）：补 http:// 才能解析出 Path。
	if u.Scheme == "" && u.Host == "" && !strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "?") {
		if pu, perr := url.Parse("http://" + target); perr == nil {
			u = pu
		}
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = foldIDPathSegments(p)
	if q := queryParamNames(u.Query()); q != "" {
		return m + " " + p + "?" + q, raw
	}
	return m + " " + p, raw
}

func isHTTPMethod(s string) bool {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT":
		return true
	}
	return false
}

// foldIDPathSegments 把纯数字段与 UUID 段折叠成 {id}：
// /api/user/123/profile → /api/user/{id}/profile。
func foldIDPathSegments(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if reNumeric.MatchString(s) || reUUID.MatchString(s) {
			segs[i] = "{id}"
		}
	}
	return strings.Join(segs, "/")
}

// queryParamNames 只取参数名（去值），排序去重后用 "&" 连接：
// ?id=1&x=2 → "id&x"。
func queryParamNames(v url.Values) string {
	if len(v) == 0 {
		return ""
	}
	names := make([]string, 0, len(v))
	for k := range v {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, "&")
}

// NormalizeComponent 归一化一个组件指纹：key = product@major.minor（product
// 小写去空格，版本截到前两段；无版本 → product@*），value = 人类可读原文。
//
// product 可带版本（"nginx/1.18.0" / "PHP:7.4.33" / "Apache 2.4.49"），
// version 参数为空时从 product 里拆。空输入返回空 key。
func NormalizeComponent(product, version string) (key, value string) {
	nameRaw := strings.TrimSpace(product)
	verRaw := strings.TrimSpace(version)
	if nameRaw == "" && verRaw == "" {
		return "", ""
	}
	if nameRaw == "" {
		nameRaw, verRaw = verRaw, ""
	}
	origProduct := nameRaw
	if verRaw == "" {
		if i := strings.IndexAny(nameRaw, "/:"); i > 0 {
			nameRaw, verRaw = nameRaw[:i], nameRaw[i+1:]
		}
	}
	name := strings.ToLower(strings.Join(strings.Fields(nameRaw), ""))
	if name == "" {
		return "", ""
	}
	mm := "*"
	if m := reVersionLead.FindStringSubmatch(strings.TrimSpace(verRaw)); m != nil {
		mm = m[1]
		if m[2] != "" {
			mm += "." + m[2]
		}
	}
	// value 用调用方原文：内嵌版本（"nginx/1.18.0"）不重复拼一次版本。
	value = origProduct
	if v := strings.TrimSpace(version); v != "" {
		value = strings.TrimSpace(origProduct + " " + v)
	}
	return name + "@" + mm, value
}

// 凭据 kind 白名单（与 schema/README 口径一致）。
var intelCredentialKinds = map[string]bool{
	"password": true, "hash": true, "token": true, "cookie": true, "key": true,
}

// ValidIntelCredentialKind 报告 kind 是否属于凭据枚举。
func ValidIntelCredentialKind(kind string) bool {
	return intelCredentialKinds[strings.ToLower(strings.TrimSpace(kind))]
}

// NormalizeCredential 归一化一条凭据：key = kind|username|service（全小写；
// username/service 为空用 "-"）。value 是人类可读的**脱敏描述**（如
// "password for admin@10.0.0.5"），绝不承载明文——明文只允许以
// detail.secret_masked（前 2 后 2）出现，由抽取侧负责。
//
// 空 kind / 非法 kind / username 与 service 同时为空 → 空 key（调用方跳过）：
// 一条没有任何归属的凭据无法参与"同账号同服务"的比对。
func NormalizeCredential(kind, username, service string) (key, value string) {
	k := strings.ToLower(strings.TrimSpace(kind))
	if !intelCredentialKinds[k] {
		return "", ""
	}
	uRaw := strings.TrimSpace(username)
	sRaw := strings.TrimSpace(service)
	if uRaw == "" && sRaw == "" {
		return "", ""
	}
	u := strings.ToLower(uRaw)
	if u == "" {
		u = "-"
	}
	s := strings.ToLower(sRaw)
	if s == "" {
		s = "-"
	}
	switch {
	case uRaw != "" && sRaw != "":
		value = k + " for " + uRaw + "@" + sRaw
	case uRaw != "":
		value = k + " for " + uRaw
	default:
		value = k + " for " + sRaw
	}
	return k + "|" + u + "|" + s, value
}

// IntelMatchKey 是纯函数：把一个精确情报键（kind+key）粗化成"跨任务可比对"
// 的匹配键。精确 key 适合断言"同一条情报"，但跨任务勾连要的是"同一层面的
// 东西"——方法不同（GET vs POST）、query 参数不同、组件小版本不同，都不该
// 让两个任务错过彼此。因此比对面拆成两层：
//
//	key       精确键（落库唯一约束、下钻展示用，不做放宽）
//	match_key 粗粒度键（request_reader_links 只按它比对）
//
// 规则（与 schema.sql 的存量回填表达式一致）：
//   - endpoint：去掉方法前缀与 query，只留路径；末尾 "/" 归一到恰好一个
//     （"get /vulnerabilities/sqli/?id" → "/vulnerabilities/sqli/"）。
//   - component：只留产品名（"mariadb@10.1" → "mariadb"）——版本差不该断链。
//   - asset：只留 host（"127.0.0.1:9081" → "127.0.0.1"）——端口差不该断链。
//   - credential：kind|username（丢掉 service）——凭据可跨端口复用。
//   - vuln：空串（标题做粗匹配会把"SQL 注入"这种泛词误连，宁可不连）。
//
// 空 kind / 空 key / 未知 kind 返回空串（调用方跳过该键）。
func IntelMatchKey(kind, key string) string {
	k := strings.ToLower(strings.TrimSpace(kind))
	key = strings.TrimSpace(key)
	if k == "" || key == "" {
		return ""
	}
	switch k {
	case IntelKindEndpoint:
		path := key
		// "method /path?params"：方法前缀只影响"怎么打"，不影响"打哪里"。
		if i := strings.IndexByte(path, ' '); i > 0 {
			path = strings.TrimSpace(path[i+1:])
		}
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		path = strings.TrimSpace(path)
		if path == "" {
			return ""
		}
		// 末尾斜杠归一：有则恰好保留一个，无则不补（与回填 SQL 同口径）。
		if strings.HasSuffix(path, "/") {
			path = strings.TrimRight(path, "/") + "/"
		}
		return path
	case IntelKindComponent:
		if i := strings.IndexByte(key, '@'); i >= 0 {
			return strings.TrimSpace(key[:i])
		}
		return key
	case IntelKindAsset:
		if i := strings.IndexByte(key, ':'); i >= 0 {
			return strings.TrimSpace(key[:i])
		}
		return key
	case IntelKindCredential:
		// 与回填 SQL 的 split_part(key,'|',1)||'|'||split_part(key,'|',2) 对齐。
		parts := strings.Split(key, "|")
		first := strings.TrimSpace(parts[0])
		second := ""
		if len(parts) > 1 {
			second = strings.TrimSpace(parts[1])
		}
		return first + "|" + second
	case IntelKindVuln:
		return ""
	}
	return ""
}

// ---------------------------------------------------------------------------
// 落库 / 读取
// ---------------------------------------------------------------------------

const taskIntelCols = `id, project_id, task_id, kind, key, match_key, value, detail, source, source_id, rev, created_at, updated_at`

// UpsertIntelResult 是一次批量写入的统计（信号摘要只报**新增**行数：重复生成
// 不产生新攻击面，不该反复唤醒 reader）。
type UpsertIntelResult struct {
	Total    int            `json:"total"`
	Inserted int            `json:"inserted"`
	Updated  int            `json:"updated"`
	// Unchanged 是内容与库里完全一致、没有 bump rev 的行数。ticker 每 5 分钟
	// 重抽一次，绝大多数行属于这一类；不区分的话"更新"会掩盖真实变化。
	Unchanged int            `json:"unchanged"`
	ByKind    map[string]int `json:"by_kind"` // kind → 本次新增条数
}

// UpsertTaskIntel 批量落一个任务的情报行，按 UNIQUE(project_id,task_id,kind,key)
// 幂等 upsert（value/detail/source 覆盖为最新计算值，created_at 保留首见时刻）。
// 整批一个事务：中途失败不留半份情报表。projectID<=0 或空 rows 为 no-op。
func (d *DB) UpsertTaskIntel(ctx context.Context, projectID, taskID int64, rows []TaskIntel) (UpsertIntelResult, error) {
	return d.upsertTaskIntel(ctx, projectID, taskID, rows, false)
}

// ReplaceTaskIntel 与 UpsertTaskIntel 相同，但在同一事务里先删除本任务由抽取
// 生成的行（source=finding/fact/asset），再写入新行——rebuild 用它把历史上抽错
// 的噪声行清掉。source=manual 的行保留；task_intel_links.matched 里的 key 不做
// 级联清理（链接是历史决策，保留原样）。
func (d *DB) ReplaceTaskIntel(ctx context.Context, projectID, taskID int64, rows []TaskIntel) (UpsertIntelResult, error) {
	return d.upsertTaskIntel(ctx, projectID, taskID, rows, true)
}

func (d *DB) upsertTaskIntel(ctx context.Context, projectID, taskID int64, rows []TaskIntel, replace bool) (UpsertIntelResult, error) {
	res := UpsertIntelResult{ByKind: map[string]int{}}
	if projectID <= 0 || taskID <= 0 {
		return res, nil
	}
	if len(rows) == 0 && !replace {
		return res, nil
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer tx.Rollback() //nolint:errcheck // 提交成功后是 no-op
	if replace {
		if _, err := tx.ExecContext(ctx, `DELETE FROM task_intel
WHERE task_id=$1 AND project_id=$2 AND source IN ('finding','fact','asset')`, taskID, projectID); err != nil {
			return UpsertIntelResult{ByKind: map[string]int{}}, err
		}
	}
	for _, r := range rows {
		detail := r.Detail
		if len(detail) == 0 || !json.Valid(detail) {
			detail = json.RawMessage(`{}`)
		}
		src := strings.TrimSpace(r.Source)
		if src == "" {
			src = "manual"
		}
		// match_key 是跨任务比对的粗粒度键：调用方没给就按 kind/key 现算，
		// 保证任何写入口（抽取行/手工行/rebuild）都不会漏。
		mk := strings.TrimSpace(r.MatchKey)
		if mk == "" {
			mk = IntelMatchKey(r.Kind, r.Key)
		}
		var inserted bool
		var rev int64
		// rev 是内容变更序列：只在 match_key/value/detail/source 真的变了时 bump。
		// 无条件 bump 会让 ticker 每 5 分钟把所有行重新推给阅读者，增量变全量。
		// WHERE 不成立时 DO UPDATE 不返回行（sql.ErrNoRows）= 内容未变。
		err := tx.QueryRowContext(ctx, `
INSERT INTO task_intel(project_id, task_id, kind, key, match_key, value, detail, source, source_id, rev)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, nextval('task_intel_rev_seq'))
ON CONFLICT (project_id, task_id, kind, key) DO UPDATE
SET match_key = EXCLUDED.match_key,
    value = EXCLUDED.value,
    detail = EXCLUDED.detail,
    source = EXCLUDED.source,
    source_id = EXCLUDED.source_id,
    rev = nextval('task_intel_rev_seq'),
    updated_at = now()
WHERE task_intel.match_key IS DISTINCT FROM EXCLUDED.match_key
   OR task_intel.value IS DISTINCT FROM EXCLUDED.value
   OR task_intel.detail IS DISTINCT FROM EXCLUDED.detail
   OR task_intel.source IS DISTINCT FROM EXCLUDED.source
   OR task_intel.source_id IS DISTINCT FROM EXCLUDED.source_id
RETURNING (xmax = 0), rev`,
			projectID, taskID, r.Kind, truncateRunes(utf8Clean(r.Key), 500), mk,
			truncateRunes(utf8Clean(r.Value), 2000), string(detail),
			truncateRunes(src, 32), r.SourceID).Scan(&inserted, &rev)
		if errors.Is(err, sql.ErrNoRows) {
			res.Total++
			res.Unchanged++
			continue
		}
		if err != nil {
			return UpsertIntelResult{ByKind: map[string]int{}}, err
		}
		res.Total++
		if inserted {
			res.Inserted++
			res.ByKind[r.Kind]++
		} else {
			res.Updated++
		}
	}
	if err := tx.Commit(); err != nil {
		return UpsertIntelResult{ByKind: map[string]int{}}, err
	}
	return res, nil
}

// TaskIntelScopeCounts 返回任务侧的 finding / intent 计数（任务小结 summary
// 的 counts 用：情报行只覆盖五类可比对单元，finding 与 intent 是任务的"工作量"
// 维度，单独查库，不从情报表推断）。
func (d *DB) TaskIntelScopeCounts(ctx context.Context, taskID int64) (findings, intents int, err error) {
	if taskID <= 0 {
		return 0, 0, nil
	}
	err = d.QueryRowContext(ctx, `
SELECT (SELECT COUNT(*) FROM findings WHERE task_id=$1),
       (SELECT COUNT(*) FROM exploration_nodes en
          JOIN tasks t ON t.exploration_id = en.exploration_id
         WHERE t.id=$1 AND en.kind='intent')`, taskID).Scan(&findings, &intents)
	return findings, intents, err
}

// TaskIntelForTask 返回某任务的全部情报行（kind 升序、key 升序，稳定可断言）。
func (d *DB) TaskIntelForTask(ctx context.Context, taskID int64) ([]TaskIntel, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+taskIntelCols+`
FROM task_intel WHERE task_id=$1 ORDER BY kind, key`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTaskIntelRows(rows)
}

// IntelSince 按 rev 水位增量读某项目的情报行（reader 侧用）。
//
// V11 起水位从 id 换成 rev：id 只增不改，接口行被 ticker 更新（purpose/params/
// status 变丰富）时按 id 读不到，阅读者会一直拿着旧版本比对。rev 在内容变更时
// bump，新增和更新都能被捕获。
//
// 返回 (rows, watermark)：watermark = 本批最大 rev（无行时等于 afterRev），
// 调用方下次传回即可；单批上限 500 行，循环调用直到 rows 为空。
func (d *DB) IntelSince(ctx context.Context, projectID, afterRev int64) ([]TaskIntel, int64, error) {
	if projectID <= 0 {
		return nil, afterRev, nil
	}
	rows, err := d.QueryContext(ctx, `SELECT `+taskIntelCols+`
FROM task_intel WHERE project_id=$1 AND rev>$2 ORDER BY rev LIMIT 500`, projectID, afterRev)
	if err != nil {
		return nil, afterRev, err
	}
	defer rows.Close()
	list, err := scanTaskIntelRows(rows)
	if err != nil {
		return nil, afterRev, err
	}
	watermark := afterRev
	for _, r := range list {
		if r.Rev > watermark {
			watermark = r.Rev
		}
	}
	return list, watermark, nil
}

func scanTaskIntelRows(rows *sql.Rows) ([]TaskIntel, error) {
	var out []TaskIntel
	for rows.Next() {
		var r TaskIntel
		var detail []byte
		var sourceID sql.NullInt64
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.TaskID, &r.Kind, &r.Key, &r.MatchKey, &r.Value,
			&detail, &r.Source, &sourceID, &r.Rev, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		if len(detail) == 0 {
			detail = []byte(`{}`)
		}
		r.Detail = json.RawMessage(detail)
		if sourceID.Valid {
			v := sourceID.Int64
			r.SourceID = &v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// 跨任务勾连结果（下一单的读写面；本单只落表 + 函数）
// ---------------------------------------------------------------------------

// TaskIntelLink 是 task_intel_links 的一行：发起方任务对某个候选任务给出
// 保留/舍弃决策，以及命中的情报明细。
type TaskIntelLink struct {
	ID            int64           `json:"id"`
	ProjectID     int64           `json:"project_id"`
	TaskID        int64           `json:"task_id"`
	RelatedTaskID int64           `json:"related_task_id"`
	Decision      string          `json:"decision"`
	Reason        string          `json:"reason"`
	Matched       json.RawMessage `json:"matched"`
	DecidedBy     string          `json:"decided_by"`
	// MatchStrength/MatchScore/MatchHits 是 SQL 侧命中打分（进候选的门槛）。
	// Strong = Σ≥2.0；Medium = Σ≥1.0（1 条精确或 2 条模糊）；Weak 不进候选。
	MatchStrength string  `json:"match_strength"`
	MatchScore    float64 `json:"match_score"`
	MatchHits     int     `json:"match_hits"`
	// RelevanceScore/RelevanceStrength 是阅读者读完整图后的相关性评分
	// （0-100，≥60 strong / 40-59 medium / <40 dismissed）。暴露门槛看它。
	RelevanceScore    int             `json:"relevance_score"`
	RelevanceStrength string          `json:"relevance_strength"`
	Chains            json.RawMessage `json:"chains"`
	GraphReadAt       *time.Time      `json:"graph_read_at,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

// ReaderChain 是阅读者判案时读到的一条利用链摘要。暴露给规划者的是它，
// 不是原始边：原始边是 (src,rel,dst) id 三元组，规划者要读懂必须逐个
// node_detail，成本高于收益；链摘要已经是编译过的语义。
type ReaderChain struct {
	Entry    string   `json:"entry"`    // 入口，如 "GET /api/sso/userinfo"
	Steps    []string `json:"steps"`    // 中间结论，["未校验 token 归属","遍历 user_id 读他人信息"]
	Outcome  string   `json:"outcome"`  // 终点，如 "越权读取"
	Verified bool     `json:"verified"` // 对方任务里是否已验证
	NodeIDs  []int64  `json:"node_ids"` // 出处节点，下钻用
}

// ValidIntelLinkDecision 报告决策是否属于 adopted|dismissed|candidate。
func ValidIntelLinkDecision(d string) bool {
	switch d {
	case "adopted", "dismissed", "candidate":
		return true
	}
	return false
}

// SaveTaskIntelLink 幂等写一条勾连决策（同 task_id+related_task_id 覆盖决策/
// 理由/命中明细），返回行 id。
func (d *DB) SaveTaskIntelLink(ctx context.Context, l TaskIntelLink) (int64, error) {
	if l.ProjectID <= 0 || l.TaskID <= 0 || l.RelatedTaskID <= 0 {
		return 0, fmt.Errorf("intel link: project/task/related task id required")
	}
	if !ValidIntelLinkDecision(l.Decision) {
		return 0, fmt.Errorf("intel link: invalid decision %q", l.Decision)
	}
	matched := l.Matched
	if len(matched) == 0 || !json.Valid(matched) {
		matched = json.RawMessage(`[]`)
	}
	chains := l.Chains
	if len(chains) == 0 || !json.Valid(chains) {
		chains = json.RawMessage(`[]`)
	}
	// 评分档位留空时按分数补：写入方可能只给分数（SQL 打分侧），也可能只给
	// 档位（阅读者判案侧）。两处都不给就保持空串，审计里显示"未评分"。
	ms := strings.ToLower(strings.TrimSpace(l.MatchStrength))
	rs := strings.ToLower(strings.TrimSpace(l.RelevanceStrength))
	var id int64
	err := d.QueryRowContext(ctx, `
INSERT INTO task_intel_links(project_id, task_id, related_task_id, decision, reason, matched, decided_by,
                             match_strength, match_score, match_hits,
                             relevance_score, relevance_strength, chains, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13, now())
ON CONFLICT (task_id, related_task_id) DO UPDATE
SET decision = EXCLUDED.decision,
    reason = EXCLUDED.reason,
    matched = EXCLUDED.matched,
    decided_by = EXCLUDED.decided_by,
    match_strength = COALESCE(NULLIF(EXCLUDED.match_strength,''), task_intel_links.match_strength),
    match_score = GREATEST(EXCLUDED.match_score, task_intel_links.match_score),
    match_hits = GREATEST(EXCLUDED.match_hits, task_intel_links.match_hits),
    relevance_score = GREATEST(EXCLUDED.relevance_score, task_intel_links.relevance_score),
    relevance_strength = COALESCE(NULLIF(EXCLUDED.relevance_strength,''), task_intel_links.relevance_strength),
    chains = CASE WHEN EXCLUDED.chains = '[]'::jsonb THEN task_intel_links.chains ELSE EXCLUDED.chains END,
    graph_read_at = CASE WHEN EXCLUDED.relevance_score > 0 THEN now() ELSE task_intel_links.graph_read_at END,
    updated_at = now()
RETURNING id`,
		l.ProjectID, l.TaskID, l.RelatedTaskID, l.Decision,
		truncateRunes(utf8Clean(l.Reason), 1000), string(matched),
		truncateRunes(utf8Clean(l.DecidedBy), 40),
		ms, l.MatchScore, l.MatchHits, l.RelevanceScore, rs, string(chains)).Scan(&id)
	return id, err
}

// taskIntelLinkCols 是 task_intel_links 的读取列，顺序与 scanTaskIntelLink 一致。
const taskIntelLinkCols = `id, project_id, task_id, related_task_id, decision, reason, matched, decided_by,
       match_strength, match_score, match_hits, relevance_score, relevance_strength, chains, graph_read_at,
       created_at, updated_at`

func scanTaskIntelLink(sc interface{ Scan(...any) error }) (TaskIntelLink, error) {
	var l TaskIntelLink
	var matched, chains []byte
	var graphRead sql.NullTime
	err := sc.Scan(&l.ID, &l.ProjectID, &l.TaskID, &l.RelatedTaskID,
		&l.Decision, &l.Reason, &matched, &l.DecidedBy,
		&l.MatchStrength, &l.MatchScore, &l.MatchHits, &l.RelevanceScore, &l.RelevanceStrength,
		&chains, &graphRead, &l.CreatedAt, &l.UpdatedAt)
	if err != nil {
		return l, err
	}
	if len(matched) == 0 {
		matched = []byte(`[]`)
	}
	if len(chains) == 0 {
		chains = []byte(`[]`)
	}
	l.Matched = json.RawMessage(matched)
	l.Chains = json.RawMessage(chains)
	if graphRead.Valid {
		t := graphRead.Time
		l.GraphReadAt = &t
	}
	return l, nil
}

// ListTaskIntelLinks 返回某发起方任务的全部勾连决策（新在前）。
func (d *DB) ListTaskIntelLinks(ctx context.Context, taskID int64) ([]TaskIntelLink, error) {
	rows, err := d.QueryContext(ctx, `
SELECT `+taskIntelLinkCols+`
FROM task_intel_links WHERE task_id=$1 ORDER BY id DESC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskIntelLink
	for rows.Next() {
		l, err := scanTaskIntelLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// 抽取原料
// ---------------------------------------------------------------------------

// IntelFinding 是抽取用的 finding 最小投影（列表/详情字段混在一起太胖，
// 情报表只要标题/严重度/正文/证据/关联资产）。
type IntelFinding struct {
	ID        int64
	Name      string
	VulnClass string
	Severity  string
	Summary   string
	Evidence  string
	AssetIDs  []int64
}

// TaskFindingsForIntel 取某任务的全部 findings（id 升序，保证重复生成稳定）。
func (d *DB) TaskFindingsForIntel(ctx context.Context, taskID int64) ([]IntelFinding, error) {
	rows, err := d.QueryContext(ctx, `
SELECT id, COALESCE(name,''), COALESCE(vulnclass,''), COALESCE(severity,''),
       COALESCE(summary,''), COALESCE(evidence,''), COALESCE(asset_ids, '{}')
FROM findings WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IntelFinding
	for rows.Next() {
		var f IntelFinding
		var aids string
		if err := rows.Scan(&f.ID, &f.Name, &f.VulnClass, &f.Severity, &f.Summary, &f.Evidence, &aids); err != nil {
			return nil, err
		}
		f.AssetIDs = parsePGIntArray(aids)
		out = append(out, f)
	}
	return out, rows.Err()
}

// IntelFact 是抽取用的 fact 投影。
type IntelFact struct {
	NodeID   int64
	Summary  string
	Detail   string
	Evidence string
}

// TaskFactsForIntel 取某任务的 fact 节点（kind='fact'，排除已否决/已删的
// dismissed/deleted 节点——被人工否掉的结论不该进情报面）。id 升序稳定。
func (d *DB) TaskFactsForIntel(ctx context.Context, taskID int64) ([]IntelFact, error) {
	rows, err := d.QueryContext(ctx, `
SELECT en.id, en.payload
FROM exploration_nodes en
JOIN tasks t ON t.exploration_id = en.exploration_id
WHERE t.id=$1 AND en.kind='fact' AND COALESCE(en.state,'') NOT IN ('dismissed','deleted')
ORDER BY en.id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IntelFact
	for rows.Next() {
		var id int64
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		out = append(out, IntelFact{
			NodeID:   id,
			Summary:  payloadText(m, "summary"),
			Detail:   payloadText(m, "detail", "description"),
			Evidence: payloadText(m, "evidence"),
		})
	}
	return out, rows.Err()
}

// payloadText 取 payload 里第一个非空字符串字段（字段值也可能是对象/数组，
// 统一 marshal 成文本，抽取侧只做正则扫描，不依赖结构）。
func payloadText(m map[string]any, keys ...string) string {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch s := v.(type) {
		case string:
			if strings.TrimSpace(s) != "" {
				return s
			}
		default:
			if b, err := json.Marshal(v); err == nil && len(b) > 2 {
				return string(b)
			}
		}
	}
	return ""
}

// parsePGIntArray 解析 `{1,2,3}` 形式的 BIGINT[] 文本（NULL 元素跳过）。
func parsePGIntArray(s string) []int64 {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	if s == "" {
		return nil
	}
	var out []int64
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" || part == "NULL" {
			continue
		}
		var n int64
		if _, err := fmt.Sscan(part, &n); err == nil {
			out = append(out, n)
		}
	}
	return out
}
