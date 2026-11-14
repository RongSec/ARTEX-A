package server

// T12 项目洞察 → planner 注入（架构 §2.4，裁决1 后的定稿语义）。
//
// 门控链（每 planner 轮现查，零缓存——开关翻转与洞察增删即时生效，与
// SetConstraintInject 同款「闭包每轮读」范式）：
//   任务存在 → 挂了项目 → 项目段（scope='project'）看 observer_enabled。
//
// V7-LINK：跨项目自动注入已拆除。reader_enabled 不再决定「往 planner prompt
// 里塞什么」，只作为 request_reader_links(scope=cross) 的闸门——跨项目情报改由
// planner 主动申请、自己下钻判断（详见 server/task_intel_link.go）。本文件只
// 保留项目内洞察注入，planner 侧 projectInsightsRendered 见空串即整段不出现，
// prompt 与原版逐字节一致 = 三停收编后的"注入停"。
//
// 限量与命中：ListInsights(matchKeywords=当前任务 open 意图锚定资产的归一化
// 键) 让「与本任务正在打的资产相交」的洞察排最前，取 ≤3 条、每条正文截
// 200 rune、带「（来源任务#N）」回链。keywords 交集为空时退化为按时间新在
// 前补位——跨任务阅读者攒的经验值得被看见，但绝不挤过直接命中的。
//
// 命中键来源（障碍1，三级并集，任一级非空即停）：
//   a. 本探索图 state IN ('open','running') 的意图锚定资产（running 也很常见：
//      带锚定的种子意图一生成就被 worker 认领）；
//   b. assets.task_ids 命中本任务的资产；
//   c. findings.asset_ids 命中本任务的资产（已落库发现的关联资产）；
//   d. 任务名称/目标文本里的 host:port 或域名（轻量正则提取）；
//   e. 任务/项目名称与描述的分词（长度≥3、去停用词；弱键，仅用于洞察
//      keywords 打分，不参与 asset_keys 交集）。
//
// 键形（障碍2）：每个资产产出父子两级键（host、host:port、host:port/path），
// asset_keys 的 `&&` 交集因此支持站点级 ↔ 页面级互含。

import (
	"context"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"golang.org/x/net/publicsuffix"
)

const (
	insightInjectMax      = 3   // 每轮最多注入条数（token 预算：3×200 字有上限）
	insightInjectMaxRunes = 200 // 单条正文截断
	// insightWarnEvery 是洞察链路 DB 错误的告警限频（照 project_indexer 的
	// maybeWarnDrop 30s 范式）。OBS-1：resolver 出错→静默返回 "" 会让「四个
	// planner 轮无注入」这类故障完全无线索，必须留一条 warn；但每轮一条会
	// 刷屏，所以 30s 至多一条、带累计计数。
	insightWarnEvery = 30 * time.Second
)

// insightErrWarner 限频告器（一次构造、跨 planner 轮共享，CAS 防并发刷屏）。
// 返回是否真的打了这条日志（测试可直调断言，不劫持全局 log 输出）。
type insightErrWarner struct {
	last       atomic.Int64 // 上次告警时刻（unix nano）
	suppressed atomic.Int64 // 距上次告警后被限频吞掉的错误数
}

func (w *insightErrWarner) warn(what string, taskID int64, err error) {
	ts := time.Now().UnixNano()
	n := w.suppressed.Add(1)
	last := w.last.Load()
	if ts-last < int64(insightWarnEvery) {
		return
	}
	if !w.last.CompareAndSwap(last, ts) {
		return
	}
	w.suppressed.Store(0)
	log.Printf("[project-insight] %s 查询失败（task %d，%.0fs 内另有 %d 次同类错误被限频）：注入静默跳过 =%v", what, taskID, insightWarnEvery.Seconds(), n-1, err)
}

// insightWarner 是包级单例：全局限频（resolver 每任务一构造，per-task 实例会
// 让刷屏按任务数翻倍；OBS-1 要的是「出错了看得见」而非「谁出的错」）。
var insightWarner insightErrWarner

// projectInsightResolverFor 构造 planner 的洞察渲染闭包。只捕获 pg（无状态），
// taskID 由 planner 每轮 Plan 传入（engine.go:880 的 taskIDInt=DB 任务 id，与
// TaskInsightContext 的 t.id 查询同源）。
//
// 命中键（五级，见 insightMatchSources）分两档：Anchors（资产键，可与
// asset_keys 精确求交）与 Weak（名称/描述分词，只参与项目洞察 keywords 打分）。
// V7-LINK 起只注入项目内洞察：跨项目情报由 planner 调 request_reader_links
// 主动申请，不在 prompt 里自动出现。
func (s *Server) projectInsightResolverFor() func(taskID int64) string {
	pg := s.m.pg
	return func(taskID int64) string {
		if pg == nil || taskID <= 0 {
			return ""
		}
		ctx := context.Background()
		tctx, err := pg.TaskInsightContext(ctx, taskID)
		if err != nil {
			// OBS-1：区分「查询失败静默」与「三停正常空转」——后者是预期空串
			// 不该告警，前者必须留限频线索。
			insightWarner.warn("TaskInsightContext", taskID, err)
			return ""
		}
		if tctx.ProjectID <= 0 {
			return "" // 未挂项目
		}
		// 项目内洞察只看 observer_enabled（跨任务/项目内尺度）。reader_enabled
		// 从 V7-LINK 起不再决定 prompt 注入。
		if !tctx.ObserverOn {
			return ""
		}
		// 命中原料：五级并集，查询抖动按「该级为空」降级，绝不因旁路查询报错
		// 把整段注入打掉。
		match := s.insightMatchSources(ctx, pg, tctx, taskID)
		// 项目洞察：ListInsights 内部走单表 scope='project'（U2）。
		list, err := pg.ListInsights(ctx, tctx.ProjectID, match.keys(), insightInjectMax)
		if err != nil {
			insightWarner.warn("ListInsights", taskID, err)
			return ""
		}
		return buildInsightBody(tctx, list)
	}
}

// insightMatch 是命中原料的两档：
//   - Anchors：资产键（意图锚定 / 任务资产 / finding 资产 / 目标文本 host），
//     用于和 project_insights.asset_keys 精确求交；
//   - Weak：任务/项目名称与描述的分词，只用于项目洞察 keywords 打分与
//     「本任务在做什么」的弱信号，绝不当作资产键做交集（否则 "canal" 这类
//     组件名会误命中 asset_keys）。
type insightMatch struct {
	Anchors []string
	Weak    []string
}

// keys 返回两档并集（小写去重、保序），供 ListInsights 的 keywords 打分。
func (m insightMatch) keys() []string { return mergeInsightKeys(m.Anchors, m.Weak) }

// buildInsightBody 是纯函数：resolver 的 SQL 之后全部逻辑（observer 闸门 +
// 渲染）都在这里，测试可直构 tctx 与候选行、无需数据库。
//
// V7-LINK：跨项目段已移除，body 只可能是项目洞察（或空串）。
func buildInsightBody(tctx *db.TaskInsightContext, projectList []db.Insight) string {
	if tctx == nil || !tctx.ObserverOn {
		return ""
	}
	return renderProjectInsights(projectList)
}

// insightMatchSources 是命中原料的五级并集（前三级任一级非空即停止，后两级
// 只在无资产键时补弱键）：
//
//	a. 探索图里 state IN ('open','running') 的意图锚定资产；
//	b. assets.task_ids 命中本任务的资产；
//	c. findings.asset_ids 命中本任务的资产（已落库发现的关联资产，新维度）；
//	d. 任务名称/目标文本里的 host:port 或域名（extractHostKeys，纯函数）；
//	e. 任务/项目名称与描述的分词（tokenizeInsightKeywords，纯函数）——弱键，
//	   只参与项目洞察 keywords 打分，不参与 asset_keys 交集。
//
// 各级查询失败只 warn 并视该级为空，继续降级——注入是旁路，不该因一次
// 查询抖动整段消失。c 级放在 d 级前：真实资产比文本提取可靠。
func (s *Server) insightMatchSources(ctx context.Context, pg *db.DB, tctx *db.TaskInsightContext, taskID int64) insightMatch {
	resolve := func(ids []int64) []string {
		keys, err := pg.AssetKeysForIDs(ids)
		if err != nil {
			insightWarner.warn("AssetKeysForIDs", taskID, err)
			return nil
		}
		return keys
	}
	anchorIDs, err := pg.IntentAnchorAssetIDs(ctx, tctx.ExplorationID)
	if err != nil {
		insightWarner.warn("IntentAnchorAssetIDs", taskID, err)
		anchorIDs = nil
	}
	taskIDs, err := pg.TaskAssetIDs(ctx, taskID)
	if err != nil {
		insightWarner.warn("TaskAssetIDs", taskID, err)
		taskIDs = nil
	}
	findingIDs, err := pg.TaskFindingAssetIDs(ctx, taskID)
	if err != nil {
		insightWarner.warn("TaskFindingAssetIDs", taskID, err)
		findingIDs = nil
	}
	text := strings.Join([]string{tctx.TaskName, tctx.TaskGoal, tctx.ProjectName}, " ")
	return collectInsightMatch(anchorIDs, taskIDs, findingIDs, resolve, text)
}

// insightMatchKeys 保留旧签名（既有测试与调用方）：返回两档并集。需要区分
// 强/弱键时直接用 insightMatchSources 的 Anchors，别拿 Weak 当资产键。
func (s *Server) insightMatchKeys(ctx context.Context, pg *db.DB, tctx *db.TaskInsightContext, taskID int64) []string {
	return s.insightMatchSources(ctx, pg, tctx, taskID).keys()
}

// collectInsightMatch 是纯函数（除 resolve 回调外无 IO）：按 a→b→c→d→e 五级
// 取键，前四级任一非空即返回 Anchors；全空才返回 e 级弱键。
// resolve 负责把资产 id 解析成归一化键（生产=AssetKeysForIDs，测试可注入假表）。
func collectInsightMatch(anchorIDs, taskIDs, findingIDs []int64, resolve func([]int64) []string, text string) insightMatch {
	keysFor := func(ids []int64) []string {
		if len(ids) == 0 || resolve == nil {
			return nil
		}
		return mergeInsightKeys(resolve(ids))
	}
	// a. 意图锚定（open+running）
	if keys := keysFor(anchorIDs); len(keys) > 0 {
		return insightMatch{Anchors: keys}
	}
	// b. 本任务资产
	if keys := keysFor(taskIDs); len(keys) > 0 {
		return insightMatch{Anchors: keys}
	}
	// c. 本任务 finding 的关联资产（没有就跳过）
	if keys := keysFor(findingIDs); len(keys) > 0 {
		return insightMatch{Anchors: keys}
	}
	// d. 目标文本轻量提取
	if keys := mergeInsightKeys(extractHostKeys(text)); len(keys) > 0 {
		return insightMatch{Anchors: keys}
	}
	// e. 名称/描述分词（弱键）
	return insightMatch{Weak: tokenizeInsightKeywords(text)}
}

// mergeInsightKeys 是纯函数：多组键并集，小写去重、保序、丢空串。
func mergeInsightKeys(groups ...[]string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, g := range groups {
		for _, k := range g {
			k = strings.ToLower(strings.TrimSpace(k))
			if k == "" || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// insightKeywordMinRunes 是分词键的最小 rune 数（中英文同阈：挡 "go"/"a"
// 这类噪声，也挡 2 字泛词压过真正的组件名）。
const (
	insightKeywordMinRunes = 3
	insightKeywordMaxHan   = 12 // 汉字片段超过该长度按 3 字窗口近似分词
	insightKeywordMax      = 32 // 单任务分词键上限（防长 goal 撑爆匹配数组）
)

// insightKeywordStopwords 是分词停用词：通用动词/连接的英文词与泛化中文词。
// 只影响「弱键」召回，不影响资产键（Anchors）的任何一级。
var insightKeywordStopwords = map[string]bool{
	// 英文
	"the": true, "and": true, "for": true, "with": true, "from": true,
	"this": true, "that": true, "http": true, "https": true, "www": true,
	"task": true, "goal": true, "test": true, "use": true, "not": true,
	"all": true, "any": true, "can": true, "you": true, "are": true,
	// 中文（整段命中才剔除；长句会走 3 字窗口，泛词另有条目）
	"测试": true, "任务": true, "目标": true, "系统": true, "服务": true,
	"进行": true, "通过": true, "一个": true, "这个": true, "可以": true,
	"我们": true, "需要": true, "使用": true, "以及": true, "相关": true,
	"信息": true, "功能": true, "漏洞": true, "问题": true, "方法": true,
}

// tokenizeInsightKeywords 是纯函数：把任务/项目名称与描述切成弱键。
// 规则（无词典的轻量近似，宁少勿滥）：
//   - 按「汉字段 / 拉丁字母数字段 / 其他分隔符」切段；
//   - 拉丁段：小写、长度≥3、去停用词，纯数字段丢弃（端口/版本号是噪声）；
//   - 汉字段：长度≥3 且 ≤12 整段保留；更长的按 3 字滑动窗口切（近似分词）；
//   - 去重、保序、总数上限 insightKeywordMax。
func tokenizeInsightKeywords(text string) []string {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" {
		return nil
	}
	seen := make(map[string]bool)
	out := make([]string, 0, 8)
	add := func(tok string) {
		if len(out) >= insightKeywordMax {
			return
		}
		if utf8.RuneCountInString(tok) < insightKeywordMinRunes || insightKeywordStopwords[tok] {
			return
		}
		if seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	var seg []rune
	segHan := false
	flush := func() {
		if len(seg) == 0 {
			return
		}
		if !segHan {
			allDigit := true
			for _, r := range seg {
				if !unicode.IsDigit(r) {
					allDigit = false
					break
				}
			}
			if !allDigit {
				add(string(seg))
			}
		} else if len(seg) <= insightKeywordMaxHan {
			add(string(seg))
		} else {
			for i := 0; i+insightKeywordMinRunes <= len(seg); i++ {
				add(string(seg[i : i+insightKeywordMinRunes]))
			}
		}
		seg = seg[:0]
	}
	for _, r := range text {
		switch {
		case unicode.Is(unicode.Han, r):
			if len(seg) > 0 && !segHan {
				flush()
			}
			segHan = true
			seg = append(seg, r)
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			if len(seg) > 0 && segHan {
				flush()
			}
			segHan = false
			seg = append(seg, r)
		default:
			flush()
		}
	}
	flush()
	return out
}

var (
	// reGoalHostPort 匹配 [host:port]：host 是带点的域名或 IPv4 字面量。
	// 只用于从任务目标文本里做轻量提取（障碍1 第三级），命不中最多退化为
	// 无关键词，不承担精确解析职责。
	reGoalHostPort = regexp.MustCompile(`(?i)\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b`)
	// reGoalHost 匹配裸主机名（域名或 IPv4）。
	reGoalHost = regexp.MustCompile(`(?i)\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})\b`)
)

// extractHostKeys 是纯函数：从任务名称/目标文本里轻量提取资产键。
// 产出 host:port 与 host（父键），小写去重；host 需是合法 IP 或 ICANN 域名
// （publicsuffix 校验，挡掉 "login.php" 这类把路径当域名的误命中）。
// 文本里没有资产线索时返回 nil（调用方据此判定「三级全空才不注入」）。
func extractHostKeys(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(k string) {
		if k == "" || seen[k] {
			return
		}
		seen[k] = true
		out = append(out, k)
	}
	for _, m := range reGoalHostPort.FindAllStringSubmatch(text, -1) {
		host := strings.ToLower(m[1])
		if !validGoalHost(host) {
			continue
		}
		port, err := strconv.Atoi(m[2])
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		add(net.JoinHostPort(host, strconv.Itoa(port)))
		add(host)
	}
	for _, m := range reGoalHost.FindAllStringSubmatch(text, -1) {
		host := strings.ToLower(m[1])
		if validGoalHost(host) {
			add(host)
		}
	}
	return out
}

// validGoalHost 判定提取到的 host 是否值得当资产键：IP 字面量合法，或域名
// 的公共后缀是 ICANN 注册后缀（"login.php" 的 "php" 不是，直接丢弃）。
func validGoalHost(host string) bool {
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if !strings.Contains(host, ".") {
		return false
	}
	_, icann := publicsuffix.PublicSuffix(host)
	return icann
}

// truncateInsightContent 是两条渲染路径共用的正文规整：trim + 按 rune 截
// insightInjectMaxRunes，截断补省略号（绝不切半字节）。
func truncateInsightContent(content string) string {
	content = strings.TrimSpace(content)
	if utf8.RuneCountInString(content) > insightInjectMaxRunes {
		return string([]rune(content)[:insightInjectMaxRunes]) + "…"
	}
	return content
}

// renderProjectInsights 纯函数：洞察列表 → 注入正文（不含段标题——标题由
// planner 侧 projectInsightsRendered 统一加，口径单源）。每条一行：
// 「- 来源任务#N：正文」，正文按 rune 截 insightInjectMaxRunes；
// SourceTaskID<=0 时省「来源任务#N：」前缀段。空列表返回 ""。
func renderProjectInsights(list []db.Insight) string {
	if len(list) == 0 {
		return ""
	}
	var b strings.Builder
	for i, in := range list {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("- ")
		if in.SourceTaskID > 0 {
			b.WriteString("来源任务#")
			b.WriteString(strconv.FormatInt(in.SourceTaskID, 10))
			b.WriteString("：")
		}
		b.WriteString(truncateInsightContent(in.Content))
		if in.ID > 0 {
			// 行尾带洞察 id：planner 的 reject_insight 靠它定位（注入行里唯一
			// 可操作的句柄；「来源任务#N」是任务 id，不是洞察 id）。
			b.WriteString("（洞察#")
			b.WriteString(strconv.FormatInt(in.ID, 10))
			b.WriteString("）")
		}
	}
	return b.String()
}
