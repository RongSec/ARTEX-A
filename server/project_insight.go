package server

// T12 项目洞察 → planner 注入（架构 §2.4，裁决1 后的定稿语义）。
//
// 门控链（每 planner 轮现查，零缓存——统一阅读者开关翻转与洞察增删即时生效，
// 与 SetConstraintInject 同款「闭包每轮读」范式）：
//   任务存在 → 挂了项目 → 该项目统一阅读者开关为 true → 才可能注入。
//   （observer_enabled 主开关，reader_enabled 兼容别名，两列镜像同值。）
// 任一不满足返回 ""（planner 侧 projectInsightsRendered 见空串即整段不出现，
// prompt 与原版逐字节一致 = 三停收编后的"注入停"）。
// V6-U4：项目/跨项目两次查询保留为两个适配函数，但 U2 起内部都走
// project_insights 单表、按 scope='project' / scope='cross' 分流。
//
// 限量与命中：ListInsights(matchKeywords=当前任务 open 意图锚定资产的归一化
// 键) 让「与本任务正在打的资产相交」的洞察排最前，取 ≤3 条、每条正文截
// 200 rune、带「（来源任务#N）」回链。keywords 交集为空时退化为按时间新在
// 前补位——观察者攒的经验值得被看见，但绝不挤过直接命中的。
//
// V5-A 跨项目回流：同一预算（≤3 条）里项目洞察与跨项目条目按配额分配
// （V5-C 障碍3：项目洞察最多 2 条；存在可注入跨项目行时项目洞察压到 2，
// 至少给跨项目留 1 位；跨项目最多 2 条）。project_insights 中 scope='cross'
// 且 status='active' 且 asset_keys 与本任务命中键相交的条目才注入；该项目
// reader_enabled=false 时整段跨项目条目都不注入（兼容别名与主开关镜像同值，
// 与写出侧 readerVisibleProjects 同一 opt-in 口径）。跨项目条目额外带
// 「仅作假设」标注。
//
// V5-C 命中键来源（障碍1，三级并集，任一级非空即停）：
//   a. 本探索图 state IN ('open','running') 的意图锚定资产（running 也很常见：
//      带锚定的种子意图一生成就被 worker 认领）；
//   b. assets.task_ids 命中本任务的资产；
//   c. 任务名称/目标文本里的 host:port 或域名（轻量正则提取）。
//
// 键形（障碍2）：每个资产产出父子两级键（host、host:port、host:port/path），
// asset_keys 的 `&&` 交集因此支持站点级 ↔ 页面级互含。

import (
	"context"
	"log"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"golang.org/x/net/publicsuffix"
)

const (
	insightInjectMax      = 3   // 每轮最多注入条数（token 预算：3×200 字有上限）
	insightInjectMaxRunes = 200 // 单条正文截断
	// V5-C 障碍3 配额：项目洞察/跨项目洞察各自的上限。跨项目存在时项目洞察
	// 压到 insightProjectMax，保证跨项目至少 1 位（旧实现项目洞察先占满 3，
	// 项目 3 有 18 条洞察时跨项目永远拿不到名额）。
	insightProjectMax = 2
	insightCrossMax   = 2
	// insightCrossScanMax 是跨项目条目的扫描上限：SQL limit 之后还要按
	// asset_keys 交集数在 Go 侧排序（交集多的优先），扫 2 条会漏掉后面的强命中。
	insightCrossScanMax = 50
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
// V5-C：命中键三级并集（意图锚定 → 任务资产 → 目标文本），配额按
// insightQuota 分配。项目洞察渲染在前、跨项目条目在后（顺序不变）。
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
		// V6-U4 统一阅读者：单一开关闸门。tctx.Enabled 取主开关
		// observer_enabled（reader_enabled 是镜像兼容别名、与它同值）；关则
		// 整段零注入（三停之一"注入停"，原版逐字节一致）。下面两次查询保留
		// 为适配函数，U2 起内部各走 project_insights 单表、按 scope 分流。
		if !tctx.Enabled {
			return ""
		}
		// 命中原料：三级并集（障碍1）。查询抖动按「该级为空」降级，绝不因旁路
		// 查询报错把整段注入打掉。
		match := s.insightMatchKeys(ctx, pg, tctx, taskID)
		var projectList []db.Insight
		// 项目洞察：ListInsights 内部走单表 scope='project'（U2）。
		if tctx.ObserverOn {
			list, err := pg.ListInsights(ctx, tctx.ProjectID, match, insightInjectMax)
			if err != nil {
				insightWarner.warn("ListInsights", taskID, err)
				return ""
			}
			projectList = list
		}
		var crossKept []db.GlobalInsight
		// 跨项目洞察：ListCrossProjectInsights 内部走单表 scope='cross'（U2）。
		if tctx.ReaderOn && len(match) > 0 {
			cross, err := pg.ListCrossProjectInsights(ctx, match, insightCrossScanMax)
			if err != nil {
				insightWarner.warn("ListCrossProjectInsights", taskID, err)
			} else {
				// 按交集数→时间排序并截到跨项目配额（障碍3）。
				crossKept = filterInjectableCross(cross, match, true, insightCrossMax)
			}
		}
		projectN, crossN := insightQuota(len(projectList), len(crossKept))
		var parts []string
		if projectN > 0 {
			if body := renderProjectInsights(projectList[:projectN]); body != "" {
				parts = append(parts, body)
			}
		}
		if crossN > 0 {
			if body := renderCrossProjectInsight(crossKept[:crossN]); body != "" {
				parts = append(parts, body)
			}
		}
		return strings.Join(parts, "\n")
	}
}

// insightMatchKeys 是 V5-C 障碍1 的三级并集命中键来源（任一级非空即停止）：
//
//	a. 探索图里 state IN ('open','running') 的意图锚定资产；
//	b. assets.task_ids 命中本任务的资产；
//	c. 任务名称/目标文本里的 host:port 或域名（extractHostKeys，纯函数）。
//
// 各级查询失败只 warn 并视该级为空，继续降级——注入是旁路，不该因一次
// 查询抖动整段消失。
func (s *Server) insightMatchKeys(ctx context.Context, pg *db.DB, tctx *db.TaskInsightContext, taskID int64) []string {
	keysForIDs := func(ids []int64) []string {
		if len(ids) == 0 {
			return nil
		}
		keys, err := pg.AssetKeysForIDs(ids)
		if err != nil {
			insightWarner.warn("AssetKeysForIDs", taskID, err)
			return nil
		}
		return keys
	}
	// a. 意图锚定（open+running）
	if ids, err := pg.IntentAnchorAssetIDs(ctx, tctx.ExplorationID); err != nil {
		insightWarner.warn("IntentAnchorAssetIDs", taskID, err)
	} else if keys := keysForIDs(ids); len(keys) > 0 {
		return keys
	}
	// b. 本任务资产
	if ids, err := pg.TaskAssetIDs(ctx, taskID); err != nil {
		insightWarner.warn("TaskAssetIDs", taskID, err)
	} else if keys := keysForIDs(ids); len(keys) > 0 {
		return keys
	}
	// c. 目标文本轻量提取
	return extractHostKeys(tctx.TaskName + " " + tctx.TaskGoal)
}

// insightQuota 是纯函数：按「项目洞察/跨项目洞察」的可用条数分配总预算
// （≤insightInjectMax）。规则：
//   - 无跨项目可注入行 → 项目洞察可用满 3；
//   - 有跨项目行 → 项目洞察压到 2，至少给跨项目留 1 位；
//   - 跨项目最多 2 条，总数绝不超过 3（项目 0 条时跨项目也只能拿 2）。
func insightQuota(projectAvailable, crossAvailable int) (projectN, crossN int) {
	if projectAvailable < 0 {
		projectAvailable = 0
	}
	if crossAvailable < 0 {
		crossAvailable = 0
	}
	projectN = projectAvailable
	if projectN > insightInjectMax {
		projectN = insightInjectMax
	}
	if crossAvailable == 0 {
		return projectN, 0
	}
	if projectN > insightProjectMax {
		projectN = insightProjectMax
	}
	crossN = insightInjectMax - projectN
	if crossN > insightCrossMax {
		crossN = insightCrossMax
	}
	if crossN > crossAvailable {
		crossN = crossAvailable
	}
	return projectN, crossN
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

// renderCrossProjectInsight 纯函数：跨项目洞察 → 注入正文。每条一行：
//
//   - 【跨项目】来源项目#2/#3：正文（洞察#12，来自其他项目，仅作假设，须在本目标验证）
//
// 与项目洞察刻意不同：①【跨项目】提示来源层级；② 末尾钉死不确定性标注——
// 跨项目经验是「别的目标上成立」的假设，直接照搬会误导本任务（尤其资产相同
// 但版本/权限模型不同时）。SourceProjects 为空时省来源段。截断与项目洞察共用
// truncateInsightContent（同一 token 预算口径）。空列表返回 ""。
func renderCrossProjectInsight(list []db.GlobalInsight) string {
	if len(list) == 0 {
		return ""
	}
	var b strings.Builder
	for i, g := range list {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("- 【跨项目】")
		if refs := crossProjectSourceRefs(g.SourceProjects); refs != "" {
			b.WriteString("来源项目#")
			b.WriteString(refs)
			b.WriteString("：")
		}
		b.WriteString(truncateInsightContent(g.Content))
		b.WriteString("（")
		if g.ID > 0 {
			b.WriteString("洞察#")
			b.WriteString(strconv.FormatInt(g.ID, 10))
			b.WriteString("，")
		}
		b.WriteString("来自其他项目，仅作假设，须在本目标验证）")
	}
	return b.String()
}

// crossProjectSourceRefs 把来源项目 id 列表渲染成 "2/#3" 风格的引用串
// （调用方在其前拼「来源项目#」，最终成「来源项目#2/#3」）。去重、保持入参
// 顺序、非正值丢弃。空=不写来源段。
func crossProjectSourceRefs(ids []int64) string {
	seen := make(map[int64]bool, len(ids))
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		ref := strconv.FormatInt(id, 10)
		if len(parts) > 0 {
			ref = "#" + ref
		}
		parts = append(parts, ref)
	}
	return strings.Join(parts, "/")
}

// filterInjectableCross 是纯函数：把 ListCrossProjectInsights 的结果再按注入
// 规则裁一遍（SQL 已过滤 active/交集，这里做防御 + 可无库单测的语义单源）：
//   - readerOn=false（projects.reader_enabled 关）→ 全空，绝不注入；
//   - match 为空（本任务无锚定资产键）→ 全空（无据可验的跨项目经验只会有害）；
//   - status≠active（含 superseded/rejected，以及未显式赋值的零值按 active）→ 剔除；
//   - asset_keys 与 match 无交集 → 剔除；
//   - 按「交集键数降序 → 时间降序（入参序，SQL 已按时间排）」稳定排序，
//     最后按 limit 截断（跨项目配额，障碍3）。
func filterInjectableCross(list []db.GlobalInsight, match []string, readerOn bool, limit int) []db.GlobalInsight {
	if !readerOn || len(match) == 0 || limit <= 0 {
		return nil
	}
	want := make(map[string]bool, len(match))
	for _, m := range match {
		if k := strings.ToLower(strings.TrimSpace(m)); k != "" {
			want[k] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	type hitRow struct {
		insight db.GlobalInsight
		hits    int
	}
	rows := make([]hitRow, 0, len(list))
	for _, g := range list {
		// 零值（测试/历史构造）按 active 处理；只有显式非 active 才剔除。
		if g.Status != "" && g.Status != db.InsightStatusActive {
			continue
		}
		hits := 0
		for _, k := range g.AssetKeys {
			if want[strings.ToLower(strings.TrimSpace(k))] {
				hits++
			}
		}
		if hits == 0 {
			continue
		}
		rows = append(rows, hitRow{insight: g, hits: hits})
	}
	// 稳定排序：交集多的优先；交集数相同保留入参序（SQL 的 created_at DESC），
	// 双保险再比一次时间，避免调用方传入乱序时结果不稳定。
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].hits != rows[j].hits {
			return rows[i].hits > rows[j].hits
		}
		return rows[i].insight.CreatedAt.After(rows[j].insight.CreatedAt)
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	out := make([]db.GlobalInsight, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.insight)
	}
	return out
}
