package server

// T12 项目洞察 → planner 注入（架构 §2.4，裁决1 后的定稿语义）。
//
// 门控链（每 planner 轮现查，零缓存——projects.observer_enabled 翻转与洞察
// 增删即时生效，与 SetConstraintInject 同款「闭包每轮读」范式）：
//   任务存在 → 挂了项目 → 该项目 observer_enabled=true → 才可能注入。
// 任一不满足返回 ""（planner 侧 projectInsightsRendered 见空串即整段不出现，
// prompt 与原版逐字节一致 = 三停收编后的"注入停"）。
//
// 限量与命中：ListInsights(matchKeywords=当前任务 open 意图锚定资产的归一化
// 键) 让「与本任务正在打的资产相交」的洞察排最前，取 ≤3 条、每条正文截
// 200 rune、带「（来源任务#N）」回链。keywords 交集为空时退化为按时间新在
// 前补位——观察者攒的经验值得被看见，但绝不挤过直接命中的。
//
// V5-A 跨项目回流：同一预算（≤3 条）里项目洞察优先占位，剩余名额给
// global_insights 中 status='active' 且 asset_keys 与本任务锚定键相交的条目；
// 该项目 projects.reader_enabled=false 时整段跨项目条目都不注入（与写出侧
// readerVisibleProjects 同一 opt-in 口径）。跨项目条目额外带「仅作假设」标注。

import (
	"context"
	"log"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
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
	last     atomic.Int64 // 上次告警时刻（unix nano）
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
// V5-A 跨项目回流：项目洞察（observer）占位在前，剩余名额给「asset_keys 与本
// 任务锚定键相交」的 active global_insights（reader 产出），总条数仍 ≤3。
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
		// 项目洞察看 observer_enabled，跨项目条目看 reader_enabled（V5-A：与写出
		// 侧 readerVisibleProjects 同阈，避免绕过项目级 opt-in）。两者全关=三停之一
		// 的"注入停"，原版逐字节零注入。
		if !tctx.ObserverOn && !tctx.ReaderOn {
			return ""
		}
		// 命中原料：本任务 open 意图锚定的资产 → 归一化键。任一环节失败退化为
		// 无关键词（时间序补位）——注入是锦上添花，绝不该因查询抖动报错。
		var match []string
		if ids, err := pg.OpenIntentAnchorAssetIDs(ctx, tctx.ExplorationID); err == nil && len(ids) > 0 {
			if keys, err := pg.AssetKeysForIDs(ids); err == nil {
				match = keys
			}
		}
		var parts []string
		used := 0
		if tctx.ObserverOn {
			list, err := pg.ListInsights(ctx, tctx.ProjectID, match, insightInjectMax)
			if err != nil {
				insightWarner.warn("ListInsights", taskID, err)
				return ""
			}
			if body := renderProjectInsights(list); body != "" {
				parts = append(parts, body)
				used = len(list)
			}
		}
		// 剩余名额给跨项目条目（项目洞察优先占位：哪怕项目侧只有 1 条，跨项目也
		// 只能拿 2 条）。查全量再按剩余名额裁，limit 由 filterInjectableCross 管。
		if remaining := insightInjectMax - used; tctx.ReaderOn && remaining > 0 {
			cross, err := pg.ListCrossProjectInsights(ctx, match, insightInjectMax)
			if err != nil {
				insightWarner.warn("ListCrossProjectInsights", taskID, err)
			} else if kept := filterInjectableCross(cross, match, true, remaining); len(kept) > 0 {
				parts = append(parts, renderCrossProjectInsight(kept))
			}
		}
		return strings.Join(parts, "\n")
	}
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
//   - 最后按 limit 截断（剩余名额，项目洞察优先占位）。
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
	out := make([]db.GlobalInsight, 0, len(list))
	for _, g := range list {
		// 零值（测试/历史构造）按 active 处理；只有显式非 active 才剔除。
		if g.Status != "" && g.Status != db.InsightStatusActive {
			continue
		}
		hit := false
		for _, k := range g.AssetKeys {
			if want[strings.ToLower(strings.TrimSpace(k))] {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		out = append(out, g)
		if len(out) >= limit {
			break
		}
	}
	return out
}
