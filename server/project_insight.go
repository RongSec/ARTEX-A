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
		if !tctx.ObserverOn || tctx.ProjectID <= 0 {
			return "" // 未挂项目/观察者关——三停之一的"注入停"
		}
		// 命中原料：本任务 open 意图锚定的资产 → 归一化键。任一环节失败退化为
		// 无关键词（时间序补位）——注入是锦上添花，绝不该因查询抖动报错。
		var match []string
		if ids, err := pg.OpenIntentAnchorAssetIDs(ctx, tctx.ExplorationID); err == nil && len(ids) > 0 {
			if keys, err := pg.AssetKeysForIDs(ids); err == nil {
				match = keys
			}
		}
		list, err := pg.ListInsights(ctx, tctx.ProjectID, match, insightInjectMax)
		if err != nil {
			insightWarner.warn("ListInsights", taskID, err)
			return ""
		}
		if len(list) == 0 {
			return ""
		}
		return renderProjectInsights(list)
	}
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
		content := strings.TrimSpace(in.Content)
		if utf8.RuneCountInString(content) > insightInjectMaxRunes {
			content = string([]rune(content)[:insightInjectMaxRunes]) + "…"
		}
		b.WriteString("- ")
		if in.SourceTaskID > 0 {
			b.WriteString("来源任务#")
			b.WriteString(strconv.FormatInt(in.SourceTaskID, 10))
			b.WriteString("：")
		}
		b.WriteString(content)
	}
	return b.String()
}
