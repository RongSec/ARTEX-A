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
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

const (
	insightInjectMax      = 3   // 每轮最多注入条数（token 预算：3×200 字有上限）
	insightInjectMaxRunes = 200 // 单条正文截断
)

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
		if err != nil || !tctx.ObserverOn || tctx.ProjectID <= 0 {
			return "" // 任务不存在/未挂项目/观察者关——三停之一的"注入停"
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
		if err != nil || len(list) == 0 {
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
