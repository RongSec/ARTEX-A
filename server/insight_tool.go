package server

// V5-A planner 的洞察否决工具（reject_insight）。
//
// 为什么需要：跨项目洞察注入 planner 后，「别人的经验」可能与本目标的事实冲突
// （版本不同、权限模型不同）。planner 是唯一掌握本任务全图的一方，让它能把某条
// 洞察显式标成 rejected，比每次都在 prompt 里重复忍受同一条噪声更省 token，也让
// 后续轮次/任务不再被同一条误导。
//
// 落点：只置 status='rejected' + rejected_reason，绝不物理删（人工复核/回滚仍需
// 原文）。工具是 host 工具（server 层持有 pg），装配后按 tools 表 agents 过滤——
// seed 时只绑 planner，worker/mainagent 看不到（照 report_finding 的绑定方式）。
// 审计走既有的 tool usage 计量通道（assembly.go ToolResolve → meterTool），与其它
// 工具同一条账。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// toolRejectInsight 把一条洞察置为 rejected。
//
// 语义细节（对应任务书的幂等/越权要求）：
//   - id 不存在 → 返回「未找到」文本，不报错（模型可以继续干活，不因一次误判
//     的 id 中断整轮）；
//   - 已 rejected 再拒 → 幂等成功文本（无副作用，不重复改 reason）；
//   - kind 只认 project/global，其他值明确报错（防模型瞎填把两类表混淆）。
func (s *Server) toolRejectInsight() actool.CoreTool {
	return wrTool("reject_insight",
		"否决一条洞察（后续注入不再包含它）。kind=project(本项目观察者洞察)/global(跨项目阅读者洞察)，id 用洞察的 id，"+
			"reason 写一句为什么在本目标不成立（如「版本不同/该入口已修复/资产非同一实例」）。"+
			"仅当洞察的结论与本任务已确认的事实冲突、或明显不适用时用；不要用它表达「还没试」。"+
			"id 不存在会返回未找到（不算失败），重复否决是幂等的。",
		objSchema(map[string]any{
			"kind":   map[string]any{"type": "string", "enum": []any{"project", "global"}, "description": "洞察类型：project=项目洞察(project_insights) / global=跨项目洞察(global_insights)"},
			"id":     map[string]any{"type": "integer", "description": "洞察 id（注入行里带的来源 id）"},
			"reason": strParam("否决原因（一句话，落库供人工复核）"),
		}, "kind", "id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Kind   string          `json:"kind"`
				ID     json.RawMessage `json:"id"`
				Reason string          `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			kind := strings.ToLower(strings.TrimSpace(a.Kind))
			if kind != "project" && kind != "global" {
				return actool.Errorf("kind 必须是 project 或 global"), nil
			}
			id := parseProfileID(a.ID) // 复用「数字或数字字符串」解析
			if id <= 0 {
				return actool.Errorf("id 无效"), nil
			}
			if s.m == nil || s.m.pg == nil {
				return actool.Errorf("洞察存储不可用"), nil
			}
			changed, err := s.m.pg.RejectInsight(ctx, kind, id, a.Reason)
			if errors.Is(err, db.ErrInsightNotFound) {
				return actool.Text(fmt.Sprintf("未找到 %s insight#%d（可能已被删除），未做任何改动", kind, id)), nil
			}
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if !changed {
				return actool.Text(fmt.Sprintf("%s insight#%d 已是 rejected，无需重复否决", kind, id)), nil
			}
			return actool.Text(fmt.Sprintf("%s insight#%d 已标记 rejected，后续注入将不再包含", kind, id)), nil
		})
}
