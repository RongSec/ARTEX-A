package server

// T14(2/2)：复现步骤 ↔ 流量自动关联的 server 装配（架构 §4.2）。
//
// report_finding 拿到 agent 填的结构化 reproduction 后，在【落库前】由 host
// 回调把每一步的逐字 request/response 解析成本任务时间窗内真实录制的 exchange
// id（traffic.ResolveSteps：method+path 收窄→body/query/响应判别词逐级细化→
// 最早候选；多义 abstain）。解析是旁路增强：流量库不可用/任务行缺失/任何
// 失败 → 原样返回入参（复现文本照记不误，view-time 再兜底），绝不影响登记。

import (
	"encoding/json"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/report"
	"github.com/Autumn-27/artex/traffic"
)

// reproExchangeIDs 把 reproduction JSON 里每步未填的 exchange_id 用时间窗
// [first_run_at|created_at, now] 内的真实流量补齐（唯一候选才绑，宁缺毋滥）。
// 返回增强后的 JSON；解不动/无流量库/无候选时原样返回。已回填的步骤保留原
// exchange_id、不重复解析。落库（record-time）与查看（view-time）共用——
// 后者可补上「先报漏洞、流量稍后才落盘」的时序空档。
func reproExchangeIDs(tr *traffic.Traffic, sinceUnix, untilUnix int64, raw json.RawMessage) json.RawMessage {
	if tr == nil || len(raw) <= 2 { // ""/"{}" 都短于 3 字节
		return raw
	}
	var rp report.Reproduction
	if json.Unmarshal(raw, &rp) != nil || len(rp.Steps) == 0 {
		return raw
	}
	refs := make([]traffic.StepRef, len(rp.Steps))
	for i, st := range rp.Steps {
		refs[i] = traffic.StepRef{Request: st.Request, Response: st.Response}
	}
	ids := tr.ResolveSteps(sinceUnix, untilUnix, refs)
	changed := false
	for i, id := range ids {
		if id != "" && rp.Steps[i].ExchangeID == "" {
			rp.Steps[i].ExchangeID = id
			changed = true
		}
	}
	if !changed {
		return raw
	}
	out, err := json.Marshal(rp)
	if err != nil {
		return raw
	}
	return out
}

// reproResolverFor 是装配进 worker/planner/mainagent ToolSet 的回调闭包
// （SetReproResolver 注入面）：每次调用现查任务行拿时间窗（低频：只在真发生
// report_finding 且 agent 填了 reproduction 时才被调，不缓存防过期）。
// traffic 为 nil（未开录制）时回调返回原样 = 与不装该功能逐字节等价。
func (s *Server) reproResolverFor() agent.ReproResolver {
	return func(taskID int64, repro json.RawMessage) json.RawMessage {
		tr := s.m.Traffic()
		if tr == nil || taskID <= 0 {
			return repro
		}
		since := time.Now().Add(-24 * time.Hour) // 任务行缺失的兜底窗口
		if tk, err := s.m.PG().GetTask(taskID); err == nil {
			if tk.FirstRunAt != nil {
				since = *tk.FirstRunAt
			} else {
				since = tk.CreatedAt
			}
		}
		return reproExchangeIDs(tr, since.Unix(), time.Now().Unix(), repro)
	}
}
