package server

// T14(2/2)：复现步骤 ↔ 流量自动关联的 server 装配（架构 §4.2）。
//
// report_finding 拿到 agent 填的结构化 reproduction 后，finding【先完整落库】
// （steps 尚无 exchange_id），再由 host 回调在【后台协程】里把每一步的逐字
// request/response 解析成本任务时间窗内真实录制的 exchange id
// （traffic.ResolveSteps：method/host/path 端点谓词 → body/query/响应判别词
// 逐级软收窄 → 最早候选；多义/零命中 abstain），最后 UPDATE findings.reproduction
// 回填。整条链路是旁路增强：任何失败（流量库未开/任务行缺失/JSON 非法/PG 抖
// 动）只 log 一行，绝不回抛——登记路径已在异步派发前完成，本回调失败对 finding
// 零影响。view-time（getFinding）再兜底一次，补上「先报漏洞、流量稍后才落盘」
// 的时序空档。
//
// 关联的落点选择：写 findings.reproduction JSONB 内的 steps[].exchange_id，
// 而不是 finding_traffic_bindings 表——后者语义是「人工核实过的证据绑定」
// （role=baseline/proof/...、参与 evidence_version 计数、reporter 逐条核对后
// 写入），自动关联未经人工确认、绑错即污染证据；steps[].exchange_id 是
// 「步骤→流量」的溯源提示（宁缺毋滥 + view-time 兜底），与 T14(1/2) schema
// 注释为列内回填预留的消费语义（T16 证据穿插按 step_index 取包）一致。

import (
	"encoding/json"
	"log"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
	"github.com/Autumn-27/artex/traffic"
)

// reproEnricherFor 是装配进 worker/planner/mainagent ToolSet 的异步回调
// （SetReproEnricher 注入面）。闭包在后台协程里执行，独占自己的一切失败：
// panic 一律 recover，PG/SQLite 错误只 log。绝不与 finding 写入路径共享事务——
// finding 早已提交，这里做的是「之后尽力补关联」。
func (s *Server) reproEnricherFor() agent.ReproEnricher {
	return func(findingID, taskID int64, repro json.RawMessage) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[repro] finding %d 异步关联 panic（已吞，不影响登记）: %v", findingID, r)
			}
		}()
		if s.m == nil || findingID <= 0 {
			return
		}
		tr := s.m.Traffic()
		if tr == nil || !db.HasReproSteps(repro) {
			return // 未开流量/无步骤：本回调零行为，finding 保持原样
		}
		var rp report.Reproduction
		if json.Unmarshal(repro, &rp) != nil || len(rp.Steps) == 0 {
			return
		}
		since, until := s.taskTrafficWindow(taskID)
		ids := resolveReproSteps(tr, since.Unix(), until.Unix(), rp.Steps)
		changed := false
		for i, id := range ids {
			if id != "" && rp.Steps[i].ExchangeID == "" {
				rp.Steps[i].ExchangeID = id
				changed = true
			}
		}
		if !changed {
			return
		}
		out, err := json.Marshal(rp)
		if err != nil {
			return
		}
		if err := s.m.PG().UpdateFindingReproduction(findingID, out); err != nil {
			log.Printf("[repro] finding %d 回填 exchange_id 失败: %v", findingID, err)
		}
	}
}

// resolveReproSteps is the shared narrowing entry: hand the step texts (plus
// the task window) to the traffic resolver. Returns per-step exchange ids
// ("" = abstain).
func resolveReproSteps(tr *traffic.Traffic, sinceUnix, untilUnix int64, steps []report.ReproStep) []string {
	refs := make([]traffic.StepRef, len(steps))
	for i, st := range steps {
		refs[i] = traffic.StepRef{Request: st.Request, Response: st.Response}
	}
	return tr.ResolveSteps(sinceUnix, untilUnix, refs)
}

// taskTrafficWindow returns the [start, now] window to search exchanges in.
// start = tasks.first_run_at（任务首次真正开跑、流量开始录制的时刻），退到
// created_at，任务行缺失时兜底滚动 24h。until = now（流量可能在 finding 之后
// 的微秒级才落盘）。
func (s *Server) taskTrafficWindow(taskID int64) (time.Time, time.Time) {
	since := time.Now().Add(-24 * time.Hour)
	if tk, err := s.m.PG().GetTask(taskID); err == nil && tk != nil {
		if tk.FirstRunAt != nil {
			since = *tk.FirstRunAt
		} else {
			since = tk.CreatedAt
		}
	}
	return since, time.Now()
}

// viewReproExchangeIDs is the getFinding view-time back-fill: it takes a
// stored reproduction JSON (from the findings column), runs the SAME resolver
// over steps still missing exchange_id, and returns the enriched JSON —
// WITHOUT persisting. The read-only fallback covers findings recorded before
// the async enricher could land a match (traffic arrived after the report, or
// a transient failure). Persisting on read is deliberately avoided: it would
// couple a GET handler's latency to SQLite/PG writes and race concurrent
// viewers. Empty raw / no traffic / no unresolved steps → input passthrough.
func (s *Server) viewReproExchangeIDs(raw json.RawMessage, taskID *int64) json.RawMessage {
	if s.m == nil || !db.HasReproSteps(raw) || taskID == nil || *taskID <= 0 {
		return raw
	}
	tr := s.m.Traffic()
	if tr == nil {
		return raw
	}
	var rp report.Reproduction
	if json.Unmarshal(raw, &rp) != nil || len(rp.Steps) == 0 {
		return raw
	}
	// 只对「还缺 exchange_id」的步再解析；整份复现的时序由原始顺序约束。
	pending := make([]report.ReproStep, 0, len(rp.Steps))
	indexes := make([]int, 0, len(rp.Steps))
	for i, st := range rp.Steps {
		if st.ExchangeID == "" {
			pending = append(pending, st)
			indexes = append(indexes, i)
		}
	}
	if len(pending) == 0 {
		return raw
	}
	since, until := s.taskTrafficWindow(*taskID)
	ids := resolveReproSteps(tr, since.Unix(), until.Unix(), pending)
	changed := false
	for j, id := range ids {
		if id != "" {
			rp.Steps[indexes[j]].ExchangeID = id
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
