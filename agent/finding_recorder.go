package agent

import (
	"context"
	"encoding/json"

	"github.com/Autumn-27/artex/db"
)

// FindingRecorder is injected by the host; agents never synthesize or copy
// evidence bodies themselves. Its implementation owns the atomic write.
type FindingRecorder interface {
	Record(context.Context, db.RecordFindingInput, []db.TrafficRef) (*db.RecordedFinding, error)
}

// Tool-use guidance is appended without replacing the user's editable prompt.
// It does not require capture or claim that unavailable traffic tools exist.
const findingTrafficGuidance = "\n\n**漏洞流量证据（可选）**：调用 report_finding 上报漏洞时，如有已查看并确认支持漏洞结论的 HTTP 请求/响应，可用 traffic_refs 按复现顺序绑定真实 ID；域名和时间只作候选筛选，不推定关联。TCP 等非 HTTP 漏洞、未采集或无确切匹配时省略或传 []，在 evidence 保留命令输出、日志等其他可验证证据，建议说明未绑定原因。不要猜测 ID，也不要仅为补包重复探测。"

func (t *ToolSet) SetFindingRecorder(r FindingRecorder)   { t.findingRecorder = r }
func (w *Worker) SetFindingRecorder(r FindingRecorder)    { w.findingRecorder = r }
func (p *Planner) SetFindingRecorder(r FindingRecorder)   { p.findingRecorder = r }
func (m *MainAgent) SetFindingRecorder(r FindingRecorder) { m.findingRecorder = r }

// ReproEnricher is the host-side callback that back-fills a finding's
// structured reproduction with real recorded exchange ids AFTER the finding row
// is durably written. The agent handler invokes it asynchronously (go …) so it
// is non-blocking: report_finding returns immediately with the finding saved,
// and enrichment (traffic ResolveSteps → UPDATE findings.reproduction) lands a
// moment later. It is best-effort by contract — the implementation owns its
// own panic-recovery and logging and MUST NOT surface errors back into the
// tool path, so a traffic failure can NEVER fail or corrupt the finding write.
// The signature takes the persisted finding_id + owning task_id and the raw
// reproduction the agent submitted; nil = feature not wired = original behavior.
type ReproEnricher func(findingID, taskID int64, repro json.RawMessage)

func (t *ToolSet) SetReproEnricher(r ReproEnricher)   { t.reproEnricher = r }
func (w *Worker) SetReproEnricher(r ReproEnricher)    { w.reproEnricher = r }
func (p *Planner) SetReproEnricher(r ReproEnricher)   { p.reproEnricher = r }
func (m *MainAgent) SetReproEnricher(r ReproEnricher) { m.reproEnricher = r }
