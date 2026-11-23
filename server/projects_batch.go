package server

// T06 批量下发：POST /api/projects/{id}/batch-tasks。
// 拆行（handler 层）→ 逐行走现成建任务内部逻辑（CreateTaskWithOptions 带
// ProjectID）→ 建后**不调 launchTask**，改 EnqueueTaskProjectBatch 落
// queued=true ∧ queue_mode='project_batch' → 任务停在「待项目调度」，由
// T07 projectDispatcher 按项目额度认领放行。不造第二套等待态：等待态就是
// 原版队列三元组（queued/queued_at/queue_mode），只是 mode 值换了消费方。

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// maxBatchCreate 是单次批量下发的行数上限（照 maxBatchControlIDs 范式，
// 建任务比批量暂停重，给 200）。
const maxBatchCreate = 200

// splitBatchTargets 把 textarea 文本拆成目标行。语义已升级为 ParseTargets
// （V12-TARGET）：除空行/重复外，还剔除非法的域名/IP/URL，并返回 invalid 供
// 前端核对。前端「解析」按钮用同一套规则做即时预览。
func splitBatchTargets(text string) (targets, skipped, invalid []string) {
	r := ParseTargets(text)
	return r.Targets, r.Duplicate, r.Invalid
}

// batchCreateReq 是批量下发入参。common 继承原版建任务参数面（对照
// createTaskReq 的子集：不做 source/company/intercept_rules 这类单任务语义）。
type batchCreateReq struct {
	Targets     string `json:"targets"` // 一行一目标
	Concurrency *int   `json:"concurrency,omitempty"`
	Common      struct {
		NamePrefix           string  `json:"name_prefix,omitempty"`
		DescTemplate         string  `json:"desc_template,omitempty"` // 含 {target} 占位；空=「目标：{target}」
		CategoryID           *int64  `json:"category_id,omitempty"`
		LLMProfileIDs        []int64 `json:"llm_profile_ids,omitempty"`
		TimeoutSeconds       int     `json:"timeout_seconds,omitempty"`
		PlanHeartbeatSeconds int     `json:"plan_heartbeat_seconds,omitempty"`
		SeedFirstIntent      *bool   `json:"seed_first_intent,omitempty"`
		CoverageEnabled      *bool   `json:"coverage_enabled,omitempty"`
		// Credentials 是本批任务要用的凭据池。每条可带 target 指定适用目标，
		// 留空=全部目标；落库到目标资产的 auth（agent 用 list_assets 可读）。
		Credentials []TaskCredentialInput `json:"credentials,omitempty"`
	} `json:"common"`
}

// projectsBatchTasks 拆行建 N 任务、全部落 queued 不即跑。
// 返回 201 {created:[id...], skipped:[line...], project_id, concurrency}。
func (s *Server) projectsBatchTasks(w http.ResponseWriter, r *http.Request) {
	pid, ok := projectIDParam(w, r)
	if !ok {
		return
	}
	proj, err := s.m.PG().GetProject(pid)
	if errors.Is(err, db.ErrProjectNotFound) {
		writeErr(w, 404, "项目不存在")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if proj.Status != "active" {
		writeErr(w, 400, "项目已归档，不能批量下发（先恢复为 active）")
		return
	}
	var req batchCreateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	targets, skipped, invalid := splitBatchTargets(req.Targets)
	if len(targets) == 0 {
		writeErr(w, 400, "targets 为空（一行一个目标）")
		return
	}
	if len(targets) > maxBatchCreate {
		writeErr(w, 400, fmt.Sprintf("单批最多 %d 个目标（本批有效 %d 行）", maxBatchCreate, len(targets)))
		return
	}
	if len(req.Common.LLMProfileIDs) > 0 {
		if err := s.validateTaskProfileIDs(req.Common.LLMProfileIDs); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	}
	// 分类整体前置校验（现成 GetTaskCategory）：不挡的话每一行都会以同一个
	// 错误失败，批量整批 400 比逐行 500 个例友好。
	if req.Common.CategoryID != nil {
		if *req.Common.CategoryID <= 0 {
			writeErr(w, 400, "任务分类无效")
			return
		}
		c, err := s.m.PG().GetTaskCategory(*req.Common.CategoryID)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if c == nil {
			writeErr(w, 400, "任务分类不存在或无效")
			return
		}
	}
	// 凭据整批前置校验：人工录入的少量数据，错了当场 400，不像目标那样静默剔除。
	creds, err := normalizeTaskCredentials(req.Common.Credentials)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	descTmpl := strings.TrimSpace(req.Common.DescTemplate)
	if descTmpl == "" {
		descTmpl = "目标：{target}"
	}
	// concurrency 若随请求带上：先落项目行再调度（Step 读到的是最新额度）。
	concurrency := proj.Concurrency
	if req.Concurrency != nil {
		p, err := s.m.PG().UpdateProject(pid, db.UpdateProjectPatch{Concurrency: req.Concurrency})
		if err != nil {
			writeErr(w, 400, "concurrency 无效: "+err.Error())
			return
		}
		concurrency = p.Concurrency
	}

	created := make([]string, 0, len(targets))
	var failed []string
	for _, target := range targets {
		desc := strings.TrimSpace(strings.ReplaceAll(descTmpl, "{target}", target))
		t, err := s.m.CreateTaskWithOptions(desc, target, db.TaskCreateOptions{
			Name:                 strings.TrimSpace(req.Common.NamePrefix + target),
			CategoryID:           req.Common.CategoryID,
			LLMProfileIDs:        req.Common.LLMProfileIDs,
			TimeoutSeconds:       req.Common.TimeoutSeconds,
			PlanHeartbeatSeconds: req.Common.PlanHeartbeatSeconds,
			CoverageEnabled:      req.Common.CoverageEnabled,
			ProjectID:            &pid, // 创建时直接挂项目（存在性已在 opts 校验里挡过）
		})
		if err != nil {
			// 单行失败不中断整批（分类不存在等已在前面整体校验过，这里失败
			// 基本只剩 DB 层个例）；记进 failed 供前端回显。
			failed = append(failed, target)
			continue
		}
		// 与原版建后流程同源的 seed（解析目标建站点资产）；本批凭据按 target
		// 匹配后写进该资产的 auth。不调 launchTask。
		s.seedWithAuth(t, desc+" "+target, authItemsFor(creds, target))
		if req.Common.SeedFirstIntent != nil && *req.Common.SeedFirstIntent {
			s.seedFirstIntent(t)
		}
		if err := s.m.EnqueueTaskProjectBatch(t.ID); err != nil {
			failed = append(failed, target)
			continue
		}
		created = append(created, t.ID)
	}
	if len(created) == 0 {
		writeErr(w, 500, fmt.Sprintf("全部 %d 行创建失败", len(targets)))
		return
	}
	// 小项 X：批量任务建队列时回调已随 taskFromPG 绑定（创建即挂项目），seed 与
	// 首波图事件本会实时进投影；这里仍补一次后台异步重建兜底——建队列瞬间若
	// 投影通道恰满（事件被 drop），本次重建把 seed 产物一次性补齐，用户进大图
	// tab 永远不用手动点重建。同项目一次即可（pid 恒定），fire-and-forget 不占
	// 请求时延。
	s.scheduleProjectRebuild([]int64{pid})
	out := map[string]any{
		"created":     created,
		"skipped":     skipped,
		"project_id":  pid,
		"concurrency": concurrency,
	}
	if invalid != nil {
		out["invalid"] = invalid
	}
	if failed != nil {
		out["failed"] = failed
	}
	writeJSON(w, http.StatusCreated, out)
}
