package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// maxBatchFindingIDs 是单次批量状态操作的 id 上限
//（照 maxBatchControlIDs=100 / maxBatchCreate=200 的常量范式）。
const maxBatchFindingIDs = 200

// parseBatchFindingIDs 把原始 id 列表按传入顺序去重并解析为 int64。
// ids 兼容 JSON 数字与数字字符串（前端 finding_id 是 string，外部脚本常传 number）。
// 解析失败或非正数的条目原样进 invalid，由调用方计入 not_found 如实回报。
// 纯函数，无库单测。
func parseBatchFindingIDs(raw []json.RawMessage) (ids []int64, invalid []string) {
	seen := make(map[int64]bool, len(raw))
	invalid = []string{}
	for _, item := range raw {
		id := parseProfileID(item)
		if id <= 0 {
			var s string
			if json.Unmarshal(item, &s) != nil {
				s = string(item)
			}
			invalid = append(invalid, strings.TrimSpace(s))
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, invalid
}

// findingsBatchStatus 批量修改漏洞处置状态：POST /api/exploration/findings/batch-status。
//
// 逐条循环走 SetFindingStatusWithNotify——与单条 PATCH 完全同语义
// （状态更新与「状态变更推送事件」同事务落库；批量绕过它会静默丢通知）。
// 部分失败不 4xx：逐条 UPDATE 非单事务，批量标记是低一致性要求操作，
// 响应体如实报告 updated/not_found；单条 DB 错误直接 500 中断（前端整体回滚）。
func (s *Server) findingsBatchStatus(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	var req struct {
		IDs    []json.RawMessage `json:"ids"`
		Status string            `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if !db.ValidFindingStatus(req.Status) {
		writeErr(w, 400, "bad status: "+req.Status)
		return
	}
	ids, invalid := parseBatchFindingIDs(req.IDs)
	if total := len(ids) + len(invalid); total == 0 {
		writeErr(w, 400, "ids 不能为空")
		return
	} else if total > maxBatchFindingIDs {
		writeErr(w, 400, fmt.Sprintf("单批最多 %d 个漏洞（本批 %d 个）", maxBatchFindingIDs, total))
		return
	}
	updated := []int64{}
	notFound := append([]string{}, invalid...)
	for _, id := range ids {
		from, found, notified, err := s.m.pg.SetFindingStatusWithNotify(r.Context(), id, req.Status)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if !found {
			notFound = append(notFound, strconv.FormatInt(id, 10))
			continue
		}
		if !notified && from != req.Status {
			log.Printf("[notify] 批量状态变更事件未登记 finding=%d %s→%s（状态已更新）", id, from, req.Status)
		}
		updated = append(updated, id)
	}
	writeJSON(w, 200, map[string]any{"updated": updated, "not_found": notFound})
}
