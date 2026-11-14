package server

// 情报覆盖率审计（V8-INTEL3）：回答"任务做过的接口，情报表收全了吗"。
//
// 口径：
//   seen      该任务全部 fact/finding 正文里识别出的接口路径集合（与情报表
//             抽取**同一套规则**：intelScanParagraph）；
//   captured  seen 里已经出现在 task_intel endpoint 行中的路径数；
//   pct       captured/seen 四舍五入到整数；seen=0 视为 100（没有证据就谈不上漏）；
//   missing   seen 里有、表里没有的接口（带方法 + 来源证据串）。
//
// 只读不写：它不触发 rebuild，避免审计动作改数据。

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// intelCoverageMissing 是一条"正文见过、表里没有"的接口。
type intelCoverageMissing struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Evidence string `json:"evidence"`
}

// intelCoverageResp 是 GET /api/tasks/{id}/intel/coverage 的响应体。
type intelCoverageResp struct {
	TaskID      int64                  `json:"task_id"`
	Seen        int                    `json:"seen"`
	Captured    int                    `json:"captured"`
	CoveragePct int                    `json:"coverage_pct"`
	Missing     []intelCoverageMissing `json:"missing"`
	Notes       []string               `json:"notes"`
}

// intelSeenEndpoint 是一条从正文里识别出的接口（覆盖率审计的原料）。
type intelSeenEndpoint struct {
	Method     string
	Path       string // 归一化路径（数字/UUID 段折叠，与情报表 key 同口径）
	RawPath    string // 正文原样路径（证据串用）
	SourceKind string // fact | finding
	SourceID   int64
	Status     int
}

// scanTaskIntelEndpoints 扫描 fact/finding 正文，返回按归一化路径去重的接口清单。
// 同一路径出现多次只记首条（带最早来源），排序稳定。
func scanTaskIntelEndpoints(findings []db.IntelFinding, facts []db.IntelFact) []intelSeenEndpoint {
	byPath := map[string]intelSeenEndpoint{}
	addText := func(text, kind string, id int64) {
		if strings.TrimSpace(text) == "" {
			return
		}
		for _, para := range intelTextParagraphs(text) {
			codes := intelTextStatusCodes(para)
			status := 0
			if len(codes) > 0 {
				status = codes[0]
			}
			for _, hit := range intelScanParagraph(para) {
				key, _ := db.NormalizeEndpoint(hit.method, hit.target)
				if key == "" {
					continue
				}
				method, path := splitEndpointKey(key)
				if path == "" {
					continue
				}
				if _, ok := byPath[path]; ok {
					continue
				}
				byPath[path] = intelSeenEndpoint{
					Method: method, Path: path,
					RawPath:    intelPathOfTarget(hit.target),
					SourceKind: kind, SourceID: id, Status: status,
				}
			}
		}
	}
	for _, f := range findings {
		addText(f.Summary+"\n"+f.Evidence, "finding", f.ID)
	}
	for _, fact := range facts {
		addText(fact.Summary+"\n"+fact.Detail+"\n"+fact.Evidence, "fact", fact.NodeID)
	}
	out := make([]intelSeenEndpoint, 0, len(byPath))
	for _, e := range byPath {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// intelSeenEvidence 拼一条可读证据：`fact#119 的 GET /login.php 返回 200`。
func intelSeenEvidence(e intelSeenEndpoint) string {
	p := e.RawPath
	if p == "" {
		p = e.Path
	}
	s := e.SourceKind + "#" + strconv.FormatInt(e.SourceID, 10) + " 的 " +
		strings.ToUpper(e.Method) + " " + p
	if e.Status > 0 {
		s += " 返回 " + strconv.Itoa(e.Status)
	}
	return s
}

// buildIntelCoverage 纯函数：seen 与已入表的 endpoint 路径集合 → 覆盖率报告。
func buildIntelCoverage(taskID int64, seen []intelSeenEndpoint, rows []db.TaskIntel) intelCoverageResp {
	captured := map[string]bool{}
	assetWithoutPort := 0
	endpointNoHost := 0
	endpointFromFact := 0
	for _, r := range rows {
		switch r.Kind {
		case db.IntelKindEndpoint:
			_, path := splitEndpointKey(r.Key)
			if path != "" {
				captured[path] = true
			}
			d := decodeIntelDetail(r.Detail)
			if len(d.Hosts) == 0 {
				endpointNoHost++
			}
			if r.Source == "fact" {
				endpointFromFact++
			}
		case db.IntelKindAsset:
			if !strings.Contains(r.Key, ":") {
				assetWithoutPort++
			}
		}
	}

	resp := intelCoverageResp{
		TaskID:  taskID,
		Seen:    len(seen),
		Missing: []intelCoverageMissing{},
		Notes:   []string{},
	}
	for _, e := range seen {
		if captured[e.Path] {
			resp.Captured++
			continue
		}
		resp.Missing = append(resp.Missing, intelCoverageMissing{
			Method: e.Method, Path: e.Path, Evidence: intelSeenEvidence(e),
		})
	}
	if resp.Seen == 0 {
		// 没有正文证据：按 100% 计，并说明原因（不是"完美覆盖"）。
		resp.CoveragePct = 100
		resp.Notes = append(resp.Notes, "任务无 fact/finding 正文：seen=0，覆盖率按 100% 计")
	} else {
		resp.CoveragePct = (resp.Captured*100 + resp.Seen/2) / resp.Seen
		if len(resp.Missing) == 0 {
			resp.Notes = append(resp.Notes, "正文里识别出的接口已全部入表")
		} else {
			resp.Notes = append(resp.Notes, strconv.Itoa(len(resp.Missing))+" 条接口只出现在正文、尚未入表（可在情报表点「重建」补全）")
		}
	}
	if assetWithoutPort > 0 {
		resp.Notes = append(resp.Notes, strconv.Itoa(assetWithoutPort)+" 条 asset 键仍无端口（正文没有可补的端口证据）")
	} else {
		resp.Notes = append(resp.Notes, "asset 键均含端口")
	}
	if endpointNoHost > 0 {
		resp.Notes = append(resp.Notes, strconv.Itoa(endpointNoHost)+" 条接口缺主机（正文未给出 URL/Host 头）")
	}
	if endpointFromFact > 0 {
		resp.Notes = append(resp.Notes, strconv.Itoa(endpointFromFact)+" 条接口仅出现在事实正文，已纳入")
	}
	return resp
}

// taskIntelCoverage GET /api/tasks/{id}/intel/coverage。
func (s *Server) taskIntelCoverage(w http.ResponseWriter, r *http.Request) {
	taskID, ok := pathInt(r, "id")
	if !ok || taskID <= 0 {
		writeErr(w, 400, "任务 id 无效")
		return
	}
	t, err := s.m.pg.GetTask(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if t == nil {
		writeErr(w, 404, "任务不存在")
		return
	}
	ctx := r.Context()
	findings, err := s.m.pg.TaskFindingsForIntel(ctx, taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	facts, err := s.m.pg.TaskFactsForIntel(ctx, taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	rows, err := s.m.pg.TaskIntelForTask(ctx, taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	seen := scanTaskIntelEndpoints(findings, facts)
	writeJSON(w, 200, buildIntelCoverage(taskID, seen, rows))
}
