package server

// T22（N3）报文→证据截图的 server 侧装配：
//
//  1. 自动通道（旁路，零回归）：finding_repro.go 的 reproEnricher 回填
//     exchange_id 成功后同协程续渲——对每个**有新关联**的复现步骤渲染
//     request/response 两张 PNG 落盘（report_assets/evidence/<fid>/
//     auto-<step>-req|resp-<nano>.png），并写 finding_evidence_images 行
//     （source='auto'，caption 带 `packet#<exchange_id>` 渲染指纹）。
//     幂等覆盖：先删该 (step,kind) 的旧 auto 行+文件再插新——**paste/upload
//     手工行永不动**（source='auto' 隔离，红线）。
//  2. 手动补渲：POST /api/findings/{id}/evidence/auto-generate（存量 finding
//     一键补图；query ?step_index=N 只渲单步）。全同步、返回 {steps,rendered}。
//  3. 开关双层：全局 db setting `packet_shot_enabled`（默认 **false**=零
//     回归，开=新登记漏洞 enrich 成功即自动出图）+ 手动端点**不受全局闸
//     约束**（显式按钮=显式意图）。
//
// 旁路纪律全套（reproEnricherFor 同款）：panic recover、失败只 log 一行、
// 绝不影响 finding 主链路；渲染发生在 enricher 后台协程内。

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
	"github.com/Autumn-27/artex/report/packetshot"
)

// settingPacketShotEnabled 全局自动截图闸（默认 false=零回归）。
const settingPacketShotEnabled = "packet_shot_enabled"

// packetShotOpts 渲染选项（本期固定默认：宽 980、脱敏+行号开、隐藏/马赛克
// 关。模板 style.packet_shot 覆盖留后续——截图发生在 finding 落库期，与
// 报告模板无绑定，塞 style 里语义错位；偏差已记交付报告）。
func (s *Server) packetShotOpts() packetshot.Options {
	return packetshot.DefaultOptions()
}

// packetShotEnabled 全局闸（GetBool 缺省 false）。
func (s *Server) packetShotEnabled() bool {
	return s.m != nil && s.m.pg != nil && s.m.pg.GetBool(settingPacketShotEnabled, false)
}

// renderPacketShots 是 enricher 续渲入口（回填成功后同协程调用）。
//   - force=false：先查全局闸，关=零行为；步骤须已关联 exchange_id
//     （宁缺毋滥：未关联=报文来源不可靠，留给下次 enrich/手动通道）。
//   - force=true（手动端点）：不看闸、exchange_id 可空（caption 记 '-'）。
//   - stepFilter：nil=全部步骤；非 nil=只渲列表内步骤（1 起，手动单步用）。
//     force 模式下 stepFilter 同时豁免 exchange_id 条件。
//
// 返回实际渲染的步骤数。永不 panic/回抛。
func (s *Server) renderPacketShots(findingID int64, repro []byte, force bool, stepFilter []int) int {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[packetshot] finding %d 续渲 panic（已吞）: %v", findingID, r)
		}
	}()
	if s.m == nil || s.m.pg == nil || findingID <= 0 {
		return 0
	}
	if !force && !s.packetShotEnabled() {
		return 0
	}
	var rp report.Reproduction
	if json.Unmarshal(repro, &rp) != nil || len(rp.Steps) == 0 {
		return 0
	}
	inFilter := func(step int) bool {
		if stepFilter == nil {
			return true
		}
		for _, f := range stepFilter {
			if f == step {
				return true
			}
		}
		return false
	}
	n := 0
	for i := range rp.Steps {
		step := i + 1
		if !inFilter(step) {
			continue
		}
		st := &rp.Steps[i]
		if !force && strings.TrimSpace(st.ExchangeID) == "" {
			continue
		}
		done := false
		if strings.TrimSpace(st.Request) != "" {
			if s.renderPacketShotImage(findingID, step, "req", st.Request, st.ExchangeID) {
				done = true
			}
		}
		if strings.TrimSpace(st.Response) != "" {
			if s.renderPacketShotImage(findingID, step, "resp", st.Response, st.ExchangeID) {
				done = true
			}
		}
		if done {
			n++
		}
	}
	if n > 0 {
		log.Printf("[packetshot] finding %d 截图 %d 步（source=auto，手工行未动）", findingID, n)
	}
	return n
}

// renderPacketShotImage 渲单报文 PNG 并幂等替换该 (finding,step,kind) 的
// auto 行。先渲染→临时文件→改名→删旧行+旧文件→插新行：任一步失败=清理
// 半途文件、旧行保留（宁缺毋滥）。kind ∈ {req,resp}；req/resp 两行同 step
// 共存是预期（一步两张图），删旧按文件名 "-<kind>-" 段隔离。
func (s *Server) renderPacketShotImage(findingID int64, step int, kind, packet, exchangeID string) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[packetshot] finding %d step %d %s panic（已吞）: %v", findingID, step, kind, r)
			ok = false
		}
	}()
	pngBytes, err := packetshot.Render(packet, "", s.packetShotOpts())
	if err != nil {
		log.Printf("[packetshot] finding %d step %d %s 渲染失败: %v", findingID, step, kind, err)
		return false
	}
	dirRel := filepath.Join("report_assets", "evidence", strconv.FormatInt(findingID, 10))
	name := fmt.Sprintf("auto-%d-%s-%d.png", step, kind, time.Now().UnixNano())
	absTmp := filepath.Join(s.m.dir, dirRel, name+".tmp")
	abs := filepath.Join(s.m.dir, dirRel, name)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		log.Printf("[packetshot] mkdir: %v", err)
		return false
	}
	if err := os.WriteFile(absTmp, pngBytes, 0o644); err != nil {
		_ = os.Remove(absTmp)
		log.Printf("[packetshot] write: %v", err)
		return false
	}
	if err := os.Rename(absTmp, abs); err != nil {
		_ = os.Remove(absTmp)
		log.Printf("[packetshot] rename: %v", err)
		return false
	}
	xid := strings.TrimSpace(exchangeID)
	if xid == "" {
		xid = "-"
	}
	caption := fmt.Sprintf("packet#%s step%d %s", xid, step, kind)
	// req 在前 resp 在后（步内排序留空隙）。
	sortOrder := (step-1)*100 + 10 + map[bool]int{true: 0, false: 10}[kind == "req"]

	// 幂等替换旧 auto 行（只同 kind；手工行 source 不同天然躲开）。
	if old, err := s.m.pg.ListFindingEvidenceImages(findingID); err == nil {
		for _, e := range old {
			if e.Source == db.EvidenceSourceAuto && e.StepIndex == step &&
				strings.Contains(filepath.Base(filepath.FromSlash(e.Filename)), "-"+kind+"-") {
				if _, del, derr := s.m.pg.DeleteFindingEvidenceImage(e.ID, findingID); derr == nil && del {
					_ = os.Remove(filepath.Join(s.m.dir, filepath.FromSlash(e.Filename)))
				}
			}
		}
	}
	relSlash := filepath.ToSlash(filepath.Join(dirRel, name))
	if _, err := s.m.pg.AddFindingEvidenceImageSource(findingID, step, relSlash, caption, sortOrder, db.EvidenceSourceAuto); err != nil {
		_ = os.Remove(abs)
		log.Printf("[packetshot] finding %d step %d %s 入库失败: %v", findingID, step, kind, err)
		return false
	}
	return true
}

// POST /api/findings/{id}/evidence/auto-generate — 存量补渲（同步，不受全局
// 闸约束）。query ?step_index=N 只渲单步（1 起）。exchange_id 未关联的步骤
// 也渲（手动=显式意图，caption 记 '-'）。
func (s *Server) findingEvidenceAutoGenerate(w http.ResponseWriter, r *http.Request) {
	fid, rok := s.evidenceImageAccess(w, r)
	if !rok {
		return
	}
	f, err := s.m.pg.GetFinding(fid)
	if err != nil || f == nil {
		writeErr(w, 404, "发现不存在")
		return
	}
	var rp report.Reproduction
	if len(f.Reproduction) == 0 || json.Unmarshal(f.Reproduction, &rp) != nil || len(rp.Steps) == 0 {
		writeErr(w, 400, "该发现没有结构化复现步骤")
		return
	}
	var filter []int
	if v := strings.TrimSpace(r.URL.Query().Get("step_index")); v != "" {
		n, cerr := strconv.Atoi(v)
		if cerr != nil || n < 1 || n > len(rp.Steps) {
			writeErr(w, 400, "step_index 超出范围")
			return
		}
		filter = []int{n}
	}
	rendered := s.renderPacketShots(fid, f.Reproduction, true, filter)
	writeJSON(w, 200, map[string]any{"steps": len(rp.Steps), "rendered": rendered})
}

// installPacketShot 一次性 seed 设置键（InsertSettingIfAbsent=仅缺时补显式
// 'false'，已有值不覆——前端设置页读到确定值）。在 server.New 的 PG 分支
// 调用（照 installAutoReportHook）。
func (s *Server) installPacketShot() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	if _, err := s.m.pg.InsertSettingIfAbsent(settingPacketShotEnabled, "false"); err != nil {
		log.Printf("[packetshot] seed setting: %v", err)
	}
}
