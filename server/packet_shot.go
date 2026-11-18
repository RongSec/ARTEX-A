package server

// T22（N3）报文→证据截图的 server 侧装配：
//
//  1. 自动通道（旁路，零回归）：finding_repro.go 的 reproEnricher 回填
//     exchange_id 成功后同协程续渲——对每个**有新关联**的复现步骤渲染
//     **一张** request+response 纵向双面板合成 PNG 落盘
//     （report_assets/evidence/<fid>/auto-<step>-<nano>.png），并写
//     finding_evidence_images 行（source='auto'，caption 带
//     `packet#<exchange_id> step<N>` 渲染指纹）。
//     幂等覆盖：先删该 **step** 的全部旧 auto 行+文件再插新——**paste/upload
//     手工行永不动**（source='auto' 隔离，红线）。按 step 粒度删除谓词使
//     V2 遗留的 req/resp 双图存量在下次重渲时自然收敛成单图（不做全表扫
//     描式主动清理，零迁移成本）。
//  2. 手动补渲：POST /api/findings/{id}/evidence/auto-generate（存量 finding
//     一键补图；query ?step_index=N 只渲单步）。全同步、返回 {steps,rendered}。
//  3. 开关双层：全局 db setting `packet_shot_enabled`（V9-SHOT 起默认
//     **true**=报告带报文截图；关=不再自动出图）+ 手动端点**不受全局闸
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

// settingPacketShotEnabled 全局自动截图闸（V9-SHOT 起默认 true=报告带报文截图）。
const settingPacketShotEnabled = "packet_shot_enabled"

// packetShotOpts 渲染选项：深色编辑器风格、左请求右响应并排、**不脱敏不改写**
// 报文（用户口径：截图必须完整反映原始请求响应），高度上限 2600px（约
// 22cm@300dpi，插入报告时按 19cm 等比收缩）。
func (s *Server) packetShotOpts() packetshot.Options {
	o := packetshot.DefaultOptions() // 宽 1680 / Scale 2.5 / 不脱敏 / 无行号
	o.MaxHeight = 2600
	return o
}

// packetShotEnabled 全局闸（GetBool 缺省 true——V9-SHOT 起报告默认带报文
// 截图；关掉即报告不再带图）。
func (s *Server) packetShotEnabled() bool {
	return s.m != nil && s.m.pg != nil && s.m.pg.GetBool(settingPacketShotEnabled, true)
}

// packetShotRenderFn 渲染入口（单测注入点：替换即可断言「无图时触发补渲」，
// 不必起 DB）。生产恒等于 (*Server).renderPacketShots。
var packetShotRenderFn = (*Server).renderPacketShots

// ensurePacketShots 报告渲染前的补图通道（V9-SHOT）：对**没有既有截图**且
// reproduction 里确实带 request/response 的 finding，强制就地渲一遍（force=
// true 不看全局闸——报告要图是显式意图）。返回**实际出图**的 finding 数。
// 渲染失败只 log（renderPacketShots 内部已吞），不阻断报告。
func (s *Server) ensurePacketShots(fs []*db.DBFinding, have map[int64][]report.EvidenceImage) int {
	n := 0
	for _, f := range fs {
		if f == nil || f.ID <= 0 || len(have[f.ID]) > 0 || len(f.Reproduction) == 0 {
			continue
		}
		var rp report.Reproduction
		if json.Unmarshal(f.Reproduction, &rp) != nil || !reproductionHasPacket(rp) {
			continue
		}
		if packetShotRenderFn(s, f.ID, f.Reproduction, true, nil) > 0 {
			n++
		}
	}
	return n
}

// reproductionHasPacket 复现步骤里是否有可渲的报文（请求或响应非空）。
func reproductionHasPacket(rp report.Reproduction) bool {
	for _, st := range rp.Steps {
		if strings.TrimSpace(st.Request) != "" || strings.TrimSpace(st.Response) != "" {
			return true
		}
	}
	return false
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
		if s.renderPacketShot(findingID, step, st.Request, st.Response, st.ExchangeID) {
			n++
		}
	}
	if n > 0 {
		log.Printf("[packetshot] finding %d 截图 %d 步（source=auto，手工行未动）", findingID, n)
	}
	return n
}

// renderPacketShot 渲一步的 req+resp **单张**合成 PNG（render.go 的双面板
// 布局：左请求、右响应并排），幂等替换该 finding step 的全部 auto 行。
// 先渲染→临时文件→改名→删旧行+旧文件→插新行：任一步失败=清理半途文件、
// 旧行保留（宁缺毋滥）。删除谓词只按 step（V2 的 req/resp 旧双图行一并
// 清掉=存量自动收敛成单图）；手工行 source 不同天然躲开。
// req/resp 全空=无可渲，返回 false。
func (s *Server) renderPacketShot(findingID int64, step int, req, resp, exchangeID string) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[packetshot] finding %d step %d panic（已吞）: %v", findingID, step, r)
			ok = false
		}
	}()
	if strings.TrimSpace(req) == "" && strings.TrimSpace(resp) == "" {
		return false
	}
	pngBytes, err := packetshot.Render(req, resp, s.packetShotOpts())
	if err != nil {
		log.Printf("[packetshot] finding %d step %d 渲染失败: %v", findingID, step, err)
		return false
	}
	dirRel := filepath.Join("report_assets", "evidence", strconv.FormatInt(findingID, 10))
	name := fmt.Sprintf("auto-%d-%d.png", step, time.Now().UnixNano())
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
	// 图注由报告填充器统一生成「图1、图2…」（全报告连续编号），这里不再写
	// 步骤号与 packet id——它们会随 exchangeID 变成一长串噪声。
	caption := ""
	sortOrder := step * 100

	// 幂等替换该 step 全部 auto 行（含 V2 的 "-req-"/"-resp-" 旧命名形态；
	// 手工行 source 不同天然躲开）。
	if old, err := s.m.pg.ListFindingEvidenceImages(findingID); err == nil {
		for _, e := range old {
			if e.Source == db.EvidenceSourceAuto && e.StepIndex == step {
				if _, del, derr := s.m.pg.DeleteFindingEvidenceImage(e.ID, findingID); derr == nil && del {
					_ = os.Remove(filepath.Join(s.m.dir, filepath.FromSlash(e.Filename)))
				}
			}
		}
	}
	relSlash := filepath.ToSlash(filepath.Join(dirRel, name))
	if _, err := s.m.pg.AddFindingEvidenceImageSource(findingID, step, relSlash, caption, sortOrder, db.EvidenceSourceAuto); err != nil {
		_ = os.Remove(abs)
		log.Printf("[packetshot] finding %d step %d 入库失败: %v", findingID, step, err)
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
// 'true'，已有值不覆——前端设置页读到确定值）。在 server.New 的 PG 分支
// 调用（照 installTerminalHooks）。
func (s *Server) installPacketShot() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	if _, err := s.m.pg.InsertSettingIfAbsent(settingPacketShotEnabled, "true"); err != nil {
		log.Printf("[packetshot] seed setting: %v", err)
	}
}
