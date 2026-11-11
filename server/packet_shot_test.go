package server

// T22 报文自动截图的 server 侧测试：
//   - 无库：auto-generate 路由冒烟（注册期无 panic + pg=nil 命中 503 而非 404）、
//     stepFilter 纯逻辑（force+filter 语义）、默认关闸行为；
//   - PG 集成（无库 skip）：auto 行幂等覆盖、**paste/upload 手工行永不动**、
//     全局闸、盘上文件不堆积。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
)

// reproJSON 两步复现：step1 带 exchange_id（自动通道可渲），step2 空（需
// force/手动才渲）。报文含待脱敏的 Bearer 与 password 字段。
func t22ReproJSON(t *testing.T, xid1 string) []byte {
	t.Helper()
	rp := report.Reproduction{
		EntryPoint: "GET /a",
		Steps: []report.ReproStep{
			{
				Request:    "GET /a?x=1 HTTP/1.1\r\nHost: demo.example.com\r\nAuthorization: Bearer abcdefghijklmnopqrstuvwx\r\n\r\n",
				Response:   "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nleaked",
				ExchangeID: xid1,
			},
			{
				Request:    "POST /b HTTP/1.1\r\nHost: demo.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=a&password=TopSecretValue999",
				Response:   "HTTP/1.1 302 Found\r\nLocation: /c\r\n\r\n",
				ExchangeID: "",
			},
		},
	}
	raw, err := json.Marshal(rp)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// listAutoFiles 列 finding 证据目录下匹配 -kind- 的 auto png 文件数。
func t22CountAutoPNG(t *testing.T, dataDir string, fid int64) int {
	t.Helper()
	dir := filepath.Join(dataDir, "report_assets", "evidence", fmt.Sprint(fid))
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "auto-") && strings.HasSuffix(e.Name(), ".png") {
			n++
		}
	}
	return n
}

func TestPacketShotRoutesRegistered(t *testing.T) {
	s := &Server{m: &Manager{}, jwtKey: []byte("t22-test-key")}
	// 注册期 panic=路由冲突（auto-generate 与 /{eid} 的遮蔽验证）。
	h := s.Handler()
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/findings/1/evidence/auto-generate", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// pg=nil：evidenceImageAccess 的 pgReportDBGuard 回 503=路由已注册非 404。
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("auto-generate route: want 503, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestPacketShotGateOff 无库环境的闸默认值判定（GetBool 缺省 false=零回归
// 的静态保证；pg=nil 时 packetShotEnabled 必须 false 且不 panic）。
func TestPacketShotGateOff(t *testing.T) {
	s := &Server{m: &Manager{}}
	if s.packetShotEnabled() {
		t.Fatal("pg=nil must report gate off")
	}
	// 闸关 + 非 force=零行为（不 panic 即证明 nil 守卫链完整）。
	if n := s.renderPacketShots(1, t22ReproJSON(t, "ex1"), false, nil); n != 0 {
		t.Fatalf("gate off must render nothing, got %d", n)
	}
}

// TestPacketShotAutoIdempotentAndManualUntouched 红线用例（PG）：
// 闸开→step1（有 exchange_id）渲染 2 张 auto；重跑幂等（行数/文件数不涨、
// 旧文件删掉）；手工 paste 行与 upload 行在任何自动重渲后原样保留。
func TestPacketShotAutoIdempotentAndManualUntouched(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	dataDir := t.TempDir()
	s := New(context.Background(), m, t.TempDir(), dataDir, t.TempDir())

	task, err := m.pg.CreateTask("t22 desc", "t22 goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	repro := t22ReproJSON(t, "ex-1001")
	fid, err := m.pg.AddFinding(task.ID, 0, "sqli", "T22 测试漏洞", "high", "sum", "ev", "w", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.pg.UpdateFindingReproduction(fid, repro); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.DeleteFinding(fid) })

	// 1) 闸关（默认）：零行为。
	if n := s.renderPacketShots(fid, repro, false, nil); n != 0 {
		t.Fatalf("default gate off must render 0, got %d", n)
	}
	list, _ := m.pg.ListFindingEvidenceImages(fid)
	if len(list) != 0 {
		t.Fatalf("gate off left rows: %d", len(list))
	}

	// 2) 开闸→只渲 step1（step2 无 exchange_id=宁缺毋滥跳过）。
	if err := m.pg.SetSetting(settingPacketShotEnabled, "true"); err != nil {
		t.Fatal(err)
	}
	if n := s.renderPacketShots(fid, repro, false, nil); n != 1 {
		t.Fatalf("want 1 step rendered, got %d", n)
	}
	list, _ = m.pg.ListFindingEvidenceImages(fid)
	if len(list) != 2 {
		t.Fatalf("want req+resp two auto rows, got %d", len(list))
	}
	for _, e := range list {
		if e.Source != db.EvidenceSourceAuto || e.StepIndex != 1 {
			t.Fatalf("bad auto row: %+v", e)
		}
		if !strings.Contains(e.Caption, "packet#ex-1001") {
			t.Fatalf("caption missing fingerprint: %q", e.Caption)
		}
	}
	files1 := t22CountAutoPNG(t, dataDir, fid)
	if files1 != 2 {
		t.Fatalf("want 2 png on disk, got %d", files1)
	}

	// 3) 用户手工贴一张（paste）+ 传一张（upload）。
	manual, err := m.pg.AddFindingEvidenceImageSource(fid, 1, "report_assets/evidence/manual-p1.png", "手工证据", 5, db.EvidenceSourcePaste)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.AddFindingEvidenceImageSource(fid, 1, "report_assets/evidence/manual-u1.png", "手工上传", 6, db.EvidenceSourceUpload); err != nil {
		t.Fatal(err)
	}

	// 4) 重渲幂等：auto 行数不变、盘上 auto 文件不涨（旧文件删+新文件写）、
	//    手工两行原样。
	if n := s.renderPacketShots(fid, repro, false, nil); n != 1 {
		t.Fatalf("re-render want 1, got %d", n)
	}
	list, _ = m.pg.ListFindingEvidenceImages(fid)
	if len(list) != 4 {
		t.Fatalf("idempotent re-render changed row count: %d", len(list))
	}
	manualKept, uploadKept := false, false
	for _, e := range list {
		if e.ID == manual.ID && e.Source == db.EvidenceSourcePaste && e.Caption == "手工证据" {
			manualKept = true
		}
		if e.Source == db.EvidenceSourceUpload && e.Caption == "手工上传" {
			uploadKept = true
		}
	}
	if !manualKept || !uploadKept {
		t.Fatalf("manual rows must never be touched: paste=%v upload=%v", manualKept, uploadKept)
	}
	if files2 := t22CountAutoPNG(t, dataDir, fid); files2 != 2 {
		t.Fatalf("auto png files must stay 2 after re-render (old deleted), got %d", files2)
	}

	// 5) 手动通道（force）stepFilter 单步：step2 无 exchange_id 也渲，caption
	//    记 '-'；step1 已有 auto 行不受影响。
	if n := s.renderPacketShots(fid, repro, true, []int{2}); n != 1 {
		t.Fatalf("force step2 want 1, got %d", n)
	}
	list, _ = m.pg.ListFindingEvidenceImages(fid)
	step2Auto := 0
	for _, e := range list {
		if e.Source == db.EvidenceSourceAuto && e.StepIndex == 2 {
			step2Auto++
			if !strings.Contains(e.Caption, "packet#-") {
				t.Fatalf("unlinked caption must mark '-': %q", e.Caption)
			}
		}
	}
	if step2Auto != 2 {
		t.Fatalf("step2 req+resp auto rows want 2, got %d", step2Auto)
	}
}

// TestPacketShotAutoGenerateHandler 手动端点语义（PG）：无复现步骤→400；
// 有步骤→200 {steps,rendered} 且落 auto 行；step_index 越界→400。
func TestPacketShotAutoGenerateHandler(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	dataDir := t.TempDir()
	s := New(context.Background(), m, t.TempDir(), dataDir, t.TempDir())
	h := s.Handler()
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	post := func(path string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(""))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	task, err := m.pg.CreateTask("t22h", "t22h goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	fid, err := m.pg.AddFinding(task.ID, 0, "xss", "T22H", "medium", "s", "e", "w", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.DeleteFinding(fid) })

	// 1) 无复现步骤→400。
	if code, _ := post(fmt.Sprintf("/api/findings/%d/evidence/auto-generate", fid)); code != http.StatusBadRequest {
		t.Fatalf("no-repro want 400, got %d", code)
	}
	// 塞复现（两步，均无 exchange_id=手动通道也渲）。
	if err := m.pg.UpdateFindingReproduction(fid, t22ReproJSON(t, "")); err != nil {
		t.Fatal(err)
	}
	// 2) 全量补渲=2 步全渲（手动不受闸/未关联约束）。
	code, out := post(fmt.Sprintf("/api/findings/%d/evidence/auto-generate", fid))
	if code != http.StatusOK {
		t.Fatalf("generate want 200, got %d %v", code, out)
	}
	if out["steps"] != float64(2) || out["rendered"] != float64(2) {
		t.Fatalf("result=%v want steps=2 rendered=2", out)
	}
	if files := t22CountAutoPNG(t, dataDir, fid); files != 4 {
		t.Fatalf("want 4 png (req+resp × 2 steps), got %d", files)
	}
	// 3) 单步 + 越界。
	if code, _ := post(fmt.Sprintf("/api/findings/%d/evidence/auto-generate?step_index=1", fid)); code != http.StatusOK {
		t.Fatalf("step1 want 200, got %d", code)
	}
	if code, _ := post(fmt.Sprintf("/api/findings/%d/evidence/auto-generate?step_index=9", fid)); code != http.StatusBadRequest {
		t.Fatalf("bad step want 400, got %d", code)
	}
	// 幂等：跑完单步后总数仍 4（重渲替换不堆积）。
	if files := t22CountAutoPNG(t, dataDir, fid); files != 4 {
		t.Fatalf("idempotent disk count want 4, got %d", files)
	}
}

// TestPacketShotSettingSeed installPacketShot 的 if-absent 语义：已有值不覆、
// 缺时补显式 false、再跑幂等。
func TestPacketShotSettingSeed(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	// 清掉可能残留的键（本测试独占该键语义，先置空再验）。
	_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, settingPacketShotEnabled)
	// 1) 缺时 seed=false。
	s.installPacketShot()
	if v, ok, _ := m.pg.GetSetting(settingPacketShotEnabled); !ok || v != "false" {
		t.Fatalf("seed must write explicit false, got %q ok=%v", v, ok)
	}
	// 2) 用户已改 true 后再 seed 不覆。
	if err := m.pg.SetSetting(settingPacketShotEnabled, "true"); err != nil {
		t.Fatal(err)
	}
	s.installPacketShot()
	if v, _, _ := m.pg.GetSetting(settingPacketShotEnabled); v != "true" {
		t.Fatalf("seed must not overwrite user value, got %q", v)
	}
	// 3) 幂等。
	s.installPacketShot()
	if v, _, _ := m.pg.GetSetting(settingPacketShotEnabled); v != "true" {
		t.Fatalf("repeat seed changed it: %q", v)
	}
}

// TestPacketShotSettingsRoundTrip 缺口1：packet_shot_enabled 走完整设置 API
// 往返——PUT 白名单收键并落库、PUT 响应体与 GET /api/settings 均回显该键。
// （V2 部署实测：键曾只 seed 在 DB、不在 settings 结构体=UI 无法开启。）
func TestPacketShotSettingsRoundTrip(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	h := s.Handler()
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, body string) map[string]any {
		req := httptest.NewRequest(method, "/api/settings", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s want 200, got %d body=%s", method, rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// 初始态：seed/默认 false。
	if v, ok := call(http.MethodGet, "")["packet_shot_enabled"]; !ok || v != false {
		t.Fatalf("GET must echo packet_shot_enabled=false, got %v ok=%v", v, ok)
	}
	// PUT true → 响应体回显 true + DB 落值（照 agent_traffic_binding 断言口径）。
	if v := call(http.MethodPut, `{"packet_shot_enabled":true}`)["packet_shot_enabled"]; v != true {
		t.Fatalf("PUT response must echo true, got %v", v)
	}
	if !m.pg.GetBool(settingPacketShotEnabled, false) {
		t.Fatal("switch was not persisted")
	}
	// GET 再读回=true（读写两条路径共用 settingsPayload）。
	if v := call(http.MethodGet, "")["packet_shot_enabled"]; v != true {
		t.Fatalf("GET after set must be true, got %v", v)
	}
	// PUT false 关闸 + 部分 PUT 不重置（只发别的键时该键保持 false）。
	call(http.MethodPut, `{"packet_shot_enabled":false}`)
	if v := call(http.MethodPut, `{"llm_record":false}`)["packet_shot_enabled"]; v != false {
		t.Fatalf("unrelated partial PUT must keep packet_shot=false, got %v", v)
	}
}

var _ = time.Now
