package server

// V6-CFG：短路规则 API（GET/PUT/校验失败/权限）+ 重启端点（只验排程与审计）。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
)

func newShortCircuitTestServer(t *testing.T, dir string) (*Server, http.Handler, string) {
	t.Helper()
	// 让包级生效配置也指向本测试的 dataDir（默认值），避免开发机上的
	// data/shortcircuit_rules.json 影响断言。
	if err := guard.ReloadShortCircuit(dir); err != nil {
		t.Fatalf("加载测试短路配置: %v", err)
	}
	s := &Server{m: &Manager{dir: dir}, jwtKey: []byte("v6cfg-test-key-0123456789abcdef")}
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return s, s.Handler(), tok
}

func scRequest(h http.Handler, method, path, tok, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestShortCircuitAPIGetPutReset(t *testing.T) {
	dir := t.TempDir()
	s, h, tok := newShortCircuitTestServer(t, dir)
	_ = s

	// GET：默认配置 + 文件路径 + 未脏
	rec := scRequest(h, http.MethodGet, "/api/system/shortcircuit", tok, "")
	if rec.Code != 200 {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Config   guard.ShortCircuitConfig `json:"config"`
		Defaults guard.ShortCircuitConfig `json:"defaults"`
		FilePath string                   `json:"file_path"`
		LoadedAt string                   `json:"loaded_at"`
		Dirty    bool                     `json:"dirty"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("GET body: %v (%s)", err, rec.Body.String())
	}
	wantPath := filepath.Join(dir, guard.ShortCircuitConfigFile)
	if got.FilePath != wantPath {
		t.Fatalf("file_path=%q, want %q", got.FilePath, wantPath)
	}
	if len(got.Config.Tools.Deny) == 0 || len(got.Defaults.PlatformPaths) == 0 {
		t.Fatalf("GET 配置不完整: %+v", got)
	}
	if got.Dirty {
		t.Fatal("首次启动（无文件）不应 dirty")
	}
	effectiveBefore := got.Config

	// PUT：合法配置 → 200 need_restart，文件落盘 0600，生效配置不变（不热改）
	body := `{"config":{"version":1,"tools":{"deny":["custom_deny_tool"]},"bare_read_names":["tenant.secret"]}}`
	rec = scRequest(h, http.MethodPut, "/api/system/shortcircuit", tok, body)
	if rec.Code != 200 {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	var put struct {
		OK          bool `json:"ok"`
		NeedRestart bool `json:"need_restart"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &put); err != nil || !put.OK || !put.NeedRestart {
		t.Fatalf("PUT 响应 %s (%v)", rec.Body.String(), err)
	}
	if _, err := os.Stat(wantPath); err != nil {
		t.Fatalf("配置未落盘: %v", err)
	}

	rec = scRequest(h, http.MethodGet, "/api/system/shortcircuit", tok, "")
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Dirty {
		t.Fatal("PUT 后未重启应 dirty=true")
	}
	if len(got.Config.Tools.Deny) != len(effectiveBefore.Tools.Deny) || got.Config.Tools.Deny[0] != effectiveBefore.Tools.Deny[0] {
		t.Fatalf("PUT 不得热改生效配置: before=%v after=%v", effectiveBefore.Tools.Deny, got.Config.Tools.Deny)
	}

	// reset：文件回到默认，仍需重启
	rec = scRequest(h, http.MethodPost, "/api/system/shortcircuit/reset", tok, "")
	if rec.Code != 200 {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}
	raw, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := guard.ParseShortCircuitConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(onDisk.Tools.Deny) != len(guard.Defaults().Tools.Deny) {
		t.Fatalf("reset 未写默认值: %+v", onDisk.Tools.Deny)
	}
}

func TestShortCircuitAPIValidationAndAuth(t *testing.T) {
	dir := t.TempDir()
	_, h, tok := newShortCircuitTestServer(t, dir)

	// 非法正则 → 400，且不落盘
	bad := `{"config":{"platform_paths":["("]}}`
	rec := scRequest(h, http.MethodPut, "/api/system/shortcircuit", tok, bad)
	if rec.Code != 400 {
		t.Fatalf("非法正则应为 400，得到 %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, guard.ShortCircuitConfigFile)); !os.IsNotExist(err) {
		t.Fatalf("校验失败不应写文件，stat err=%v", err)
	}

	// 空关键列表 → 400
	rec = scRequest(h, http.MethodPut, "/api/system/shortcircuit", tok, `{"bare_read_names":[]}`)
	if rec.Code != 400 {
		t.Fatalf("空关键列表应为 400，得到 %d %s", rec.Code, rec.Body.String())
	}

	// 坏 JSON → 400
	rec = scRequest(h, http.MethodPut, "/api/system/shortcircuit", tok, `{`)
	if rec.Code != 400 {
		t.Fatalf("坏 JSON 应为 400，得到 %d", rec.Code)
	}

	// 无 JWT → 401（与 /api/settings 同权限）
	if rec := scRequest(h, http.MethodGet, "/api/system/shortcircuit", "", ""); rec.Code != 401 {
		t.Fatalf("无 token 应为 401，得到 %d", rec.Code)
	}
	if rec := scRequest(h, http.MethodPut, "/api/system/shortcircuit", "", `{}`); rec.Code != 401 {
		t.Fatalf("无 token PUT 应为 401，得到 %d", rec.Code)
	}
}

// 重启端点：排程与退出钩子（无库也能跑；真实 spawn/exit 用测试缝替换）。
func TestSystemRestartSchedules(t *testing.T) {
	dir := t.TempDir()
	s := &Server{m: &Manager{dir: dir}, jwtKey: []byte("v6cfg-test-key-0123456789abcdef")}
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}

	scheduled := make(chan struct{}, 1)
	exited := make(chan int, 1)
	s.restartFunc = func() error {
		scheduled <- struct{}{}
		return nil
	}
	s.exitFunc = func(code int) { exited <- code }
	s.restartDelay = 10 * time.Millisecond

	rec := scRequest(s.Handler(), http.MethodPost, "/api/system/restart", tok, "")
	if rec.Code != 200 {
		t.Fatalf("restart: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		OK        bool `json:"ok"`
		Scheduled bool `json:"scheduled"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || !resp.OK || !resp.Scheduled {
		t.Fatalf("响应应标记已排程: %s (%v)", rec.Body.String(), err)
	}

	select {
	case <-scheduled:
	case <-time.After(2 * time.Second):
		t.Fatal("重启未在延迟后调用排程函数")
	}
	select {
	case code := <-exited:
		if code != 0 {
			t.Fatalf("退出码应为 0，得到 %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("排程成功后应调用退出函数")
	}
}

// 重启端点：审计落库（需 PG，无库 skip）。
func TestSystemRestartAudits(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	dir := t.TempDir()
	s := &Server{m: &Manager{dir: dir, pg: pg}, jwtKey: []byte("v6cfg-test-key-0123456789abcdef")}
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}

	var before int
	_ = pg.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action='system_restart'`).Scan(&before)

	s.restartFunc = func() error { return nil }
	s.exitFunc = func(int) {}
	s.restartDelay = 10 * time.Millisecond

	rec := scRequest(s.Handler(), http.MethodPost, "/api/system/restart", tok, "")
	if rec.Code != 200 {
		t.Fatalf("restart: %d %s", rec.Code, rec.Body.String())
	}

	var after int
	if err := pg.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action='system_restart'`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after <= before {
		t.Fatalf("重启审计未落库: before=%d after=%d", before, after)
	}
	var payload []byte
	var actor, reason string
	if err := pg.QueryRow(`SELECT actor, reason, payload FROM audit_events WHERE action='system_restart' ORDER BY seq DESC LIMIT 1`).
		Scan(&actor, &reason, &payload); err != nil {
		t.Fatal(err)
	}
	if actor != "ARTEX" || !strings.Contains(reason, "重启") {
		t.Fatalf("审计内容不符: actor=%q reason=%q", actor, reason)
	}
	if !bytes.Contains(payload, []byte("executable")) {
		t.Fatalf("审计 payload 应记录可执行文件: %s", payload)
	}
}
