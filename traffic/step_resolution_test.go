package traffic

// T14(2/2) 收窄核心纯函数单测（ResolveReproSteps）：无 PG、无 SQLite——
// 候选直接以摘要列表喂入。覆盖 b4-spec 的八类判例：唯一命中 / 多候选弃权 /
// 零候选 / 时间窗裁剪 / method 不符 / path token 打分 / body 特征 / Host
// 缺失，另加有序 cursor、状态消歧、curl 形态与响应判别词收窄。

import (
	"strings"
	"testing"
	"time"
)

// candOK is the canonical recorded exchange pool reused across cases.
func pool(cs ...Cand) []Cand { return cs }

func testCand(id string, ts int64, host, method, url string, status int, reqSnip, respSnip string) Cand {
	return Cand{ID: id, TS: ts, Host: host, Method: method, URL: url, Status: status,
		ReqHead:  method + " " + url + " HTTP/1.1\nHost: " + host + "\n\n",
		ReqSnip:  reqSnip,
		RespHead: "HTTP 200\nContent-Type: application/json\n",
		RespSnip: respSnip}
}

// 1. 唯一命中：窗口+method+path 收窄后只剩一条 → 绑。
func TestResolveUniqueHit(t *testing.T) {
	cands := pool(
		testCand("a", 100, "x.com", "POST", "/upload.php", 200, `{"f":"evil.php"}`, `{"msg":"uploaded ok"}`),
		testCand("b", 101, "y.com", "GET", "/index.html", 200, ``, `home`),
	)
	steps := []StepRef{{Request: "POST /upload.php HTTP/1.1\nHost: x.com\n\n{\"f\":\"evil.php\"}"}}
	ids := ResolveReproSteps(0, 200, steps, cands)
	if len(ids) != 1 || ids[0] != "a" {
		t.Fatalf("want [a], got %v", ids)
	}
}

// 2. 多候选弃权：同端点两条、无任何可生效的收窄特征 → 宁缺毋滥。
func TestResolveAmbiguousAbstain(t *testing.T) {
	cands := pool(
		testCand("a", 100, "x.com", "POST", "/upload.php", 200, `{"f":"one.php"}`, `{"id":1001}`),
		testCand("b", 101, "x.com", "POST", "/upload.php", 200, `{"f":"two.php"}`, `{"id":2002}`),
	)
	// 步骤只给端点、body 特征又对不上任何一条（收窄被回滚）→ 多义 abstain。
	steps := []StepRef{{Request: "POST /upload.php HTTP/1.1\nHost: x.com\n\nnonexistent-payload-xyz"}}
	ids := ResolveReproSteps(0, 200, steps, cands)
	if ids[0] != "" {
		t.Fatalf("want abstain, got %v", ids)
	}
}

// 2b. 多候选但 body 特征唯一命中 → 绑那条（收窄生效且收敛到 1）。
func TestResolveBodyTokenNarrowsToUnique(t *testing.T) {
	cands := pool(
		testCand("a", 100, "x.com", "POST", "/upload.php", 200, `{"f":"one.php"}`, `{"id":1001}`),
		testCand("b", 101, "x.com", "POST", "/upload.php", 200, `{"f":"two.php"}`, `{"id":2002}`),
	)
	steps := []StepRef{{Request: "POST /upload.php HTTP/1.1\nHost: x.com\n\n{\"f\":\"two.php\"}"}}
	ids := ResolveReproSteps(0, 200, steps, cands)
	if ids[0] != "b" {
		t.Fatalf("want b, got %v", ids)
	}
}

// 3. 零候选：窗口内没有该端点 → abstain，不抛错。
func TestResolveZeroCandidates(t *testing.T) {
	cands := pool(testCand("a", 100, "x.com", "GET", "/index.html", 200, ``, `home`))
	steps := []StepRef{{Request: "GET /never-recorded HTTP/1.1\nHost: x.com"}}
	ids := ResolveReproSteps(0, 200, steps, cands)
	if ids[0] != "" {
		t.Fatalf("want abstain, got %v", ids)
	}
}

// 4. 时间窗裁剪：path/method 全同，但候选落在窗口外 → abstain。
func TestResolveTimeWindow(t *testing.T) {
	cands := pool(
		testCand("early", 50, "x.com", "GET", "/flag", 200, ``, `f`),
		testCand("late", 500, "x.com", "GET", "/flag", 200, ``, `f`),
	)
	steps := []StepRef{{Request: "GET /flag HTTP/1.1\nHost: x.com"}}
	ids := ResolveReproSteps(100, 200, steps, cands)
	if ids[0] != "" {
		t.Fatalf("window must exclude both, got %v", ids)
	}
	// 同一条改成窗口覆盖它 → 命中，证明 abstain 是裁剪所致而非匹配失败。
	ids = ResolveReproSteps(100, 600, steps, cands)
	if ids[0] != "late" {
		t.Fatalf("want late inside window, got %v", ids)
	}
}

// 5. method 不符：path 相同但方法不同 → abstain。
func TestResolveMethodMismatch(t *testing.T) {
	cands := pool(testCand("a", 100, "x.com", "GET", "/upload.php", 200, ``, `ok`))
	steps := []StepRef{{Request: "POST /upload.php HTTP/1.1\nHost: x.com"}}
	ids := ResolveReproSteps(0, 200, steps, cands)
	if ids[0] != "" {
		t.Fatalf("method mismatch must abstain, got %v", ids)
	}
}

// 6. path token 打分：步骤带 /api/v1 前缀、录制端模板化了 id 段，token 集合
// 仍然包含 → 收窄命中唯一候选。
func TestResolvePathTokens(t *testing.T) {
	cands := pool(
		testCand("a", 100, "x.com", "GET", "/api/v1/users/42/profile", 200, ``, `ok`),
		testCand("b", 101, "x.com", "GET", "/api/v1/login", 200, ``, `ok`),
	)
	steps := []StepRef{{Request: "GET /users/{id}/profile HTTP/1.1\nHost: x.com"}}
	ids := ResolveReproSteps(0, 200, steps, cands)
	if ids[0] != "a" {
		t.Fatalf("want a via token match, got %v", ids)
	}
}

// 7. Host 缺失：裸报文不带 Host 头 → 不收窄 host，仍可命中唯一候选；
// 同名 path 在两个 host 各一条时 → 多义 abstain。
func TestResolveHostMissing(t *testing.T) {
	one := pool(testCand("a", 100, "x.com", "GET", "/flag", 200, ``, `f`))
	steps := []StepRef{{Request: "GET /flag HTTP/1.1\n\n"}}
	if ids := ResolveReproSteps(0, 200, steps, one); ids[0] != "a" {
		t.Fatalf("missing Host must not drop the match, got %v", ids)
	}
	two := pool(
		testCand("a", 100, "x.com", "GET", "/flag", 200, ``, `f`),
		testCand("b", 101, "y.com", "GET", "/flag", 200, ``, `f`),
	)
	if ids := ResolveReproSteps(0, 200, steps, two); ids[0] != "" {
		t.Fatalf("two hosts + no Host header = ambiguous, got %v", ids)
	}
}

// 8. 有序 cursor 链：同端点重放两次，step1 绑最早、step2 绑其后一条。
func TestResolveOrderedCursor(t *testing.T) {
	cands := pool(
		testCand("a", 100, "x.com", "POST", "/login", 200, `{"u":"admin","p":"123"}`, `{"token":"AAA111BBBB"}`),
		testCand("b", 101, "x.com", "POST", "/login", 200, `{"u":"admin","p":"123"}`, `{"token":"BBB222CCCC"}`),
	)
	steps := []StepRef{
		{Request: "POST /login HTTP/1.1\nHost: x.com\n\n{\"u\":\"admin\",\"p\":\"123\"}", Response: "HTTP/1.1 200 OK\n{\"token\":\"AAA111BBBB\"}"},
		{Request: "POST /login HTTP/1.1\nHost: x.com\n\n{\"u\":\"admin\",\"p\":\"123\"}", Response: "HTTP/1.1 200 OK\n{\"token\":\"BBB222CCCC\"}"},
	}
	ids := ResolveReproSteps(0, 200, steps, cands)
	if ids[0] != "a" || ids[1] != "b" {
		t.Fatalf("want [a b], got %v", ids)
	}
}

// 9. 多候选状态消歧：body 收窄后仍两条（同 payload 重放），步骤自述 500 →
// 唯一 500 者胜出。
func TestResolveStatusDisambiguation(t *testing.T) {
	cands := pool(
		testCand("a", 100, "x.com", "POST", "/inject", 200, `id=1'`, `{"ok":1}`),
		testCand("b", 101, "x.com", "POST", "/inject", 500, `id=1'`, `SQL syntax error near 1'`),
	)
	steps := []StepRef{{Request: "POST /inject HTTP/1.1\nHost: x.com\n\nid=1'", Response: "HTTP/1.1 500 Internal Server Error\nSQL syntax error near 1'"}}
	ids := ResolveReproSteps(0, 200, steps, cands)
	if ids[0] != "b" {
		t.Fatalf("want b (the 500), got %v", ids)
	}
}

// 10. curl 形态 + 响应判别词收窄：长 token 唯一命中。
func TestResolveCurlAndRespDiscriminator(t *testing.T) {
	cands := pool(
		testCand("a", 100, "x.com", "GET", "/search?q=flag", 200, ``, `here is CTFFLAG2026`),
		testCand("b", 101, "x.com", "GET", "/search?q=flag", 200, ``, `no match found`),
	)
	steps := []StepRef{{Request: `curl http://x.com/search?q=flag -H 'Host: x.com'`, Response: "HTTP/1.1 200 OK\nhere is CTFFLAG2026"}}
	ids := ResolveReproSteps(0, 200, steps, cands)
	if ids[0] != "a" {
		t.Fatalf("want a via response token, got %v", ids)
	}
}

// 11. 解析健壮性：无 URL 无报文明细 → 解析失败 abstain，不 panic。
func TestResolveUnparseableAbstain(t *testing.T) {
	cands := pool(testCand("a", 100, "x.com", "GET", "/flag", 200, ``, `f`))
	steps := []StepRef{{Request: "本地复现，命令已遗失"}, {Request: ""}}
	ids := ResolveReproSteps(0, 200, steps, cands)
	if ids[0] != "" || ids[1] != "" {
		t.Fatalf("unparseable steps must abstain, got %v", ids)
	}
}

// 12. 纯函数侧的辅助单测：path token 归一、绝对 URI 请求行、host 提取。
func TestParseHelpers(t *testing.T) {
	m, p, q, _ := parseStepRequest("GET http://x.com/a/b?c=1 HTTP/1.1\nHost: x.com\n\n")
	if m != "GET" || p != "/a/b" || q != "c=1" {
		t.Fatalf("absolute-form request line: got %q %q %q", m, p, q)
	}
	if h := parseStepHost("GET /a HTTP/1.1\nHost: X.Com:8443\n\n"); h != "x.com" {
		t.Fatalf("host header parse (case+port fold): got %q", h)
	}
	if h := parseStepHost("GET /a HTTP/1.1\n\n"); h != "" {
		t.Fatalf("no host => empty, got %q", h)
	}
	if !pathMatch("/users/{id}/profile", "http://x.com/api/v1/users/42/profile") {
		t.Fatal("token containment must match templated ids")
	}
	if pathMatch("/login", "/admin/upload") {
		t.Fatal("unrelated paths must not match")
	}
	if bodyPhrase("x") != "" || bodyPhrase("abc") != "abc" {
		t.Fatal("bodyPhrase min length")
	}
	if bodyPhrase("line-one\nline-two") != "line-one" {
		t.Fatal("bodyPhrase must cut at first line")
	}
	long := strings.Repeat("z", 300)
	if len([]rune(bodyPhrase(long))) != 200 {
		t.Fatal("bodyPhrase rune cap")
	}
}

// 13. DB 侧最小拉取+端到端（record→WindowCandidates→ResolveSteps）。
func TestWindowCandidatesEndToEnd(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.record(newFlow("api.example.com", "POST", "/v1/login",
		[]byte(`{"user":"admin","password":"P@ssw0rd"}`),
		[]byte(`{"token":"abc123","note":"内网测试账号"}`)))
	tr.record(newFlow("api.example.com", "GET", "/v1/health", nil, []byte(`{"status":"ok"}`)))

	now := time.Now().Unix()
	cands, err := tr.WindowCandidates(now-60, now+60, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 2 {
		t.Fatalf("want 2 candidates, got %d", len(cands))
	}
	for i := 1; i < len(cands); i++ {
		if cands[i].TS < cands[i-1].TS {
			t.Fatal("candidates must be ts-ascending")
		}
	}
	if !strings.Contains(cands[0].ReqSnip, "P@ssw0rd") {
		t.Fatalf("login req snippet missing body: %q", cands[0].ReqSnip)
	}

	ids := tr.ResolveSteps(now-60, now+60, []StepRef{
		{Request: "POST /v1/login HTTP/1.1\nHost: api.example.com\n\n{\"user\":\"admin\",\"password\":\"P@ssw0rd\"}"},
	})
	if ids[0] == "" {
		t.Fatal("end-to-end resolve failed to bind the login exchange")
	}
	// 窗口外 → abstain。
	if ids := tr.ResolveSteps(now+10, now+60, []StepRef{
		{Request: "POST /v1/login HTTP/1.1\nHost: api.example.com\n\n{\"user\":\"admin\",\"password\":\"P@ssw0rd\"}"},
	}); ids[0] != "" {
		t.Fatalf("future window must abstain, got %v", ids)
	}
}
