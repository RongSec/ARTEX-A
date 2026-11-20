package agent

import (
	"strings"
	"testing"
)

// TestRedactTestMethod 断言「只保留测试方法」的脱敏口径：
// host / IP / 凭据值一律不出现，方法+路径/参数保留。
func TestRedactTestMethod(t *testing.T) {
	in := `POST http://oa.example-corp.com:8080/api/login?next=/home 返回 302，
Cookie: SESSION=abc123；password=Passw0rd!；内网 10.0.0.15:8080 也可访问，
GET https://admin.corp.local/api/user/1001 返回 200`
	out := redactTestMethod(in)

	for _, bad := range []string{"example-corp", "10.0.0.15", "Passw0rd", "abc123", "admin.corp.local"} {
		if strings.Contains(out, bad) {
			t.Fatalf("脱敏后不应出现 %q，got: %s", bad, out)
		}
	}
	for _, want := range []string{"/api/login?next=/home", "/api/user/1001"} {
		if !strings.Contains(out, want) {
			t.Fatalf("应保留路径 %q，got: %s", want, out)
		}
	}
}

// TestRequestsIn 断言请求行抽取：URL 只留 path，去重。
func TestRequestsIn(t *testing.T) {
	body := `先 GET http://a.example.com/api/list?page=1 200
再 GET http://a.example.com/api/list?page=2 200
最后 POST https://b.example.com/api/login {"user":"admin"}`
	got := requestsIn(body)
	if len(got) != 2 {
		t.Fatalf("应按 method+path 去重成 2 条，got %d: %v", len(got), got)
	}
	if got[0] != "GET /api/list" || got[1] != "POST /api/login" {
		t.Fatalf("请求行不对: %v", got)
	}
}

// TestWorkerAskReaderContract 锁住 worker 侧的两条硬约束：工具必须在
// WorkerTools 里，提示词必须写明「只要方法/只许路径/禁止 host/每意图 2 次」。
func TestWorkerAskReaderContract(t *testing.T) {
	names := map[string]bool{}
	for _, tool := range NewToolSet(nil, "worker").WorkerTools() {
		names[tool.Name()] = true
	}
	if !names["ask_reader"] {
		t.Fatal("WorkerTools 必须包含 ask_reader（worker 要能向阅读者下钻）")
	}
	spec := workerReaderSpec()
	for _, want := range []string{"只允许问", "禁止追问 host", "query 只写路径", "最多 2 次"} {
		if !strings.Contains(spec, want) {
			t.Errorf("worker 阅读者规约缺少 %q: %s", want, spec)
		}
	}
}

// TestReaderHostQueryGuard 断言 worker 的 query 不能夹带 URL/host/IP。
func TestReaderHostQueryGuard(t *testing.T) {
	for _, q := range []string{"http://oa.example.com/api", "10.0.0.5", "admin.corp.local"} {
		if !reReaderHostRef.MatchString(q) {
			t.Errorf("应拦截含 host/IP 的 query: %q", q)
		}
	}
	for _, q := range []string{"/api/user", "越权", "shiro"} {
		if reReaderHostRef.MatchString(q) {
			t.Errorf("不应误拦纯路径/漏洞类型: %q", q)
		}
	}
}

// TestHasConcreteReaderEvidence 区分「有请求行/步骤/正文」和「只有摘要」：
// 只有后者才值得再走一次阅读者 LLM 总结。
func TestHasConcreteReaderEvidence(t *testing.T) {
	if hasConcreteReaderEvidence([]ReaderDrillNode{{Summary: "同构接口"}}) {
		t.Fatal("只有摘要应判为证据不足")
	}
	if !hasConcreteReaderEvidence([]ReaderDrillNode{{Requests: []string{"POST /api/login"}}}) {
		t.Fatal("有请求行应判为足够")
	}
	if !hasConcreteReaderEvidence([]ReaderDrillNode{{Steps: []string{"curl · 200"}}}) {
		t.Fatal("有执行步骤应判为足够")
	}
}
