package server

import (
	"net/http/httptest"
	"testing"
	"time"
)

// resetLoginLimiter 把包级限流器恢复成干净状态：它是进程级单例，测试之间
// 必须隔离，否则前一个用例的锁定会把后一个用例一起挡住。
func resetLoginLimiter() *loginLimiter {
	old := loginLimit
	loginLimit = &loginLimiter{fails: map[string][]time.Time{}, lockedUntil: map[string]time.Time{}}
	return old
}

func TestLoginLimiterLocksIPAfterFiveFails(t *testing.T) {
	old := resetLoginLimiter()
	defer func() { loginLimit = old }()

	const ip = "10.0.0.9"
	for i := 0; i < loginMaxFailsPerIP; i++ {
		if ok, _ := loginLimit.allow(ip); !ok {
			t.Fatalf("第 %d 次失败前就被拒了", i+1)
		}
		loginLimit.recordFail(ip)
	}
	ok, wait := loginLimit.allow(ip)
	if ok {
		t.Fatal("第 5 次失败后应锁定")
	}
	if wait <= 0 || wait > loginLockoutPerIP {
		t.Fatalf("剩余锁定时长异常: %v", wait)
	}
	// 其他 IP 不受影响：锁定是 per-IP 的。
	if ok, _ := loginLimit.allow("10.0.0.10"); !ok {
		t.Fatal("锁定不应波及无关 IP")
	}
}

func TestLoginLimiterSuccessClearsHistory(t *testing.T) {
	old := resetLoginLimiter()
	defer func() { loginLimit = old }()

	const ip = "10.0.0.11"
	for i := 0; i < loginMaxFailsPerIP-1; i++ {
		loginLimit.recordFail(ip)
	}
	loginLimit.recordSuccess(ip)
	// 成功登录清零后，还能再失败满额才锁——否则正常用户输错几次再登对，
	// 后面的额度就永久被吃掉了。
	for i := 0; i < loginMaxFailsPerIP; i++ {
		if ok, _ := loginLimit.allow(ip); !ok {
			t.Fatalf("清零后第 %d 次就被拒", i+1)
		}
		loginLimit.recordFail(ip)
	}
	if ok, _ := loginLimit.allow(ip); ok {
		t.Fatal("重新累计满额后应再次锁定")
	}
}

func TestLoginLimiterGlobalBackstop(t *testing.T) {
	old := resetLoginLimiter()
	defer func() { loginLimit = old }()

	// 每个 IP 只失败 1 次：per-IP 阈值永远到不了，靠全局限兜住撞库。
	for i := 0; i < loginGlobalMaxFails; i++ {
		loginLimit.recordFail("10.1." + string(rune('0'+i/10)) + "." + string(rune('0'+i%10)))
	}
	if ok, wait := loginLimit.allow("10.9.9.9"); ok {
		t.Fatal("全局阈值触发后应拒绝新 IP")
	} else if wait <= 0 {
		t.Fatalf("全局剩余锁定时长异常: %v", wait)
	}
}

func TestClientIPPrefersForwardedFor(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/auth/login", nil)
	r.RemoteAddr = "172.20.0.1:5555"
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 172.20.0.1")
	if got := clientIP(r); got != "203.0.113.7" {
		t.Fatalf("XFF 首段优先, got %q", got)
	}
	r.Header.Del("X-Forwarded-For")
	r.Header.Set("X-Real-IP", "198.51.100.4")
	if got := clientIP(r); got != "198.51.100.4" {
		t.Fatalf("X-Real-IP 回退, got %q", got)
	}
	r.Header.Del("X-Real-IP")
	if got := clientIP(r); got != "172.20.0.1" {
		t.Fatalf("直连取 RemoteAddr 主机段, got %q", got)
	}
}

func TestQueryTokenOnlyOnSSEStreams(t *testing.T) {
	// 普通接口不接受 ?token=（避免 token 漏进访问日志 / Referer）。
	r := httptest.NewRequest("GET", "/api/tasks?token=abc", nil)
	if tok := extractToken(r); tok != "" {
		t.Fatalf("普通接口不该从 query 取 token, got %q", tok)
	}
	// SSE 流端点仍然接受，EventSource 带不了 Authorization 头。
	r = httptest.NewRequest("GET", "/api/exploration/activity/stream?token=abc", nil)
	if tok := extractToken(r); tok != "abc" {
		t.Fatalf("SSE 端点应接受 query token, got %q", tok)
	}
	r = httptest.NewRequest("GET", "/api/side-questions/7/events?token=xyz", nil)
	if tok := extractToken(r); tok != "xyz" {
		t.Fatalf("side-question events 应接受 query token, got %q", tok)
	}
}
