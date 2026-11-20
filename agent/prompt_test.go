package agent

import (
	"strings"
	"testing"
)

func TestPlannerPromptAdoptsReaderHint(t *testing.T) {
	// V11-WORKER-READER：hint 只给方向，细节由执行者 ask_reader 下钻；
	// 规划者仍不持有勾连工具，但要知道 worker 有 ask_reader。
	t.Cleanup(func() { PromptOverride = nil })
	PromptOverride = nil
	got := plannerSystem("拿下X", "/data", "/data")
	for _, banned := range []string{"request_reader_links", "adopt_related_task", "dismiss_related_task", "worker 没有这个工具"} {
		if strings.Contains(got, banned) {
			t.Errorf("planner prompt 不应再出现 %q: %s", banned, got)
		}
	}
	for _, want := range []string{"方向提示", "不是可直接执行的细节", "ask_reader 规划者和 worker 都有", "readonly=true", "drill_via=reader"} {
		if !strings.Contains(got, want) {
			t.Errorf("planner prompt 缺少新协作口径 %q: %s", want, got)
		}
	}
}

func TestPlannerPromptForbidsForeignHosts(t *testing.T) {
	// V9-SCOPE：阅读者 hint 只是经验参考，不能把规划者引向其它任务的资产。
	t.Cleanup(func() { PromptOverride = nil })
	PromptOverride = nil
	got := plannerSystem("拿下X", "/data", "/data")
	for _, want := range []string{
		"经验参考", "reference_only",
		"禁止对 foreign_hosts", "发起任何请求/扫描/利用",
		"要把经验用到", "本任务已有资产",
		"先由本任务正常登记资产后再打",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("planner prompt 缺少跨任务资产边界规则 %q", want)
		}
	}
}

func TestRenderSystemOverrideAndFallback(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })

	// no override → built-in default
	PromptOverride = nil
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "g"}); got != "DEFAULT" {
		t.Fatalf("no override should give default, got %q", got)
	}

	// override → rendered with vars
	PromptOverride = func(k string) (string, bool) {
		if k == "planner" {
			return "目标:{{.Goal}} 范围:{{.Scope}}", true
		}
		return "", false
	}
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "拿下X", Scope: "*.x.com"}); got != "目标:拿下X 范围:*.x.com" {
		t.Fatalf("override render: %q", got)
	}

	// override referencing a non-catalog var → execution error → fallback to default
	PromptOverride = func(k string) (string, bool) { return "{{.NotInCatalog}}", true }
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "x"}); got != "DEFAULT" {
		t.Fatalf("bad var should fall back to default, got %q", got)
	}

	// full plannerSystem path: DB body [A] is honored, then the code-owned tail
	// [C] (中间产物输出规约) is ALWAYS appended — editing the body can't drop it.
	PromptOverride = func(k string) (string, bool) { return "PLANNER {{.Goal}}", true }
	got := plannerSystem("拿下X", "/data", "/data")
	if !strings.HasPrefix(got, "PLANNER 拿下X") {
		t.Fatalf("plannerSystem body not honored: %q", got)
	}
	if !strings.Contains(got, "中间产物输出规约") || !strings.Contains(got, "/data") {
		t.Fatalf("plannerSystem missing code-owned artifact tail: %q", got)
	}

	// worker dual-text via {{if .ProxyAddr}} in a user template, plus the code tail:
	// [B] trafficTool present only when RECORDING (caCert set — the MITM is on, so
	// the traffic_* tools exist), [C] artifact spec always present. The trafficTool
	// block is gated on the CA (arg 2), NOT on ProxyAddr — a global egress proxy
	// with capture off routes traffic but records nothing.
	PromptOverride = func(k string) (string, bool) {
		return "{{if .ProxyAddr}}走代理 {{.ProxyAddr}}{{else}}手动{{end}}", true
	}
	recording := workerSystem("127.0.0.1:8080", "/ca.pem", "/data", "/data")
	if !strings.HasPrefix(recording, "走代理 127.0.0.1:8080") {
		t.Fatalf("worker proxy branch body: %q", recording)
	}
	if !strings.Contains(recording, "traffic_search") {
		t.Fatalf("worker while recording should inject trafficTool: %q", recording)
	}
	if strings.Contains(recording, "traffic_refs") {
		t.Fatalf("worker bypassed shared optional evidence policy: %q", recording)
	}
	if !strings.Contains(recording, "中间产物输出规约") {
		t.Fatalf("worker missing artifact tail: %q", recording)
	}
	// Egress proxy set but capture OFF (no CA): the ProxyAddr template branch still
	// renders, but the trafficTool block must NOT — those tools are not registered.
	egressOnly := workerSystem("127.0.0.1:8080", "", "/data", "/data")
	if !strings.HasPrefix(egressOnly, "走代理 127.0.0.1:8080") {
		t.Fatalf("worker egress-only branch body: %q", egressOnly)
	}
	if strings.Contains(egressOnly, "traffic_search") {
		t.Fatalf("worker without recording must NOT inject trafficTool: %q", egressOnly)
	}
	noProxy := workerSystem("", "", "/data", "/data")
	if !strings.HasPrefix(noProxy, "手动") {
		t.Fatalf("worker no-proxy branch body: %q", noProxy)
	}
	if strings.Contains(noProxy, "traffic_search") {
		t.Fatalf("worker without proxy must NOT inject trafficTool: %q", noProxy)
	}
}
