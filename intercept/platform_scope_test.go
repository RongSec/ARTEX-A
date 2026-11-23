package intercept

// V12-RULES：远程豁免与平台地址占位符的纯函数单测（无需数据库）。
//
// 这两条是「规则合并后仍然不能误拦」的关键：
//   - 远程豁免：按命中位置判上下文，用例见 remote_context_test.go；
//   - 占位符：{{PLATFORM_IPS}} 必须展开成实际地址，且一个候选都没有时不能
//     退化成「匹配一切」。

import (
	"regexp"
	"testing"
)

func TestExpandPlatformPlaceholders(t *testing.T) {
	pat := `(?:{{PLATFORM_IPS}}):(?:{{PLATFORM_PORTS}})/api/settings`
	got := ExpandPlatformPlaceholders(pat, []string{"192.0.2.10"}, []string{"8801", "8787"})
	re, err := regexp.Compile(got)
	if err != nil {
		t.Fatalf("展开后的正则编译失败: %v（%s）", err, got)
	}
	mustHit := []string{
		"http://127.0.0.1:8801/api/settings",
		"http://localhost:8787/api/settings",
		"http://192.0.2.10:8801/api/settings",
	}
	for _, s := range mustHit {
		if !re.MatchString(s) {
			t.Errorf("应命中: %s（展开为 %s）", s, got)
		}
	}
	if re.MatchString("http://192.0.2.11:8801/api/settings") {
		t.Error("192.0.2.11 不在地址集合里，不该命中")
	}
	if re.MatchString("http://127.0.0.1:9999/api/settings") {
		t.Error("9999 不是平台端口，不该命中")
	}
}

func TestExpandPlatformPlaceholdersNeverMatchesEverything(t *testing.T) {
	// 端口集合为空 → 用默认值，绝不能生成空分组 `()` 让任何端口都命中。
	got := ExpandPlatformPlaceholders(`x:(?:{{PLATFORM_PORTS}})`, nil, nil)
	re, err := regexp.Compile(got)
	if err != nil {
		t.Fatal(err)
	}
	if re.MatchString("x:12345") {
		t.Errorf("默认端口集合不该匹配 12345，展开为 %s", got)
	}
}


// TestProcessEnvironPrecision 钉死用户指出的误拦：/proc/self/environ 是 agent
// 自己的环境，不该拦；/proc/<pid>/environ 才是别人的。
func TestProcessEnvironPrecision(t *testing.T) {
	re := regexp.MustCompile(`/proc/\d+/envi(?:ron)?\b`)
	if !re.MatchString("/proc/1/environ") {
		t.Error("/proc/1/environ 应命中")
	}
	if !re.MatchString("/proc/1234/environ") {
		t.Error("/proc/1234/environ 应命中")
	}
	if re.MatchString("/proc/self/environ") {
		t.Error("/proc/self/environ 不该命中（读自己的环境无害）")
	}
	if re.MatchString("/proc/mounts") {
		t.Error("/proc/mounts 不该命中")
	}
}
