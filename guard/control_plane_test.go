package guard

// V6-CP：渗透测试 agent 自主绕过热加载规则的链路回归。
//
// 威胁模型不是「人持 JWT 关规则」，而是 agent 自己：
//   ① 读平台 dataDir 下的 jwt.key（绝对路径）→ 拿 token；
//   ② 用 token 调平台管理 API（/api/intercept/**、/api/settings）
//      → 关规则 / 改设置 → 热加载规则被自主绕过。
// 短路表存在的意义就是这条链路的最后一道闸，因此两组判定都必须在这里钉死。
//
// 测试纪律：
//   - 平台绝对路径用临时 dataDir 注入（ReloadShortCircuit），不写死线上路径；
//   - 靶机同名文件（/tmp/target/jwt.key）与靶标端口（:9081）必须放行，
//     证明不是「按 basename / 按端口通配」的一刀切；
//   - 判定结果 nil = 未命中短路表（继续走 DB 规则与判官）。

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/intercept"
)

func bashInput(cmd string) []byte {
	return []byte(fmt.Sprintf(`{"command":%s}`, strconv.Quote(cmd)))
}

func assertDeny(t *testing.T, cmd string) *intercept.Decision {
	t.Helper()
	dec := shortCircuit("Bash", bashInput(cmd))
	if dec == nil {
		t.Fatalf("应命中短路表 deny，实际放行: %s", cmd)
	}
	if dec.Action != "deny" {
		t.Fatalf("应为 deny，得到 %s: %s", dec.Action, cmd)
	}
	if !strings.HasPrefix(dec.RuleName, "[代码常量]") {
		t.Fatalf("RuleName 必须以 [代码常量] 开头（db 层靠它识别来源），得到 %q", dec.RuleName)
	}
	return dec
}

func assertPass(t *testing.T, cmd string) {
	t.Helper()
	if dec := shortCircuit("Bash", bashInput(cmd)); dec != nil {
		t.Fatalf("不应命中短路表，得到 %s/%s: %s", dec.Action, dec.RuleName, cmd)
	}
}

// 1. 平台 dataDir 的绝对路径密钥：旧版只认 /app/... 与 ../../jwt.key，
// 线上实测 `cat /root/Desktop/sec/artex-hs/data/jwt.key` 被放行。
func TestPlatformAbsDirCredentialDenied(t *testing.T) {
	restoreDefaultShortCircuit(t)
	dir := t.TempDir()
	if err := ReloadShortCircuit(dir); err != nil {
		t.Fatalf("加载空配置（默认规则 + 临时 dataDir）失败: %v", err)
	}
	slashed := filepath.ToSlash(dir)
	// 该字段供 UI 只读展示（运行时生成，不落盘）。
	if got := EffectiveShortCircuitConfig().PlatformAbsDir; got != slashed {
		t.Fatalf("platform_abs_dir 应为运行时 dataDir 绝对路径 %q，得到 %q", slashed, got)
	}

	for _, leaf := range []string{"jwt.key", ".jwt", ".env", "shortcircuit_rules.json"} {
		assertDeny(t, "cat "+slashed+"/"+leaf)
	}
	// MITM CA 私钥/证书
	assertDeny(t, "cat "+slashed+"/traffic/_ca/ca.pem")
	// 反斜杠写法（Windows 风格命令文本）同样要拦。
	if dec := shortCircuit("Bash", bashInput(`type `+strings.ReplaceAll(slashed, "/", `\`)+`\jwt.key`)); dec == nil {
		t.Fatal("反斜杠形态的 dataDir 绝对路径应命中 deny")
	}
	// ./ 与 x/../ 归一的常见写法。
	assertDeny(t, "cat "+slashed+"/./jwt.key")
	assertDeny(t, "cat "+slashed+"/x/../jwt.key")
}

// 2. 相对回溯：既有 (?:\.\./){2,}jwt\.key 不得回归。
func TestRelativeTraversalCredentialStillDenied(t *testing.T) {
	restoreDefaultShortCircuit(t)
	assertDeny(t, "cat ../../jwt.key")
}

// 3. 靶机同名文件不误伤：只拦解析到平台 dataDir 的路径，不按 basename 兜底。
func TestTargetSameNameFileNotBlocked(t *testing.T) {
	restoreDefaultShortCircuit(t)
	dir := t.TempDir()
	if err := ReloadShortCircuit(dir); err != nil {
		t.Fatal(err)
	}
	assertPass(t, "cat /tmp/target/jwt.key")
	assertPass(t, "cat /tmp/target/config.json")
	assertPass(t, "cat my_config.json")
}

// 4-6. 平台控制面 API：带 Bearer 读规则、POST 关规则、PUT 改设置。
func TestControlPlaneAPIDenied(t *testing.T) {
	restoreDefaultShortCircuit(t)
	dir := t.TempDir()
	if err := ReloadShortCircuit(dir); err != nil {
		t.Fatal(err)
	}
	cases := []string{
		`curl -H "Authorization: Bearer x" http://127.0.0.1:8801/api/intercept/rules`,
		`curl -X POST http://127.0.0.1:8801/api/intercept/rules/1/toggle -d '{"enabled":false}'`,
		`curl -X PUT http://127.0.0.1:8801/api/settings -d '{"intercept_judge_all_tools":false}'`,
		// 代码默认端口 8787 与 localhost 形态同样覆盖。
		`curl http://localhost:8787/api/settings`,
		// 任务控制面。
		`curl -X POST http://127.0.0.1:8801/api/tasks/12/control -d '{"action":"stop"}'`,
	}
	for _, cmd := range cases {
		dec := assertDeny(t, cmd)
		if dec.RuleName != "[代码常量] 平台控制面 API" {
			t.Fatalf("控制面判定应使用独立 RuleName，得到 %q", dec.RuleName)
		}
	}
	// 第二道：显式 Bearer + 本机平台端口，无论路径。
	assertDeny(t, `curl -H "Authorization: Bearer x" http://127.0.0.1:8801/anything`)
}

// 7. 只读业务面不误伤：agent 自查健康是合法动作。
func TestControlPlaneReadOnlyEndpointsAllowed(t *testing.T) {
	restoreDefaultShortCircuit(t)
	dir := t.TempDir()
	if err := ReloadShortCircuit(dir); err != nil {
		t.Fatal(err)
	}
	assertPass(t, "curl http://127.0.0.1:8801/api/health")
	assertPass(t, "curl http://127.0.0.1:8801/api/facts")
	assertPass(t, "curl http://127.0.0.1:8801/function/facts")
	// 带 token 查健康也应放行（只读面豁免优先于 Bearer 第二道）。
	assertPass(t, `curl -H "Authorization: Bearer x" http://127.0.0.1:8801/api/health`)
}

// 8. 靶标不被误伤：本机端口但不是平台端口。
func TestTargetLocalPortNotBlocked(t *testing.T) {
	restoreDefaultShortCircuit(t)
	dir := t.TempDir()
	if err := ReloadShortCircuit(dir); err != nil {
		t.Fatal(err)
	}
	assertPass(t, "curl -s http://127.0.0.1:9081/login.php")
	assertPass(t, "curl -s http://127.0.0.1:9081/api/settings")
}

// 9. 只拦本机控制面：外部主机的同名端口/路径属于打靶流量。
func TestExternalHostControlPathNotBlocked(t *testing.T) {
	restoreDefaultShortCircuit(t)
	dir := t.TempDir()
	if err := ReloadShortCircuit(dir); err != nil {
		t.Fatal(err)
	}
	assertPass(t, "curl http://10.20.30.40:8801/api/settings")
	assertPass(t, `curl -H "Authorization: Bearer x" http://target.example:8801/api/intercept/rules`)
}
