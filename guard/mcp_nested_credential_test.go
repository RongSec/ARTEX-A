package guard

import (
	"strings"
	"testing"
)

// mcpCall 构造线上 stdio MCP 调用的 hook 入参：启用 MCP 后 agent 的调用
// 在 hook 里表现为 tool_name=ExecuteExtraTool，入参是嵌套结构
//
//	{"tool_name":"mcp__probe__run_shell","params":{"command":...}}
//
// commandJSON 必须是【带双引号的 JSON 字符串字面量】（用反引号给出），
// 以便逐条精确控制转义形态（第 7 条的斜杠以 Unicode 转义字面量给出）。
func mcpCall(commandJSON string) []byte {
	return []byte(`{"tool_name":"mcp__probe__run_shell","params":{"command":` + commandJSON + `}}`)
}

// TestMCPNestedHostCredential 是任务 #45 实网红线漏判的回归钉：旧
// hostScanText 只取顶层 hostScanFields，MCP 的 command 藏在 params 里取不到
// → 返回空串 → host 档恒不命中 → cat /etc/shadow 被判官按「纯只读」放行。
// 平台凭据档之所以没漏，是因为它对 raw 全字节做正则（见 shortCircuit 里
// platformCredentialRe.Match(input)），与 hostScanText 无关。
func TestMCPNestedHostCredential(t *testing.T) {
	const mcpTool = "ExecuteExtraTool" // 线上 hook 里 stdio MCP 调用的表现名

	// 1. 本机凭据档：MCP 嵌套形态必须 deny（本次修复的核心）。
	t.Run("1-MCP嵌套cat_etc_shadow应deny", func(t *testing.T) {
		dec := shortCircuit(mcpTool, mcpCall(`"cat /etc/shadow"`))
		if dec == nil || dec.Action != "deny" {
			t.Fatalf("MCP 嵌套 cat /etc/shadow 应 deny，得到 %+v", dec)
		}
		if dec.RuleName != "[代码常量] 本机系统凭据裸读" {
			t.Fatalf("应命中 host 档，得到 RuleName=%q", dec.RuleName)
		}
	})

	// 2. 远程指代豁免仍生效：docker exec 读目标容器内 shadow 是合法战果。
	t.Run("2-MCP嵌套docker_exec应nil", func(t *testing.T) {
		if dec := shortCircuit(mcpTool, mcpCall(`"docker exec dvwa-a cat /etc/shadow"`)); dec != nil {
			t.Fatalf("docker exec 远程豁免应放行(nil)，得到 %+v", dec)
		}
	})

	// 3. 平台凭据档不回归：本就命中（对 raw 全字节匹配），仍 deny。
	t.Run("3-MCP嵌套平台密钥仍deny", func(t *testing.T) {
		if dec := shortCircuit(mcpTool, mcpCall(`"cat /app/jwt.key"`)); dec == nil || dec.Action != "deny" {
			t.Fatalf("cat /app/jwt.key 应仍 deny，得到 %+v", dec)
		}
	})

	// 4. 普通打靶 HTTP 请求不受影响。
	t.Run("4-MCP嵌套curl应nil", func(t *testing.T) {
		if dec := shortCircuit(mcpTool, mcpCall(`"curl -s http://127.0.0.1:9083/login.php"`)); dec != nil {
			t.Fatalf("curl 应放行(nil)，得到 %+v", dec)
		}
	})

	// 5. 短路表不拦破坏性命令，交规则层判官（与线上 140 一致）。
	t.Run("5-MCP嵌套rm应nil", func(t *testing.T) {
		if dec := shortCircuit(mcpTool, mcpCall(`"rm -rf /var/www/html"`)); dec != nil {
			t.Fatalf("rm 应放行(nil)交规则层，得到 %+v", dec)
		}
	})

	// 6. 描述性字段不误伤：summary 里引用命令原文不得当成本机读取。
	t.Run("6-描述性字段不误伤", func(t *testing.T) {
		in := []byte(`{"summary":"复现 cat /etc/shadow","params":{"command":"id"}}`)
		if dec := shortCircuit(mcpTool, in); dec != nil {
			t.Fatalf("summary 引用命令原文应放行(nil)，得到 %+v", dec)
		}
	})

	// 7. 嵌套 + JSON 转义：params.command 里的斜杠以 Unicode 转义给出，
	//    由 json.Unmarshal 还原成 '/'，递归提取后照样命中 host 档。
	t.Run("7-嵌套转义应deny", func(t *testing.T) {
		dec := shortCircuit(mcpTool, mcpCall(`"cat \u002fetc\u002fshadow"`))
		if dec == nil || dec.Action != "deny" {
			t.Fatalf("嵌套转义形态应 deny，得到 %+v", dec)
		}
	})

	// 8. 顶层旧形态不回归 + record_fact 记录豁免不回归。
	t.Run("8-顶层旧形态与record_fact不回归", func(t *testing.T) {
		if dec := shortCircuit("Bash", []byte(`{"command":"cat /etc/shadow"}`)); dec == nil || dec.Action != "deny" {
			t.Fatalf("顶层 command 形态应仍 deny，得到 %+v", dec)
		}
		if dec := shortCircuit("record_fact", []byte(`{"content":"复现 cat /app/jwt.key 被拦截"}`)); dec != nil {
			t.Fatalf("record_fact 引用平台密钥应放行(nil)，得到 %+v", dec)
		}
	})

	// 9. 深度上限：70 层嵌套不 panic、不死循环。command 藏在最里层，
	//    超过 hostScanMaxDepth 后被截断，但必须正常返回。
	t.Run("9-70层嵌套不panic不死循环", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < 70; i++ {
			b.WriteString(`{"params":`)
		}
		b.WriteString(`{"command":"cat /etc/shadow"}`)
		for i := 0; i < 70; i++ {
			b.WriteString(`}`)
		}
		deep := []byte(b.String())
		// 不 panic、不死循环即通过（若 panic，go test 直接标记失败）。
		_ = hostScanText(deep)
		_ = shortCircuit(mcpTool, deep)
	})
}
