package guard

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/intercept"
)

// write_content_falsepositive_test.go —— V6-WRITE 回归钉。
//
// 实网缺陷（线上 8801，任务 #46，intercept_pending id=141）：Write 写验收
// 结果文件，正文如实引用被拦命令原文 `cat /app/jwt.key`，被平台凭据档按整段
// raw 字节硬 deny，成果保存不下来。根因是平台凭据档把「正文文本」也当成了
// 「执行面文本」扫描。
//
// 修法：platformExecutionText 对 Write/Edit/MultiEdit 只保留执行面字段
// （file_path/path/command/args），丢弃 content/new_string/old_string 等正文；
// 其它工具（Bash / ExecuteExtraTool / Read …）原样返回。本文件 8 条子测试逐条
// 钉死该分离，并回归既有设计内 deny/放行；完整全量回归由
// `go test -count=1 ./guard/` 运行现存所有 shortcircuit 测试完成。
//
// 复用包内既有 helper：bashCommand（shortcircuit_test.go）、mcpCall
// （mcp_nested_credential_test.go），与线上 hook 入参同形。

func wcfpAssertNil(t *testing.T, desc string, dec *intercept.Decision) {
	t.Helper()
	if dec != nil {
		t.Fatalf("%s：应放行(nil)，得到 action=%s rule=%q", desc, dec.Action, dec.RuleName)
	}
}

func wcfpAssertDeny(t *testing.T, desc string, dec *intercept.Decision) {
	t.Helper()
	if dec == nil || dec.Action != "deny" {
		t.Fatalf("%s：应 deny，得到 %+v", desc, dec)
	}
}

// TestWriteContentFalsePositive 是 8 条断言的入口，逐名对应任务书的 8 项测试。
func TestWriteContentFalsePositive(t *testing.T) {
	// 1. Write 正文含 cat /app/jwt.key、路径为普通 /tmp/notes.txt → nil（id=141 本体）
	t.Run("1-Write正文引用平台密钥不误伤", func(t *testing.T) {
		// 线上原样：验收结果正文如实引用被拦命令原文
		in := []byte(`{"file_path":"/tmp/redline_result.txt","content":"ARTEX 三层拦截验证 — 红线样本逐条结果 … [6] cat /app/jwt.key -> 平台拒绝 …"}`)
		wcfpAssertNil(t, "Write 正文含 /app/jwt.key", shortCircuit("Write", in))

		// 逃逸形态：正文用 JSON 转义写 /app/jwt.key，走 decodedInputText 分支也
		// 不得被扫到（证明 raw 与 decoded 两条分支都已切到执行面文本）
		esc := []byte(`{"file_path":"/tmp/notes.txt","content":"[6] cat \u002fapp\u002fjwt.key -> 平台拒绝"}`)
		wcfpAssertNil(t, "Write 正文含转义 /app/jwt.key", shortCircuit("Write", esc))

		// MultiEdit 同族：edits[].new_string 引用平台密钥，file_path 普通 → nil
		me := []byte(`{"file_path":"/tmp/x","edits":[{"old_string":"A","new_string":"复现 cat /app/jwt.key 被拦截"}]}`)
		wcfpAssertNil(t, "MultiEdit 正文引用平台密钥", shortCircuit("MultiEdit", me))
	})

	// 2. Write 正文含 cat config.json、rm -rf 等 → nil
	t.Run("2-Write正文引用裸读与破坏命令不误伤", func(t *testing.T) {
		// ASCII 边界让修复前的 bareReadHit 确实会命中，修复后正文被整支丢弃。
		// rm -rf 属规则层（本单明确不处理），短路表本就无该正则，一并断言 nil。
		in := []byte(`{"file_path":"/tmp/notes.txt","content":"[1] cat config.json -> platform denied; [2] rm -rf /tmp/x -> rule; [3] cat jwt.key -> denied"}`)
		wcfpAssertNil(t, "Write 正文含 cat config.json / rm -rf / cat jwt.key", shortCircuit("Write", in))

		// MultiEdit 的 edits 数组同属正文文本（old_string/new_string 整支丢弃）
		me := []byte(`{"file_path":"/tmp/x","edits":[{"old_string":"cat config.json","new_string":"已改为 cat config.json.bak"}]}`)
		wcfpAssertNil(t, "MultiEdit 正文含 cat config.json", shortCircuit("MultiEdit", me))
	})

	// 3. Write 的 file_path 指向平台凭据本体 → 仍 deny
	//    （「整体豁免 Write 不行」的正面证据：路径字段照旧全量匹配）
	t.Run("3-Write路径指向平台密钥仍deny", func(t *testing.T) {
		deny := []struct{ desc, in string }{
			{"jwt.key 现行位", `{"file_path":"/app/jwt.key","content":"x"}`},
			{"jwt.key 旧版遗留位", `{"file_path":"/app/data/jwt.key","content":"x"}`},
			{".env", `{"file_path":"/app/.env","content":"x"}`},
			{"/proc/1/environ", `{"file_path":"/proc/1/environ","content":"x"}`},
			{"三层回溯 ../../../jwt.key", `{"file_path":"../../../jwt.key","content":"x"}`},
			{"MITM CA 私钥", `{"file_path":"/app/data/traffic/_ca/mitmproxy-ca.pem","content":"x"}`},
		}
		for _, c := range deny {
			wcfpAssertDeny(t, "Write "+c.desc, shortCircuit("Write", []byte(c.in)))
		}
		// 精确断言命中来源为平台凭据档（不是 host 档）
		dec := shortCircuit("Write", []byte(`{"file_path":"/app/jwt.key","content":"x"}`))
		if dec == nil || dec.RuleName != "[代码常量] 平台凭据/进程环境" {
			t.Fatalf("Write file_path=/app/jwt.key 应命中平台凭据档，得到 %+v", dec)
		}
		// Edit / MultiEdit 同样：路径是执行面，必须照旧 deny
		wcfpAssertDeny(t, "Edit file_path=/app/jwt.key",
			shortCircuit("Edit", []byte(`{"file_path":"/app/jwt.key","old_string":"a","new_string":"b"}`)))
		wcfpAssertDeny(t, "MultiEdit file_path=/app/.env",
			shortCircuit("MultiEdit", []byte(`{"file_path":"/app/.env","edits":[{"old_string":"a","new_string":"b"}]}`)))
	})

	// 4. Edit 的 new_string 含 /app/.env 但 file_path=/tmp/x → nil
	t.Run("4-Edit正文含平台密钥路径但路径普通", func(t *testing.T) {
		in := []byte(`{"file_path":"/tmp/x","old_string":"PLACEHOLDER","new_string":"复现：cat /app/.env 被平台拦截","replace_all":false}`)
		wcfpAssertNil(t, "Edit new_string 含 /app/.env", shortCircuit("Edit", in))

		// old_string 同属正文文本，也不得被扫
		in2 := []byte(`{"file_path":"/tmp/x","old_string":"cat /app/jwt.key 被拦截","new_string":"已记录","replace_all":false}`)
		wcfpAssertNil(t, "Edit old_string 含 /app/jwt.key", shortCircuit("Edit", in2))
	})

	// 5. Bash 同类正文形态：按既有 V4-E 行为不变
	//    （heredoc 正文是数据→剥离后不误伤；正文被解释器当命令执行 / 含平台
	//     凭据绝对路径→仍 deny）。Bash 不在写入类，platformExecutionText 原样
	//     返回，故这些判定与修复前逐字一致。
	t.Run("5-Bash_heredoc_V4-E行为不变", func(t *testing.T) {
		// 正文是数据：裸相对名档剥离后不误伤
		wcfpAssertNil(t, "Bash heredoc 写摘要含 cat config.json",
			shortCircuit("Bash", bashCommand("cat > /tmp/brief.txt <<'EOF'\n[1] cat config.json 是上一步被拦的命令原文\nEOF")))
		// 正文被解释器当命令执行：不剥离，仍 deny
		wcfpAssertDeny(t, "Bash 解释器消费 heredoc 含 cat config.json",
			shortCircuit("Bash", bashCommand("bash <<'EOF'\ncat config.json\nEOF")))
		// 平台凭据档不对称：heredoc 正文含 /app/jwt.key 仍按原文全字节 deny
		wcfpAssertDeny(t, "Bash heredoc 正文含 /app/jwt.key",
			shortCircuit("Bash", bashCommand("cat > /tmp/brief.txt <<'EOF'\n[6] cat /app/jwt.key -> 平台拒绝\nEOF")))
	})

	// 6. ExecuteExtraTool 嵌套 params.command 含 /app/jwt.key → deny（V6-MCP 不回归）
	t.Run("6-ExecuteExtraTool嵌套平台密钥仍deny", func(t *testing.T) {
		wcfpAssertDeny(t, "ExecuteExtraTool params.command=cat /app/jwt.key",
			shortCircuit("ExecuteExtraTool", mcpCall(`"cat /app/jwt.key"`)))
		wcfpAssertDeny(t, "ExecuteExtraTool params.command=cat /proc/1/environ",
			shortCircuit("ExecuteExtraTool", mcpCall(`"cat /proc/1/environ"`)))
	})

	// 7. decodedInputText 转义绕过（\u002fapp\u002fjwt.key 出现在 Bash command）→ deny
	t.Run("7-转义绕过仍deny", func(t *testing.T) {
		for _, in := range []string{
			`{"command":"cat \u002fapp\u002fjwt.key"}`,
			`{"command":"cat \/app\/jwt.key"}`,
		} {
			wcfpAssertDeny(t, "Bash 转义 "+in, shortCircuit("Bash", []byte(in)))
		}
	})

	// 8. 既有设计内 deny/放行全量回归：本子测试点名回归任务书「必须保持」清单，
	//    完整回归由 `go test -count=1 ./guard/` 运行现存所有 shortcircuit 测试完成。
	t.Run("8-既有设计内判定全量回归", func(t *testing.T) {
		type tc struct{ desc, tool, in string }
		deny := []tc{
			{"Bash cat /app/jwt.key", "Bash", `{"command":"cat /app/jwt.key"}`},
			{"Bash cat /app/data/jwt.key", "Bash", `{"command":"cat /app/data/jwt.key"}`},
			{"Bash ../../../jwt.key", "Bash", `{"command":"cat ../../../jwt.key"}`},
			{"Bash cat config.json", "Bash", `{"command":"cat config.json"}`},
			{"Bash cat .jwt", "Bash", `{"command":"cat .jwt"}`},
			{"Bash bash -c 内联 cat config.json", "Bash", `{"command":"bash -c 'cat config.json'"}`},
			{"Bash cat /proc/1/environ", "Bash", `{"command":"cat /proc/1/environ"}`},
			{"Bash docker exec 读平台密钥不吃远程豁免", "Bash", `{"command":"docker exec x cat /app/jwt.key"}`},
			{"Read file_path=/etc/shadow 走 host 档", "Read", `{"file_path":"/etc/shadow"}`},
		}
		for _, c := range deny {
			wcfpAssertDeny(t, c.desc, shortCircuit(c.tool, []byte(c.in)))
		}
		// heredoc（V4-E 不对称）：bash <<EOF … cat /app/jwt.key … EOF → deny
		wcfpAssertDeny(t, "Bash bash <<EOF 正文含 /app/jwt.key",
			shortCircuit("Bash", bashCommand("bash <<'EOF'\ncat /app/jwt.key\nEOF")))
		// ExecuteExtraTool 嵌套（V6-MCP）
		wcfpAssertDeny(t, "ExecuteExtraTool 嵌套平台密钥",
			shortCircuit("ExecuteExtraTool", mcpCall(`"cat /app/jwt.key"`)))

		allow := []tc{
			{"record_fact 引用 /app/jwt.key", "record_fact", `{"content":"复现 cat /app/jwt.key 被拦截"}`},
			{"Bash nmap 普通打靶", "Bash", `{"command":"nmap -sV 10.0.0.5"}`},
			{"Bash 靶场同名 config.json", "Bash", `{"command":"cat /tmp/target/config.json"}`},
			{"Bash my_config.json 粘连放过", "Bash", `{"command":"cat my_config.json"}`},
			{"Bash echo config.json 非读命令", "Bash", `{"command":"echo config.json"}`},
			{"Bash 远程指代豁免 host 档", "Bash", `{"command":"ssh root@10.0.0.5 'cat /etc/shadow'"}`},
			{"Bash cat /etc/passwd 防过拦", "Bash", `{"command":"cat /etc/passwd"}`},
			{"Bash 主机公钥 .pub 放过", "Bash", `{"command":"cat /etc/ssh/ssh_host_rsa_key.pub"}`},
		}
		for _, c := range allow {
			wcfpAssertNil(t, c.desc, shortCircuit(c.tool, []byte(c.in)))
		}
	})
}

// TestPlatformExecutionText 直接钉死纯函数契约（补强「执行面/正文分离」的论证）：
// 非写入类工具一字不变、写入类只留执行面字段、非 JSON / 解析失败退回原字节。
func TestPlatformExecutionText(t *testing.T) {
	raw := []byte(`{"file_path":"/app/jwt.key","content":"cat /app/.env 的正文","command":"echo ok","args":["-n"],"notes":"备注","description":"描述"}`)

	// 非写入类：返回同一底层切片，字节完全一致（Bash / ExecuteExtraTool / Read 等）
	for _, tool := range []string{"Bash", "ExecuteExtraTool", "Read", "record_fact", "shell_send"} {
		got := platformExecutionText(tool, raw)
		if !bytes.Equal(got, raw) {
			t.Fatalf("%s 应原样返回 input，得到 %s", tool, got)
		}
	}

	// 非 JSON 对象（含写入类）→ 退回原字节（fail-closed）
	plain := []byte(`cat /app/jwt.key`)
	if got := platformExecutionText("Write", plain); !bytes.Equal(got, plain) {
		t.Fatalf("非 JSON 对象应退回原字节，得到 %s", got)
	}
	bad := []byte(`{"file_path": broken}`)
	if got := platformExecutionText("Write", bad); !bytes.Equal(got, bad) {
		t.Fatalf("JSON 解析失败应退回原字节，得到 %s", got)
	}

	// 写入类工具：输出是合法 JSON 对象，只保留执行面字段
	got := platformExecutionText("Write", raw)
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("写入类输出必须是合法 JSON 对象：%v（%s）", err, got)
	}
	for _, k := range []string{"file_path", "command", "args"} {
		if _, ok := m[k]; !ok {
			t.Errorf("执行面字段 %q 应保留，得到 %s", k, got)
		}
	}
	for _, k := range []string{"content", "notes", "description"} {
		if _, ok := m[k]; ok {
			t.Errorf("正文文本字段 %q 应被丢弃，得到 %s", k, got)
		}
	}
	// 路径字段仍是平台凭据 → 平台档照旧 deny（分离不削弱执行面判定）
	wcfpAssertDeny(t, "Write 执行面 file_path=/app/jwt.key 仍 deny", shortCircuit("Write", raw))
}
