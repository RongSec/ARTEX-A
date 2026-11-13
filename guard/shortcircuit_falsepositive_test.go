package guard

import "testing"

// ============================================================================
// V6-FP：短路表把「正常渗透动作」误判为 deny 的三条实测缺陷回归钉。
//
// 数据来源：临时探针 fp_probe_test.go 的 34 条样本（修复前
// deny=9 / ask=1 / allow=1 / none=23）。其中 6 条 deny 是设计内，3 条是
// 真实误伤：
//
//	#09  echo "cat config.json" > /tmp/notes.txt —— 引号内是数据，echo 不读文件
//	#12  ls -la /root/.ssh/                      —— 列目录是只读侦察
//	#19  docker exec dvwa-a cat /etc/shadow      —— 读的是目标容器内 shadow
//
// 修复全部落在 shortcircuit.go 的三处正则，架构未动。
//
// Bash 入参用 shortcircuit_test.go 定义的 bashCommand 构造，即
// json.Marshal(map[string]string{"command": cmd})，与线上 hook 同形
// （不重复定义同名 helper）；其余工具入参用裸 JSON 对象字节串。
// ============================================================================

// 三条真实误伤：修复后 PreviewShortCircuit 必须返回 nil（不 deny）。
func TestV6FPFalsePositivesNoLongerDenied(t *testing.T) {
	cases := []struct{ desc, cmd string }{
		{"#09 引号内是被写入的数据，echo 不读文件", `echo "cat config.json" > /tmp/notes.txt`},
		{"#12 列 .ssh 目录是只读侦察，不泄露私钥", `ls -la /root/.ssh/`},
		{"#19 读的是目标容器内的 shadow，不是平台本机", `docker exec dvwa-a cat /etc/shadow`},
	}
	for _, c := range cases {
		if dec := PreviewShortCircuit("Bash", bashCommand(c.cmd)); dec != nil {
			t.Errorf("%s：应放行(nil)，得到 action=%s rule=%q", c.desc, dec.Action, dec.RuleName)
		}
	}
}

// 设计内 deny 必须保持：探针对照集里 6 条设计内 deny 逐条回归。
func TestV6FPDesignedDenyUnchanged(t *testing.T) {
	bashDeny := []struct{ desc, cmd string }{
		{"平台注入配置裸名", `cat config.json`},
		{"平台进程环境块", `cat /proc/self/environ`},
		{"平台签名密钥", `cat /app/jwt.key`},
	}
	for _, c := range bashDeny {
		if dec := PreviewShortCircuit("Bash", bashCommand(c.cmd)); dec == nil || dec.Action != "deny" {
			t.Errorf("%s：应仍 deny，得到 %+v", c.desc, dec)
		}
	}
	// 非 Bash 工具：入参是裸 JSON 对象（与探针/线上一致）。
	otherDeny := []struct{ desc, tool, in string }{
		{"MCP 工具读本机 shadow", "mcp__shell__run", `{"command":"cat /etc/shadow"}`},
		{"MCP 工具读平台密钥", "mcp__shell__run", `{"command":"cat /app/jwt.key"}`},
		{"create_mcp 注册凭据汇", "create_mcp", `{"name":"probe"}`},
	}
	for _, c := range otherDeny {
		if dec := PreviewShortCircuit(c.tool, []byte(c.in)); dec == nil || dec.Action != "deny" {
			t.Errorf("%s：应仍 deny，得到 %+v", c.desc, dec)
		}
	}
}

// 设计内放行必须保持（任务书逐条点名，回归钉）。
func TestV6FPDesignedAllowUnchanged(t *testing.T) {
	allow := []struct{ desc, cmd string }{
		{"远程指代豁免", `ssh root@127.0.0.1 "cat /etc/shadow"`},
		{"主机公钥放行(.pub 过滤未坏)", `cat /etc/ssh/ssh_host_ed25519_key.pub`},
		{"靶场同名文件", `cat /tmp/target/config.json`},
		{"粘连文件名", `cat my_config.json`},
		{"目标 .env", `cat .env`},
		{"find 通配找 key", `find / -name "*.key"`},
		{"V4-E heredoc 正文剥离", "cat > /tmp/brief.txt <<'EOF'\n[1] cat config.json 是上一步被拦的命令原文\nEOF"},
	}
	for _, c := range allow {
		if dec := PreviewShortCircuit("Bash", bashCommand(c.cmd)); dec != nil {
			t.Errorf("%s：应仍放行(nil)，得到 action=%s rule=%q", c.desc, dec.Action, dec.RuleName)
		}
	}
	// record_fact：描述性文本引用 /app/jwt.key 是审计刚需（recordOnlyTools 豁免）。
	rec := `{"summary":"复现记录","detail":"上一步 cat /app/jwt.key 被平台拦截"}`
	if dec := PreviewShortCircuit("record_fact", []byte(rec)); dec != nil {
		t.Errorf("record_fact 引用 /app/jwt.key 应仍放行，得到 %+v", dec)
	}
}

// 探针里剩余两档（ask / allow）也保持不变。
func TestV6FPOtherVerdictsUnchanged(t *testing.T) {
	cases := []struct{ desc, tool, in, want string }{
		{"平台工具需审批", "create_custom_tool", `{"name":"probe"}`, "ask"},
		{"低危面显式放行", "create_skill", `{"name":"probe"}`, "allow"},
	}
	for _, c := range cases {
		dec := PreviewShortCircuit(c.tool, []byte(c.in))
		if dec == nil || dec.Action != c.want {
			t.Errorf("%s：应仍 %s，得到 %+v", c.desc, c.want, dec)
		}
	}
}

// 边界钉：三处「不能改坏」的收紧面，以及 #09 取舍的已知漏判。
func TestV6FPBoundaryVerdicts(t *testing.T) {
	deny := []struct{ desc, cmd string }{
		{"#12 子路径私钥仍拦", `cat /root/.ssh/id_rsa`},
		{"#19 平台档不吃远程豁免", `docker exec x cat /app/jwt.key`},
		{"#09 正常读命令位置仍拦", `cat "config.json"`},
	}
	for _, c := range deny {
		if dec := PreviewShortCircuit("Bash", bashCommand(c.cmd)); dec == nil || dec.Action != "deny" {
			t.Errorf("%s：应仍 deny，得到 %+v", c.desc, dec)
		}
	}

	// 【已知漏判，按取舍接受，不作失败用例】
	// `bash -c 'cat config.json'` / `bash -c "cat config.json"`：#09 把前置
	// 边界类里的引号去掉后，读命令紧贴引号不再处于命令位，platformConfig
	// BareReadRe 不命中 → 返回 nil。按「宁漏不误伤」接受，闭合需 shell AST
	// 或 realpath 级执行前校验；与 shortcircuit_test.go 同名取舍注释呼应。
	// 这里刻意不断言（既不断言 deny 也不断言 nil），避免把取舍钉成回归契约。
}
