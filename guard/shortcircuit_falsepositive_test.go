package guard

import (
	"strings"
	"testing"
)

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
// V6-FP 的修复落在 shortcircuit.go 的三处正则；V6-FP2 又恢复 #09 那处
// 正则的前置引号边界并新增写命令豁免纯函数（maskWriteCommandQuoteArgs），
// 逐条回归见本文件末尾的 V6-FP2 测试组。
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

// 探针里剩余两档（allow / deny）按 V6-AUTO 的默认值保持：平台配置类工具
// 显式放行，删除业务资产硬拦。
func TestV6FPOtherVerdictsUnchanged(t *testing.T) {
	cases := []struct{ desc, tool, in, want string }{
		{"平台配置工具自主放行", "create_custom_tool", `{"name":"probe"}`, "allow"},
		{"低危面显式放行", "create_skill", `{"name":"probe"}`, "allow"},
		{"删除业务资产硬拦", "delete_assets_by_host", `{"host":"probe"}`, "deny"},
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

	// V6-FP2：上面「bash -c 内联漏判按取舍接受」的裁决已被推翻——它是平台
	// 凭据裸读保护的真实绕过，不能留。恢复引号边界后内联形态重新 deny；这里
	// 从「刻意不断言」改为逐条断言，与 shortcircuit_test.go 同名用例呼应。
	inlineDeny := []struct{ desc, cmd string }{
		{"bash -c 单引号内联", `bash -c 'cat config.json'`},
		{"bash -c 双引号内联", `bash -c "cat config.json"`},
	}
	for _, c := range inlineDeny {
		if dec := PreviewShortCircuit("Bash", bashCommand(c.cmd)); dec == nil || dec.Action != "deny" {
			t.Errorf("%s：V6-FP2 应恢复 deny，得到 %+v", c.desc, dec)
		}
	}
}

// ============================================================================
// V6-FP2：#09 修复收窄回归钉。
//
// 上一笔为修 echo 写命令误伤，把 platformConfigBareReadRe 前置边界类里的
// 双/单引号去掉，副作用是 bash -c / sh -c / eval 内联「读命令紧贴引号」的
// 平台凭据裸读被放行——这是真实绕过。本笔恢复引号边界堵住绕过，并只对
// echo/printf/tee 的引号参数（数据）做豁免，逐条钉死下列判定。
// ============================================================================

// 上表 7 条逐条断言：写命令豁免不误伤、解释器内联恢复 deny、裸读既有行为不变。
func TestV6FP2QuoteBoundaryAndWriteExemption(t *testing.T) {
	cases := []struct {
		desc, cmd string
		wantDeny  bool
	}{
		{"#1 echo 写命令引号内是数据", `echo "cat config.json" > /tmp/notes.txt`, false},
		{"#2 printf 写命令引号内是数据", `printf 'cat config.json' > /tmp/notes.txt`, false},
		{"#3 bash -c 内联恢复 deny", `bash -c 'cat config.json'`, true},
		{"#4 sh -c 内联恢复 deny", `sh -c "cat config.json"`, true},
		{"#5 eval 内联恢复 deny", `eval 'cat config.json'`, true},
		{"#6 文件名带引号的裸读仍拦", `cat "config.json"`, true},
		{"#7a 裸读仍拦", `cat config.json`, true},
		{"#7b 带路径的同名文件放过", `cat /tmp/x/config.json`, false},
		{"#7c 粘连文件名放过", `cat my_config.json`, false},
		// 实现约束：复合命令里有真实读，不得因首段是写命令而整体豁免该档。
		{"复合命令有真实读仍 deny", `echo x && cat config.json`, true},
		{"写命令引号数据后接真实读仍 deny", `echo "cat config.json" && cat jwt.key`, true},
	}
	for _, c := range cases {
		dec := PreviewShortCircuit("Bash", bashCommand(c.cmd))
		if c.wantDeny {
			if dec == nil || dec.Action != "deny" {
				t.Errorf("%s：应 deny，得到 %+v", c.desc, dec)
			}
		} else if dec != nil {
			t.Errorf("%s：应放行(nil)，得到 action=%s rule=%q", c.desc, dec.Action, dec.RuleName)
		}
	}
}

// 纯函数层：只屏蔽 echo/printf/tee 段的引号参数，等长替换；引号外骨架与
// 非写命令段（bash -c / eval / cat）原样保留。
func TestMaskWriteCommandQuoteArgs(t *testing.T) {
	cases := []struct {
		desc, in  string
		bareAfter bool // 屏蔽后 platformConfigBareReadRe 是否应命中
		unchanged bool // 输出应与输入逐字节相同
	}{
		{"echo 双引号数据", `echo "cat config.json" > /tmp/notes.txt`, false, false},
		{"printf 单引号数据", `printf 'cat config.json' > /tmp/notes.txt`, false, false},
		{"tee 单引号数据", `tee 'cat config.json' < f`, false, false},
		{"bash -c 内联原样", `bash -c 'cat config.json'`, true, true},
		{"sh -c 内联原样", `sh -c "cat config.json"`, true, true},
		{"eval 内联原样", `eval 'cat config.json'`, true, true},
		{"cat 带引号裸读原样", `cat "config.json"`, true, true},
		{"复合命令真实读不被屏蔽", `echo x && cat config.json`, true, true},
		{"echo 引号数据后接独立读只屏蔽前者", `echo "cat config.json" && cat jwt.key`, true, false},
		{"无引号文本原样", `cat config.json`, true, true},
	}
	for _, c := range cases {
		got := maskWriteCommandQuoteArgs(c.in)
		if len(got) != len(c.in) {
			t.Errorf("%s：屏蔽必须等长，%d -> %d（%q）", c.desc, len(c.in), len(got), got)
		}
		if c.unchanged && got != c.in {
			t.Errorf("%s：非写命令段应原样保留，得到 %q", c.desc, got)
		}
		if hit := platformConfigBareReadRe.MatchString(got); hit != c.bareAfter {
			t.Errorf("%s：屏蔽后裸名档命中应为 %v，得到 %v（文本 %q）", c.desc, c.bareAfter, hit, got)
		}
		if !c.unchanged && strings.Contains(got, "cat config.json") {
			t.Errorf("%s：写命令引号数据应被屏蔽，输出仍含明文：%q", c.desc, got)
		}
	}
}
