package guard

// V6-CP：堵住「agent 自主绕过热加载规则」的两条链路。
//
// 威胁模型以题为准：agent 自己（不是持 JWT 的人）在靶场里执行 Bash，
//   ① 读平台自己的密钥文件（绝对路径版）→ 拿到 JWT；
//   ② 用该 JWT 调平台管理 API（/api/intercept/**、/api/settings 等）
//      → 关掉规则 / 改设置 → 热加载规则被绕过。
// 短路表是唯一「不受 DB/settings 热改面影响」的防线，所以这两条必须在
// 短路表内闭合，且只能靠启动时生成的运行时路径/监听地址来闭合。
//
// 两条新增判定都落在 shortCircuit 的平台凭据档之后、host 档之前：
//   - platformAbsRe：dataDir 的绝对路径（含 jwt.key/.jwt/.env/短路配置文件/
//     MITM CA），按运行时 dataDir 生成，只拦「解析到平台 dataDir」的路径。
//   - controlPlane：对平台自身监听地址（127.0.0.1/localhost/[::1]:端口）
//     发起的平台管理 API 请求；第二道是「Authorization: Bearer + 本机平台
//     端口」的任意路径请求。
//
// 与既有 platformCredentialRe 的边界：
//   - 既有档认 /app/... 与 ../../jwt.key，不认运行时绝对路径（线上实测
//     `cat /root/Desktop/sec/artex-hs/data/jwt.key` 被放行）；
//   - 本档只按【绝对路径前缀】匹配，不按 basename 兜底：靶机上同名
//     /tmp/target/jwt.key、工作区 my_config.json 一律不命中。

import (
	"net"
	"path/filepath"
	"regexp"
	"strings"
)

// guardListenAddr 是平台实际监听地址，main 在 InitShortCircuit 之前注入
// （cmd/artex/main.go 的 -addr）。默认值与内置默认模式里的端口保持一致
// （8801 为线上运维端口，8787 为代码默认端口）。
var guardListenAddr = ":8801"

// SetShortCircuitListenAddr 设置控制面判定使用的平台监听地址。
// 必须在 InitShortCircuit / 任何 Guard 构造之前调用。
func SetShortCircuitListenAddr(addr string) {
	if strings.TrimSpace(addr) != "" {
		guardListenAddr = strings.TrimSpace(addr)
	}
}

// controlPlaneDefaultHosts 是"本机"的字符串形态。0.0.0.0 只在作为客户端
// 目标时出现（Linux 上可路由到本机），一并纳入；不做 DNS 解析——
// 字符串预筛不解析域名（连 localhost 都只按字面认）。
var controlPlaneDefaultHosts = []string{
	`127\.0\.0\.1`, `localhost`, `\[::1\]`, `0\.0\.0\.0`,
}

// controlPlaneDefaultPorts 与内置默认 control_plane_patterns 的端口一致。
var controlPlaneDefaultPorts = []string{"8801", "8787"}

// splitListenAddr 从 -addr 形态（":8801" / "127.0.0.1:8801" / "8801"）
// 取 host/port。解析失败时把整串当端口候选（仅当全数字）。
func splitListenAddr(addr string) (host, port string) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", ""
	}
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	if strings.HasPrefix(addr, ":") {
		return "", addr[1:]
	}
	if isAllDigits(addr) {
		return "", addr
	}
	return addr, ""
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// controlPlaneAddrAlt 返回本机平台地址的正则片段：
//
//	(?i)(?:127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0|<实际 host>):(?:8801|8787|<实际 port>)
//
// 实际 host 为通配（空 / 0.0.0.0 / ::）时不追加——客户端不会用通配地址访问。
// 非 ASCII 的 IPv6 字面带方括号写法超出字符串预筛范围（已在报告声明）。
func controlPlaneAddrAlt() string {
	hosts := append([]string(nil), controlPlaneDefaultHosts...)
	ports := append([]string(nil), controlPlaneDefaultPorts...)

	host, port := splitListenAddr(guardListenAddr)
	if port != "" && !stringInSlice(port, ports) {
		ports = append(ports, port)
	}
	if host != "" && host != "0.0.0.0" && host != "::" && !strings.Contains(host, ":") {
		if !stringInSlice(host, hosts) {
			hosts = append(hosts, regexp.QuoteMeta(host))
		}
	}
	return `(?i)(?:` + strings.Join(hosts, "|") + `):(?:` + strings.Join(ports, "|") + `)`
}

func stringInSlice(s string, list []string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// controlPlanePathAlt 是平台控制面路径（不含只读业务面）：
//
//	/api/(intercept|settings|system|agents|mcp|tools)…
//	/api/tasks/<id>/control
//	/api/tasks/control(/batch)   —— 批量控制任务，与单任务 control 同档
//
// 刻意【不含】/api/health、/api/facts、/function/facts：agent 自查健康与
// 事实库是合法只读业务面，拦了会误伤自主任务。
const controlPlanePathAlt = `(?:/api/(?:intercept|settings|system|agents|mcp|tools)` +
	`|/api/tasks/[^/\s"'` + "`" + `;&|]+/control` +
	`|/api/tasks/control(?:/batch)?)`

// controlPlanePathEnd 是路径词尾边界：允许子路径/查询/片段/空白/引号/管道/
// JSON 闭合符或行尾，避免 /api/toolsomething 这类前缀误命中。
const controlPlanePathEnd = `(?:[/?#\s"'` + "`" + `;&|)>},.]|$)`

// buildControlPlaneMatcher 编译控制面判定。
//
// deny：本机平台地址 + 管理路径（配置组 control_plane_patterns 的默认值 +
// 按实际监听地址生成的同形模式）；
// addr：本机平台地址（任意路径），仅供 Bearer 第二道使用；
// readonly：只读业务面（health/facts），供 Bearer 第二道剥离豁免；
// bearer：Authorization: Bearer 字面（-H/头两种写法都命中）。
func buildControlPlaneMatcher(patterns []string) (controlPlaneMatcher, error) {
	var out controlPlaneMatcher
	addr := controlPlaneAddrAlt()

	all := append([]string(nil), patterns...)
	all = append(all,
		addr+controlPlanePathAlt+controlPlanePathEnd,
	)
	re, err := compileAlternation("control_plane_patterns", all, "", "")
	if err != nil {
		return out, err
	}
	out.deny = re

	// 任意路径的本机平台地址（Bearer 第二道）。端口后必须是路径/空白/引号/
	// 行尾，防止 :88010 这类更长端口误命中。
	out.addr, err = regexp.Compile(addr + `(?:[/?#\s"'` + "`" + `;&|)>},]|$)`)
	if err != nil {
		return out, err
	}
	// 只读业务面：Bearer 第二道里整段剥离，避免「带 token 查健康」被误伤。
	out.readonly, err = regexp.Compile(addr +
		`(?:/api/(?:health|facts)|/function/facts)(?:[/?#\s"'` + "`" + `;&|)>},.]|$)`)
	if err != nil {
		return out, err
	}
	out.bearer, err = regexp.Compile(`(?i)authorization["']?\s*[:=]\s*bearer\b`)
	if err != nil {
		return out, err
	}
	return out, nil
}

// controlPlaneMatcher 是控制面 API 判定的编译结果。
type controlPlaneMatcher struct {
	deny     *regexp.Regexp
	addr     *regexp.Regexp
	readonly *regexp.Regexp
	bearer   *regexp.Regexp
}

// hit 判定一段执行面文本是否构成"agent 调平台控制面"。
//
// 第一道：本机平台地址 + 管理路径 → 直接命中。
// 第二道：显式 Authorization: Bearer + 本机平台地址（任意路径）→ 命中；
// 先剥离只读业务面再判，保证「curl -H 'Authorization: Bearer x' …/api/health」
// 仍放行（agent 自查健康），而「同一命令里还打了 settings」照拦。
func (m controlPlaneMatcher) hit(text string) bool {
	if m.deny == nil || m.addr == nil || m.readonly == nil || m.bearer == nil {
		return false
	}
	if m.deny.MatchString(text) {
		return true
	}
	if !m.bearer.MatchString(text) {
		return false
	}
	return m.addr.MatchString(m.readonly.ReplaceAllString(text, " "))
}

// --- 平台 dataDir 绝对路径 ---

// platformAbsLeafPatterns 是 dataDir 下必须保护的平台文件（相对 dataDir）。
// 只列具体凭据/配置文件，不按目录或扩展名通配——同 platformCredentialRe
// 的收窄纪律：靶机/工作区里的同名文件不能一起拦。
var platformAbsLeafPatterns = []string{
	`jwt\.key`,
	`\.jwt`,
	`\.env`,
	`shortcircuit_rules\.json`,
	`traffic[\\/]+_ca[\\/]+[^\s"'` + "`" + `]*\.(?:pem|key|crt)`,
}

// ambiguousPathBoundary 是路径前后允许的字符：命令边界、引号、重定向、
// JSON 闭合/赋值符。刻意不含 `/`——保证前缀必须从路径词首开始
// （loot/root/…/data/jwt.key 这类战利品副本不误伤）。
const ambiguousPathBoundary = `(?:^|[\s"'` + "`" + `;&|(<>{},=:])`
const ambiguousPathEnd = `(?:$|[\s"'` + "`" + `;&|)<>{},=:])`

// buildPlatformAbsRegexp 按运行时 dataDir 生成绝对路径档。
//
// 分隔符同时接受 / 与 \（[\\/]+）；每段用 QuoteMeta，避免 dataDir 里的
// 正则元字符（如 "+"、"("）被当成语法。dataDir 为空/根目录时返回 nil
// （没有可保护的平台路径，且根目录前缀会拦掉一切）。
func buildPlatformAbsRegexp(dataDir string) (*regexp.Regexp, error) {
	abs := strings.TrimSpace(dataDir)
	if abs == "" {
		return nil, nil
	}
	if a, err := filepath.Abs(abs); err == nil {
		abs = a
	}
	abs = filepath.ToSlash(filepath.Clean(abs))
	if abs == "" || abs == "." || abs == "/" {
		return nil, nil
	}

	var b strings.Builder
	rest := abs
	if len(abs) >= 2 && abs[1] == ':' { // Windows 盘符
		b.WriteString(`(?i)` + regexp.QuoteMeta(abs[:2]) + `[\\/]+`)
		rest = abs[2:]
	} else {
		b.WriteString(`[\\/]+`)
	}
	segs := strings.Split(strings.Trim(rest, "/"), "/")
	quoted := make([]string, 0, len(segs))
	for _, s := range segs {
		if s == "" || s == "." {
			continue
		}
		quoted = append(quoted, regexp.QuoteMeta(s))
	}
	if len(quoted) == 0 {
		return nil, nil
	}
	b.WriteString(strings.Join(quoted, `[\\/]+`))
	dir := b.String()

	expr := `(?i)` + ambiguousPathBoundary + dir + `[\\/]+(?:` +
		strings.Join(platformAbsLeafPatterns, "|") + `)` + ambiguousPathEnd
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}
	return re, nil
}

// dotDotSegmentRe 匹配 "<段>/../" 形态（RE2 无环视，消费式替换）。
var dotDotSegmentRe = regexp.MustCompile(`/[^/\s"'` + "`" + `;&|()<>]+/\.\./`)

// collapseDotSegments 近似 filepath.Clean：反复折叠 "/./" 与 "x/../"。
// 只对文本做近似归一——不做词法级路径解析，也不处理变量展开（字符串
// 预筛的固有上限，与既有短路上限一致）。
func collapseDotSegments(s string) string {
	s = strings.ReplaceAll(s, "/./", "/")
	for i := 0; i < 32; i++ { // 防病态长串死循环
		next := dotDotSegmentRe.ReplaceAllString(s, "/")
		if next == s {
			break
		}
		s = strings.ReplaceAll(next, "/./", "/")
	}
	return s
}

// pathTextVariants 返回同一段命令文本的等价形态：
//   - 原文
//   - 反斜杠→正斜杠（Windows 风格写法；Linux 上 \ 不是路径分隔符，转换只
//     会多匹配，不会漏匹配）
//   - 原文折叠 ./ 与 x/../ 后的形态
//   - 反斜杠形态折叠后的形态
//
// 逐形态匹配 = 同时接受「清理前/后的文本」，避免为每个 ./、../ 组合
// 生成组合爆炸的正则。
func pathTextVariants(s string) []string {
	slashed := strings.ReplaceAll(s, `\`, "/")
	candidates := []string{s, collapseDotSegments(s)}
	if slashed != s {
		candidates = append(candidates, slashed, collapseDotSegments(slashed))
	}
	out := make([]string, 0, len(candidates))
	seen := make(map[string]bool, len(candidates))
	for _, c := range candidates {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

// platformAbsHit 在给定文本的全部等价形态上判定 dataDir 绝对路径。
func platformAbsHit(re *regexp.Regexp, text string) bool {
	if re == nil || text == "" {
		return false
	}
	for _, v := range pathTextVariants(text) {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}
