package intercept

// 规则里的「平台自身地址」占位符与远程指代识别（V12-RULES）。
//
// 背景：合并三类规则后，只剩下 intercept_rules（DB）一套。原先写在短路规则
// 里的「平台控制面 API」需要匹配平台自己的监听地址，但一台机器往往有多张
// 网卡（127.0.0.1、10.x、172.17.x…），把地址写死在正则里必然漏。
//
// 做法：规则 pattern 里写占位符，编译时展开——
//
//	{{PLATFORM_IPS}}    → (?:127\.0\.0\.1|10\.24\.188\.85|…)
//	{{PLATFORM_PORTS}}  → (?:8787|8801|8802)
//
// 地址来源 = 回环 + 本机所有非回环网卡地址 + 设置项 platform_ips 里用户额外
// 配的。这样换机器、加网卡都不用改规则。
//
// 另一个必需的能力是「远程指代」识别：`ssh root@target 'cat /etc/shadow'` 是
// 合法打靶战果，不该被「本机系统凭据」规则拦下。规则上标 remote_exempt=true，
// 引擎看到命令里有 ssh/scp/curl/psql -h 这类指向别处的迹象就整条跳过。

import (
	"encoding/json"
	"net"
	"regexp"
	"strings"
)

// DefaultPlatformIPs 返回「平台自身」的候选地址：回环 + 本机所有非回环 IP。
//
// 为什么要把网卡地址算进来：容器的服务端口监听在 0.0.0.0，agent 完全可能用
// 宿主机/容器的实际 IP 访问 /api/settings——只匹配 127.0.0.1 会漏成筛子，
// 而那条规则的语义是「别碰平台自己的管理面」，跟从哪个地址访问无关。
func DefaultPlatformIPs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(ip string) {
		ip = strings.TrimSpace(ip)
		if ip == "" || seen[ip] {
			return
		}
		seen[ip] = true
		out = append(out, ip)
	}
	// 回环与通配。IPv6 回环在正则里显式写成 \[::1\] 才安全，这里只收 IPv4
	// 与字面量 ::1，展开时统一转义。
	add("127.0.0.1")
	add("0.0.0.0")
	add("localhost")
	add("::1")
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() {
				continue
			}
			if v4 := ipnet.IP.To4(); v4 != nil {
				add(v4.String())
			}
		}
	}
	return out
}

// DefaultPlatformPorts 是平台默认监听端口：8787 是标准端口，8801/8802 是
// artex-hs 实测部署用的（-addr :8801 -proxy :8802）。用户可在设置里覆盖。
func DefaultPlatformPorts() []string { return []string{"8787", "8801", "8802"} }

// ExpandPlatformPlaceholders 把规则 pattern 里的占位符替换成转义好的正则分组。
// 未知占位符原样保留（宁可匹配不到，也不要静默改成「匹配一切」）。
func ExpandPlatformPlaceholders(pattern string, extraIPs, ports []string) string {
	if !strings.Contains(pattern, "{{") {
		return pattern
	}
	ips := append(DefaultPlatformIPs(), extraIPs...)
	ips = dedupeStrings(ips)
	if ps := dedupeStrings(ports); len(ps) > 0 {
		ports = ps
	} else {
		ports = DefaultPlatformPorts()
	}
	pattern = strings.ReplaceAll(pattern, "{{PLATFORM_IPS}}", alternation(ips, true))
	pattern = strings.ReplaceAll(pattern, "{{PLATFORM_PORTS}}", alternation(ports, false))
	return pattern
}

// alternation 生成 (?:a|b|c)。escapeDots=true 时把 '.' 转义成 '\.'——
// IP 字面量必须精确匹配，否则 10.1.1.5 会命中 10x1x1x5。
func alternation(items []string, escapeDots bool) string {
	if len(items) == 0 {
		// 一个候选都没有时给一个永不匹配的分支，绝不退化成「空分组匹配一切」。
		return `(?!x)x`
	}
	parts := make([]string, 0, len(items))
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		it = regexp.QuoteMeta(it)
		if escapeDots {
			// QuoteMeta 已经把 . 转成 \.，这里无需再动；保留参数是为了可读性
			// 与未来切换成手写转义时不改签名。
			_ = escapeDots
		}
		parts = append(parts, it)
	}
	if len(parts) == 0 {
		return `(?!x)x`
	}
	return "(?:" + strings.Join(parts, "|") + ")"
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// remoteTargetingRe 是「这条命令指向了另一台机器」的判据。只服务
// remote_exempt=true 的规则（目前只有「本机系统凭据」一条）：
//
//   - ssh / scp / sftp / rsync / ansible / winrm / 各种 nc：参数后面必然跟远端；
//   - proxychains 包着的命令：目标是代理链对端；
//   - mysql/psql/mariadb 带 -h/--host：连的是远端库；
//   - user@host 形态；
//   - http(s):// 直接打 URL（curl/wget 的常态）；
//   - docker/podman/kubectl exec：命令跑在容器/远端 Pod 里，读的是那边的文件。
//
// 命中就跳过该规则——注意这只是「不拦」，不是「放行」：同一次调用后面还有
// 其它规则和判官。
var remoteTargetingRe = []*regexp.Regexp{
	regexp.MustCompile(`(?:^|[\s"'\x60;&|(<>$])(?:ssh|scp|sftp|rsync|proxychains(?:4|chain)?[0-9]*|netcat|ncat|nc|winrm|ansible)\b`),
	regexp.MustCompile(`(?:^|[\s"'\x60;&|(<>$])(?:mysql|psql|mariadb)\b[^\n]*?\s-{1,2}h(?:ost)?[=\s]`),
	regexp.MustCompile(`@(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9][a-z0-9._-]*[a-z0-9])(?:[:/'"\s)|,;-]|$)`),
	regexp.MustCompile(`https?://\S`),
	regexp.MustCompile(`(?:^|[\s"'\x60;&|(<>$])(?:docker|podman|kubectl)\b[^\n]*?\bexec\b`),
}

// HasRemoteTargeting 判断命令文本里是否出现指向远端的迹象。
func HasRemoteTargeting(texts ...string) bool {
	for _, t := range texts {
		if t == "" {
			continue
		}
		for _, re := range remoteTargetingRe {
			if re.MatchString(t) {
				return true
			}
		}
	}
	return false
}

// platformScopeFromSettings 读用户额外配置的平台地址与端口。
//
// 设置项（settings 表，JSON 数组字符串）：
//
//	platform_ips    额外要当作「平台自身」的地址（多网卡/域名/DNAT 地址）
//	platform_ports  平台实际监听端口；空则用 DefaultPlatformPorts
//
// 读失败一律退化为默认值：这条链只影响「控制面 API」一条规则的覆盖范围，
// 不能因为设置读不出来就让整个规则表加载失败。
func (i *Interceptor) platformScopeFromSettings() (extraIPs []string, ports []string) {
	if i.db == nil {
		return nil, nil
	}
	if v, ok, _ := i.db.GetSetting("platform_ips"); ok {
		extraIPs = parseStringListSetting(v)
	}
	if v, ok, _ := i.db.GetSetting("platform_ports"); ok {
		ports = parseStringListSetting(v)
	}
	return extraIPs, ports
}

// parseStringListSetting 解析 ["a","b"] 或 "a,b" 两种写法（前者是前端存的
// JSON，后者是运维手写的逗号分隔）。解析不出来就当空。
func parseStringListSetting(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if strings.HasPrefix(raw, "[") {
		var list []string
		if json.Unmarshal([]byte(raw), &list) == nil {
			return dedupeStrings(list)
		}
		return nil
	}
	return dedupeStrings(strings.Split(raw, ","))
}
