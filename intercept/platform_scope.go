package intercept

// 规则里的「平台自身地址」占位符（V12-RULES3）。
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
// 规则目前只剩「控制面 API」一条，全部判定都在这里；原先的远程豁免
// （remote_exempt 列）随「本机凭据」规则一起删除，不再需要「远程指代」识别。

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

// 远程上下文判定已迁到 remote_context.go（V12-RULES2）：旧实现是「出现远程
// 指代就整条规则跳过」，会把「本地读 + 远程送」一并放行（scp 本地私钥、
// curl -d @/etc/shadow、管道送 nc）。现在按命中位置判上下文。

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
