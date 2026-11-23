package server

// 批量目标解析（V12-TARGET）：把用户粘贴的一坨文本拆成「一行一个有效目标」。
//
// 为什么要有这一步：批量下发原来是「按行 trim、丢空行、去重」，垃圾行会被
// 原样建任务——`# 备注`、`10.0.0.`、`http://` 这类都要人工发现再删。现在
// 前端有一个「解析」按钮做即时清洗，后端用同一套规则做权威校验：前端看得
// 到的数量与后端实际建的数量必须一致，否则用户会以为提交少了。
//
// 接受的形态（一行一个，也容忍逗号/分号/空格分隔的粘贴）：
//
//	http://10.0.0.5:8080/path   完整 URL（scheme 任意，host 必须合法）
//	10.0.0.5                    裸 IPv4/IPv6
//	10.0.0.5:8080               IP + 端口
//	10.0.0.0/24                 CIDR 网段
//	shop.example.com            域名
//	shop.example.com:443        域名 + 端口
//	dc01                        单标签内网主机名（允许，但不允许纯数字/含下划线）
//
// 丢弃：空行、`#`/`//` 注释行、含空白的残句、非法域名/IP/端口、重复项（保留首条）。

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// TargetParseResult 是一次解析的完整结果，前端统计与后端建任务共用。
type TargetParseResult struct {
	Targets []string // 有效目标（规范化、去重、保序）
	Duplicate []string // 重复行（保留首条，后续进这里）
	Invalid []string // 非法行（原样带回，供用户核对）
}

// ParseTargets 解析整段文本。权威实现——前端 parseTargets 必须与它同语义。
func ParseTargets(text string) TargetParseResult {
	var res TargetParseResult
	seen := map[string]bool{}
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// 先整行解析；不成立再按分隔符切开（粘贴 CSV / 空格分隔的常见形态）。
		candidates := []string{line}
		if _, ok := normalizeTarget(line); !ok {
			candidates = splitTargetTokens(line)
		}
		for _, cand := range candidates {
			norm, ok := normalizeTarget(cand)
			if !ok {
				res.Invalid = append(res.Invalid, cand)
				continue
			}
			if seen[norm] {
				res.Duplicate = append(res.Duplicate, norm)
				continue
			}
			seen[norm] = true
			res.Targets = append(res.Targets, norm)
		}
	}
	return res
}

// splitTargetTokens 把一行切成候选目标。只在整行不是合法目标时调用，
// 所以 `http://a/x,y` 这种 URL 内的逗号不会被误切。
func splitTargetTokens(line string) []string {
	fields := strings.FieldsFunc(line, func(r rune) bool {
		return r == ',' || r == ';' || r == '，' || r == '；' || r == '\t' || r == ' '
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// normalizeTarget 校验并规范化单个目标。返回空 + false 表示非法。
func normalizeTarget(s string) (string, bool) {
	s = strings.TrimSpace(strings.Trim(s, `"'`))
	if s == "" || strings.ContainsAny(s, " \t\r\n") {
		return "", false
	}
	// URL：scheme://host[:port][/path]
	if i := strings.Index(s, "://"); i > 0 {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", false
		}
		host := u.Hostname()
		if host == "" || !validHost(host) {
			return "", false
		}
		if p := u.Port(); p != "" {
			if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
				return "", false
			}
		}
		return s, true
	}
	// CIDR
	if strings.Contains(s, "/") {
		if _, _, err := net.ParseCIDR(s); err != nil {
			return "", false
		}
		return s, true
	}
	// host:port（IPv6 必须写成 [::1]:80，与 URL 一致）
	if h, p, err := net.SplitHostPort(s); err == nil {
		if !validHost(h) {
			return "", false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
		return strings.ToLower(h) + ":" + p, true
	}
	// 裸 IP / 裸域名 / 单标签主机名
	if !validHost(s) {
		return "", false
	}
	return strings.ToLower(s), true
}

// validHost 校验主机：IP 字面量，或合法域名（允许内网单标签）。
//
// 单标签允许的理由：内网主机名 `dc01`、`fileserver` 是常见目标，一刀切会
// 误杀。但纯数字（是残缺 IP）、含下划线、首尾连字符、超长标签一律拒。
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	// 去掉 IPv6 的方括号（URL 解析时已剥，这里兜底手工输入）
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	if net.ParseIP(h) != nil {
		return true
	}
	if strings.Contains(h, "..") || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
		return false
	}
	labels := strings.Split(h, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	// 全数字的单标签（如 "8080"）不是主机名，多半是端口写串行了。
	if len(labels) == 1 {
		allDigits := true
		for _, r := range labels[0] {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return false
		}
	}
	return true
}
