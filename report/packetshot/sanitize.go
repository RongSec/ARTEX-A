package packetshot

// T22（N3）报文脱敏与清洗纯函数集：截图渲染前对逐字报文做安全处理。
// 设计红线（incremental-v2.md §3）：截图会进报告/分享链路，凭据类头值必须
// 打码；打码规则=**保留前 7 …后 4**（可读性优先，够定位是哪个 token），值
// 短于 12 时整体打星（保留首尾等于全漏）。所有函数零依赖、可无库单测。

import (
	"regexp"
	"strings"
	"unicode"
)

// SensitiveValue 打码单个敏感值：≥20 保留前7…后4；12..19 保留前7…后4 也嫌
// 多——按任务书 ≥20 与 <12 两条硬规则，中间段（12..19）保留前 4…后 3（弱
// 化）；<12 全打星。空串原样。
func SensitiveValue(v string) string {
	v = strings.TrimSpace(v)
	n := len([]rune(v))
	switch {
	case n == 0:
		return v
	case n < 12:
		return strings.Repeat("*", n)
	case n < 20:
		r := []rune(v)
		return string(r[:4]) + "…" + string(r[n-3:])
	default:
		r := []rune(v)
		return string(r[:7]) + "…" + string(r[n-4:])
	}
}

// mosaicRE 判定「疑似密文/token」：长度 ≥12、无空白、字母数字下划线横杠点
// 占比 ≥70%（base64/hex/JWT 段形态）。任务书口径：≥12 无空格字母数字≥70%。
func ShouldMosaic(v string) bool {
	v = strings.TrimSpace(v)
	r := []rune(v)
	if len(r) < 12 || strings.ContainsAny(v, " \t\r\n") {
		return false
	}
	var alnum int
	for _, c := range r {
		if unicode.IsLetter(c) || unicode.IsDigit(c) || c == '_' || c == '-' || c == '.' || c == '+' || c == '/' || c == '=' {
			alnum++
		}
	}
	return alnum*100 >= len(r)*70
}

// redundantReqHeaders/RedundantRespHeaders 是默认折叠的冗余头清单（Burp 式
// 降噪：这些头对复现无信息量）。可经 Options.ExtraHideHeaders 追加、
// KeepHeaders 白名单豁免。
var (
	defaultRedundantReq = []string{
		"accept-language", "accept-encoding", "upgrade-insecure-requests",
		"connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
		"sec-fetch-mode", "sec-fetch-site", "sec-fetch-user", "dnt",
		"cache-control", "pragma",
	}
	defaultRedundantResp = []string{
		"connection", "cache-control", "pragma", "expires",
		"content-encoding", "x-powered-by", "vary",
	}
)

// DefaultRedundantRequestHeaders / DefaultRedundantResponseHeaders 暴露默认
// 清单（前端设置区展示用；复制返回防调用方改内部切片）。
func DefaultRedundantRequestHeaders() []string {
	return append([]string(nil), defaultRedundantReq...)
}

func DefaultRedundantResponseHeaders() []string {
	return append([]string(nil), defaultRedundantResp...)
}

// sensitiveReqHeaderRE 命中即整行值打码：Authorization（含 Bearer/Basic 值）、
// Cookie（逐 k=v 打值）、X-*-Api-Key / *-Token / *-Secret / *-Password /
// Set-Cookie（值打码，保留 k=v 结构头名）。key 名含 token|secret|session|auth
// 的任意头整对打码（任务书口径：k 名含 token|secret|session|auth 整对打）。
var (
	reAuthValue  = regexp.MustCompile(`(?i)^(Bearer|Basic|Digest|NTLM)\s+(\S.*)$`)
	reKVPair     = regexp.MustCompile(`([^=;,\s]+)=([^;,]*)`)
	reSecretName = regexp.MustCompile(`(?i)(token|secret|session|auth|password|passwd|api[-_]?key|apikey|credential)`)
	// 表单键值：键名含敏感词才打值。所有分组非捕获的 `(?:)`，只留 1=前缀、
	// 2=键、3=值 三个捕获位（防内层 alternation 移动索引）。
	reFormSecret = regexp.MustCompile(`(?i)(^|&)([a-z0-9_.-]*(?:token|secret|session|pass(?:word)?|pwd|apikey|api_key|auth)[a-z0-9_.-]*)=([^&]*)`)
)

// MaskHeaderLine 对单行头（"Name: value"）做脱敏：返回打码后的整行；
// 非敏感头原样返回。
func MaskHeaderLine(line string) string {
	name, value, found := strings.Cut(line, ":")
	if !found {
		return line
	}
	lname := strings.ToLower(strings.TrimSpace(name))
	switch {
	case lname == "authorization":
		if m := reAuthValue.FindStringSubmatch(value); m != nil {
			return name + ": " + m[1] + " " + SensitiveValue(m[2])
		}
		return name + ": " + SensitiveValue(value)
	case lname == "cookie" || lname == "set-cookie" || lname == "proxy-authorization":
		return name + ": " + maskKVList(value)
	case strings.HasPrefix(lname, "x-") && strings.Contains(lname, "key"),
		strings.Contains(lname, "api-key"), strings.Contains(lname, "apikey"):
		return name + ": " + SensitiveValue(value)
	case reSecretName.MatchString(lname):
		// k 名含敏感词=整对打码（值也打）。
		return name + ": " + SensitiveValue(value)
	case ShouldMosaic(strings.TrimSpace(value)):
		// 值形态像密文（长随机串）也打——宁多勿漏？否——任务书只点名头类；
		// 任意长随机值打码会误伤签名 URL/UUID 等复现关键位，保守放行。
		return line
	default:
		return line
	}
}

// maskKVList 把 "k1=v1; k2=v2" 列表里每个 k=v 的值打码；k 名含敏感词或值
// 形似密文 → 值 SensitiveValue；其余 k=v 原样（复现需要看到结构）。
func maskKVList(value string) string {
	return reKVPair.ReplaceAllStringFunc(value, func(kv string) string {
		m := reKVPair.FindStringSubmatch(kv)
		if m == nil {
			return kv
		}
		k, v := m[1], m[2]
		if reSecretName.MatchString(k) || ShouldMosaic(v) {
			return k + "=" + SensitiveValue(v)
		}
		return kv
	})
}

// MaskBodySecrets 打码请求体里的表单/JSON 字段值：键名含 token|secret|
// session|password|pwd|api[-_]key|auth 时值打码。JSON 形态只处理
// "key":"value" 直串；覆盖不到=可接受（任务书只要求表单与头两类）。
var reJSONSecret = regexp.MustCompile(`(?i)("[a-z0-9_.-]*(?:token|secret|session|pass(?:word)?|auth|api[-_]?key)[a-z0-9_.-]*"\s*:\s*")((?:[^"\\]|\\.)*)(")`)

func MaskBodySecrets(body string) string {
	// 表单：捕获组 1=前缀(^|&)、2=键、3=值（内层全 (?:) 不占位）。
	out := reFormSecret.ReplaceAllStringFunc(body, func(s string) string {
		m := reFormSecret.FindStringSubmatch(s)
		if m == nil {
			return s
		}
		return m[1] + m[2] + "=" + SensitiveValue(m[3])
	})
	// JSON："key": 前缀 + 值 + 收尾引号 三捕获位。
	out = reJSONSecret.ReplaceAllStringFunc(out, func(s string) string {
		m := reJSONSecret.FindStringSubmatch(s)
		if m == nil {
			return s
		}
		return m[1] + SensitiveValue(m[2]) + m[3]
	})
	return out
}

// MaskPacket 对整段报文（请求或响应原文）做完整脱敏：逐行拆头/体，
// 头行走 MaskHeaderLine，体内走 MaskBodySecrets。CRLF/LF 混排按原行尾保留。
func MaskPacket(packet string) string {
	lines := splitLinesKeepEOL(packet)
	inBody := false
	var b strings.Builder
	for _, ln := range lines {
		trimmed := strings.TrimRight(ln, "\r\n")
		if !inBody {
			if trimmed == "" {
				inBody = true // 空行=头体分界
				b.WriteString(ln)
				continue
			}
			// 请求行/状态行（无冒号结构）原样。
			if !strings.Contains(trimmed, ":") {
				b.WriteString(ln)
				continue
			}
			b.WriteString(MaskHeaderLine(trimmed))
			b.WriteString(ln[len(trimmed):]) // 还原行尾
			continue
		}
		b.WriteString(MaskBodySecrets(ln))
	}
	return b.String()
}

func splitLinesKeepEOL(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i+1])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
