// Package redact 把一段可能含 host / IP / 凭据的文本压成「测试方法」。
//
// 为什么单独成包：阅读者暴露给规划者的所有文本（任务目标、接口用途、节点摘要、
// 下钻详情）都要走同一套脱敏；db 层读取时与 agent 层下钻时各用一次，口径必须
// 完全一致，否则「概览不带 host、摘要却带」这种漏法最难发现。
package redact

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	// 顺序很重要：先整段 URL（保路径）、再 IP、再域名、最后凭据。
	anyURL  = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>\)\]]+`)
	ipv4    = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b`)
	domains = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|cn|net|org|io|co|cc|top|xyz|info|biz|edu|gov|mil|local|lan|corp|internal|intra|test|dev|cloud|site|online)(?::\d{1,5})?\b`)
	secrets = regexp.MustCompile(`(?i)\b(password|passwd|pwd|pass|secret|token|api[_-]?key|access[_-]?key|authorization|cookie|session(?:id)?)\b\s*[:=]\s*("[^"]*"|'[^']*'|\S+)`)
	reqLine = regexp.MustCompile(`(?i)\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s"'<>]+)`)
)

// TestMethod 脱敏：URL 只留 path?query，IP/域名换占位符，凭据值 <redacted>。
func TestMethod(s string) string {
	if s == "" {
		return ""
	}
	s = anyURL.ReplaceAllStringFunc(s, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil || u.Path == "" {
			return "<url>"
		}
		out := u.Path
		if u.RawQuery != "" {
			out += "?" + u.RawQuery
		}
		return out
	})
	s = ipv4.ReplaceAllString(s, "<ip>")
	s = domains.ReplaceAllString(s, "<host>")
	s = secrets.ReplaceAllString(s, "$1=<redacted>")
	return s
}

// RequestsIn 从文本里抽请求行（method 大写 + 路径），去重保序。
func RequestsIn(s string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, m := range reqLine.FindAllStringSubmatch(s, 20) {
		target := anyURL.ReplaceAllStringFunc(m[2], func(raw string) string {
			if u, err := url.Parse(raw); err == nil && u.Path != "" {
				return u.Path
			}
			return "<url>"
		})
		k := strings.ToUpper(m[1]) + " " + target
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out
}

// 说明：TestMethod 的顺序是「先整段 URL、再 IP、再域名、最后凭据」。中文正文里
// 的「资产 10.0.0.5:8080」依赖 \b 在中文与数字之间成立（Go 的 \b 是 ASCII 词界，
// 中文按非词字符处理），单测锁住这个行为，避免日后换实现时漏掉带端口的形态。
