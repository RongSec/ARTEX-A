package packetshot

// JSON 逐 token 着色 tokenizer（render.go 的 Body 着色层用）。设计：按行
// 独立处理（报文体里的 JSON 通常已格式化、一行一两个 token），key（串后
// 跟冒号）蓝、串绿、数字橙、true/false/null 紫、其余默认色。非严格 lexer——
// 只保证着色不错位，不校验 JSON 合法性。

import (
	"regexp"
	"strings"
)

type jsonToken struct {
	kind int8
	text string
}

const (
	tokPlain  = int8(iota) // 标点/结构
	tokKey                 // "…": 的键
	tokString              // 字符串值
	tokNumber              // 数字
	tokLit                 // true/false/null
)

var (
	reNumTok = regexp.MustCompile(`^-?\d+(\.\d+)?([eE][+-]?\d+)?$`)
	reLit    = regexp.MustCompile(`^(true|false|null)$`)
)

// tokenizeJSONLine 单行 → token 序列（拼接=原文，不丢字符）。
func tokenizeJSONLine(line string) []jsonToken {
	var toks []jsonToken
	rs := []rune(line)
	i := 0
	flushWord := func(word string) {
		if word == "" {
			return
		}
		switch {
		case reNumTok.MatchString(word):
			toks = append(toks, jsonToken{tokNumber, word})
		case reLit.MatchString(word):
			toks = append(toks, jsonToken{tokLit, word})
		default:
			toks = append(toks, jsonToken{tokPlain, word})
		}
	}
	for i < len(rs) {
		c := rs[i]
		switch {
		case c == '"':
			j := i + 1
			for j < len(rs) {
				if rs[j] == '\\' && j+1 < len(rs) {
					j += 2
					continue
				}
				if rs[j] == '"' {
					j++
					break
				}
				j++
			}
			if j > len(rs) {
				j = len(rs)
			}
			seg := string(rs[i:j])
			// 键判定：串后第一个非空白是冒号。
			k := j
			for k < len(rs) && (rs[k] == ' ' || rs[k] == '\t') {
				k++
			}
			if k < len(rs) && rs[k] == ':' {
				toks = append(toks, jsonToken{tokKey, seg})
			} else {
				toks = append(toks, jsonToken{tokString, seg})
			}
			i = j
		default:
			j := i
			for j < len(rs) && rs[j] != '"' {
				j++
			}
			run := string(rs[i:j])
			// 按分隔符切词；分隔符本身归 tokPlain。
			start := 0
			for p := 0; p < len(run); p++ {
				if strings.IndexByte(",[]{}: \t", run[p]) >= 0 {
					flushWord(run[start:p])
					toks = append(toks, jsonToken{tokPlain, string(run[p])})
					start = p + 1
				}
			}
			flushWord(run[start:])
			i = j
		}
	}
	return toks
}
