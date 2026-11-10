package server

// T12 纯逻辑单测（无库）：项目洞察注入正文的渲染（格式/来源回链/rune 截断/
// 空列表）。限量 ≤3 由调用方（resolver 传给 ListInsights 的 limit）保证，
// 这里断言渲染器对任意长度列表的忠实输出；命中排序在 db.ListInsights 的
// matchKeywords SQL 侧（T09 已测交集语义）。

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

func TestRenderProjectInsights(t *testing.T) {
	list := []db.Insight{
		{Content: "canal v1.1.5 未认证RCE已验证，可借鉴", SourceTaskID: 12},
		{Content: "同一 nginx 指纹的后台入口在 3 号任务已打通", SourceTaskID: 3},
	}
	got := renderProjectInsights(list)
	lines := strings.Split(got, "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), got)
	}
	// 每条带项目符号与「来源任务#N：」前缀（任务书 T12-3 钉死的格式）。
	if !strings.HasPrefix(lines[0], "- 来源任务#12：") || !strings.Contains(lines[0], "canal v1.1.5") {
		t.Errorf("line0 format wrong: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "- 来源任务#3：") {
		t.Errorf("line1 source prefix missing: %q", lines[1])
	}

	// SourceTaskID<=0：省略来源段（observer 批量/未知来源）。
	got2 := renderProjectInsights([]db.Insight{{Content: "通用经验", SourceTaskID: 0}})
	if got2 != "- 通用经验" {
		t.Errorf("no-source line = %q want %q", got2, "- 通用经验")
	}

	// 空列表→空串（resolver 靠它决定整段不出现）。
	if g := renderProjectInsights(nil); g != "" {
		t.Errorf("nil must render empty, got %q", g)
	}
	if g := renderProjectInsights([]db.Insight{}); g != "" {
		t.Errorf("empty slice must render empty, got %q", g)
	}

	// 正文按 rune 截断：205 个汉字截到 200 + 省略号（绝不切半字节——rune 截）。
	long := strings.Repeat("经", insightInjectMaxRunes+5)
	out := renderProjectInsights([]db.Insight{{Content: long}})
	body := strings.TrimPrefix(out, "- ")
	body = strings.TrimSuffix(body, "…")
	if utf8.RuneCountInString(body) != insightInjectMaxRunes {
		t.Errorf("truncated body rune count = %d want %d", utf8.RuneCountInString(body), insightInjectMaxRunes)
	}
	if !strings.HasSuffix(out, "…") {
		t.Errorf("truncated line must end with ellipsis, got tail %q", out[len(out)-8:])
	}
	// 短正文不截、不加省略号。
	short := renderProjectInsights([]db.Insight{{Content: "短经验"}})
	if strings.Contains(short, "…") {
		t.Errorf("short content must not gain ellipsis: %q", short)
	}

	// 正文首尾空白被 trim（防 observer 写入带换行的脏内容破坏注入段版式）。
	ws := renderProjectInsights([]db.Insight{{Content: "\n  带空白  \n"}})
	if ws != "- 带空白" {
		t.Errorf("whitespace not trimmed: %q", ws)
	}
}
