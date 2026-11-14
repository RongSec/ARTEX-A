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

// TestRenderInsightCarriesID 守「注入行带洞察 id」——reject_insight 只能靠它
// 定位；「来源任务#N」是任务 id，不是洞察 id（历史格式里两者混用易误判）。
func TestRenderInsightCarriesID(t *testing.T) {
	proj := renderProjectInsights([]db.Insight{{ID: 31, Content: "经验", SourceTaskID: 7}})
	if proj != "- 来源任务#7：经验（洞察#31）" {
		t.Errorf("project line with id = %q", proj)
	}
}

// TestExtractHostKeys 守 V5-C 障碍1 第三级来源：从任务名称/目标文本里轻量提取
// host:port 与 host（父键），并挡掉 "login.php" 这类把路径当域名的误命中。
func TestExtractHostKeys(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []string
	}{
		{
			name: "URL 里的 host:port",
			text: "对 http://127.0.0.1:9081/login.php 做未授权测试",
			want: []string{"127.0.0.1:9081", "127.0.0.1"},
		},
		{
			name: "裸域名与 host:port",
			text: "打 demo.example.com:8443 与 api.example.com 两个面",
			want: []string{"demo.example.com:8443", "demo.example.com", "api.example.com"},
		},
		{
			name: "端口越界只留 host",
			text: "example.com:99999 不是合法端口",
			want: []string{"example.com"},
		},
		{
			name: "路径片段不当域名",
			text: "登录页是 login.php，接口是 api.json",
			want: nil,
		},
		{
			name: "无资产线索",
			text: "把后台打穿",
			want: nil,
		},
	}
	for _, c := range cases {
		got := extractHostKeys(c.text)
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: extractHostKeys()=%v want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: extractHostKeys()[%d]=%q want %q (all %v)", c.name, i, got[i], c.want[i], got)
			}
		}
	}
}

// TestBuildInsightBodyProjectOnly 守 V7-LINK：注入正文只剩项目洞察——
// observer_enabled 关时零注入；reader_enabled 与跨项目候选不再参与渲染
// （跨项目情报改由 planner 主动 request_reader_links 拉取）。
func TestBuildInsightBodyProjectOnly(t *testing.T) {
	projectRows := []db.Insight{
		{Content: "项目经验：同项目内可复用", SourceTaskID: 1},
		{Content: "项目经验-2", SourceTaskID: 2},
	}
	cases := []struct {
		name       string
		observerOn bool
		want       bool
	}{
		{"observer 开 → 只注入项目段", true, true},
		{"observer 关 → 零注入", false, false},
	}
	for _, c := range cases {
		tctx := &db.TaskInsightContext{ProjectID: 1, ObserverOn: c.observerOn, ReaderOn: true}
		body := buildInsightBody(tctx, projectRows)
		if got := body != ""; got != c.want {
			t.Errorf("%s: body=%q want non-empty=%v", c.name, body, c.want)
		}
		if strings.Contains(body, "【跨项目") {
			t.Errorf("%s: 不得再自动注入跨项目条目: %q", c.name, body)
		}
	}
	if body := buildInsightBody(nil, projectRows); body != "" {
		t.Errorf("nil tctx 必须零注入，got %q", body)
	}
}
