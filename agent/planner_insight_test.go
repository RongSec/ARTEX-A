package agent

// T12 纯逻辑单测（无 LLM/无库）：planner 侧洞察段渲染——resolver 为 nil、
// resolver 返回空串（开关关/未挂项目/无洞察三态在 server 侧统一收敛为空）
// 都必须产出【逐字节空串】，保证 prompt 与原版零差异；有正文时标题格式固定。

import (
	"strconv"
	"strings"
	"testing"
)

func TestProjectInsightsRendered(t *testing.T) {
	// nil resolver（默认=未装配）：恒空串。
	var p Planner
	if got := p.projectInsightsRendered(7); got != "" {
		t.Errorf("nil resolver must render empty, got %q", got)
	}

	// resolver 返回空串/纯空白：同样整段不出现（server 侧三停收敛点）。
	p.SetProjectInsightResolver(func(int64) string { return "" })
	if got := p.projectInsightsRendered(7); got != "" {
		t.Errorf("empty resolver output must render nothing, got %q", got)
	}
	p.SetProjectInsightResolver(func(int64) string { return "  \n\t " })
	if got := p.projectInsightsRendered(7); got != "" {
		t.Errorf("whitespace-only resolver output must render nothing, got %q", got)
	}

	// 有正文：标题 + 正文原样（正文的限量/截断在 server 渲染器已完成）。
	p.SetProjectInsightResolver(func(taskID int64) string {
		return "- canal v1.1.5 RCE 可借鉴（来源任务#12）"
	})
	got := p.projectInsightsRendered(7)
	if !strings.HasPrefix(got, "\n\n## 项目经验（观察者）\n") {
		t.Errorf("missing heading prefix: %q", got)
	}
	if !strings.HasSuffix(got, "（来源任务#12）") {
		t.Errorf("body altered: %q", got)
	}
	// taskID 透传验证：resolver 收到的是调用方给的值。
	p.SetProjectInsightResolver(func(taskID int64) string { return strconv.FormatInt(taskID, 10) })
	if got := p.projectInsightsRendered(42); !strings.HasSuffix(got, "42") {
		t.Errorf("taskID not passed through: %q", got)
	}
	// 正文首尾空白 trim 后拼接（server 侧多行正文以换行结尾时不产生三连换行）。
	p.SetProjectInsightResolver(func(int64) string { return "line1\nline2\n" })
	if got := p.projectInsightsRendered(1); strings.Contains(got, "\n\n\n") {
		t.Errorf("trailing newline not trimmed: %q", got)
	}
}
