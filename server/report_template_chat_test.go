package server

import "testing"

// R3：对话渲染意图判定（纯函数）。用户原话「按现有数据重新生成渲染一份报告」
// 必须命中，且明确否定时不得误渲染。
func TestChatRequestsRender(t *testing.T) {
	yes := []string{
		"按现有数据重新生成渲染一份报告",
		"用示例数据渲染看看效果",
		"预览一下这份报告",
		"帮我出一份报告",
	}
	for _, s := range yes {
		if !chatRequestsRender(s) {
			t.Errorf("应判定为渲染请求: %q", s)
		}
	}
	no := []string{
		"把漏洞明细标题改成「发现事项」",
		"不要渲染，只改模板",
		"别预览了",
		"正文字体换成宋体",
		"",
	}
	for _, s := range no {
		if chatRequestsRender(s) {
			t.Errorf("不应判定为渲染请求: %q", s)
		}
	}
}
