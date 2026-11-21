package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRenderBorrowBlock 守「借鉴 + 自测」合并工单的渲染：意图里带 borrow 时，
// 执行者必须看到两段（复现基线 / 自主验证），而不是一个背景字段。
func TestRenderBorrowBlock(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"summary": "复测 userinfo 越权",
		"borrow": map[string]any{
			"related_task_id": 136,
			"endpoint":        "GET /api/sso/userinfo",
			"baseline":        "alice token 传 user_id=2 返回 bob",
			"self_test":       "换 bob token 传 user_id=9，确认是否仍越权",
		},
	})
	got := renderBorrowBlock(payload)
	for _, want := range []string{"task#136", "GET /api/sso/userinfo", "alice token", "bob token", "两段", "只复现"} {
		if !strings.Contains(got, want) {
			t.Errorf("borrow 渲染缺少 %q：\n%s", want, got)
		}
	}
	if b := renderBorrowBlock([]byte(`{"summary":"x"}`)); b != "" {
		t.Errorf("无 borrow 时不应渲染，得到 %q", b)
	}
}
