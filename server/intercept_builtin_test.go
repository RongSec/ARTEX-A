package server

// V9-UI：内置规则只读接口。不依赖 PG，直接调 handler。

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/Autumn-27/artex/guard"
)

func TestInterceptBuiltinRulesEndpoint(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("GET", "/api/intercept/builtin-rules", nil)
	rec := httptest.NewRecorder()
	s.interceptBuiltinRules(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Rules []guard.BuiltinRule `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Rules) == 0 {
		t.Fatal("内置规则列表不能为空")
	}
	keys := map[string]bool{}
	for _, r := range resp.Rules {
		if r.Name == "" || r.Description == "" || r.Action != "deny" {
			t.Fatalf("规则字段不完整: %+v", r)
		}
		keys[r.Key] = true
	}
	for _, want := range []string{"platform_control_plane", "platform_credentials", "foreign_task_assets"} {
		if !keys[want] {
			t.Fatalf("缺少内置规则 %s", want)
		}
	}
}
