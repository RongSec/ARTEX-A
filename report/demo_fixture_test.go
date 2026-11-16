package report

import (
	"encoding/json"
	"strings"
	"testing"
)

// R2：模板「预览渲染」使用内置示例数据，规格要求 2 个资产 / 3 条漏洞（含
// PoC）/ 1 个凭据。这里钉住 fixture 承诺，避免后续改样例时静默退化。
func TestDemoFixtureShape(t *testing.T) {
	in := DemoInput()
	if len(in.Targets) != 2 {
		t.Fatalf("demo targets=%d, want 2: %v", len(in.Targets), in.Targets)
	}
	if len(in.Findings) != 3 {
		t.Fatalf("demo findings=%d, want 3", len(in.Findings))
	}
	for _, f := range in.Findings {
		var rp Reproduction
		if len(f.Reproduction) == 0 || json.Unmarshal(f.Reproduction, &rp) != nil || len(rp.Steps) == 0 {
			t.Fatalf("finding %q 缺少 PoC 复现步骤", f.Name)
		}
	}
	cred := false
	for _, f := range in.Findings {
		if strings.Contains(string(f.Reproduction), "demo_user / Demo#2026") {
			cred = true
			break
		}
	}
	if !cred {
		t.Fatal("demo fixture 应包含 1 个示例凭据")
	}
}
