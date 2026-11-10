package report

import (
	"encoding/json"
	"strings"
	"testing"
)

// MergeExchangeIDs 纯函数：无 PG、无 traffic——直接喂 ids 列表。T14(2/2) 收窄
// 结果与复现原文的合并契约（宁缺毋滥 + 不覆写已绑步）。

// 1. 唯一命中回填：ids 非空的步拿到 exchange_id，其余保持空。
func TestMergeExchangeIDsFillsEmpty(t *testing.T) {
	in := json.RawMessage(`{"steps":[{"request":"GET /a"},{"request":"GET /b"},{"request":"GET /c"}]}`)
	out, changed := MergeExchangeIDs(in, []string{"1-0001", "", "1-0003"})
	if !changed {
		t.Fatal("want changed=true")
	}
	var rp Reproduction
	if json.Unmarshal(out, &rp) != nil {
		t.Fatal("unparseable result")
	}
	if rp.Steps[0].ExchangeID != "1-0001" || rp.Steps[1].ExchangeID != "" || rp.Steps[2].ExchangeID != "1-0003" {
		t.Fatalf("ids mis-merged: %+v", rp.Steps)
	}
}

// 2. 已有值不覆写：view-time 再跑一次，record-time 已绑的步不被后来的候选覆盖。
func TestMergeExchangeIDsNeverOverwrites(t *testing.T) {
	in := json.RawMessage(`{"steps":[{"request":"GET /a","exchange_id":"bound-1"},{"request":"GET /b"}]}`)
	out, changed := MergeExchangeIDs(in, []string{"different", "bound-2"})
	if !changed {
		t.Fatal("want changed=true for step 2")
	}
	var rp Reproduction
	_ = json.Unmarshal(out, &rp)
	if rp.Steps[0].ExchangeID != "bound-1" {
		t.Fatalf("already-bound exchange_id overwritten: %s", rp.Steps[0].ExchangeID)
	}
	if rp.Steps[1].ExchangeID != "bound-2" {
		t.Fatalf("want bound-2 on step 2, got %s", rp.Steps[1].ExchangeID)
	}
}

// 3. 全 abstain（零命中/多义）→ changed=false + 原样返回，绝不空跑 UPDATE。
func TestMergeExchangeIDsAllAbstain(t *testing.T) {
	in := json.RawMessage(`{"steps":[{"request":"GET /a"},{"request":"GET /b"}]}`)
	out, changed := MergeExchangeIDs(in, []string{"", ""})
	if changed {
		t.Fatal("all-abstain must report changed=false")
	}
	if string(out) != string(in) {
		t.Fatalf("input must pass through byte-identical, got %s", out)
	}
}

// 4. 非法/空壳 JSON → 原样返回，不 panic。
func TestMergeExchangeIDsMalformedPassthrough(t *testing.T) {
	for _, in := range []string{"", "{}", "null", "not json", `{"steps":[]}`} {
		out, changed := MergeExchangeIDs(json.RawMessage(in), []string{"x"})
		if changed || string(out) != in {
			t.Fatalf("malformed input %q must pass through, got (%q,%v)", in, out, changed)
		}
	}
}

// 5. ids 比 steps 长/短都安全：多余 ids 丢弃，越界不 panic。
func TestMergeExchangeIDSRaggedLengths(t *testing.T) {
	in := json.RawMessage(`{"steps":[{"request":"GET /a"}]}`)
	out, changed := MergeExchangeIDs(in, []string{"1-0001", "extra", "more"})
	if !changed {
		t.Fatal("want changed")
	}
	if strings.Contains(string(out), "extra") {
		t.Fatalf("ids beyond step count leaked into JSON: %s", out)
	}
	out, changed = MergeExchangeIDs(in, nil)
	if changed || string(out) != string(in) {
		t.Fatal("nil ids must abstain")
	}
}

// 6. 已绑齐的复现（全步非空）+ 空 ids → changed=false，view-time 直接透传。
func TestMergeExchangeIDsAlreadyComplete(t *testing.T) {
	in := json.RawMessage(`{"steps":[{"request":"GET /a","exchange_id":"x1"},{"request":"GET /b","exchange_id":"x2"}]}`)
	out, changed := MergeExchangeIDs(in, []string{"y1", "y2"})
	if changed || string(out) != string(in) {
		t.Fatalf("completed repro must never be rewritten, got (%q,%v)", out, changed)
	}
}
