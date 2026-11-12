package db

// T14(1/2) 带库集成测（无 PG 自动 skip）：RecordFindingTx 双写链路的
// 「填了进两处、不传零回归」两态。零回归断言刻意做逐字节级：不传 reproduction
// 时节点 payload 必须与改造前的固定五键序列化完全一致（json.Marshal 对
// map 恒按 key 字典序，改造前后同为字母序，可直接字符串相等），列必须是 '{}'。

import (
	"context"
	"encoding/json"
	"testing"
)

func TestRecordFindingReproductionDualWrite(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("repro 双写", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)

	repro := json.RawMessage(`{"entry_point":"POST /upload","prerequisites":["需管理员会话"],"steps":[{"request":"POST /upload HTTP/1.1","response":"HTTP/1.1 200 OK","expected":"落地 webshell","proves":"任意文件上传"}],"provenance":"chain: 弱口令→后台→上传"}`)

	rec, err := es.RecordFinding(context.Background(), RecordFindingInput{
		TaskID: tk.ID, VulnClass: "上传漏洞", Name: "任意文件上传", Severity: "high",
		Summary: "s", Evidence: "e", Worker: "w", Reproduction: repro,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 读回节点 payload：必须带 reproduction 键且结构原样（exchange_id 未回填=
	// 1/2 棒语义：只落原文，关联是 2/2 的事）。
	node, err := es.GetNode(rec.NodeID)
	if err != nil || node == nil {
		t.Fatalf("node readback: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(node.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	rp, ok := payload["reproduction"]
	if !ok {
		t.Fatalf("node payload missing reproduction key: %s", node.Payload)
	}
	m := rp.(map[string]any)
	if m["entry_point"] != "POST /upload" || len(m["steps"].([]any)) != 1 {
		t.Errorf("payload reproduction distorted: %v", m)
	}
	// 读回 findings.reproduction 列：与入参等值（jsonb 语义比较，取规范化文本再比结构）。
	var col string
	if err := d.QueryRow(`SELECT reproduction::text FROM findings WHERE id=$1`, rec.FindingID).Scan(&col); err != nil {
		t.Fatal(err)
	}
	var colObj, wantObj map[string]any
	if err := json.Unmarshal([]byte(col), &colObj); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(repro, &wantObj); err != nil {
		t.Fatal(err)
	}
	if len(colObj["steps"].([]any)) != 1 || colObj["provenance"] != wantObj["provenance"] {
		t.Errorf("column reproduction mismatch: %s", col)
	}
}

func TestRecordFindingWithoutReproductionZeroRegression(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("repro 零回归", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)

	// 原版调用形态：五个基础字段，Reproduction=nil 与传 "{}" 两种空壳都要测。
	for i, repro := range []json.RawMessage{nil, json.RawMessage("{}")} {
		rec, err := es.RecordFinding(context.Background(), RecordFindingInput{
			TaskID: tk.ID, VulnClass: "v", Name: "n", Severity: "low",
			Summary: "s", Evidence: "e", Worker: "w", Reproduction: repro,
		})
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		node, err := es.GetNode(rec.NodeID)
		if err != nil || node == nil {
			t.Fatalf("case %d node: %v", i, err)
		}
		// 逐字节口径：payload 必须恰等于改造前的固定五键序列化（json.Marshal
		// 对 map 字母序稳定；键集合里绝不能出现 reproduction）。
		want, _ := json.Marshal(map[string]any{"vulnclass": "v", "name": "n", "severity": "low", "summary": "s",
			"evidence": map[string]any{"by": "w", "poc": "e"}})
		if string(node.Payload) != string(want) {
			t.Errorf("case %d payload changed: got %s want %s", i, node.Payload, want)
		}
		var col string
		if err := d.QueryRow(`SELECT reproduction::text FROM findings WHERE id=$1`, rec.FindingID).Scan(&col); err != nil {
			t.Fatal(err)
		}
		if col != "{}" {
			t.Errorf("case %d column = %s, want {} (未填必须保持列默认)", i, col)
		}
	}
}
