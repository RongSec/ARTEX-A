package server

import "testing"

func TestParseReaderJudgeJSONFromThinking(t *testing.T) {
	// 推理模型把 JSON 夹在 thinking 文本里：先出现无关 {}, 再出现真正的判定。
	raw := `先看候选 214：{这不是 JSON}。结论如下
{"score": 72, "reason": "GET /api/x 同构，测法可迁移", "overlap": ["GET /api/x"], "chains": []}`
	out, err := parseReaderJudgeJSON(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if out.Score != 72 || out.Reason == "" {
		t.Fatalf("wrong verdict: %+v", out)
	}
}
