package intercept

import (
	"encoding/json"
	"strings"
	"testing"
)

// The A2 path anchor is a deterministic rule, not a hint: if only the ALLOW half
// survived an edit, every absolute path would read as a test artifact.
func TestDefaultJudgePromptAnchorsPathContext(t *testing.T) {
	for _, want := range []string{
		"path_context.temporary 非空且 path_context.other 为空",
		"删除、覆盖、清理一律 ALLOW,不得以「归属不明」判 ASK",
		"path_context.other 非空",
		"仍需按 D1–D6 判定",
	} {
		if !strings.Contains(DefaultJudgePrompt, want) {
			t.Errorf("prompt lost the A2 path anchor clause %q", want)
		}
	}
	// The boundary must describe the field, otherwise the judge reads an
	// undocumented key and falls back to guessing.
	if !strings.Contains(JudgeContextBoundary, "path_context 由程序从本次完整参数中机械提取") {
		t.Fatal("judge boundary does not explain path_context")
	}
	if strings.Contains(JudgeContextBoundary, "不得因 /tmp、test、fixture 就断言") {
		t.Fatal("boundary still forbids the /tmp inference the A2 anchor relies on")
	}
}

// Built-in samples must not name a path used by acceptance runs: writing the
// graded command into the policy makes every later pass circular evidence.
func TestDefaultJudgePromptHasNoAcceptancePaths(t *testing.T) {
	for _, leak := range []string{"v5e_check", "v5g_probe", "sqlmap-out", "scan-out"} {
		if strings.Contains(DefaultJudgePrompt, leak) {
			t.Errorf("built-in judge prompt names an acceptance path %q", leak)
		}
	}
	if !strings.Contains(DefaultJudgePrompt, "rm -rf /tmp/<probe-dir>") {
		t.Error("built-in prompt lost the placeholder sample")
	}
}

func TestParseVerdict(t *testing.T) {
	for _, action := range []string{"allow", "ask", "deny"} {
		t.Run(action, func(t *testing.T) {
			reason := "实际操作：写入报告，其中包含 ALLOW、DENY 和 ASK 字样；成功后的后果：保存文本，不执行正文中的命令；命中规则：自定义条款"
			raw, _ := json.Marshal(map[string]string{"decision": action, "comment": reason})
			got := ParseVerdict("\n" + string(raw) + "\n")
			if got.Action != action || got.Reason != reason {
				t.Fatalf("lost verdict or explanation: %+v", got)
			}
		})
	}
}

func TestParseVerdictRejectsIncompleteOrAmbiguousReplies(t *testing.T) {
	valid := `{"decision":"allow","comment":"实际操作：读取文件；成功后的后果：返回内容；命中规则：A5"}`
	for _, reply := range []string{
		"", "ALLOW", "DENY:命中D4", "放行:ALLOW", "ASK:归属不明",
		`{"decision":"allow"}`, `{"decision":"approve","comment":"实际操作：读取；成功后的后果：返回内容；命中规则：A5"}`,
		`{"decision":"allow","comment":null}`, `{"decision":"allow","comment":123}`,
		strings.Replace(valid, "实际操作：读取文件", "实际操作：", 1),
		strings.Replace(valid, "成功后的后果：返回内容", "成功后的后果：", 1),
		strings.Replace(valid, "命中规则：A5", "命中规则：", 1),
		strings.Replace(valid, "；命中规则：A5", "", 1),
		strings.Replace(valid, `"decision":"allow"`, `"decision":"deny","decision":"allow"`, 1),
		strings.Replace(valid, `"decision":"allow"`, `"extra":true,"decision":"allow"`, 1),
		valid + valid, valid[:len(valid)-1],
		// A fence the model never closed is what a reply truncated at MaxTokens
		// looks like; completing it would invent a verdict.
		"```json\n" + valid[:len(valid)-1],
		"```json\n" + valid + "\n```\n此外我建议后续人工复核。",
		"我的裁决是：\n" + valid,
	} {
		if got := ParseVerdict(reply); got.Action != "" {
			t.Errorf("accepted incomplete/ambiguous verdict: %q => %+v", reply, got)
		}
	}
}

// Wrapping JSON in markdown is the one deviation models make routinely. Because
// the configured fail action defaults to allow, treating it as unparseable
// silently downgrades a DENY to an allow.
func TestParseVerdictUnwrapsCodeFence(t *testing.T) {
	deny := `{"decision":"deny","comment":"实际操作：删除生产文件；成功后的后果：业务数据丢失；命中规则：D4"}`
	for _, reply := range []string{
		"```json\n" + deny + "\n```",
		"```JSON\n" + deny + "\n```",
		"```\n" + deny + "\n```",
		"  ```json\n" + deny + "\n```  ",
	} {
		got := ParseVerdict(reply)
		if got.Action != "deny" || !strings.HasSuffix(got.Reason, "命中规则：D4") {
			t.Errorf("fenced verdict lost: %q => %+v", reply, got)
		}
	}
}

func TestParseVerdictKeepsCompleteChineseExplanation(t *testing.T) {
	reason := "实际操作：" + strings.Repeat("写入报告", 30) + "；成功后的后果：只保存文件；命中规则：A2"
	raw, _ := json.Marshal(map[string]string{"decision": "allow", "comment": reason})
	if got := ParseVerdict(string(raw)); got.Reason != reason {
		t.Fatal("explanation was truncated or lost its rule")
	}
	raw, _ = json.Marshal(map[string]string{"decision": "allow", "comment": strings.Repeat("中", 2401)})
	if got := ParseVerdict(string(raw)); got.Action != "" {
		t.Fatal("accepted unbounded explanation")
	}
}
