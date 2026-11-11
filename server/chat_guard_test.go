package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func chatTestBase() *db.ReportTemplate {
	return &db.ReportTemplate{
		ID:         1,
		Name:       "基线模板",
		OutputLang: "zh-CN",
		Skeleton:   db.ParseSkeletonJSON(nil),
		Style:      json.RawMessage(`{"body_font":"仿宋"}`),
		Prompts:    json.RawMessage(`{}`),
		Issuer:     "示例安全",
		Personnel:  json.RawMessage(`[]`),
		Remark:     "old remark",
	}
}

// TestParseChatPatch 覆盖设计要求的 8 类形态：干净 JSON、围栏、非法骨架、
// 未知 style 键、非 JSON、全量替换语义、超长 reply、中文内容。
func TestParseChatPatch(t *testing.T) {
	base := chatTestBase()

	t.Run("干净JSON带reply外壳", func(t *testing.T) {
		raw := `{"reply":"已改名","patch":{"name":"新名"}}`
		patch, reply, warnings, err := parseChatPatch(raw, base)
		if err != nil {
			t.Fatal(err)
		}
		if reply != "已改名" || len(patch) != 1 || len(warnings) != 0 {
			t.Fatalf("got reply=%q patch=%d warn=%v", reply, len(patch), warnings)
		}
	})

	t.Run("markdown围栏包裹", func(t *testing.T) {
		raw := "好的，这是修改：\n```json\n{\"reply\":\"ok\",\"patch\":{\"issuer\":\"某某公司\"}}\n```\n以上。"
		patch, reply, _, err := parseChatPatch(raw, base)
		if err != nil || reply != "ok" || patch["issuer"] == nil {
			t.Fatalf("fence strip failed: %v %v %v", err, reply, patch)
		}
		var v string
		_ = json.Unmarshal(patch["issuer"], &v)
		if v != "某某公司" {
			t.Fatalf("issuer value=%q", v)
		}
	})

	t.Run("非法骨架整键丢弃", func(t *testing.T) {
		raw := `{"reply":"r","patch":{"skeleton":[{"key":"nonexistent","title":"x","enabled":true}]}}`
		patch, _, warnings, err := parseChatPatch(raw, base)
		if err != nil {
			t.Fatal(err)
		}
		if _, has := patch["skeleton"]; has {
			t.Fatal("invalid skeleton must be dropped")
		}
		if len(warnings) == 0 {
			t.Fatal("must warn")
		}
	})

	t.Run("重复章节键非法", func(t *testing.T) {
		raw := `{"reply":"r","patch":{"skeleton":[{"key":"cover","title":"a","enabled":true},{"key":"cover","title":"b","enabled":true}]}}`
		patch, _, _, err := parseChatPatch(raw, base)
		if err != nil {
			t.Fatal(err)
		}
		if _, has := patch["skeleton"]; has {
			t.Fatal("duplicate keys must be dropped")
		}
	})

	t.Run("合法骨架归一化", func(t *testing.T) {
		raw := `{"reply":"r","patch":{"skeleton":[{"key":"summary","title":"","enabled":false}]}}`
		patch, _, _, err := parseChatPatch(raw, base)
		if err != nil {
			t.Fatal(err)
		}
		skel, has := patch["skeleton"]
		if !has {
			t.Fatal("valid skeleton must pass")
		}
		var secs []db.ReportSection
		if json.Unmarshal(skel, &secs) != nil || len(secs) != 1 || secs[0].Title != "风险等级汇总" {
			t.Fatalf("normalize missing title fallback failed: %s", skel)
		}
	})

	t.Run("未知style键透传加警告", func(t *testing.T) {
		raw := `{"reply":"r","patch":{"style":{"body_font":"黑体","bogus_key":123}}}`
		patch, _, warnings, err := parseChatPatch(raw, base)
		if err != nil {
			t.Fatal(err)
		}
		st, has := patch["style"]
		if !has {
			t.Fatal("style must pass")
		}
		if !strings.Contains(string(st), "bogus_key") {
			t.Fatalf("unknown key must passthrough: %s", st)
		}
		joined := strings.Join(warnings, "|")
		if !strings.Contains(joined, "bogus_key") {
			t.Fatalf("must warn unknown key: %v", warnings)
		}
	})

	t.Run("非JSON整体报错", func(t *testing.T) {
		for _, raw := range []string{"抱歉，我无法处理。", "", "```json\n{broken\n```", "[]"} {
			if _, _, _, err := parseChatPatch(raw, base); err == nil {
				t.Fatalf("must reject %q", raw)
			}
		}
	})

	t.Run("裸patch无外壳警告", func(t *testing.T) {
		raw := `{"name":"直接就是patch","remark":"r2"}`
		patch, reply, warnings, err := parseChatPatch(raw, base)
		if err != nil {
			t.Fatal(err)
		}
		if patch["name"] == nil || patch["remark"] == nil {
			t.Fatalf("bare patch keys lost: %v", patch)
		}
		if reply == "" {
			t.Fatal("reply must fallback non-empty")
		}
		if len(warnings) == 0 {
			t.Fatal("must warn bare-patch")
		}
	})

	t.Run("reply超长截断", func(t *testing.T) {
		long := strings.Repeat("汉", chatMaxReplyRunes+500)
		raw := fmt.Sprintf(`{"reply":%q,"patch":{}}`, long)
		_, reply, warnings, err := parseChatPatch(raw, base)
		if err != nil {
			t.Fatal(err)
		}
		if r := []rune(reply); len(r) != chatMaxReplyRunes+1 || !strings.HasSuffix(reply, "…") {
			t.Fatalf("truncate broken len=%d", len(r))
		}
		if len(warnings) == 0 {
			t.Fatal("must warn truncation")
		}
	})

	t.Run("输出超字节上限报错", func(t *testing.T) {
		raw := fmt.Sprintf(`{"reply":"r","patch":{"remark":"%s"}}`, strings.Repeat("x", chatGuardMaxPatchBytes))
		if _, _, _, err := parseChatPatch(raw, base); err == nil {
			t.Fatal("oversized patch must error")
		}
	})

	t.Run("中文内容全链路", func(t *testing.T) {
		raw := "```json\n{\"reply\":\"把出具方改成「示例科技安全」并加一条备注\",\"patch\":{\"issuer\":\"示例科技安全\",\"remark\":\"仅限内部使用\"}}\n```"
		patch, reply, _, err := parseChatPatch(raw, base)
		if err != nil || !strings.Contains(reply, "示例科技安全") {
			t.Fatalf("cn roundtrip: %v %q", err, reply)
		}
		var iss string
		_ = json.Unmarshal(patch["issuer"], &iss)
		if iss != "示例科技安全" {
			t.Fatalf("issuer=%q", iss)
		}
	})

	t.Run("白名单外键丢弃", func(t *testing.T) {
		// logo_path 有意不在对话补丁白名单（设计 §1.2B patch 字段集；logo 走
		// 上传通道），与 evil 一样应被丢弃并警告。
		raw := `{"reply":"r","patch":{"logo_path":"x","evil":"y","name":"n"}}`
		patch, _, warnings, err := parseChatPatch(raw, base)
		if err != nil {
			t.Fatal(err)
		}
		if patch["name"] == nil {
			t.Fatalf("legal key lost: %v", patch)
		}
		if _, has := patch["evil"]; has {
			t.Fatal("evil key must be dropped")
		}
		if _, has := patch["logo_path"]; has {
			t.Fatal("logo_path must be dropped (not in chat patch whitelist)")
		}
		joined := strings.Join(warnings, "|")
		if !strings.Contains(joined, "evil") {
			t.Fatalf("must warn dropped key: %v", warnings)
		}
	})

	t.Run("output_lang枚举校验", func(t *testing.T) {
		raw := `{"reply":"r","patch":{"output_lang":"fr-FR"}}`
		patch, _, _, err := parseChatPatch(raw, base)
		if err != nil {
			t.Fatal(err)
		}
		if _, has := patch["output_lang"]; has {
			t.Fatal("bad lang must be dropped")
		}
	})
}

// TestMergeTemplateDraft 全量替换语义：patch 里的键整值覆盖、缺席键保原值；
// 不改动 base 本体。
func TestMergeTemplateDraft(t *testing.T) {
	base := chatTestBase()
	patch := map[string]json.RawMessage{
		"name":    json.RawMessage(`"改名后"`),
		"style":   json.RawMessage(`{"body_font":"黑体","h1_size":22}`),
		"style2x": json.RawMessage(`{}`), // 不在合并白名单的键应被忽略
	}
	merged := mergeTemplateDraft(base, patch)
	if merged.Name != "改名后" {
		t.Fatalf("name=%q", merged.Name)
	}
	if !strings.Contains(string(merged.Style), "黑体") {
		t.Fatalf("style=%s", merged.Style)
	}
	if merged.Issuer != base.Issuer || merged.Remark != base.Remark {
		t.Fatal("absent keys must keep base values")
	}
	if base.Name != "基线模板" {
		t.Fatal("merge must not mutate base")
	}
	if merged.ID != base.ID {
		t.Fatal("id must passthrough unchanged")
	}
}

// TestExtractFencedJSON 围栏提取的边角：多块取首个合法、未闭合抢救、裸 JSON。
func TestExtractFencedJSON(t *testing.T) {
	if s, ok := extractFencedJSON("```json\n{\"a\":1}\n```\n```json\n{\"b\":2}\n```"); !ok || !strings.Contains(s, `"a":1`) {
		t.Fatalf("first-valid: %q %v", s, ok)
	}
	// 未闭合围栏（max_tokens 切断）且内容是合法 JSON 前缀整体 → 抢救。
	if s, ok := extractFencedJSON("```json\n{\"a\":1}"); !ok || !strings.Contains(s, `"a":1`) {
		t.Fatalf("unclosed salvage: %q %v", s, ok)
	}
	// 无围栏裸 JSON。
	if s, ok := extractFencedJSON("{\"a\":1}"); !ok || s != "{\"a\":1}" {
		t.Fatalf("bare: %q %v", s, ok)
	}
	// 围栏内容非 JSON → 继续找；全无 → false。
	if _, ok := extractFencedJSON("```js\nconsole.log(1)\n``` plain"); ok {
		t.Fatal("non-json fence must not pass")
	}
}
