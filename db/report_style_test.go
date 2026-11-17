package db

import (
	"encoding/json"
	"testing"
)

// TestSanitizeStyleJSONDropsEmptyStrings 复现用户场景：模板编辑器把未填写的
// 输入框写成 ""，直接进渲染会让 python-docx 的 Pt("") 抛错、整份报告 502。
// 这里断言空值被剔除（=保留默认），数字键转成数字，未知键丢弃。
func TestSanitizeStyleJSONDropsEmptyStrings(t *testing.T) {
	raw := json.RawMessage(`{"h1_size":"","body_font":"","body_size":"","head_font":"","vuln_size":"","west_font":""}`)
	got := string(SanitizeStyleJSON(raw))
	if got != "{}" {
		t.Fatalf("空字符串应全部剔除，得到 %s", got)
	}
}

func TestSanitizeStyleJSONCoercesValues(t *testing.T) {
	raw := json.RawMessage(`{"body_size":"12","h1_size":16,"body_font":" 仿宋 ","first_line_indent":"false","unknown":"x","line_spacing":"abc"}`)
	var out map[string]any
	if err := json.Unmarshal(SanitizeStyleJSON(raw), &out); err != nil {
		t.Fatalf("非法 JSON: %v", err)
	}
	if out["body_size"] != 12.0 {
		t.Fatalf("body_size 应为 12，得到 %#v", out["body_size"])
	}
	if out["h1_size"] != 16.0 {
		t.Fatalf("h1_size 应为 16，得到 %#v", out["h1_size"])
	}
	if out["body_font"] != "仿宋" {
		t.Fatalf("body_font 应去空格保留，得到 %#v", out["body_font"])
	}
	if out["first_line_indent"] != false {
		t.Fatalf("first_line_indent 应为 false，得到 %#v", out["first_line_indent"])
	}
	if _, ok := out["unknown"]; ok {
		t.Fatalf("未知键应被丢弃")
	}
	if _, ok := out["line_spacing"]; ok {
		t.Fatalf("无法解析的数字键应被丢弃")
	}
}

func TestSanitizeStyleJSONKeepsBadJSONAsIs(t *testing.T) {
	raw := json.RawMessage(`not-json`)
	if string(SanitizeStyleJSON(raw)) != "not-json" {
		t.Fatalf("非法入参应原样返回，交给渲染侧兜底")
	}
}
