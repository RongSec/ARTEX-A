package server

// V12-TARGET：批量目标解析单测。这些用例同时是前端 parseTargets 的对齐基准——
// 前端解析按钮显示的数量必须与后端建的任务数一致。

import (
	"reflect"
	"testing"
)

func TestParseTargets(t *testing.T) {
	in := `
# 这是一行注释，应被丢弃
// 另一种注释
http://10.0.0.5:8080/login
https://shop.example.com
10.0.0.6
10.0.0.7:2222
10.0.0.0/24
dc01
fileserver.corp.local:445
shop.example.com
10.0.0.6
10.0.0.
http://
8080
bad_host
,,
10.0.0.8,10.0.0.9
10.0.0.10; 10.0.0.11
`
	got := ParseTargets(in)
	want := []string{
		"http://10.0.0.5:8080/login",
		"https://shop.example.com",
		"10.0.0.6",
		"10.0.0.7:2222",
		"10.0.0.0/24",
		"dc01",
		"fileserver.corp.local:445",
		// 裸域名与 https:// 形态不合并：scheme 不同等于不同的探测入口，
		// 合并会悄悄丢掉 https 那条。
		"shop.example.com",
		"10.0.0.8",
		"10.0.0.9",
		"10.0.0.10",
		"10.0.0.11",
	}
	if !reflect.DeepEqual(got.Targets, want) {
		t.Fatalf("targets 不一致\n got=%v\nwant=%v", got.Targets, want)
	}
	if len(got.Duplicate) != 1 { // 只有 10.0.0.6 完全重复
		t.Errorf("重复项应为 1，得到 %v", got.Duplicate)
	}
	for _, bad := range []string{"10.0.0.", "http://", "8080", "bad_host"} {
		found := false
		for _, s := range got.Invalid {
			if s == bad {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("应判为非法却没出现: %q（invalid=%v）", bad, got.Invalid)
		}
	}
}

func TestNormalizeTargetForms(t *testing.T) {
	ok := map[string]string{
		"10.0.0.5":                 "10.0.0.5",
		"10.0.0.5:80":              "10.0.0.5:80",
		"::1":                      "::1",
		"http://Example.COM/path":  "http://Example.COM/path", // URL 原样保留
		"https://10.0.0.5:8443":    "https://10.0.0.5:8443",
		"example.com":              "example.com",
		"EXAMPLE.com":              "example.com",
		"10.0.0.0/24":              "10.0.0.0/24",
		"localhost":                "localhost",
		"a-b.c-d.local":            "a-b.c-d.local",
	}
	for in, want := range ok {
		got, valid := normalizeTarget(in)
		if !valid || got != want {
			t.Errorf("normalizeTarget(%q) = (%q,%v)，期望 (%q,true)", in, got, valid, want)
		}
	}
	bad := []string{
		"", " ", "10.0.0.5 10.0.0.6", "10.0.0.5:0", "10.0.0.5:70000",
		"-bad.com", "bad-.com", "a..b", "bad_host", "8080", "http://",
		"ftp://", "10.0.0.0/33", "\"", "例子.中国",
	}
	for _, in := range bad {
		if got, valid := normalizeTarget(in); valid {
			t.Errorf("normalizeTarget(%q) 应非法，得到 (%q,true)", in, got)
		}
	}
}
