package server

// T16(3/3) 发现证据截图：路由注册冒烟 + 存储名/类型映射纯函数测。全程无库
// （pg=nil → handler 命中必回 503，与 mux 404 区分），Windows 也能跑。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEvidenceRoutesRegistered(t *testing.T) {
	s := &Server{m: &Manager{}, jwtKey: []byte("t163-test-key")}
	// s.Handler() 内部逐条 mux.HandleFunc；若某条新路由与既有路由在同 method+
	// pattern 上冲突，Go ServeMux 会在注册期 panic。能返回 handler 即结构证明
	// /api/findings/* 未与 /api/exploration/findings/* 等原版路由遮蔽。
	h := s.Handler()
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	cases := []struct{ method, path string }{
		{http.MethodPost, "/api/findings/1/evidence"},
		{http.MethodGet, "/api/findings/1/evidence"},
		{http.MethodDelete, "/api/findings/1/evidence/2"},
		{http.MethodGet, "/api/findings/1/evidence/2"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(""))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("route %s %s: want 503 (registered, pg-guard), got %d body=%s",
				c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	// 遮蔽性不在此实际请求原版路由验证：既有 getFinding handler 无 pg=nil 兜底
	// （直接 s.m.pg.GetFinding 会空指针 panic，原版是 PG-only 设计）。真正的
	// 「同 method+pattern 冲突」在 s.Handler() 注册期就会 panic（上面已成功
	// 构造即证明），而 /api/findings/* 与 /api/exploration/findings/* 是不同
	// 段、ServeMux 精确匹配不会互相抢。
}

func TestEvidenceStoredName(t *testing.T) {
	// 中文名 + 空格 + 路径残留字符全部下划线化；扩展名原样附加；纳秒前缀防撞。
	// stem=C:\x\截图 1 → C(留) :(→_) \(→_) x \(→_) 截(→_) 图(→_) space(→_) 1(留) = C__x____1
	got := evidenceStoredName(`C:\x\截图 1.png`, ".png", 123)
	want := "123-C__x____1.png"
	if got != want {
		t.Errorf("storedName = %q want %q", got, want)
	}
	// ASCII 安全名基本保留（. _ - 合法）。
	if got := evidenceStoredName("p0r-t_.jpg", ".jpg", 7); got != "7-p0r-t_.jpg" {
		t.Errorf("safe ascii mangled: %q", got)
	}
	// 空干名不炸。
	if got := evidenceStoredName(".gif", ".gif", 1); !strings.HasSuffix(got, ".gif") || !strings.HasPrefix(got, "1-") {
		t.Errorf("empty stem broken: %q", got)
	}
}

func TestContentTypeForImage(t *testing.T) {
	cases := map[string]string{
		"a.png": "image/png", "b.JPG": "image/jpeg", "c.jpeg": "image/jpeg",
		"d.gif": "image/gif", "e.webp": "image/webp", "f.bmp": "image/bmp",
		"g.txt": "application/octet-stream",
	}
	for in, want := range cases {
		if got := contentTypeForImage(in); got != want {
			t.Errorf("contentTypeForImage(%q)=%q want %q", in, got, want)
		}
	}
}

func TestEvidenceImageExtWhitelist(t *testing.T) {
	// 白名单键必须小写带点（大小写混用/漏点会绕过 filepath.Ext 小写化后的比对）。
	for ext := range evidenceImageExts {
		if !strings.HasPrefix(ext, ".") || strings.ToLower(ext) != ext {
			t.Errorf("bad ext key (must be lowercase, dot-prefixed): %q", ext)
		}
	}
	// svg 明确不收（可内嵌脚本，XSS 面）。
	if evidenceImageExts[".svg"] {
		t.Error(".svg must not be accepted")
	}
	// 每个白名单扩展名都能映射到 image/* MIME（校验两张表口径一致）。
	for ext := range evidenceImageExts {
		if ct := contentTypeForImage("x" + ext); !strings.HasPrefix(ct, "image/") {
			t.Errorf("ext %q → non-image content-type %q", ext, ct)
		}
	}
}
