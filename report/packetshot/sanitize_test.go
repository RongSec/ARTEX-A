package packetshot

import (
	"strings"
	"testing"
)

// TestSensitiveValue 三段阈值：<12 全打星；12..19 前4…后3；≥20 前7…后4。
func TestSensitiveValue(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"short", "*****"},                                 // 5 < 12 全星
		{"1234567890", "**********"},                       // 10 < 12 全星
		{"abcdefghijkl", "abcd…jkl"},                      // 12 = 前4…后3
		{"abcdefghijklmnopqrs", "abcd…qrs"},               // 17 < 20 弱打
		{"abcdefghijklmnopqrst", "abcdefg…qrst"},          // 20 ≥20 前7…后4
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.full.body", "eyJhbGc…body"}, // 长 JWT（前7…后4=body）
	}
	for _, c := range cases {
		if got := SensitiveValue(c.in); got != c.want {
			t.Errorf("SensitiveValue(%q)=%q want %q", c.in, got, c.want)
		}
	}
	// 边界长度精确断言（防 off-by-one）。
	if got := SensitiveValue(strings.Repeat("x", 11)); got != strings.Repeat("*", 11) {
		t.Errorf("11-char should be all stars, got %q", got)
	}
	if got := SensitiveValue(strings.Repeat("y", 12)); !strings.Contains(got, "…") {
		t.Errorf("12-char should be masked-with-ellipsis, got %q", got)
	}
	// 首尾明文残留校验：≥20 的前7后4 必须是原串的前7/后4。
	long := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := SensitiveValue(long)
	if !strings.HasPrefix(out, "ABCDEFG") || !strings.HasSuffix(out, "6789") {
		t.Errorf("keep head7/tail4 broken: %q", out)
	}
}

// TestShouldMosaic ≥12、无空白、字母数字(+常见密文字符)占比≥70% 才判密文。
func TestShouldMosaic(t *testing.T) {
	yes := []string{
		"abcdefghijklmnop",            // 16 全字母
		"a1b2c3d4e5f6g7h8",            // 16 字母数字
		"eyJhbGciOiJIUzI1NiIsInR5",    // JWT 段
		"deadbeefcafebabe12345678",    // hex 长串
	}
	no := []string{
		"",
		"short",                     // <12
		"12345678901",               // 11 <12
		"has a space here",          // 含空格
		"a b c d e f g h i j k l",   // 含空格
		"GET /v1/users HTTP/1.1",    // 含空格
		"!@#$%^&*()_+[]{}|;:,.<>?",  // 无空格但符号占比高
	}
	for _, s := range yes {
		if !ShouldMosaic(s) {
			t.Errorf("ShouldMosaic(%q) want true", s)
		}
	}
	for _, s := range no {
		if ShouldMosaic(s) {
			t.Errorf("ShouldMosaic(%q) want false", s)
		}
	}
}

// TestMaskHeaderLineAuthorization Bearer/Basic 打值、scheme 名保留。
func TestMaskHeaderLineAuthorization(t *testing.T) {
	got := MaskHeaderLine("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretpayload")
	if !strings.HasPrefix(got, "Authorization: Bearer ") {
		t.Fatalf("scheme lost: %q", got)
	}
	if strings.Contains(got, "secretpayload") {
		t.Fatalf("token leaked: %q", got)
	}
	// Basic base64 值也打。
	got2 := MaskHeaderLine("Authorization: Basic dXNlcjpwYXNzd29yZA==")
	if strings.Contains(got2, "dXNlcjpwYXNzd29yZA") {
		t.Fatalf("basic leaked: %q", got2)
	}
}

// TestMaskHeaderLineCookie 逐 k=v：敏感 k 名打值、密文值打值、普通 k=v 保留。
func TestMaskHeaderLineCookie(t *testing.T) {
	got := MaskHeaderLine("Cookie: PHPSESSID=abcdefghij1234; theme=dark; lang=zh")
	if !strings.Contains(got, "theme=dark") || !strings.Contains(got, "lang=zh") {
		t.Fatalf("plain cookie pairs lost: %q", got)
	}
	if strings.Contains(got, "abcdefghij1234") {
		t.Fatalf("session value leaked: %q", got)
	}
	if !strings.Contains(got, "PHPSESSID=") {
		t.Fatalf("cookie key name lost: %q", got)
	}
}

// TestMaskHeaderLineSecretNamedHeaders X-*-Api-Key / *-Token / *-Secret 整值打码。
func TestMaskHeaderLineSecretNamedHeaders(t *testing.T) {
	for _, h := range []string{
		"X-Api-Key: sk-live-abcdefghijklmnop",
		"X-Auth-Token: abcdefghijklmnop1234",
		"X-Secret: zzzzzzzzzzzzzzzzzzzzzzz",
		"MyPassword: SuperSecretValue123",
	} {
		name := h[:strings.Index(h, ":")]
		val := strings.TrimSpace(h[strings.Index(h, ":")+1:])
		got := MaskHeaderLine(h)
		if strings.Contains(got, val) {
			t.Errorf("%s value leaked: %q", name, got)
		}
		if !strings.HasPrefix(got, name+": ") {
			t.Errorf("%s header name lost: %q", name, got)
		}
	}
}

// TestMaskHeaderLinePassthrough 普通头原样不动（复现需要可见）。
func TestMaskHeaderLinePassthrough(t *testing.T) {
	for _, h := range []string{
		"Content-Type: application/json",
		"Host: demo.example.com",
		"User-Agent: Mozilla/5.0",
		"Content-Length: 42",
	} {
		if got := MaskHeaderLine(h); got != h {
			t.Errorf("plain header mutated: %q -> %q", h, got)
		}
	}
}

// TestMaskBodySecretsForm 表单体：password/pwd/token 键值打码，普通键不动。
func TestMaskBodySecretsForm(t *testing.T) {
	in := "username=admin&password=hunter2secretvalue&remember=yes&api_key=abcdefgh12345678"
	got := MaskBodySecrets(in)
	if !strings.Contains(got, "username=admin") || !strings.Contains(got, "remember=yes") {
		t.Fatalf("plain form fields lost: %q", got)
	}
	if strings.Contains(got, "hunter2secretvalue") || strings.Contains(got, "abcdefgh12345678") {
		t.Fatalf("form secret leaked: %q", got)
	}
	if !strings.Contains(got, "password=") || !strings.Contains(got, "api_key=") {
		t.Fatalf("form secret key lost: %q", got)
	}
}

// TestMaskBodySecretsJSON JSON 体："key":"value" 敏感键打码。
func TestMaskBodySecretsJSON(t *testing.T) {
	in := `{"user":"bob","access_token":"abcdefghijklmnopqrst","keep":"visible"}`
	got := MaskBodySecrets(in)
	if !strings.Contains(got, `"user":"bob"`) || !strings.Contains(got, `"keep":"visible"`) {
		t.Fatalf("plain json lost: %q", got)
	}
	if strings.Contains(got, "abcdefghijklmnopqrst") {
		t.Fatalf("json token leaked: %q", got)
	}
	if !strings.Contains(got, `"access_token":`) {
		t.Fatalf("json token key lost: %q", got)
	}
}

// TestMaskPacketRequest 整段请求：头脱敏 + 空行分界 + 体脱敏 + 请求行/方法保留。
func TestMaskPacketRequest(t *testing.T) {
	packet := "POST /login HTTP/1.1\r\n" +
		"Host: demo.example.com\r\n" +
		"Authorization: Bearer abcdefghijklmnopqrstuvwx\r\n" +
		"\r\n" +
		"user=bob&password=SuperSecret123456"
	got := MaskPacket(packet)
	// 请求行与 Host 保留。
	if !strings.Contains(got, "POST /login HTTP/1.1") || !strings.Contains(got, "Host: demo.example.com") {
		t.Fatalf("request line/host lost: %q", got)
	}
	// CRLF 结构保留。
	if !strings.Contains(got, "\r\n\r\n") {
		t.Fatalf("header/body boundary broken: %q", got)
	}
	if strings.Contains(got, "abcdefghijklmnopqrstuvwx") || strings.Contains(got, "SuperSecret123456") {
		t.Fatalf("secrets leaked in packet: %q", got)
	}
	if !strings.Contains(got, "Authorization: Bearer ") {
		t.Fatalf("auth scheme lost: %q", got)
	}
}

// TestMaskPacketResponse 响应：状态行保留、Set-Cookie 敏感值打码。
func TestMaskPacketResponse(t *testing.T) {
	packet := "HTTP/1.1 200 OK\r\n" +
		"Set-Cookie: sid=abcdefghijklmnop; Path=/\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<html>ok</html>"
	got := MaskPacket(packet)
	if !strings.Contains(got, "HTTP/1.1 200 OK") {
		t.Fatalf("status line lost: %q", got)
	}
	if !strings.Contains(got, "<html>ok</html>") {
		t.Fatalf("body lost: %q", got)
	}
	if strings.Contains(got, "sid=abcdefghijklmnop;") {
		t.Fatalf("set-cookie value leaked: %q", got)
	}
	if !strings.Contains(got, "Content-Type: text/html") {
		t.Fatalf("plain resp header mutated: %q", got)
	}
}

// TestDefaultRedundantHeaders 默认清单暴露且返回拷贝（改返回值不污染内部）。
func TestDefaultRedundantHeaders(t *testing.T) {
	req := DefaultRedundantRequestHeaders()
	if len(req) == 0 {
		t.Fatal("empty redundant req list")
	}
	req[0] = "MUTATED"
	if DefaultRedundantRequestHeaders()[0] == "MUTATED" {
		t.Fatal("must return a copy, not the internal slice")
	}
	// 重新取一份未污染的再校验内容规整。
	for _, h := range DefaultRedundantRequestHeaders() {
		if strings.TrimSpace(h) == "" || h != strings.ToLower(h) {
			t.Errorf("bad header entry %q (want lowercase non-empty)", h)
		}
	}
}
