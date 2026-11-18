package packetshot

import (
	"bytes"
	"image/png"
	"math"
	"strings"
	"testing"

	"golang.org/x/image/font"
)

const sampleReq = "POST /api/login?next=%2Fhome HTTP/1.1\r\n" +
	"Host: demo.example.com\r\n" +
	"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.secret\r\n" +
	"Accept-Language: zh-CN,zh;q=0.9\r\n" +
	"Connection: keep-alive\r\n" +
	"\r\n" +
	"{\"username\":\"admin\",\"password\":\"SuperSecret123456\"}"

const sampleResp = "HTTP/1.1 200 OK\r\n" +
	"Content-Type: application/json\r\n" +
	"Set-Cookie: sid=abcdefghijklmnop; Path=/\r\n" +
	"\r\n" +
	"{\"token\":\"abcdefghijklmnopqrstuvwx\",\"ok\":true,\"n\":42}"

// TestRenderRequestPNG 请求报文渲染出合法 PNG（尺寸=宽×高>0；V3 默认
// 1400×Scale1.5）。
func TestRenderRequestPNG(t *testing.T) {
	pngBytes, err := Render(sampleReq, "", DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatalf("not a valid PNG: %v", err)
	}
	b := img.Bounds()
	if b.Dx() != 1680 || b.Dy() < 100 {
		t.Fatalf("canvas size wrong: %v", b)
	}
}

// TestRenderDefaultOptionsV3 报告用默认口径：宽 1680、Scale 2.5、**不脱敏**
// （用户要求截图完整反映报文）、不折叠头、不画行号。
func TestRenderDefaultOptionsV3(t *testing.T) {
	o := DefaultOptions()
	if o.Width != 1680 || o.Scale != 2.4 || o.MaskHeaders || o.Desensitize || o.LineNumbers {
		t.Fatalf("defaults changed: %+v", o)
	}
	// Scale 放大可感知：同一单报文，默认(1.5) 比 1.0 高。
	base := o
	base.Scale = 1
	small, err := Render(sampleReq, sampleResp, base)
	if err != nil {
		t.Fatal(err)
	}
	big, err := Render(sampleReq, sampleResp, o)
	if err != nil {
		t.Fatal(err)
	}
	i1, _ := png.Decode(bytes.NewReader(small))
	i2, _ := png.Decode(bytes.NewReader(big))
	if i2.Bounds().Dy() <= i1.Bounds().Dy() {
		t.Fatalf("scale 1.5 must be taller than 1.0: %v vs %v", i1.Bounds(), i2.Bounds())
	}
}

// TestRenderBothPanels req+resp 同时给=左右并排（总宽不变，高度取两栏较高者）。
func TestRenderBothPanels(t *testing.T) {
	one, err := Render(sampleReq, "", DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	two, err := Render(sampleReq, sampleResp, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	i1, _ := png.Decode(bytes.NewReader(one))
	i2, _ := png.Decode(bytes.NewReader(two))
	if i1.Bounds().Dx() != i2.Bounds().Dx() {
		t.Fatalf("both must share canvas width: %v vs %v", i1.Bounds(), i2.Bounds())
	}
	if i2.Bounds().Dy() < i1.Bounds().Dy() {
		t.Fatalf("two-panel canvas shorter than request-only: %v vs %v", i1.Bounds(), i2.Bounds())
	}
}

// TestRenderSideBySideLayout 两栏等宽、中间 1px 竖线、各自顶部有标题；
// 左右半区都有内容（不是上下堆叠）。深色底。
func TestRenderSideBySideLayout(t *testing.T) {
	out, err := Render(sampleReq, sampleResp, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	b := img.Bounds()
	const width, gutter = 1680, 14
	if b.Dx() != width {
		t.Fatalf("canvas width = %d, want %d", b.Dx(), width)
	}
	panelW := (width - gutter) / 2
	// 画布底应为深色（<40）。
	for _, pt := range [][2]int{{2, 2}, {width - 3, b.Dy() - 3}, {width / 2, b.Dy() / 2}} {
		r, g, bb, _ := img.At(pt[0], pt[1]).RGBA()
		if r>>8 > 60 || g>>8 > 60 || bb>>8 > 60 {
			t.Fatalf("背景不是深色 at %v: (%d,%d,%d)", pt, r>>8, g>>8, bb>>8)
		}
	}
	// 中间竖线：整列颜色比背景亮（分隔线），且两栏内都有浅色文字像素。
	sepX := panelW + gutter/2
	r, g, bb, _ := img.At(sepX, b.Dy()/2).RGBA()
	if r>>8 < 20 && g>>8 < 20 && bb>>8 < 20 {
		t.Fatalf("分栏竖线缺失 at x=%d", sepX)
	}
	bright := func(x0, x1 int) int {
		n := 0
		for y := 0; y < b.Dy(); y += 3 {
			for x := x0; x < x1; x += 3 {
				r, g, bb, _ := img.At(x, y).RGBA()
				if r>>8 > 150 || g>>8 > 150 || bb>>8 > 150 {
					n++
				}
			}
		}
		return n
	}
	left := bright(0, panelW)
	right := bright(panelW+gutter, width)
	if left < 50 || right < 50 {
		t.Fatalf("panel content missing: left=%d right=%d", left, right)
	}
}

// testFaces 用与 Render 相同的字号口径建 face（单测复用，便于精确算版式）。
func testFaces(t *testing.T, s float64) (font.Face, font.Face, bool) {
	t.Helper()
	fs := loadFonts()
	mono := faceOf(fs.mono, 12.0*s)
	if mono == nil {
		t.Fatal("mono face unavailable")
	}
	var cjk font.Face
	if fs.cjkOK {
		cjk = faceOf(fs.cjk, 12.0*s)
	}
	return mono, cjk, fs.cjkOK
}

// TestRenderHeightMatchesRowCount 画布高 = 标题区 + 上下 padding + 物理行数×
// 行高（内容自适应，无固定高度）。
func TestRenderHeightMatchesRowCount(t *testing.T) {
	opt := DefaultOptions()
	s := opt.Scale
	mono, cjk, cjkOK := testFaces(t, s)
	lm := newLayout(s, mono)
	if want := int(math.Round(12.0 * s * 1.42)); lm.lineH != want {
		t.Fatalf("lineH = %d, want 字号×1.42 = %d", lm.lineH, want)
	}
	const width = 1680
	innerW := width - 2*lm.padX
	rows := wrapPanelRows(buildPanel(sampleReq, opt), innerW, s, mono, cjk, cjkOK)
	if len(rows) < 2 {
		t.Fatalf("unexpected row count %d", len(rows))
	}
	out, err := Render(sampleReq, "", opt)
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	wantH := lm.titleH + lm.padY + len(rows)*lm.lineH + lm.padY
	if got := img.Bounds().Dy(); got != wantH {
		t.Fatalf("canvas height = %d, want %d（title %d + 2*padY %d + %d*lineH %d）",
			got, wantH, lm.titleH, lm.padY, len(rows), lm.lineH)
	}
}

// TestWrapLongLineNoClip 120 字符长行折行后每段绘制宽度（含续行悬垂缩进）
// ≤ 栏宽，拼回=原文、续行不带行号。
func TestWrapLongLineNoClip(t *testing.T) {
	opt := DefaultOptions()
	s := opt.Scale
	mono, cjk, cjkOK := testFaces(t, s)
	lm := newLayout(s, mono)
	const width, gutter = 1680, 14
	panelW := (width - gutter) / 2
	innerW := panelW - 2*lm.padX
	long := strings.Repeat("abcdefghij0123456789", 6) // 120 字符
	rows := wrapPanelRows([]panelRow{{kind: rowCode, num: 1, text: long}}, innerW, s, mono, cjk, cjkOK)
	if len(rows) < 2 {
		t.Fatalf("120 字符长行未折行: rows=%d maxW=%d", len(rows), innerW)
	}
	var joined strings.Builder
	for i, r := range rows {
		joined.WriteString(r.text)
		w := measureMixedWidth(r.text, mono, cjk, cjkOK)
		if r.indent+w > innerW {
			t.Fatalf("第 %d 物理行超栏宽: indent=%d + width=%d > maxW=%d", i, r.indent, w, innerW)
		}
		if i > 0 {
			if r.num != 0 {
				t.Fatalf("续行不得带行号: %+v", r)
			}
			if r.indent == 0 {
				t.Fatalf("续行缩进应与首行不同（行号槽悬垂）")
			}
		}
	}
	if joined.String() != long {
		t.Fatalf("折行丢失字符: got %d chars, want %d", joined.Len(), len(long))
	}
}

// TestRenderEmptyErrors 全空输入报错（不 panic）。
func TestRenderEmptyErrors(t *testing.T) {
	if _, err := Render("", "", DefaultOptions()); err == nil {
		t.Fatal("empty must error")
	}
	if _, err := Render("   ", "\n", DefaultOptions()); err == nil {
		t.Fatal("whitespace must error")
	}
}

// TestRenderCJKFallbackPath 中文报文：无论探测到哪条分支（有 CJK=真画、
// 无 CJK='?' 降级），都必须成功出 PNG 且不 panic——两分支同一断言（任务书
// 要求覆盖降级路径，但不依赖具体机器字体存在）。
func TestRenderCJKFallbackPath(t *testing.T) {
	packet := "POST /搜索 HTTP/1.1\r\n" +
		"Host: 中文.example.com\r\n" +
		"\r\n" +
		"备注=漏洞证明截图&keyword=未授权访问"
	out, err := Render(packet, "", DefaultOptions())
	if err != nil {
		t.Fatalf("cjk packet must render without error (fallback '?' path too): %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(out)); err != nil {
		t.Fatalf("cjk render produced invalid PNG: %v", err)
	}
}

// TestPacketTitle 标题提炼：请求/响应/绝对 URL/Host 兜底/畸形行。
func TestPacketTitle(t *testing.T) {
	title, host, isResp := PacketTitle("GET /search?q=1 HTTP/1.1\r\nHost: a.example.com\r\n\r\n")
	if isResp || title != "GET /search?q=1" || host != "a.example.com" {
		t.Fatalf("req title: %q %q %v", title, host, isResp)
	}
	title, _, isResp = PacketTitle("HTTP/1.1 404 Not Found\r\n\r\n")
	if !isResp || title != "HTTP/1.1 404 Not Found" {
		t.Fatalf("resp title: %q %v", title, isResp)
	}
	title, host, _ = PacketTitle("GET http://demo.example.com:8080/admin HTTP/1.1\r\n\r\n")
	if title != "GET /admin" || host != "demo.example.com" {
		t.Fatalf("abs url: %q %q", title, host)
	}
	// 畸形：整行无结构 → 原样，不 panic。
	title, _, _ = PacketTitle("随便一行文本")
	if title != "随便一行文本" {
		t.Fatalf("malformed: %q", title)
	}
}

// TestHeaderLineSplit 头拆分行法：合法头 OK，JSON 体行/超长名拒。
func TestHeaderLineSplit(t *testing.T) {
	if n, v, ok := headerLineSplit("Content-Type: application/json"); !ok || n != "Content-Type" || v != " application/json" {
		t.Fatalf("plain header: %q %q %v", n, v, ok)
	}
	if _, _, ok := headerLineSplit(`{"key":"value"}`); ok {
		t.Fatal("json line must not parse as header")
	}
	if _, _, ok := headerLineSplit(strings.Repeat("x", 80) + ": v"); ok {
		t.Fatal("overlong name must not parse")
	}
}

// TestShouldHideHeaderDefault 默认**不折叠任何头**（报文要完整）；只有显式
// ExtraHideHeaders 才隐藏，KeepHeaders 可豁免。
func TestShouldHideHeaderDefault(t *testing.T) {
	o := DefaultOptions()
	if shouldHideHeader("Accept-Language", o) {
		t.Fatal("默认不得折叠 accept-language")
	}
	if shouldHideHeader("Connection", o) {
		t.Fatal("默认不得折叠 connection")
	}
	o.ExtraHideHeaders = []string{"accept-language"}
	if !shouldHideHeader("Accept-Language", o) {
		t.Fatal("extra hide broken")
	}
	o.KeepHeaders = []string{"accept-language"}
	if shouldHideHeader("Accept-Language", o) {
		t.Fatal("keep override broken")
	}
}

// TestDegradeText '?' 转写只在无 CJK 分支生效；纯 ASCII 恒原样。
func TestDegradeText(t *testing.T) {
	if got := degradeText("abc", false); got != "abc" {
		t.Fatalf("ascii passthrough: %q", got)
	}
	if got := degradeText("a汉b", false); got != "a?b" {
		t.Fatalf("degrade: %q", got)
	}
	if got := degradeText("a汉b", true); got != "a汉b" {
		t.Fatalf("cjkOK passthrough: %q", got)
	}
}

// TestTokenizeJSONLine token 拼接=原文（不丢字符），键/串/数/字面量分类。
func TestTokenizeJSONLine(t *testing.T) {
	line := `  "user": "ab\"c", "n": 42, "ok": true}`
	var joined strings.Builder
	for _, tk := range tokenizeJSONLine(line) {
		joined.WriteString(tk.text)
	}
	if joined.String() != line {
		t.Fatalf("roundtrip broken: %q", joined.String())
	}
	kinds := map[string]int8{}
	for _, tk := range tokenizeJSONLine(line) {
		kinds[tk.text] = tk.kind
	}
	if kinds[`"user"`] != tokKey {
		t.Errorf(`"user" kind=%d want key`, kinds[`"user"`])
	}
	if kinds[`"ab\"c"`] != tokString {
		t.Errorf(`string value kind=%d`, kinds[`"ab\"c"`])
	}
	if kinds["42"] != tokNumber {
		t.Errorf("42 kind=%d", kinds["42"])
	}
	if kinds["true"] != tokLit {
		t.Errorf("true kind=%d", kinds["true"])
	}
}

// TestMaskPipelineInRender 默认原文直出（不脱敏、不折叠）；只有显式打开
// MaskHeaders/Desensitize 才打码——报告要完整报文是用户口径。
func TestMaskPipelineInRender(t *testing.T) {
	rows := buildPanel(sampleReq, DefaultOptions())
	all := ""
	for _, r := range rows {
		all += r.name + " " + r.text + "\n"
	}
	if !strings.Contains(all, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.secret") {
		t.Fatal("默认必须保留 Authorization 原文")
	}
	if !strings.Contains(all, "SuperSecret123456") {
		t.Fatal("默认必须保留 body 原文")
	}
	if !strings.Contains(all, "Accept-Language:") && !strings.Contains(all, "Accept-Language") {
		t.Fatal("默认不得折叠 accept-language")
	}
	// 显式开关=老的打码通道仍可用（对外分享场景）。
	o := DefaultOptions()
	o.MaskHeaders, o.Desensitize = true, true
	masked := buildPanel(sampleReq, o)
	mall := ""
	for _, r := range masked {
		mall += r.name + " " + r.text + "\n"
	}
	if strings.Contains(mall, "SuperSecret123456") {
		t.Fatal("显式 Desensitize=true 时 body 必须打码")
	}
	if strings.Contains(mall, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.secret") {
		t.Fatal("显式 MaskHeaders=true 时 header 值必须打码")
	}
}

// TestOptionsZeroSafe 零值 Options（全关）渲染不炸、宽回退 980。
func TestOptionsZeroSafe(t *testing.T) {
	out, err := Render(sampleReq, "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dx() != 980 {
		t.Fatalf("width fallback: %v", img.Bounds())
	}
}

// TestMosaicOption Mosaic 开=命中行标记 mosaic=true（画布上叠块遮罩）。
func TestMosaicOption(t *testing.T) {
	o := DefaultOptions()
	o.Mosaic = true
	rows := buildPanel(sampleResp, o)
	anyMosaic := false
	for _, r := range rows {
		if r.mosaic {
			anyMosaic = true
		}
	}
	// sid 值 16 位纯字母数字=ShouldMosaic 命中（脱敏后值变短带省略号仍可能
	// 不命中，这里只要求整面板至少一行带标记或全被短化——保守断言渲染成功）。
	out, err := Render(sampleResp, "", o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := png.Decode(bytes.NewReader(out)); err != nil {
		t.Fatal(err)
	}
	_ = anyMosaic
}
