package packetshot

// HTTP 报文 → PNG 自绘渲染器（深色编辑器风格，左请求 / 右响应并排）。
//
// 版式对齐参考稿（用户提供）：纯深色底，两栏各一段标题（Request /
// Response）+ 下划线分隔；首行是「方法徽标 + 路径 + 协议」/「协议 + 状态码
// 徽标」；请求头名蓝色、值浅灰；正文按 JSON / HTML / 表单做语法高亮；
// 不折行的长行按栏宽硬折，续行悬垂缩进。
//
// 两条硬约束：
//  1. 默认**不改写报文**：不脱敏、不折叠冗余头、不截断 body（用户口径：
//     截图必须完整反映请求响应）。仍保留 MaskHeaders / Desensitize 开关，
//     需要对外分享时才打开。
//  2. 内容高度自适应，超出 MaxHeight 时先缩字号（最多 8 档），仍超才截断
//     并在末尾标注 (truncated)，绝不静默丢行。
//
// 字体：ASCII 走内嵌 gofont 等宽；探测到系统 CJK 字体时非 ASCII 段混排，
// 未探测到则降级为 '?'（不 panic）。

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/gomono"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
)

// Options 渲染开关。零值可用（Width=0→980，Scale=0→1）。
type Options struct {
	Width            int      // 画布宽 px（默认 1680）
	Scale            float64  // 字号倍率（0=1；默认 2.5）
	MaxHeight        int      // 画布高上限 px（0=不限；超出先缩字号再截断）
	HideHeaders      bool     // 整个 Headers 区不画
	MaskHeaders      bool     // 头值脱敏（默认关：报告要完整报文）
	Desensitize      bool     // Body 键值脱敏（默认关）
	Mosaic           bool     // 形似密钥的值再叠马赛克
	LineNumbers      bool     // Body 区画行号（默认关）
	ExtraHideHeaders []string // 追加折叠的头名（默认不折叠任何头）
	KeepHeaders      []string // 从折叠清单豁免的头名
}

// DefaultOptions 报告用默认值：宽 1680、Scale 2.4（14cm 宽插图后正文约
// 6.8pt）、不脱敏、不折叠头、不画行号。
func DefaultOptions() Options {
	return Options{Width: 1680, Scale: 2.4}
}

// 深色主题调色板。
var (
	colBG      = color.NRGBA{0x0F, 0x10, 0x12, 0xFF} // 画布底
	colTitle   = color.NRGBA{0xF0, 0xF3, 0xF6, 0xFF} // 栏标题
	colRule    = color.NRGBA{0x2A, 0x2D, 0x31, 0xFF} // 标题下横线 / 分栏竖线
	colText    = color.NRGBA{0xC9, 0xD1, 0xD9, 0xFF} // 普通文字
	colStrong  = color.NRGBA{0xE6, 0xED, 0xF3, 0xFF} // 路径等强调
	colMuted   = color.NRGBA{0x6E, 0x76, 0x81, 0xFF} // 协议版本 / 提示
	colHdrName = color.NRGBA{0x79, 0xC0, 0xFF, 0xFF} // 头名 / JSON key
	colPunct   = color.NRGBA{0x8B, 0x94, 0x9E, 0xFF} // 冒号等标点
	colStr     = color.NRGBA{0xCE, 0x91, 0x78, 0xFF} // 字符串值
	colNum     = color.NRGBA{0xB5, 0xCE, 0xA8, 0xFF} // 数字
	colLit     = color.NRGBA{0x56, 0x9C, 0xD6, 0xFF} // true/false/null
	colTag     = color.NRGBA{0x56, 0x9C, 0xD6, 0xFF} // HTML 标签名
	colAttr    = color.NRGBA{0x9C, 0xDC, 0xFE, 0xFF} // HTML 属性名
	colComment = color.NRGBA{0x6A, 0x99, 0x55, 0xFF} // 注释
	colWhite   = color.NRGBA{0xFF, 0xFF, 0xFF, 0xFF}
)

// 徽标底色。
var (
	colBadgeReq = color.NRGBA{0xB4, 0x23, 0x33, 0xFF} // 方法：红
	colBadge2xx = color.NRGBA{0x23, 0x86, 0x36, 0xFF} // 2xx：绿
	colBadge3xx = color.NRGBA{0x1F, 0x6F, 0xEB, 0xFF} // 3xx：蓝
	colBadge4xx = color.NRGBA{0x9E, 0x6A, 0x03, 0xFF} // 4xx：橙
	colBadge5xx = color.NRGBA{0xDA, 0x36, 0x33, 0xFF} // 5xx：红
)

// ---------- 字体：CJK 探测（sync.Once）+ 加载 ----------

type fontSet struct {
	mono  *opentype.Font
	cjk   *opentype.Font
	cjkOK bool
}

var (
	fontOnce  sync.Once
	fontCache *fontSet
)

var cjkFontCandidates = []string{
	`C:\Windows\Fonts\msyh.ttc`,
	`C:\Windows\Fonts\msyh.ttf`,
	`C:\Windows\Fonts\simhei.ttf`,
	`C:\Windows\Fonts\simsun.ttc`,
	"/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
	"/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
	"/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
	"/usr/share/fonts/truetype/droid/DroidSansFallback.ttf",
	"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
	"/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
	"/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
	"/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
}

func cjkProbePaths() []string {
	out := append([]string(nil), cjkFontCandidates...)
	if wd := strings.TrimSpace(os.Getenv("WINDIR")); wd != "" {
		for _, f := range []string{"msyh.ttc", "simhei.ttf", "simsun.ttc"} {
			out = append(out, filepath.Join(wd, "Fonts", f))
		}
	}
	return out
}

func loadFonts() *fontSet {
	fontOnce.Do(func() {
		fs := &fontSet{}
		fs.mono, _ = opentype.Parse(gomono.TTF)
		for _, p := range cjkProbePaths() {
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			if f, err := opentype.Parse(data); err == nil {
				fs.cjk, fs.cjkOK = f, true
				break
			}
			if col, err := opentype.ParseCollection(data); err == nil && col.NumFonts() > 0 {
				if f, err := col.Font(0); err == nil {
					fs.cjk, fs.cjkOK = f, true
					break
				}
			}
		}
		fontCache = fs
	})
	return fontCache
}

// HasCJK 当前进程是否探测到可用 CJK 字体（首调触发探测）。
func HasCJK() bool { return loadFonts().cjkOK }

func faceOf(f *opentype.Font, size float64) font.Face {
	if f != nil {
		if ff, err := opentype.NewFace(f, &opentype.FaceOptions{Size: size, DPI: 72, Hinting: font.HintingFull}); err == nil {
			return ff
		}
	}
	return nil
}

// ---------- 行模型 ----------

type rowKind int8

const (
	rowTitle rowKind = iota // 首行：徽标 + 报文行
	rowText                 // 头行（name 蓝 + value 灰）
	rowMuted                // 提示（灰）
	rowJSON                 // JSON 行
	rowCode                 // 正文行（按语言高亮）
	rowRule                 // 分隔线（body 前的一条细线）
)

type panelRow struct {
	kind   rowKind
	name   string // 头名 或 徽标文字
	text   string
	proto  string // 首行协议段（HTTP/1.1），灰色排在同侧
	resp   bool   // 首行是否为响应（决定协议与徽标的左右顺序）
	num    int
	mosaic bool
	indent int
}

// hlLang 正文语法高亮语言。
type hlLang int8

const (
	hlPlain hlLang = iota
	hlJSON
	hlHTML
	hlForm
)

type panelData struct {
	rows []panelRow
	resp bool
	lang hlLang
}

// layout 版式尺度（全部由字号推导，改 Scale 即整体等比）。
type layout struct {
	font   float64
	lineH  int
	padX   int
	padY   int
	titleH int
	asc    int
	desc   int
}

func newLayout(scale float64, face font.Face) layout {
	if scale <= 0 {
		scale = 1
	}
	fontSize := 12.0 * scale
	lm := layout{
		font:   fontSize,
		lineH:  int(math.Round(fontSize * 1.42)),
		padX:   int(math.Round(12 * scale)),
		padY:   int(math.Round(10 * scale)),
		titleH: int(math.Round(fontSize*1.45)) + int(math.Round(6*scale)),
	}
	if lm.lineH < 6 {
		lm.lineH = 6
	}
	if lm.padX < 6 {
		lm.padX = 6
	}
	if lm.padY < 6 {
		lm.padY = 6
	}
	m := face.Metrics()
	lm.asc = m.Ascent.Ceil()
	lm.desc = m.Descent.Ceil()
	return lm
}

// Render 把请求/响应渲染成 PNG。两者都给 = 左请求、右响应并排。
//
// 内容完整优先：先按给定 Scale 排版，超出 MaxHeight 时逐档缩字号（×0.9，
// 最多 8 档），仍超出才截断行并在末行标注 (truncated)。
func Render(req, resp string, opt Options) ([]byte, error) {
	if strings.TrimSpace(req) == "" && strings.TrimSpace(resp) == "" {
		return nil, fmt.Errorf("packetshot: 空报文")
	}
	width := opt.Width
	if width < 420 {
		width = 980
	}
	scale := opt.Scale
	if scale <= 0 {
		scale = 1
	}

	panels := make([]panelData, 0, 2)
	if strings.TrimSpace(req) != "" {
		panels = append(panels, panelData{rows: buildPanel(req, opt), lang: detectLang(req)})
	}
	if strings.TrimSpace(resp) != "" {
		panels = append(panels, panelData{rows: buildPanel(resp, opt), resp: true, lang: detectLang(resp)})
	}

	fs := loadFonts()
	for attempt := 0; ; attempt++ {
		img, total := paint(width, scale, panels, fs)
		if opt.MaxHeight <= 0 || total <= opt.MaxHeight || attempt >= 7 {
			if opt.MaxHeight > 0 && total > opt.MaxHeight {
				img = truncateToHeight(img, opt.MaxHeight)
			}
			var buf bytes.Buffer
			if err := png.Encode(&buf, img); err != nil {
				return nil, err
			}
			return buf.Bytes(), nil
		}
		scale *= 0.9
	}
}

// paint 按给定尺度渲染一版，返回图像与实际高度。
func paint(width int, scale float64, panels []panelData, fs *fontSet) (*image.NRGBA, int) {
	mono := faceOf(fs.mono, 12.0*scale)
	defer mono.Close()
	var cjk font.Face
	if fs.cjkOK {
		cjk = faceOf(fs.cjk, 12.0*scale)
		if cjk != nil {
			defer cjk.Close()
		}
	}
	titleFace := faceOf(fs.mono, 17.0*scale)
	defer titleFace.Close()

	lm := newLayout(scale, mono)

	const gutter = 14 // 两栏之间的空白 + 1px 竖线
	n := len(panels)
	panelW := width
	if n == 2 {
		panelW = (width - gutter) / 2
	}
	innerW := panelW - 2*lm.padX
	if innerW < 40 {
		innerW = 40
	}

	// 先折行，算出各栏行数。
	rowsByPanel := make([][]panelRow, n)
	maxRows := 0
	for i := range panels {
		rowsByPanel[i] = wrapPanelRows(panels[i].rows, innerW, scale, mono, cjk, fs.cjkOK)
		if l := len(rowsByPanel[i]); l > maxRows {
			maxRows = l
		}
	}
	contentH := lm.titleH + lm.padY + maxRows*lm.lineH + lm.padY
	total := contentH

	img := image.NewNRGBA(image.Rect(0, 0, width, total))
	draw.Draw(img, img.Bounds(), &image.Uniform{colBG}, image.Point{}, draw.Src)
	if n == 2 {
		x := panelW + gutter/2
		draw.Draw(img, image.Rect(x, 0, x+1, total), &image.Uniform{colRule}, image.Point{}, draw.Src)
	}

	for i := range panels {
		x0 := 0
		if i == 1 {
			x0 = panelW + gutter
		}
		// 栏标题：粗体 + 下划线。
		label := "Request"
		if panels[i].resp {
			label = "Response"
		}
		titleBase := lm.padY + lm.titleH - int(8*scale)
		drawBold(img, label, x0+lm.padX, titleBase, colTitle, titleFace, scale)
		ruleY := lm.padY + lm.titleH - int(2*scale)
		draw.Draw(img, image.Rect(x0+lm.padX, ruleY, x0+panelW-lm.padX, ruleY+1),
			&image.Uniform{colRule}, image.Point{}, draw.Src)

		y := lm.titleH + lm.padY + lm.asc
		for _, r := range rowsByPanel[i] {
			x := x0 + lm.padX + r.indent
			switch r.kind {
			case rowTitle:
				x = drawTitleRow(img, r, x, y, lm, mono, cjk, fs.cjkOK, scale)
			case rowMuted:
				drawMixed(img, r.text, x, y, colMuted, mono, cjk, fs.cjkOK)
			case rowText:
				if r.name != "" {
					x = drawString(img, r.name, x, y, colHdrName, mono)
					x = drawString(img, ":", x, y, colPunct, mono)
					x = drawString(img, " ", x, y, colPunct, mono)
				}
				x = drawMixed(img, r.text, x, y, colText, mono, cjk, fs.cjkOK)
			case rowJSON, rowCode:
				lang := panels[i].lang
				if r.kind == rowJSON {
					lang = hlJSON
				}
				if r.num > 0 {
					ns := fmt.Sprintf("%4d ", r.num)
					x = drawString(img, ns, x, y, colMuted, mono)
				}
				if r.mosaic {
					x = drawMixed(img, r.text, x, y, colText, mono, cjk, fs.cjkOK)
					drawMosaicBox(img, x, y-lm.asc, lm.padX, lm.lineH, scale)
				} else {
					x = drawHighlighted(img, r.text, lang, x, y, mono, cjk, fs.cjkOK)
				}
			}
			y += lm.lineH
		}
	}
	return img, total
}

// drawTitleRow 报文首行：请求=[方法徽标][路径][协议灰]；响应=[协议灰][状态徽标]。
func drawTitleRow(img *image.NRGBA, r panelRow, x, y int, lm layout, mono, cjk font.Face, cjkOK bool, scale float64) int {
	if r.resp && r.proto != "" {
		x = drawMixed(img, r.proto, x, y, colMuted, mono, cjk, cjkOK)
		x += int(float64(lm.padX) * 0.5)
	}
	if r.name != "" {
		bg := badgeColor(r.name)
		bw := textWidth(mono, r.name) + int(float64(lm.padX)*1.5)
		bh := lm.lineH - int(4*scale)
		top := y - lm.asc - int(3*scale)
		fillRoundRect(img, image.Rect(x, top, x+bw, top+bh), int(5*scale), bg)
		drawString(img, r.name, x+(bw-textWidth(mono, r.name))/2, y, colWhite, mono)
		x += bw + int(float64(lm.padX)*0.55)
	}
	if r.text != "" {
		x = drawMixed(img, r.text, x, y, colStrong, mono, cjk, cjkOK)
	}
	if !r.resp && r.proto != "" {
		x += int(float64(lm.padX) * 0.55)
		x = drawMixed(img, r.proto, x, y, colMuted, mono, cjk, cjkOK)
	}
	return x
}

// drawHighlighted 按语言逐 token 着色。tokenize 只影响颜色，不增删字符。
func drawHighlighted(img *image.NRGBA, line string, lang hlLang, x, y int, mono, cjk font.Face, cjkOK bool) int {
	var toks []jsonToken
	switch lang {
	case hlJSON:
		toks = tokenizeJSONLine(line)
	case hlHTML:
		toks = tokenizeHTMLLine(line)
	case hlForm:
		toks = tokenizeFormLine(line)
	default:
		return drawMixed(img, line, x, y, colText, mono, cjk, cjkOK)
	}
	for _, t := range toks {
		c := colText
		switch t.kind {
		case tokKey:
			c = colHdrName
		case tokString:
			c = colStr
		case tokNumber:
			c = colNum
		case tokLit:
			c = colLit
		case tokTag:
			c = colTag
		case tokAttr:
			c = colAttr
		case tokComment:
			c = colComment
		}
		x = drawMixed(img, t.text, x, y, c, mono, cjk, cjkOK)
	}
	return x
}

// ---------- 折行 ----------

func wrapPanelRows(rows []panelRow, maxW int, s float64, mono, cjk font.Face, cjkOK bool) []panelRow {
	out := make([]panelRow, 0, len(rows)+8)
	for _, r := range rows {
		switch r.kind {
		case rowTitle:
			// 首行前缀 = 徽标（+ 响应侧协议）宽度，续行悬垂到正文起点。
			gap := int(12 * s)
			prefix := 0
			if r.resp && r.proto != "" {
				prefix += textWidth(mono, r.proto) + gap/2
			}
			if r.name != "" {
				prefix += textWidth(mono, r.name) + int(float64(gap)*1.5) + int(float64(gap)*0.55)
			}
			if r.text == "" {
				out = append(out, panelRow{kind: rowTitle, name: r.name, proto: r.proto, resp: r.resp})
				continue
			}
			chunks := splitToWidth(r.text, max(1, maxW-prefix), mono, cjk, cjkOK)
			out = append(out, panelRow{kind: rowTitle, name: r.name, text: chunks[0], proto: r.proto, resp: r.resp})
			for _, c := range chunks[1:] {
				out = append(out, panelRow{kind: rowText, text: c, indent: prefix})
			}
		case rowText:
			prefix := 0
			if r.name != "" {
				prefix = textWidth(mono, r.name+": ")
			}
			chunks := splitToWidth(r.text, max(1, maxW-prefix), mono, cjk, cjkOK)
			out = append(out, panelRow{kind: rowText, name: r.name, text: chunks[0], mosaic: r.mosaic})
			for _, c := range chunks[1:] {
				out = append(out, panelRow{kind: rowText, text: c, indent: prefix})
			}
		case rowJSON, rowCode:
			gutter := 0
			if r.num > 0 {
				gutter = textWidth(mono, fmt.Sprintf("%4d ", r.num))
			}
			chunks := splitToWidth(r.text, max(1, maxW-gutter), mono, cjk, cjkOK)
			out = append(out, panelRow{kind: r.kind, num: r.num, text: chunks[0], mosaic: r.mosaic})
			for _, c := range chunks[1:] {
				out = append(out, panelRow{kind: r.kind, text: c, indent: gutter})
			}
		default:
			for _, c := range splitToWidth(r.text, maxW, mono, cjk, cjkOK) {
				out = append(out, panelRow{kind: r.kind, text: c})
			}
		}
	}
	return out
}

// splitToWidth 按宽度折行（逐 rune 量宽、上取整累加，保证不越界）。
//
// 带**软断点**回溯：优先在空白、逗号、分号、&、/、?、<>、引号、冒号、等号
// 之后断行，避免把 `application` 切成 `appl`/`ication`。断点太靠前（不足本行
// 已排宽度的 2/3）时放弃回溯，防止出现过短行。
func splitToWidth(s string, maxW int, mono, cjk font.Face, cjkOK bool) []string {
	if !cjkOK || cjk == nil {
		s = degradeText(s, false)
		cjk = nil
	}
	if maxW <= 0 {
		return []string{s}
	}
	rs := []rune(s)
	if len(rs) == 0 {
		return []string{""}
	}
	out := make([]string, 0, len(rs)/16+1)
	start := 0
	for start < len(rs) {
		w := 0
		end := start
		lastBreak := -1
		for end < len(rs) {
			f := mono
			if rs[end] > 127 && cjk != nil {
				f = cjk
			}
			rw := (int(font.MeasureString(f, string(rs[end]))) + 63) / 64
			if w+rw > maxW && end > start {
				break
			}
			w += rw
			end++
			if isSoftBreak(rs[end-1]) {
				lastBreak = end
			}
		}
		if end == start { // 单 rune 超宽：独占一行，防死循环
			end = start + 1
		}
		if end < len(rs) && lastBreak > start && lastBreak >= start+(end-start)*2/3 {
			end = lastBreak
		}
		out = append(out, string(rs[start:end]))
		start = end
	}
	return out
}

// isSoftBreak 软断点字符（在其后断行不影响语义）。
func isSoftBreak(r rune) bool {
	switch r {
	case ' ', '\t', ',', ';', '&', '/', '?', '>', '<', '"', '\'', ':', '=', ')', ']', '}':
		return true
	}
	return false
}

func measureMixedWidth(s string, mono, cjk font.Face, cjkOK bool) int {
	if s == "" {
		return 0
	}
	if !cjkOK || cjk == nil {
		return textWidth(mono, s)
	}
	w := 0
	runes := []rune(s)
	i := 0
	for i < len(runes) {
		j := i
		ascii := runes[i] <= 127
		for j < len(runes) && (runes[j] <= 127) == ascii {
			j++
		}
		f := mono
		if !ascii {
			f = cjk
		}
		w += textWidth(f, string(runes[i:j]))
		i = j
	}
	return w
}

// ---------- 报文 → 行序列 ----------

// buildPanel 一段报文 → 行序列。默认原文直出（不脱敏、不折叠头）。
func buildPanel(packet string, o Options) []panelRow {
	rows := make([]panelRow, 0, 64)
	badge, first, proto, isResp := splitFirstLine(packet)
	rows = append(rows, panelRow{kind: rowTitle, name: badge, text: first, proto: proto, resp: isResp})

	lines := strings.Split(strings.ReplaceAll(packet, "\r\n", "\n"), "\n")
	bodyStart := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			bodyStart = i + 1
			break
		}
	}
	headerLines := lines[1:]
	if bodyStart >= 0 {
		headerLines = lines[1 : bodyStart-1]
	}

	if o.HideHeaders {
		rows = append(rows, panelRow{kind: rowMuted, text: "—— Headers 已隐藏 ——"})
	} else {
		for _, ln := range headerLines {
			if strings.TrimSpace(ln) == "" {
				continue
			}
			name, val, ok := headerLineSplit(ln)
			if !ok {
				rows = append(rows, panelRow{kind: rowText, text: ln})
				continue
			}
			if shouldHideHeader(name, o) {
				continue
			}
			if o.MaskHeaders {
				masked := MaskHeaderLine(name + ":" + val)
				if i := strings.Index(masked, ":"); i >= 0 {
					val = masked[i+1:]
				}
			}
			rows = append(rows, panelRow{
				kind: rowText, name: name, text: strings.TrimLeft(val, " "),
				mosaic: o.Mosaic && ShouldMosaic(val),
			})
		}
	}

	if bodyStart >= 0 && bodyStart < len(lines) {
		body := lines[bodyStart:]
		bodyText := strings.Join(body, "\n")
		if strings.TrimSpace(bodyText) != "" {
			if o.Desensitize {
				bodyText = MaskBodySecrets(bodyText)
				body = strings.Split(bodyText, "\n")
			}
			// 去掉尾部纯空行（报文常以 CRLF 结尾），不制造无意义空白行。
			for len(body) > 0 && strings.TrimSpace(body[len(body)-1]) == "" {
				body = body[:len(body)-1]
			}
			isJSON := looksJSON(bodyText)
			const maxLines = 400 // 安全阀：单条报文超 400 行才截断（并在末行标注）
			for i, ln := range body {
				if i >= maxLines {
					rows = append(rows, panelRow{kind: rowMuted,
						text: fmt.Sprintf("... (共 %d 行，超出部分已截断)", len(body))})
					break
				}
				kind := rowCode
				if isJSON {
					kind = rowJSON
				}
				num := 0
				if o.LineNumbers {
					num = i + 1
				}
				rows = append(rows, panelRow{
					kind: kind, num: num, text: ln,
					mosaic: o.Mosaic && ShouldMosaic(ln),
				})
			}
		}
	}
	return rows
}

// detectLang 正文语言判定（只影响着色）。
func detectLang(packet string) hlLang {
	lines := strings.Split(strings.ReplaceAll(packet, "\r\n", "\n"), "\n")
	bodyStart := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			bodyStart = i + 1
			break
		}
	}
	if bodyStart < 0 || bodyStart >= len(lines) {
		return hlPlain
	}
	body := strings.TrimSpace(strings.Join(lines[bodyStart:], "\n"))
	if body == "" {
		return hlPlain
	}
	if looksJSON(body) {
		return hlJSON
	}
	if strings.HasPrefix(body, "<") {
		return hlHTML
	}
	first := body
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	if strings.Contains(first, "=") && !strings.ContainsAny(first, "<>{}") {
		return hlForm
	}
	return hlPlain
}

// ---------- 语法 tokenizers ----------

// tokenizeHTMLLine 简易 HTML/XML 着色：注释、标签名、属性名、属性值、文本。
// 非严格解析，只保证不丢字符（拼接 == 原文）。
func tokenizeHTMLLine(line string) []jsonToken {
	rs := []rune(line)
	var out []jsonToken
	i := 0
	for i < len(rs) {
		// 注释
		if i+3 < len(rs) && string(rs[i:i+4]) == "<!--" {
			end := strings.Index(string(rs[i:]), "-->")
			if end < 0 {
				out = append(out, jsonToken{tokComment, string(rs[i:])})
				return out
			}
			out = append(out, jsonToken{tokComment, string(rs[i : i+end+3])})
			i += end + 3
			continue
		}
		if rs[i] == '<' {
			j := i
			// 标签段到 '>' 或行尾
			for j < len(rs) && rs[j] != '>' {
				j++
			}
			if j < len(rs) {
				j++
			}
			out = append(out, tokenizeTag(string(rs[i:j]))...)
			i = j
			continue
		}
		j := i
		for j < len(rs) && rs[j] != '<' {
			j++
		}
		out = append(out, jsonToken{tokPlain, string(rs[i:j])})
		i = j
	}
	return out
}

// tokenizeTag 一段 `<...>` 拆成 标签名 / 属性名 / 属性值 / 标点。
func tokenizeTag(tag string) []jsonToken {
	rs := []rune(tag)
	var out []jsonToken
	i := 0
	// 前导 < 或 </
	start := i
	for i < len(rs) && (rs[i] == '<' || rs[i] == '/' || rs[i] == '!') {
		i++
	}
	if i > start {
		out = append(out, jsonToken{tokPlain, string(rs[start:i])})
	}
	// 标签名
	start = i
	for i < len(rs) && !isTagDelim(rs[i]) {
		i++
	}
	if i > start {
		out = append(out, jsonToken{tokTag, string(rs[start:i])})
	}
	for i < len(rs) {
		c := rs[i]
		switch {
		case c == '>' || c == '/' || c == '=' || c == '"' || c == '\'':
			if c == '"' || c == '\'' {
				q := c
				j := i + 1
				for j < len(rs) && rs[j] != q {
					j++
				}
				if j < len(rs) {
					j++
				}
				out = append(out, jsonToken{tokString, string(rs[i:j])})
				i = j
				continue
			}
			out = append(out, jsonToken{tokPlain, string(c)})
			i++
		case c == ' ' || c == '\t':
			start = i
			for i < len(rs) && (rs[i] == ' ' || rs[i] == '\t') {
				i++
			}
			out = append(out, jsonToken{tokPlain, string(rs[start:i])})
		default:
			start = i
			for i < len(rs) && !isTagDelim(rs[i]) {
				i++
			}
			out = append(out, jsonToken{tokAttr, string(rs[start:i])})
		}
	}
	return out
}

func isTagDelim(r rune) bool {
	return r == ' ' || r == '\t' || r == '>' || r == '/' || r == '=' || r == '"' || r == '\''
}

// tokenizeFormLine 表单/查询串着色：key 蓝、= 灰、value 橙、& 灰。
func tokenizeFormLine(line string) []jsonToken {
	var out []jsonToken
	parts := strings.Split(line, "&")
	for idx, part := range parts {
		if idx > 0 {
			out = append(out, jsonToken{tokPlain, "&"})
		}
		if k, v, ok := strings.Cut(part, "="); ok {
			out = append(out, jsonToken{tokKey, k})
			out = append(out, jsonToken{tokPlain, "="})
			out = append(out, jsonToken{tokString, v})
			continue
		}
		if part != "" {
			out = append(out, jsonToken{tokPlain, part})
		}
	}
	return out
}

// ---------- 绘制原语 ----------

func drawBold(dst *image.NRGBA, s string, x, baselineY int, c color.Color, f font.Face, scale float64) {
	if s == "" || f == nil {
		return
	}
	drawString(dst, s, x, baselineY, c, f)
	// 等宽字体无粗体字重：本体右移 1px 再画一遍模拟半粗（scale≥1.5 才做）。
	if scale >= 1.5 {
		drawString(dst, s, x+1, baselineY, c, f)
	}
}

func drawMixed(dst *image.NRGBA, s string, x, baselineY int, c color.Color, mono, cjk font.Face, cjkOK bool) int {
	if s == "" {
		return x
	}
	if !cjkOK || cjk == nil {
		d := degradeText(s, false)
		drawString(dst, d, x, baselineY, c, mono)
		return x + textWidth(mono, d)
	}
	runes := []rune(s)
	i := 0
	for i < len(runes) {
		j := i
		ascii := runes[i] <= 127
		for j < len(runes) && (runes[j] <= 127) == ascii {
			j++
		}
		seg := string(runes[i:j])
		f := mono
		if !ascii {
			f = cjk
		}
		drawString(dst, seg, x, baselineY, c, f)
		x += textWidth(f, seg)
		i = j
	}
	return x
}

func drawString(dst *image.NRGBA, s string, x, baselineY int, c color.Color, f font.Face) int {
	if s == "" || f == nil {
		return x
	}
	d := &font.Drawer{Dst: dst, Src: image.NewUniform(c), Face: f, Dot: fixed.P(x, baselineY)}
	d.DrawString(s)
	return x + textWidth(f, s)
}

func textWidth(f font.Face, s string) int {
	if s == "" || f == nil {
		return 0
	}
	return int(font.MeasureString(f, s).Round())
}

// fillRoundRect 填充圆角矩形（radius 为角半径 px）。
func fillRoundRect(dst *image.NRGBA, r image.Rectangle, radius int, c color.Color) {
	if r.Dx() <= 0 || r.Dy() <= 0 {
		return
	}
	if radius <= 0 {
		draw.Draw(dst, r, &image.Uniform{c}, image.Point{}, draw.Src)
		return
	}
	if radius*2 > r.Dy() {
		radius = r.Dy() / 2
	}
	if radius*2 > r.Dx() {
		radius = r.Dx() / 2
	}
	if radius <= 0 {
		draw.Draw(dst, r, &image.Uniform{c}, image.Point{}, draw.Src)
		return
	}
	// 中段整行填充；上下 radius 行按圆内缩。
	draw.Draw(dst, image.Rect(r.Min.X, r.Min.Y+radius, r.Max.X, r.Max.Y-radius), &image.Uniform{c}, image.Point{}, draw.Src)
	for dy := 0; dy < radius; dy++ {
		inset := radius - int(math.Sqrt(float64(radius*radius-(radius-dy)*(radius-dy)))+0.5)
		if inset < 0 {
			inset = 0
		}
		draw.Draw(dst, image.Rect(r.Min.X+inset, r.Min.Y+dy, r.Max.X-inset, r.Min.Y+dy+1), &image.Uniform{c}, image.Point{}, draw.Src)
		yy := r.Max.Y - 1 - dy
		draw.Draw(dst, image.Rect(r.Min.X+inset, yy, r.Max.X-inset, yy+1), &image.Uniform{c}, image.Point{}, draw.Src)
	}
}

func badgeColor(badge string) color.NRGBA {
	if badge == "REQ" || badge == "RSP" {
		return colBadgeReq
	}
	switch {
	case strings.HasPrefix(badge, "2"):
		return colBadge2xx
	case strings.HasPrefix(badge, "3"):
		return colBadge3xx
	case strings.HasPrefix(badge, "4"):
		return colBadge4xx
	default:
		return colBadge5xx
	}
}

func drawMosaicBox(dst *image.NRGBA, xEnd, yTop, pad, h int, scale float64) {
	if scale <= 0 {
		scale = 1
	}
	x0 := max(2, xEnd-int(420*scale))
	blk := max(1, int(6*scale))
	for y := yTop; y < yTop+h; y += blk {
		for x := x0; x < xEnd; x += blk {
			if (x/blk+y/blk)%2 == 0 {
				draw.Draw(dst, image.Rect(x, y, min(x+blk, xEnd), min(y+blk, yTop+h)), &image.Uniform{colMuted}, image.Point{}, draw.Src)
			}
		}
	}
}

// truncateToHeight 兜底：极度超长时按高度硬裁（末行留提示由 buildPanel 负责）。
func truncateToHeight(img *image.NRGBA, h int) *image.NRGBA {
	if h <= 0 || img.Bounds().Dy() <= h {
		return img
	}
	out := image.NewNRGBA(image.Rect(0, 0, img.Bounds().Dx(), h))
	draw.Draw(out, out.Bounds(), img, image.Point{}, draw.Src)
	return out
}

func degradeText(s string, cjkOK bool) string {
	if cjkOK {
		return s
	}
	need := false
	for _, r := range s {
		if r > 127 {
			need = true
			break
		}
	}
	if !need {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r > 127 {
			b.WriteByte('?')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ---------- 报文结构小解析（纯函数） ----------

var (
	reReqLine    = regexp.MustCompile(`^([A-Z]+)\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?\s*$`)
	reStatus     = regexp.MustCompile(`^(HTTP/\d(?:\.\d)?)\s+(\d{3})\b`)
	reHostHeader = regexp.MustCompile(`(?im)^\s*host\s*:\s*([^\s\r\n]+)`)
	reProtoVer   = regexp.MustCompile(`HTTP/\d(?:\.\d)?\s+(\d{3})`)
)

var (
	reFirstReq  = regexp.MustCompile(`^([A-Z]+)\s+(\S+)(?:\s+(HTTP/\d(?:\.\d)?))?\s*$`)
	reFirstResp = regexp.MustCompile(`^(HTTP/\d(?:\.\d)?)\s+(\d{3})\s*(.*)$`)
)

// splitFirstLine 把首行拆成「徽标 / 正文 / 协议」三段：
//   GET /path HTTP/1.1        → ("GET", "/path", "HTTP/1.1", false)
//   HTTP/1.1 200 OK           → ("200 OK", "", "HTTP/1.1", true)
// 畸形报文原样进正文，不报错。
func splitFirstLine(packet string) (badge, text, proto string, isResp bool) {
	first := packet
	if i := strings.IndexByte(packet, '\n'); i >= 0 {
		first = packet[:i]
	}
	first = strings.TrimSpace(strings.TrimRight(first, "\r"))
	if m := reFirstResp.FindStringSubmatch(first); m != nil {
		badge = m[2]
		if r := strings.TrimSpace(m[3]); r != "" {
			badge = m[2] + " " + r
		}
		return badge, "", m[1], true
	}
	if m := reFirstReq.FindStringSubmatch(first); m != nil {
		return m[1], m[2], m[3], false
	}
	return "", first, "", false
}

// PacketTitle 提炼首行信息：请求→(METHOD /path, host)；响应→(HTTP/1.1 200 OK)。
func PacketTitle(packet string) (title, host string, isResponse bool) {
	first := packet
	if i := strings.IndexByte(packet, '\n'); i >= 0 {
		first = packet[:i]
	}
	first = strings.TrimSpace(strings.TrimRight(first, "\r"))
	if reStatus.MatchString(first) {
		return first, "", true
	}
	if m := reReqLine.FindStringSubmatch(first); m != nil {
		method, target := m[1], m[2]
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			rest := target
			scheme := "http://"
			if strings.HasPrefix(rest, "https://") {
				scheme = "https://"
			}
			rest = strings.TrimPrefix(rest, scheme)
			if slash := strings.IndexByte(rest, '/'); slash >= 0 {
				host = strings.SplitN(rest[:slash], ":", 2)[0]
				target = rest[slash:]
			} else {
				host = strings.SplitN(rest, ":", 2)[0]
				target = "/"
			}
		}
		title = method + " " + target
	} else {
		title = first
	}
	for _, ln := range strings.Split(packet, "\n") {
		if m := reHostHeader.FindStringSubmatch(ln); m != nil {
			if host == "" {
				host = m[1]
			}
			break
		}
	}
	return title, host, false
}

func statusCodeOf(title string) string {
	if m := reProtoVer.FindStringSubmatch(title); m != nil {
		return m[1]
	}
	return "RSP"
}

var reHdrName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)

func headerLineSplit(line string) (name, value string, found bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 || i > 60 {
		return "", "", false
	}
	name = line[:i]
	if !reHdrName.MatchString(name) {
		return "", "", false
	}
	return name, line[i+1:], true
}

// shouldHideHeader 只按显式清单折叠（ExtraHideHeaders − KeepHeaders）。
// 默认不折叠任何头：报告要完整反映真实请求。
func shouldHideHeader(name string, o Options) bool {
	lname := strings.ToLower(strings.TrimSpace(name))
	for _, k := range o.KeepHeaders {
		if strings.ToLower(strings.TrimSpace(k)) == lname {
			return false
		}
	}
	for _, e := range o.ExtraHideHeaders {
		if strings.ToLower(strings.TrimSpace(e)) == lname {
			return true
		}
	}
	return false
}

func looksJSON(body string) bool {
	t := strings.TrimSpace(body)
	if t == "" {
		return false
	}
	return (strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}")) ||
		(strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]"))
}
