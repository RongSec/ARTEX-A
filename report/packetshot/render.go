package packetshot

// T22（N3）报文→PNG 自绘渲染器（Burp Suite 式）：纯 Go + x/image，单二进制
// 零外部运行时依赖（选型 A，设计 §3.2——chromium/html2canvas 全放弃）。
//
// 布局：标题栏（请求=method+path / 响应=状态码彩色徽标）→ Headers 区（冗余
// 头按清单折叠）→ Body 区（可选行号；JSON 逐 token 着色 key蓝/串绿/数橙，
// 非 JSON 单色）。等宽字体（gofont gomono）。
//
// 字体策略（team-lead 拍板的 CJK 探测增强，覆盖设计稿"接受方框降级"）：
//   - 探测系统常见 CJK 字体（Windows msyh/simhei/simsun；Linux wqy/noto-cjk
//     路径候选），命中则 ASCII 段走等宽、非 ASCII 段走 CJK face 混排绘制；
//   - 未命中：回退纯 gofont 等宽 + 非 ASCII 字符转写 '?'（degradeText，设计
//     §3.2 已知边界——DejaVu 无中文字形，直画会出空白）；
//   - 探测 sync.Once 缓存（进程一次，不逐图扫盘）；解析失败=等同未命中，
//     全程不 panic、不报错（降级是预期行为）。
//
// 脱敏默认全开（MaskPacket：头值打码+体键值打码）——截图会进报告/分享链路。

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
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

// Options 渲染开关。零值可用（Width=0→980，Scale=0→1，全 bool 关=原文）。
// 默认建议值见 DefaultOptions（脱敏+行号开）。
type Options struct {
	Width            int      // 画布宽 px（默认 980）
	Scale            float64  // 全局缩放（0=1）；字号/行高/边距同乘
	HideHeaders      bool     // 整个 Headers 区不画（标题+Body 直排）
	MaskHeaders      bool     // 头值脱敏（Authorization/Cookie/X-*-Key…）
	Desensitize      bool     // Body 表单/JSON 键值脱敏
	Mosaic           bool     // 形似密钥的值再叠块状马赛克（打码之上再糊）
	LineNumbers      bool     // Body 区画行号
	ExtraHideHeaders []string // 追加折叠的头名（小写不敏感）
	KeepHeaders      []string // 从默认冗余清单豁免的头名
}

// DefaultOptions 任务书默认：宽 980、脱敏全开、行号开、隐藏/马赛克关。
func DefaultOptions() Options {
	return Options{Width: 980, Scale: 1, MaskHeaders: true, Desensitize: true, LineNumbers: true}
}

// 调色板（浅色，近 Burp 报文视图）。
var (
	colBG    = color.NRGBA{255, 255, 255, 255}
	colCard  = color.NRGBA{246, 248, 250, 255}
	colBand  = color.NRGBA{236, 240, 244, 255}
	colBorder = color.NRGBA{208, 215, 222, 255}
	colText  = color.NRGBA{31, 35, 40, 255}
	colMuted = color.NRGBA{110, 119, 129, 255}
	colKey   = color.NRGBA{9, 105, 218, 255}  // JSON key 蓝
	colStr   = color.NRGBA{10, 128, 67, 255}  // 串绿
	colNum   = color.NRGBA{154, 103, 0, 255}  // 数橙
	colLit   = color.NRGBA{130, 80, 223, 255} // 布尔/null 紫
	colHdrName = color.NRGBA{9, 105, 218, 255}
	colWhite = color.NRGBA{255, 255, 255, 255}
)

// 徽标底色（按 method 首字母 / 状态码首位）。
var (
	colBadgeReq    = color.NRGBA{9, 105, 218, 255}
	colBadge2xx    = color.NRGBA{26, 127, 55, 255}
	colBadge3xx    = color.NRGBA{4, 108, 192, 255}
	colBadge4xx    = color.NRGBA{154, 103, 0, 255}
	colBadge5xx    = color.NRGBA{207, 34, 46, 255}
)

// ---------- 字体：CJK 探测（sync.Once）+ 加载 ----------

type fontSet struct {
	mono  *opentype.Font // gofont 等宽（内嵌，恒可得）
	cjk   *opentype.Font // 系统 CJK（探测命中才非 nil）
	cjkOK bool
}

var (
	fontOnce  sync.Once
	fontCache *fontSet
)

// cjkFontCandidates 常见 CJK 字体绝对路径（Windows 盘符 + Linux 发行版常
// 见目录；%WINDIR% 变体在 probe 时再拼）。加载失败逐个跳过=可接受。
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

// cjkProbePaths 显式候选 + %WINDIR% 拼装（任务书点名 Windows 环境变量路径）。
func cjkProbePaths() []string {
	out := append([]string(nil), cjkFontCandidates...)
	if wd := strings.TrimSpace(os.Getenv("WINDIR")); wd != "" {
		for _, f := range []string{"msyh.ttc", "simhei.ttf", "simsun.ttc"} {
			out = append(out, filepath.Join(wd, "Fonts", f))
		}
	}
	return out
}

// loadFonts 探测一次缓存。ttc 是字体集合→ParseCollection 取第 0 个（雅黑/
// 思源中黑首选族）；单 ttf→Parse。任何失败都只影响 cjk 字段（=降级路径）。
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

// face 按磅号实例化 face；字体不可用返回 nil（调用方处理）。
func faceOf(f *opentype.Font, size float64) font.Face {
	if f != nil {
		if ff, err := opentype.NewFace(f, &opentype.FaceOptions{Size: size, DPI: 72, Hinting: font.HintingFull}); err == nil {
			return ff
		}
	}
	return nil
}

// ---------- 行模型（layout 与 draw 共享） ----------

type rowKind int8

const (
	rowTitle rowKind = iota // 带徽标的标题行
	rowText                 // 普通文本（头行=name 蓝 + value 黑）
	rowMuted                // 区段标签/提示（灰）
	rowJSON                 // Body JSON 着色行（可带行号）
	rowCode                 // Body 非 JSON 行（可带行号）
)

type panelRow struct {
	kind    rowKind
	name    string // 头行的 Name（rowText 且有值时着色区分）
	text    string // 主体文本（rowText=value 段 / rowJSON|Code=行内容）
	num     int    // 行号（>0 才画）
	mosaic  bool   // 尾部叠马赛克（Mosaic 命中）
}

// ---------- 排版 + 绘制主流程 ----------

// Render 把一段报文（请求或响应原文；两者都给=请求在上、响应在下两面板）渲染
// 成 PNG 字节。脱敏先于排版（截图安全底线）；空输入报错。
func Render(req, resp string, opt Options) ([]byte, error) {
	s := opt.Scale
	if s <= 0 {
		s = 1
	}
	width := opt.Width
	if width < 420 {
		width = 980
	}

	var panels [][]panelRow
	if strings.TrimSpace(req) != "" {
		panels = append(panels, buildPanel(req, opt))
	}
	if strings.TrimSpace(resp) != "" {
		panels = append(panels, buildPanel(resp, opt))
	}
	if len(panels) == 0 {
		return nil, fmt.Errorf("packetshot: 空报文")
	}

	fs := loadFonts()
	monoFace := faceOf(fs.mono, 12.0*s)
	defer monoFace.Close()
	cjkFace := font.Face(nil)
	if fs.cjkOK {
		cjkFace = faceOf(fs.cjk, 13.0*s)
		defer cjkFace.Close()
	}

	lineH := int(monoFace.Metrics().Height.Ceil()) + int(3*s)
	titleH := lineH + int(10*s)
	pad := int(10 * s)
	gap := int(14 * s)

	total := pad + gap*(len(panels)-1)
	for _, rows := range panels {
		total += titleH + len(rows)*lineH + pad*2
	}

	img := image.NewNRGBA(image.Rect(0, 0, width, total))
	draw.Draw(img, img.Bounds(), &image.Uniform{colBG}, image.Point{}, draw.Src)

	y := pad
	asc := int(monoFace.Metrics().Ascent.Ceil())
	for _, rows := range panels {
		h := titleH + len(rows)*lineH + pad*2
		// 卡片底 + 边框。
		draw.Draw(img, image.Rect(0, y, width, y+h), &image.Uniform{colCard}, image.Point{}, draw.Src)
		strokeRect(img, image.Rect(0, y, width-1, y+h-1), colBorder)
		// 标题带。
		draw.Draw(img, image.Rect(1, y+1, width-1, y+titleH), &image.Uniform{colBand}, image.Point{}, draw.Src)

		ty := y + pad + asc
		for _, r := range rows {
			x := pad
			switch r.kind {
			case rowTitle:
				badge := r.name // REQ / 2xx 等
				bg := badgeColor(badge)
				bw := textWidth(monoFace, badge) + int(10*s)
				draw.Draw(img, image.Rect(x, ty-asc-int(2*s), x+bw, ty+int(3*s)), &image.Uniform{bg}, image.Point{}, draw.Src)
				drawString(img, badge, x+int(5*s), ty, colWhite, monoFace)
				x += bw + int(8*s)
				drawString(img, r.text, x, ty, colText, monoFace)
			case rowMuted:
				drawString(img, r.text, x, ty, colMuted, monoFace)
			case rowText:
				if r.name != "" {
					nw := textWidth(monoFace, r.name)
					drawString(img, r.name, x, ty, colHdrName, monoFace)
					x += nw
				}
				x = drawMixed(img, r.text, x, ty, colText, monoFace, cjkFace, fs.cjkOK)
				if r.mosaic {
					drawMosaicBox(img, x, ty-asc, pad, int(monoFace.Metrics().Height.Ceil()))
				}
			case rowJSON:
				if r.num > 0 {
					nstr := fmt.Sprintf("%4d ", r.num)
					drawString(img, nstr, x, ty, colMuted, monoFace)
					x += textWidth(monoFace, nstr)
				}
				for _, t := range tokenizeJSONLine(r.text) {
					c := colText
					switch t.kind {
					case tokKey:
						c = colKey
					case tokString:
						c = colStr
					case tokNumber:
						c = colNum
					case tokLit:
						c = colLit
					}
					x = drawMixed(img, t.text, x, ty, c, monoFace, cjkFace, fs.cjkOK)
				}
				if r.mosaic {
					drawMosaicBox(img, x, ty-asc, pad, int(monoFace.Metrics().Height.Ceil()))
				}
			case rowCode:
				if r.num > 0 {
					nstr := fmt.Sprintf("%4d ", r.num)
					drawString(img, nstr, x, ty, colMuted, monoFace)
					x += textWidth(monoFace, nstr)
				}
				x = drawMixed(img, r.text, x, ty, colText, monoFace, cjkFace, fs.cjkOK)
				if r.mosaic {
					drawMosaicBox(img, x, ty-asc, pad, int(monoFace.Metrics().Height.Ceil()))
				}
			}
			ty += lineH
		}
		y += h + gap
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildPanel 一段报文 → 行序列（脱敏管线在此）。
func buildPanel(packet string, o Options) []panelRow {
	rows := []panelRow{}
	title, host, isResp := PacketTitle(packet)
	badge := "REQ"
	if isResp {
		badge = statusCodeOf(title)
	}
	titleText := title
	if !isResp && host != "" && !strings.HasPrefix(strings.ToLower(title), strings.ToLower(host)) {
		titleText = title + " — " + host
	}
	rows = append(rows, panelRow{kind: rowTitle, name: badge, text: titleText})

	lines := strings.Split(strings.ReplaceAll(packet, "\r\n", "\n"), "\n")
	// 空行前=头区（第 0 行是请求/状态行，已进标题）。
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
		// 脱敏：MaskHeaders 开 → 逐头行打码；关 → 原文。
		hidden := 0
		for _, ln := range headerLines {
			if strings.TrimSpace(ln) == "" {
				continue
			}
			name, val, ok := headerLineSplit(ln)
			if ok {
				if shouldHideHeader(name, o) {
					hidden++
					continue
				}
				if o.MaskHeaders {
					val = MaskHeaderLine(name + ":" + val)
					if i := strings.Index(val, ":"); i >= 0 {
						val = val[i+1:]
					}
				}
				rows = append(rows, panelRow{
					kind: rowText, name: name + ":", text: strings.TrimLeft(val, " "),
					mosaic: o.Mosaic && ShouldMosaic(val),
				})
			} else {
				rows = append(rows, panelRow{kind: rowText, text: ln})
			}
		}
		if hidden > 0 {
			rows = append(rows, panelRow{kind: rowMuted, text: fmt.Sprintf("（%d 个冗余头已折叠）", hidden)})
		}
	}

	// Body（Desensitize 控制键值打码）。
	if bodyStart >= 0 && bodyStart < len(lines) {
		body := lines[bodyStart:]
		bodyText := strings.Join(body, "\n")
		if strings.TrimSpace(bodyText) != "" {
			if o.Desensitize {
				bodyText = MaskBodySecrets(bodyText)
				body = strings.Split(bodyText, "\n")
			}
			isJSON := looksJSON(bodyText)
			maxLines := 120
			for i, ln := range body {
				if i >= maxLines {
					rows = append(rows, panelRow{kind: rowMuted, text: fmt.Sprintf("……（共 %d 行，超出已截断）", len(body))})
					break
				}
				kind := rowCode
				if isJSON {
					kind = rowJSON
				}
				rows = append(rows, panelRow{
					kind: kind, num: i + 1, text: ln,
					mosaic: o.Mosaic && ShouldMosaic(ln),
				})
			}
		}
	}
	return rows
}

// ---------- 绘制小工具 ----------

// drawMixed 混排：ASCII 段走等宽 face，非 ASCII 段走 CJK face；未探测到
// CJK（cjkOK=false）时整段 degradeText→'?' 后走等宽。返回推进后的 x。
func drawMixed(dst *image.NRGBA, s string, x, baselineY int, c color.Color, mono, cjk font.Face, cjkOK bool) int {
	if s == "" {
		return x
	}
	if !cjkOK || cjk == nil {
		drawString(dst, degradeText(s, false), x, baselineY, c, mono)
		return x + textWidth(mono, degradeText(s, false))
	}
	// 按 ASCII/非 ASCII 分段。
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

func drawString(dst *image.NRGBA, s string, x, baselineY int, c color.Color, f font.Face) {
	if s == "" {
		return
	}
	d := &font.Drawer{Dst: dst, Src: image.NewUniform(c), Face: f, Dot: fixed.P(x, baselineY)}
	d.DrawString(s)
}

func textWidth(f font.Face, s string) int {
	if s == "" {
		return 0
	}
	return int(font.MeasureString(f, s).Round())
}

func badgeColor(badge string) color.NRGBA {
	if badge == "REQ" {
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

// drawMosaicBox 在 (x0,y0) 起画 6px 交替块遮罩（宽度=后续未画区，此处
// 覆盖到 pad 宽即可——调用点在文本画完后，x 已是文本尾，矩形取文本右侧
// 一小段与行高；简化：从 x 往左回盖整行的做法更稳——取 x-420..x 区间）。
func drawMosaicBox(dst *image.NRGBA, xEnd, yTop, pad, h int) {
	x0 := max(2, xEnd-420)
	const blk = 6
	for y := yTop; y < yTop+h; y += blk {
		for x := x0; x < xEnd; x += blk {
			if (x/blk+y/blk)%2 == 0 {
				draw.Draw(dst, image.Rect(x, y, min(x+blk, xEnd), min(y+blk, yTop+h)), &image.Uniform{colMuted}, image.Point{}, draw.Src)
			}
		}
	}
}

func strokeRect(dst *image.NRGBA, r image.Rectangle, c color.Color) {
	for x := r.Min.X; x < r.Max.X; x++ {
		dst.Set(x, r.Min.Y, c)
		dst.Set(x, r.Max.Y-1, c)
	}
	for y := r.Min.Y; y < r.Max.Y; y++ {
		dst.Set(r.Min.X, y, c)
		dst.Set(r.Max.X-1, y, c)
	}
}

// degradeText CJK 未命中时非 ASCII→'?'（保结构可读）。cjkOK=true 原样。
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

// ---------- 报文结构小解析（纯函数，单测覆盖） ----------

var (
	reReqLine    = regexp.MustCompile(`^([A-Z]+)\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?\s*$`)
	reStatus     = regexp.MustCompile(`^(HTTP/\d(?:\.\d)?)\s+(\d{3})\b`)
	reHostHeader = regexp.MustCompile(`(?im)^\s*host\s*:\s*([^\s\r\n]+)`)
	reProtoVer   = regexp.MustCompile(`HTTP/\d(?:\.\d)?\s+(\d{3})`)
)

// PacketTitle 提炼标题栏信息：请求→(METHOD /path, host, false)；响应→
// (HTTP/1.1 200 OK, "", true)。绝对形式 URL（GET http://h/p）剥出 host+path。
// host 取 Host 头兜底。全假数据/畸形报文：原样首行，不报错。
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

// statusCodeOf 响应标题里的三位状态码；没有给 "RSP"。
func statusCodeOf(title string) string {
	if m := reProtoVer.FindStringSubmatch(title); m != nil {
		return m[1]
	}
	return "RSP"
}

// headerLineSplit 安全地拆 "Name: value"。Name 限可见字符且 ≤60，防把
// JSON 体里的 "key":"v" 误当头。
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

// shouldHideHeader 默认冗余清单 + Extra − Keep（大小写不敏感）。
func shouldHideHeader(name string, o Options) bool {
	lname := strings.ToLower(strings.TrimSpace(name))
	for _, k := range o.KeepHeaders {
		if strings.ToLower(strings.TrimSpace(k)) == lname {
			return false
		}
	}
	for _, d := range defaultRedundantReq {
		if d == lname {
			return true
		}
	}
	for _, e := range o.ExtraHideHeaders {
		if strings.ToLower(strings.TrimSpace(e)) == lname {
			return true
		}
	}
	return false
}

// looksJSON Body 粗判（首尾括号）。
func looksJSON(body string) bool {
	t := strings.TrimSpace(body)
	if t == "" {
		return false
	}
	return (strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}")) ||
		(strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]"))
}
