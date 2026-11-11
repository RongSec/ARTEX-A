package server

// T16(3/3) 发现证据截图 API：上传/列表/删除 + 静态服务。
//
//   POST   /api/findings/{id}/evidence        multipart "file" + step_index/caption/sort_order
//   GET    /api/findings/{id}/evidence        列表（detail 页步骤卡片/报告注入用）
//   DELETE /api/findings/{id}/evidence/{eid}  删行 + 删文件
//   GET    /api/findings/{id}/evidence/{eid}  原图字节流（<img> 用；cookie/…token= 过 JWT）
//
// 存储：data/report_assets/evidence/<finding_id>/<纳秒>-<安全名>；表里只存相对
// dataDir 路径。{id} 恒为 findings 表 id（与 detail 页句柄、finding_traffic_*
// 兄弟路由同口径，见 schema §Q 注释）。图片类型白名单=扩展名+Content-Type 双卡。

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// maxEvidenceImageBytes 单张证据图上限（截图用途，8MB 足够宽）。
const maxEvidenceImageBytes = 8 << 20

// evidenceImageExts 白名单扩展名（小写含点）。svg 不收：可内嵌脚本，XSS 面。
var evidenceImageExts = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".bmp": true}

// evidenceImageCTypes 白名单 Content-Type（与扩展名双卡）。
var evidenceImageCTypes = map[string]bool{
	"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true, "image/bmp": true, "application/octet-stream": true, // 浏览器偶发缺省类型，以扩展名卡为准
}

// evidenceImageAccess 解析 {id}（findings 表 id）并校验存在；错误已写回。
func (s *Server) evidenceImageAccess(w http.ResponseWriter, r *http.Request) (int64, bool) {
	if !s.pgReportDBGuard(w) {
		return 0, false
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "非法发现 id")
		return 0, false
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, "读取发现失败: "+err.Error())
		return 0, false
	}
	if f == nil {
		writeErr(w, 404, "发现不存在")
		return 0, false
	}
	return id, true
}

func evidenceImageDTO(e db.FindingEvidenceImage) map[string]any {
	src := e.Source
	if src == "" {
		src = db.EvidenceSourceUpload // 历史行/缺省归 upload
	}
	return map[string]any{
		"id":         e.ID,
		"step_index": e.StepIndex,
		"caption":    e.Caption,
		"sort_order": e.SortOrder,
		"source":     src, // T22：auto/paste/upload（前端角标与覆盖判定用）
		"url":        fmt.Sprintf("/api/findings/%d/evidence/%d", e.FindingID, e.ID),
		"created_at": e.CreatedAt,
	}
}

// POST /api/findings/{id}/evidence — multipart 上传一张证据图。
// 表单字段：file（必填）、step_index（默认 0）、caption、sort_order（默认取
// 同步骤现有最大 +10，留插入空隙）。
func (s *Server) findingEvidenceUpload(w http.ResponseWriter, r *http.Request) {
	fid, ok := s.evidenceImageAccess(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxEvidenceImageBytes+1<<20)
	if err := r.ParseMultipartForm(maxEvidenceImageBytes); err != nil {
		writeErr(w, 400, "解析上传失败或超出大小限制: "+err.Error())
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	src, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, 400, "缺少上传文件(表单字段 file)")
		return
	}
	defer src.Close()

	name := filepath.Base(hdr.Filename) // 剥路径成分
	ext := strings.ToLower(filepath.Ext(name))
	if !evidenceImageExts[ext] {
		writeErr(w, 400, "仅支持 png/jpg/jpeg/gif/webp/bmp 图片")
		return
	}
	if ctype := hdr.Header.Get("Content-Type"); ctype != "" && !evidenceImageCTypes[ctype] {
		writeErr(w, 400, "文件类型不是图片: "+ctype)
		return
	}

	stepIndex, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("step_index")))
	if stepIndex < 0 {
		stepIndex = 0
	}
	caption := strings.TrimSpace(r.FormValue("caption"))
	sortOrder := 0
	if v := strings.TrimSpace(r.FormValue("sort_order")); v != "" {
		sortOrder, _ = strconv.Atoi(v)
	}

	// 相对路径 = report_assets/evidence/<fid>/<纳秒>-<安全名>；纳秒前缀防撞名，
	// 安全名只保留 [A-Za-z0-9._-]（中文/空格替换下划线，仅人眼参考用）。
	rel := filepath.Join("report_assets", "evidence", strconv.FormatInt(fid, 10),
		evidenceStoredName(name, ext, time.Now().UnixNano()))
	abs := filepath.Join(s.m.dir, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		writeErr(w, 500, "创建目录失败")
		return
	}
	f, err := os.Create(abs)
	if err != nil {
		writeErr(w, 500, "写入失败")
		return
	}
	n, err := io.Copy(f, io.LimitReader(src, maxEvidenceImageBytes))
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(abs)
		writeErr(w, 500, "保存失败")
		return
	}
	if n == 0 {
		_ = os.Remove(abs)
		writeErr(w, 400, "空文件")
		return
	}

	// sort_order 缺省 = 同步骤最大值 +10（新图排最后，且预留中间插入位）。
	if r.FormValue("sort_order") == "" {
		if list, err := s.m.pg.ListFindingEvidenceImages(fid); err == nil {
			for _, e := range list {
				if e.StepIndex == stepIndex && e.SortOrder >= sortOrder {
					sortOrder = e.SortOrder + 10
				}
			}
		}
	}

	img, err := s.m.pg.AddFindingEvidenceImage(fid, stepIndex, filepath.ToSlash(rel), caption, sortOrder)
	if err != nil {
		_ = os.Remove(abs)
		writeErr(w, 500, "入库失败: "+err.Error())
		return
	}
	writeJSON(w, 200, evidenceImageDTO(*img))
}

// GET /api/findings/{id}/evidence — 列表（不分页：单漏洞证据量级 <20）。
func (s *Server) findingEvidenceList(w http.ResponseWriter, r *http.Request) {
	fid, ok := s.evidenceImageAccess(w, r)
	if !ok {
		return
	}
	list, err := s.m.pg.ListFindingEvidenceImages(fid)
	if err != nil {
		writeErr(w, 500, "读取失败: "+err.Error())
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		out = append(out, evidenceImageDTO(e))
	}
	writeJSON(w, 200, out)
}

// DELETE /api/findings/{id}/evidence/{eid} — 删行 + 尽力删文件。
func (s *Server) findingEvidenceDelete(w http.ResponseWriter, r *http.Request) {
	fid, ok := s.evidenceImageAccess(w, r)
	if !ok {
		return
	}
	eid, err := strconv.ParseInt(r.PathValue("eid"), 10, 64)
	if err != nil || eid <= 0 {
		writeErr(w, 400, "非法证据 id")
		return
	}
	filename, deleted, err := s.m.pg.DeleteFindingEvidenceImage(eid, fid)
	if err != nil {
		writeErr(w, 500, "删除失败: "+err.Error())
		return
	}
	if !deleted {
		writeErr(w, 404, "证据不存在")
		return
	}
	if filename != "" {
		// 只删记录内的相对路径（ToSlash 兼容历史行），绝不用请求参数拼路径。
		_ = os.Remove(filepath.Join(s.m.dir, filepath.FromSlash(filename)))
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/findings/{id}/evidence/{eid} — 原图字节流。<img> 同源自动带
// artex_token cookie 过 requireAuth；亦支持 ?token=（auth.go extractToken 原生）。
func (s *Server) findingEvidenceServe(w http.ResponseWriter, r *http.Request) {
	fid, ok := s.evidenceImageAccess(w, r)
	if !ok {
		return
	}
	eid, err := strconv.ParseInt(r.PathValue("eid"), 10, 64)
	if err != nil || eid <= 0 {
		writeErr(w, 400, "非法证据 id")
		return
	}
	img, err := s.m.pg.GetFindingEvidenceImage(eid, fid)
	if err != nil {
		writeErr(w, 500, "读取失败: "+err.Error())
		return
	}
	if img == nil {
		writeErr(w, 404, "证据不存在")
		return
	}
	// filename 是入库时生成的相对路径；防御性校验 = 必须是可解析到 dataDir 内
	// 部的局部路径（无 .. 段/非绝对/无卷符）且扩展名在白名单。表内恒 slash 形。
	relSlash := filepath.ToSlash(img.Filename)
	if !filepath.IsLocal(relSlash) || relSlash == "" {
		writeErr(w, 404, "证据文件不可用")
		return
	}
	if !evidenceImageExts[strings.ToLower(filepath.Ext(relSlash))] {
		writeErr(w, 404, "证据文件不可用")
		return
	}
	abs := filepath.Join(s.m.dir, filepath.FromSlash(relSlash))
	if _, err := os.Stat(abs); err != nil {
		writeErr(w, 404, "证据文件已不存在")
		return
	}
	w.Header().Set("Content-Type", contentTypeForImage(relSlash))
	w.Header().Set("Cache-Control", "private, max-age=3600")
	http.ServeFile(w, r, abs)
}

// evidenceStoredName 生成 <纳秒>-<安全名><ext>：安全名只保留 [A-Za-z0-9._-]，
// 其余（中文/空格/路径残留）替换下划线，纯参考用途、防撞名靠纳秒前缀。
func evidenceStoredName(orig, ext string, nano int64) string {
	stem := strings.TrimSuffix(orig, filepath.Ext(orig))
	safe := make([]rune, 0, len(stem))
	for _, ru := range stem {
		if ru >= 'a' && ru <= 'z' || ru >= 'A' && ru <= 'Z' || ru >= '0' && ru <= '9' || ru == '.' || ru == '_' || ru == '-' {
			safe = append(safe, ru)
		} else {
			safe = append(safe, '_')
		}
	}
	return fmt.Sprintf("%d-%s%s", nano, string(safe), ext)
}

func contentTypeForImage(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".bmp":
		return "image/bmp"
	default:
		return "application/octet-stream"
	}
}
