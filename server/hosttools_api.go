package server

// 宿主环境体检的 HTTP 面（V10-HOSTENV）。

import (
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/hosttools"
)

// GET /api/system/host-tools?refresh=1
func (s *Server) hostToolsStatus(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("refresh") == "1"
	writeJSON(w, 200, hosttools.Detect(force))
}

// POST /api/system/host-tools/install {keys: ["nmap", ...]}
//
// 只接受目录里的 key，安装命令由服务端目录决定；前端传不了任意 shell。
func (s *Server) hostToolsInstall(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Keys []string `json:"keys"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	clean := make([]string, 0, len(req.Keys))
	seen := map[string]bool{}
	for _, k := range req.Keys {
		k = strings.TrimSpace(k)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		clean = append(clean, k)
	}
	if len(clean) == 0 {
		writeErr(w, 400, "keys 不能为空")
		return
	}
	if len(clean) > 80 {
		writeErr(w, 400, "一次最多安装 80 件")
		return
	}
	job := hosttools.Install(clean)
	writeJSON(w, http.StatusAccepted, job)
}

// GET /api/system/host-tools/install/{id}
func (s *Server) hostToolsInstallStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job := hosttools.GetJob(id)
	if job == nil {
		writeErr(w, 404, "安装任务不存在")
		return
	}
	writeJSON(w, 200, job)
}
