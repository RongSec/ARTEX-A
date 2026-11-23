package server

// 查询参数数字解析（原在 sync_scopesentry.go，随 ScopeSentry 下线移出，
// 保留给通知等接口使用）。

import (
	"net/http"
	"strconv"
)

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
