package server

// V9-UI：内置规则只读目录。
//
//	GET /api/intercept/builtin-rules
//
// 规则名称/说明/动作全部来自 guard 包的代码常量（guard.BuiltinRules），前端
// 不写字面量：页面展示的条目与审计链里的 RuleName 是同一份定义。
// 这些规则不受 DB 规则表与判官影响，也没有运行期开关，所以本接口只读。

import (
	"net/http"

	"github.com/Autumn-27/artex/guard"
)

// interceptBuiltinRules 返回代码内置规则清单，供拦截规则页只读展示。
func (s *Server) interceptBuiltinRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"rules": guard.BuiltinRules()})
}
