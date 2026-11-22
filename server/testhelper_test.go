package server

// 测试用 Server 构造 helper（V12-CLEANUP 从 project_insight_test.go 迁来）。
//
// 原来叫 newInsightTestPG，跟着洞察测试文件一起被删了，但 task_intel_link_test.go
// 等一批测试仍在用它——它跟洞察没关系，只是"给我一个连着测试库的 Server"。
// 单独放一个文件，别再绑在某个业务测试里，免得下次删功能又把它带走。

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// newInsightTestPG 返回一个挂着测试库的 Server 与其 DB 句柄。
// 没有 PG 配置时 t.Skip（照仓库既有的「无库自动 skip」范式）。
func newInsightTestPG(t *testing.T) (*Server, *db.DB) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	return &Server{m: &Manager{pg: pg}}, pg
}
