package db

// 验收专用：真实库里读 ReaderRefs 的输出，证明「规划者最终看到什么」。
// 只在 ARTEX_PG_DSN 指向验收库时跑；日常测试无 DSN 会 skip。

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

func TestReaderRefsLiveDump(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("ARTEX_PG_DSN 未设置")
	}
	taskID, _ := strconv.ParseInt(os.Getenv("V11_TASK_ID"), 10, 64)
	if taskID <= 0 {
		t.Skip("V11_TASK_ID 未设置")
	}
	pg, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer pg.Close()

	var expID int64
	if err := pg.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1 AND deleted_at IS NULL`, taskID).Scan(&expID); err != nil {
		t.Fatalf("task %d: %v", taskID, err)
	}
	st := pg.Exploration(expID)
	refs, err := st.ReaderRefs(4)
	if err != nil {
		t.Fatalf("ReaderRefs: %v", err)
	}
	b, _ := json.MarshalIndent(refs, "", "  ")
	t.Logf("ReaderRefs(task=%d) =\n%s", taskID, string(b))
}
