package db

// 验收专用：下钻数据通路（检索 → 取节点 → 取执行过程 → 审计落库）。
// 阅读者判案阶段不调 ask_reader（它就是被问的一方），下钻由 worker/planner 发起；
// 这里直接验证 ask_reader 依赖的三个 DB 原语，避免验收环境里的任务处于 paused
// 而拿不到真实下钻样本。

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestReaderDrillLiveDump(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("ARTEX_PG_DSN 未设置")
	}
	taskID, _ := strconv.ParseInt(os.Getenv("V11_TASK_ID"), 10, 64)
	relatedID, _ := strconv.ParseInt(os.Getenv("V11_RELATED_ID"), 10, 64)
	if taskID <= 0 || relatedID <= 0 {
		t.Skip("V11_TASK_ID / V11_RELATED_ID 未设置")
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

	// 1) 关键词检索：worker 的 ask_reader(query=...) 走这条。
	nodes, err := st.ReaderSearchNodes(relatedID, "/api/sso/userinfo", 8)
	if err != nil {
		t.Fatalf("ReaderSearchNodes: %v", err)
	}
	t.Logf("ReaderSearchNodes(/api/sso/userinfo) → %d 条", len(nodes))
	for _, n := range nodes {
		t.Logf("  #%d %s %s | %s", n.ID, n.Kind, n.State, n.Summary)
	}
	if len(nodes) == 0 {
		t.Fatalf("检索为空：下钻会退化成「给一堆 id 自己挑」")
	}

	// 2) 按 id 取节点正文（脱敏前）。
	target := nodes[0].ID
	n, err := st.ReaderTaskNode(relatedID, target)
	if err != nil || n == nil {
		t.Fatalf("ReaderTaskNode(%d): node=%v err=%v", target, n, err)
	}
	t.Logf("ReaderTaskNode(%d) kind=%s state=%s payload=%d bytes", n.ID, n.Kind, n.State, len(n.Payload))

	// 3) intent 的执行过程（activity）。
	intents, err := st.ReaderTaskLastIntents(relatedID, 5)
	if err != nil {
		t.Fatalf("ReaderTaskLastIntents: %v", err)
	}
	for _, in := range intents {
		steps, _ := st.ReaderTaskTrace(relatedID, in.ID, 10)
		t.Logf("intent #%d %q → %d 步", in.ID, in.Summary, len(steps))
		for i, s := range steps {
			if i >= 3 {
				break
			}
			t.Logf("    %s · %s", s.Tool, s.Summary)
		}
	}

	// 4) 审计落库：每次 ask_reader 都会写一行。
	drill := ReaderDrill{
		TaskID: taskID, RelatedTaskID: relatedID, IntentID: 0,
		NodeIDs: []int64{target}, Query: "/api/sso/userinfo", Mode: "detail", ItemCount: len(nodes),
	}
	if err := st.RecordReaderDrill(context.Background(), drill); err != nil {
		t.Fatalf("RecordReaderDrill: %v", err)
	}
	rows, err := pg.ListReaderDrills(context.Background(), taskID)
	if err != nil {
		t.Fatalf("ListReaderDrills: %v", err)
	}
	t.Logf("reader_drills 行数=%d", len(rows))
	if len(rows) == 0 {
		t.Fatal("下钻审计未落库")
	}
	last := rows[0]
	t.Logf("最新一条: task=%d related=%d nodes=%v query=%q mode=%s items=%d at=%s",
		last.TaskID, last.RelatedTaskID, last.NodeIDs, last.Query, last.Mode, last.ItemCount,
		last.CreatedAt.Format(time.RFC3339))
}
