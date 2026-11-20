package db

// 验收专用：rev 变更序列。原实现按 id 水位增量，接口行被 ticker 更新
// （purpose/params 变丰富）时阅读者读不到——这是「只增不改」的根因。
// 这里直接验证三件事：新增有 rev、内容不变不 bump、内容变了能重新读到。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestIntelRevLive(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("ARTEX_PG_DSN 未设置")
	}
	pg, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer pg.Close()

	var pid, tid int64
	if err := pg.QueryRow(`
SELECT project_id, id FROM tasks WHERE name LIKE 'V11-VERIFY-T2%' AND deleted_at IS NULL ORDER BY id DESC LIMIT 1`).
		Scan(&pid, &tid); err != nil {
		t.Fatalf("找不到验收任务: %v", err)
	}
	ctx := context.Background()
	key := fmt.Sprintf("/api/rev-test-%d", time.Now().UnixNano())
	mk := func(detail string) TaskIntel {
		return TaskIntel{
			Kind: IntelKindEndpoint, Key: "get " + key, Value: "GET " + key,
			Detail: json.RawMessage(detail), Source: "manual",
		}
	}
	revOf := func() int64 {
		var rev int64
		if err := pg.QueryRow(`SELECT rev FROM task_intel WHERE task_id=$1 AND kind='endpoint' AND key=$2`, tid, "get "+key).Scan(&rev); err != nil {
			t.Fatalf("读 rev: %v", err)
		}
		return rev
	}

	// 1) 新增：rev 必须 > 0。
	res, err := pg.UpsertTaskIntel(ctx, pid, tid, []TaskIntel{mk(`{"purpose":"v1"}`)})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	rev1 := revOf()
	t.Logf("新增: inserted=%d updated=%d unchanged=%d rev=%d", res.Inserted, res.Updated, res.Unchanged, rev1)
	if res.Inserted != 1 || rev1 <= 0 {
		t.Fatalf("新增应 inserted=1 且 rev>0，实际 %+v rev=%d", res, rev1)
	}

	// 2) 同内容再写一次：不 bump rev（否则 ticker 每 5 分钟把全表重推给阅读者）。
	res2, err := pg.UpsertTaskIntel(ctx, pid, tid, []TaskIntel{mk(`{"purpose":"v1"}`)})
	if err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	rev2 := revOf()
	t.Logf("同内容重写: inserted=%d updated=%d unchanged=%d rev=%d", res2.Inserted, res2.Updated, res2.Unchanged, rev2)
	if rev2 != rev1 {
		t.Fatalf("内容未变 rev 不应变：%d → %d", rev1, rev2)
	}
	if res2.Unchanged != 1 {
		t.Fatalf("内容未变应计入 unchanged，实际 %+v", res2)
	}

	// 3) 内容变丰富：必须 bump 且能被 IntelSince 重新读到。
	res3, err := pg.UpsertTaskIntel(ctx, pid, tid, []TaskIntel{mk(`{"purpose":"v2","params":["id"]}`)})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	rev3 := revOf()
	t.Logf("内容变更: inserted=%d updated=%d unchanged=%d rev=%d", res3.Inserted, res3.Updated, res3.Unchanged, rev3)
	if res3.Updated != 1 || rev3 <= rev2 {
		t.Fatalf("内容变更应 updated=1 且 rev 增大，实际 %+v rev=%d", res3, rev3)
	}

	rows, watermark, err := pg.IntelSince(ctx, pid, rev1)
	if err != nil {
		t.Fatalf("IntelSince: %v", err)
	}
	found := false
	for _, r := range rows {
		if r.Kind == IntelKindEndpoint && r.Key == "get "+key && r.Rev == rev3 {
			found = true
		}
	}
	t.Logf("IntelSince(rev>%d): %d 行, watermark=%d, 命中更新行=%v", rev1, len(rows), watermark, found)
	if !found {
		t.Fatal("更新后的行没有被增量读到——「接口细节变丰富比不到」未修复")
	}

	// 收尾：不留下测试行。
	if _, err := pg.ExecContext(ctx, `DELETE FROM task_intel WHERE task_id=$1 AND kind='endpoint' AND key=$2`, tid, "get "+key); err != nil {
		t.Logf("cleanup 失败（不影响结论）: %v", err)
	}
}
