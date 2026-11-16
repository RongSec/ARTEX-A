package db

import (
	"context"
	"sort"
	"testing"
)

// V9-SCOPE：task_foreign_assets 迁移幂等 + 写入幂等。
// 该表是阅读者采纳任务时写入的「外部资产负向清单」，重复 adopt 不能膨胀。

func TestTaskForeignAssetsSchemaIdempotentPG(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	// Open 已应用一次 schema；再显式跑两次，守「跑两次不报错、不重复建对象」。
	for i := 0; i < 2; i++ {
		if _, err := d.Exec(schemaSQL); err != nil {
			t.Fatalf("schema 第 %d 次重放失败: %v", i+2, err)
		}
	}
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM information_schema.tables WHERE table_name='task_foreign_assets'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("task_foreign_assets 应恰好存在一张，got %d", n)
	}
}

func TestTaskForeignAssetsRecordIdempotentPG(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()
	_, taskA := intelTestTask(t, d)
	_, taskB := intelTestTask(t, d)

	// 大小写/重复输入在写入层收敛；同 host 只一行。
	if _, err := d.RecordTaskForeignAssets(ctx, taskA, taskB, []string{"10.0.0.9", "10.0.0.9", " APP.example.com "}); err != nil {
		t.Fatal(err)
	}
	if n, _ := d.CountTaskForeignAssets(ctx, taskA); n != 2 {
		t.Fatalf("首次写入应 2 行，got %d", n)
	}
	// 重复 adopt 同源同 host → 行数不变。
	if _, err := d.RecordTaskForeignAssets(ctx, taskA, taskB, []string{"10.0.0.9"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := d.CountTaskForeignAssets(ctx, taskA); n != 2 {
		t.Fatalf("重复写入不得膨胀，got %d", n)
	}
	hosts, err := d.ForeignHostsForTask(ctx, taskA)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.9", "app.example.com"}
	sort.Strings(want)
	if len(hosts) != len(want) {
		t.Fatalf("hosts=%v want %v", hosts, want)
	}
	for i := range want {
		if hosts[i] != want[i] {
			t.Fatalf("hosts=%v want %v", hosts, want)
		}
	}
	if got, _ := d.ForeignHostsForTaskSource(ctx, taskA, taskB); len(got) != 2 {
		t.Fatalf("按来源查应 2 条，got %v", got)
	}
	// 不同来源可覆盖 source_task_id，但仍然一行。
	_, taskC := intelTestTask(t, d)
	if _, err := d.RecordTaskForeignAssets(ctx, taskA, taskC, []string{"10.0.0.9"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := d.CountTaskForeignAssets(ctx, taskA); n != 2 {
		t.Fatalf("换来源不得新增行，got %d", n)
	}
	if got, _ := d.ForeignHostsForTaskSource(ctx, taskA, taskC); len(got) != 1 || got[0] != "10.0.0.9" {
		t.Fatalf("source 应更新到新任务，got %v", got)
	}
	// 空输入不写。
	if _, err := d.RecordTaskForeignAssets(ctx, taskA, taskC, nil); err != nil {
		t.Fatal(err)
	}
	if n, _ := d.CountTaskForeignAssets(ctx, taskA); n != 2 {
		t.Fatalf("空输入不得改变行数，got %d", n)
	}
}
