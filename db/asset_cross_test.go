package db

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"
)

// 行组装/排序/截断/可见集裁剪是纯逻辑，无需数据库。
func TestAssembleCrossProjectAssets(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	raw := []crossProjectAssetRaw{
		{asset: assetRow{id: 1, kind: "ip", ip: "10.0.0.1"}, projectIDs: []int64{7, 3}, findingCount: 4, lastFoundAt: now.Add(-time.Hour)},
		{asset: assetRow{id: 2, kind: "subdomain", domain: "a.example.com"}, projectIDs: []int64{5, 9}, findingCount: 1, lastFoundAt: now},
		{asset: assetRow{id: 3, kind: "app", appName: "canal"}, projectIDs: []int64{1, 2, 3}, findingCount: 2, lastFoundAt: now.Add(-2 * time.Hour)},
		// 单项目行：必须被丢弃（不是跨项目信号）
		{asset: assetRow{id: 4, kind: "ip", ip: "10.0.0.2"}, projectIDs: []int64{4}, findingCount: 9, lastFoundAt: now},
		// 重复项目 id：去重后只剩 1 个项目 → 丢弃
		{asset: assetRow{id: 5, kind: "ip", ip: "10.0.0.3"}, projectIDs: []int64{8, 8}, findingCount: 2, lastFoundAt: now},
	}
	names := map[int64]string{1: "P-one", 2: "P-two", 3: "P-three", 7: "P-seven"}

	got := assembleCrossProjectAssets(raw, names, 20)
	if len(got) != 3 {
		t.Fatalf("应保留 3 行跨项目资产，得到 %d 行: %+v", len(got), got)
	}
	// 排序：项目数 desc（3 项目的资产 id=3 在前），项目数相同按最近出现 desc（id=2 晚于 id=1）。
	if got[0].AssetID != 3 || got[1].AssetID != 2 || got[2].AssetID != 1 {
		t.Fatalf("排序错误，期望 [3 2 1]，得到 [%d %d %d]", got[0].AssetID, got[1].AssetID, got[2].AssetID)
	}
	if got[0].ProjectCount != 3 || got[0].Label != "canal" {
		t.Fatalf("首行应为 canal/3 项目，得到 %+v", got[0])
	}
	// 项目按 id 升序；取不到名字回落 project#<id>（不丢行）。
	if len(got[0].Projects) != 3 || got[0].Projects[0].ID != 1 || got[0].Projects[2].ID != 3 {
		t.Fatalf("项目列表应按 id 升序，得到 %+v", got[0].Projects)
	}
	if got[0].Projects[0].Name != "P-one" || got[0].Projects[2].Name != "P-three" {
		t.Fatalf("项目名组装错误：%+v", got[0].Projects)
	}
	last := got[2]
	if last.Projects[0].ID != 3 || last.Projects[0].Name != "P-three" {
		t.Fatalf("项目名回落/排序错误：%+v", last.Projects)
	}
	if last.Projects[1].ID != 7 || last.Projects[1].Name != "P-seven" {
		t.Fatalf("命名错误：%+v", last.Projects)
	}
	if last.Label != "10.0.0.1" || last.FindingCount != 4 {
		t.Fatalf("标签/发现数错误：%+v", last)
	}

	// 截断
	if short := assembleCrossProjectAssets(raw, names, 1); len(short) != 1 || short[0].AssetID != 3 {
		t.Fatalf("limit=1 应只留项目数最多的那一行，得到 %+v", short)
	}
	// limit<=0 回落默认值
	if d := assembleCrossProjectAssets(raw, nil, 0); len(d) != 3 {
		t.Fatalf("limit<=0 应回落默认上限（不截断这 3 行），得到 %d 行", len(d))
	}
}

// 项目名缺失时回落 project#<id>（取证：项目被删也不该让 reader 少一行信号）。
func TestAssembleCrossProjectAssetsMissingName(t *testing.T) {
	raw := []crossProjectAssetRaw{{asset: assetRow{id: 9, kind: "ip", ip: "10.9.9.9"}, projectIDs: []int64{11, 12}, findingCount: 1}}
	got := assembleCrossProjectAssets(raw, map[int64]string{}, 20)
	if len(got) != 1 {
		t.Fatalf("应保留 1 行，得到 %d", len(got))
	}
	if got[0].Projects[0].Name != "project#11" || got[0].Projects[1].Name != "project#12" {
		t.Fatalf("缺名回落错误：%+v", got[0].Projects)
	}
}

// reader_enabled 可见集裁剪：未开闸项目必须从行里剔除；剔到只剩 1 个项目
// 的行整体丢弃（否则等于绕过项目级 opt-in）。
func TestFilterCrossProjectAssetsByProjects(t *testing.T) {
	rows := []CrossProjectAssetRow{
		{AssetID: 1, ProjectCount: 3, Projects: []CrossProjectAssetProject{{ID: 1, Name: "A"}, {ID: 2, Name: "B"}, {ID: 3, Name: "C"}}},
		{AssetID: 2, ProjectCount: 2, Projects: []CrossProjectAssetProject{{ID: 1, Name: "A"}, {ID: 3, Name: "C"}}},
	}
	got := FilterCrossProjectAssetsByProjects(rows, map[int64]bool{1: true, 2: true})
	if len(got) != 1 {
		t.Fatalf("只应保留仍有 2 个项目可见的行，得到 %d 行: %+v", len(got), got)
	}
	if got[0].AssetID != 1 || got[0].ProjectCount != 2 || len(got[0].Projects) != 2 {
		t.Fatalf("裁剪结果错误：%+v", got[0])
	}
	for _, p := range got[0].Projects {
		if p.ID == 3 {
			t.Fatalf("未开启 reader_enabled 的项目 3 不应出现在行里：%+v", got[0].Projects)
		}
	}
	// 空可见集 → 全空；nil 输入原样返回。
	if out := FilterCrossProjectAssetsByProjects(rows, map[int64]bool{}); len(out) != 0 {
		t.Fatalf("空可见集应返回空，得到 %+v", out)
	}
	if out := FilterCrossProjectAssetsByProjects(nil, map[int64]bool{1: true}); len(out) != 0 {
		t.Fatalf("nil 输入应返回空，得到 %+v", out)
	}
}

// PG 集成测（无库自动 skip，照仓库 pg skip 范式）：验证真实关联链
// findings.asset_ids → tasks.project_id → assets 的聚合口径。
func TestCrossProjectAssetRows(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	// 唯一后缀，避免撞上共享开发库里的历史资产（ip 有唯一索引）。
	n := time.Now().UnixNano()
	sharedIP := fmt.Sprintf("10.99.%d.%d", n%256, (n/256)%256)
	onlyAIP := fmt.Sprintf("10.98.%d.%d", n%256, (n/256)%256)
	suffix := strconv.FormatInt(n%1000000, 10)

	projA, err := d.CreateProject(CreateProjectInput{Name: "cross-a-" + suffix, ReaderEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	projB, err := d.CreateProject(CreateProjectInput{Name: "cross-b-" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	pidA, pidB := projA.ID, projB.ID
	taskA, err := d.CreateTaskWithOptions("cross a", "goal", TaskCreateOptions{ProjectID: &pidA})
	if err != nil {
		t.Fatal(err)
	}
	taskB, err := d.CreateTaskWithOptions("cross b", "goal", TaskCreateOptions{ProjectID: &pidB})
	if err != nil {
		t.Fatal(err)
	}
	sharedID := seedTreeAsset(t, d, "ip", map[string]any{"ip": sharedIP})
	onlyAID := seedTreeAsset(t, d, "ip", map[string]any{"ip": onlyAIP})

	// 清理顺序：先删发现/任务，再删资产/项目（defer 注册，早于 d.Close 执行）。
	defer func() {
		_, _ = d.DeleteTaskCascade(taskA.ID, false, true)
		_, _ = d.DeleteTaskCascade(taskB.ID, false, true)
		_, _ = d.Exec(`DELETE FROM assets WHERE id = ANY($1::bigint[])`, marshalInt64Array([]int64{sharedID, onlyAID}))
		_ = d.DeleteProject(pidA)
		_ = d.DeleteProject(pidB)
	}()

	// A 项目 2 条发现（共享资产 + 独有资产），B 项目 1 条（共享资产）。
	if _, err := d.AddFinding(taskA.ID, 0, "rce", "A1", "high", "s", "e", "w", []int64{sharedID, onlyAID}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddFinding(taskA.ID, 0, "rce", "A2", "high", "s", "e", "w", []int64{sharedID}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddFinding(taskB.ID, 0, "sqli", "B1", "medium", "s", "e", "w", []int64{sharedID}); err != nil {
		t.Fatal(err)
	}

	rows, err := d.CrossProjectAssetRows(context.Background(), 0)
	if err != nil {
		t.Fatalf("CrossProjectAssetRows: %v", err)
	}
	var hit *CrossProjectAssetRow
	for i := range rows {
		if rows[i].AssetID == sharedID {
			hit = &rows[i]
		}
		if rows[i].AssetID == onlyAID {
			t.Fatalf("单项目资产不应出现在跨项目聚合里：%+v", rows[i])
		}
	}
	if hit == nil {
		t.Fatalf("共享资产 %d 未出现在跨项目聚合里（共 %d 行）", sharedID, len(rows))
	}
	if hit.ProjectCount != 2 || len(hit.Projects) != 2 {
		t.Fatalf("应聚合到 2 个项目，得到 %+v", hit)
	}
	if hit.Projects[0].ID != pidA || hit.Projects[1].ID != pidB {
		t.Fatalf("项目应按 id 升序且为 A/B，得到 %+v", hit.Projects)
	}
	if hit.Projects[0].Name == "" || hit.Projects[1].Name == "" {
		t.Fatalf("项目名未组装：%+v", hit.Projects)
	}
	if hit.FindingCount != 3 {
		t.Fatalf("发现数应为 3（A 两条 + B 一条），得到 %d", hit.FindingCount)
	}
	if hit.Kind != "ip" || hit.Label != sharedIP {
		t.Fatalf("标签/类型错误：%+v", hit)
	}
	if hit.LastFoundAt.IsZero() {
		t.Fatalf("最近出现时间未填充：%+v", hit)
	}

	// limit 生效
	if one, err := d.CrossProjectAssetRows(context.Background(), 1); err != nil || len(one) > 1 {
		t.Fatalf("limit=1 应最多 1 行，得到 %d 行 / err=%v", len(one), err)
	}
}
