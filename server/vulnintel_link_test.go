package server

// 资产联动验收：新同步的 CVE 命中 service 资产指纹后，受影响任务必须拿到
// 一条 `[情报联动]` hint，并锚定到该资产。
//
// 这是「情报有数据」和「任务用得上」之间的那一跳——没有它，情报库只是
// 一个没人看的网页。

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/vulnintel"
)

func TestLinkVulnIntelAssets(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	ctx := t.Context()
	task, err := d.CreateTask("联动验收：资产指纹命中", "验证情报 hint 落图", nil, 0, 0)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	taskID := task.ID

	// 一条 service 资产，指纹写成真实世界的形态（带版本号、大小写混合）。
	var assetID int64
	if err := d.QueryRowContext(ctx, `INSERT INTO assets(type, ip, port, technologies)
		VALUES ('service','10.0.0.5', 8080, ARRAY['Apache httpd 2.4.49'])
		RETURNING id`).Scan(&assetID); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	if _, err := d.ExecContext(ctx, `INSERT INTO task_asset_links(task_id, asset_id, source, source_summary)
		VALUES ($1,$2,'manual','联动验收')`, taskID, assetID); err != nil {
		t.Fatalf("link asset: %v", err)
	}

	// 一条 KEV CVE，组件是 apache/http_server（与 httpd 靠别名归一命中）。
	const cveID = "CVE-2021-41773"
	store := vulnintel.New(d)
	if err := store.UpsertCVE(ctx, vulnintel.CVE{
		ID: cveID, Title: "Apache httpd 路径穿越", Severity: "CRITICAL",
		Score: scoreOf(9.8), Published: time.Now().Add(-48 * time.Hour), Modified: time.Now(),
		Criteria: []string{"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
		Ranges: []vulnintel.CPERange{{
			Criteria:       "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
			StartIncluding: "2.4.49", EndIncluding: "2.4.49",
		}},
	}); err != nil {
		t.Fatalf("upsert cve: %v", err)
	}
	if err := store.MarkKEV(ctx, cveID, time.Now()); err != nil {
		t.Fatalf("mark kev: %v", err)
	}

	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM exploration_nodes WHERE exp_id=(SELECT exploration_id FROM tasks WHERE id=$1)`, taskID)
		_, _ = d.Exec(`DELETE FROM task_asset_links WHERE task_id=$1`, taskID)
		_, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, assetID)
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, taskID)
		_, _ = d.Exec(`DELETE FROM vuln_cves WHERE cve_id=$1`, cveID)
	})

	s := &Server{m: &Manager{pg: d}, vuln: &vulnIntelRuntime{store: store}}
	s.linkVulnIntelAssets()

	// 校验 hint 是否落到任务的探索图里。
	var expID int64
	if err := d.QueryRowContext(ctx, `SELECT exploration_id FROM tasks WHERE id=$1`, taskID).Scan(&expID); err != nil {
		t.Fatalf("read exploration: %v", err)
	}
	if expID <= 0 {
		t.Fatalf("任务没有探索图，无法挂 hint")
	}
	nodes, err := d.Exploration(expID).ListByKind(db.KindHint, 100)
	if err != nil {
		t.Fatalf("list hints: %v", err)
	}
	found := false
	for _, n := range nodes {
		var p struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		if !strings.HasPrefix(p.Text, intelHintPrefix) {
			continue
		}
		if !strings.Contains(p.Text, cveID) {
			continue
		}
		found = true
		if !strings.Contains(p.Text, "资产(id=") {
			t.Errorf("hint 缺少资产标记: %s", p.Text)
		}
		if !strings.Contains(p.Text, "KEV") {
			t.Errorf("hint 应标注 KEV: %s", p.Text)
		}
	}
	if !found {
		t.Fatalf("未找到 %s 的情报 hint（资产 apache/http_server 应命中 httpd 别名）", cveID)
	}

	// 防抖：再跑一次不应重复挂同一条。
	before := len(nodes)
	s.linkVulnIntelAssets()
	after, _ := d.Exploration(expID).ListByKind(db.KindHint, 100)
	if len(after) > before {
		t.Errorf("防抖失效：hint 从 %d 涨到 %d", before, len(after))
	}
}

func scoreOf(f float64) *float64 { return &f }
