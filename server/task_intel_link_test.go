package server

// V7-LINK 测试：surface 抽键纯函数 + 临时 PG 上的「申请候选 → 采纳/舍弃 →
// 阅读者标候选」全链路。
//
// 库集成部分照仓库 testDSN 范式：没有 database 配置/连不上 PG 时 skip；有库时
// 用带纳秒后缀的域名/项目名隔离数据。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// TestIntelSurfaceKeys 守 surface → (kind,key) 的抽取规则（≥6 例）：
// URL、裸路径、host:port、产品+版本、混合文本、空输入。
func TestIntelSurfaceKeys(t *testing.T) {
	cases := []struct {
		name    string
		surface string
		want    []db.IntelKeyRef
	}{
		{
			name:    "绝对 URL → endpoint + asset（数字段折叠/query 只留参数名）",
			surface: "https://app.example.com:8443/api/users/123/profile?uid=7&x=1",
			want: []db.IntelKeyRef{
				{Kind: db.IntelKindEndpoint, Key: "get /api/users/{id}/profile?uid&x"},
				{Kind: db.IntelKindAsset, Key: "app.example.com:8443"},
			},
		},
		{
			name:    "带方法的裸路径",
			surface: "GET /api/user/1/detail HTTP/1.1",
			want: []db.IntelKeyRef{
				{Kind: db.IntelKindEndpoint, Key: "get /api/user/{id}/detail"},
			},
		},
		{
			name:    "无方法的裸路径（多个）",
			surface: "重点看 /api/v1/login 和 /admin/index.php",
			want: []db.IntelKeyRef{
				{Kind: db.IntelKindEndpoint, Key: "get /api/v1/login"},
				{Kind: db.IntelKindEndpoint, Key: "get /admin/index.php"},
			},
		},
		{
			name:    "host:port → asset",
			surface: "10.0.0.8:8080 与 demo.example.com:443",
			want: []db.IntelKeyRef{
				{Kind: db.IntelKindAsset, Key: "10.0.0.8:8080"},
				{Kind: db.IntelKindAsset, Key: "demo.example.com:443"},
			},
		},
		{
			name:    "产品+版本 → component（截 major.minor）",
			surface: "nginx 1.18.0 / PHP:7.4.33 / Canal/1.1.5",
			want: []db.IntelKeyRef{
				{Kind: db.IntelKindComponent, Key: "nginx@1.18"},
				{Kind: db.IntelKindComponent, Key: "php@7.4"},
				{Kind: db.IntelKindComponent, Key: "canal@1.1"},
			},
		},
		{
			name:    "混合文本：方法+路径 / host:port / 组件",
			surface: "POST /api/order/create 打到 pay.example.com:9443，组件 spring boot 2.7",
			want: []db.IntelKeyRef{
				{Kind: db.IntelKindEndpoint, Key: "post /api/order/create"},
				{Kind: db.IntelKindAsset, Key: "pay.example.com:9443"},
				{Kind: db.IntelKindComponent, Key: "spring@2.7"},
			},
		},
		{
			name:    "同一 URL 重复出现只留一份",
			surface: "http://dup.example.com/api/x 和 http://dup.example.com/api/x",
			want: []db.IntelKeyRef{
				{Kind: db.IntelKindEndpoint, Key: "get /api/x"},
				{Kind: db.IntelKindAsset, Key: "dup.example.com:80"},
			},
		},
		{
			name:    "无面可抽",
			surface: "把后台打穿，拿最高权限",
			want:    nil,
		},
	}
	for _, c := range cases {
		got := intelSurfaceKeys(c.surface)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: [%d] got %+v want %+v（all %+v）", c.name, i, got[i], c.want[i], got)
			}
		}
	}
}

// intelLinkProject 造一个项目并注册清理（同项目的任务才能 scope=project 命中）。
func intelLinkProject(t *testing.T, pg *db.DB, name string, readerOn bool) int64 {
	t.Helper()
	n := time.Now().UnixNano()
	p, err := pg.CreateProject(db.CreateProjectInput{
		Name: fmt.Sprintf("%s-%d", name, n%1000000), ObserverEnabled: true, ReaderEnabled: readerOn,
	})
	if err != nil {
		t.Fatal(err)
	}
	pid := p.ID
	t.Cleanup(func() { pg.Exec(`DELETE FROM projects WHERE id=$1`, pid) }) //nolint:errcheck // task_intel/_links 级联删
	return pid
}

// intelLinkTask 在指定项目下造一个任务并注册清理。
func intelLinkTask(t *testing.T, s *Server, pg *db.DB, pid int64, name string) (*Task, int64) {
	t.Helper()
	task, err := s.m.CreateTaskWithOptions(name, "goal", db.TaskCreateOptions{ProjectID: &pid})
	if err != nil {
		t.Fatal(err)
	}
	var taskID int64
	if err := pg.QueryRow(`SELECT id FROM tasks WHERE exploration_id=$1`, task.ExpID).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pg.Exec(`DELETE FROM tasks WHERE id=$1`, taskID)            //nolint:errcheck
		pg.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExpID) //nolint:errcheck
	})
	return task, taskID
}

// floatOf 安全取 JSON 数字（缺失/类型不符返回 0）。
func floatOf(v any) float64 {
	f, _ := v.(float64)
	return f
}

func callToolJSON(t *testing.T, toolName string, call func(context.Context, json.RawMessage) (string, bool), ctx context.Context, in map[string]any, out any) {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	text, isErr := call(ctx, raw)
	if isErr {
		t.Fatalf("%s 返回错误: %s", toolName, text)
	}
	if out != nil {
		if err := json.Unmarshal([]byte(text), out); err != nil {
			t.Fatalf("%s 返回体不是预期 JSON: %v（原文 %s）", toolName, err, text)
		}
	}
}

// TestTaskIntelToolsWired 守历史 P0：工具绑定进库还不够，必须真的进 hostTools()
// 装配，否则运行时不出现。V9-READER 起五件全部只归 reader，planner 一件不持有。
func TestTaskIntelToolsWired(t *testing.T) {
	s, _ := newInsightTestPG(t)
	tools, _ := s.hostTools()
	got := names(tools)
	for _, k := range []string{
		"request_reader_links", "adopt_related_task", "dismiss_related_task",
		"read_task_intel", "link_tasks",
	} {
		if got[k] == nil {
			t.Errorf("hostTools 缺少 %s（绑定未装配）", k)
		}
	}
	if n := len(s.taskIntelReaderTools()); n != 5 {
		t.Errorf("reader 勾连工具应为 5 件，got %d", n)
	}
	// seed 绑定：工具行必须存在且只绑 reader（planner 不再持有任何一件）。
	s.seedProjectTools()
	for _, name := range []string{
		"request_reader_links", "adopt_related_task", "dismiss_related_task",
		"read_task_intel", "link_tasks",
	} {
		row, err := s.m.pg.GetTool(name)
		if err != nil || row == nil {
			t.Errorf("工具 %s 未入库: err=%v", name, err)
			continue
		}
		if !contains(row.Agents, "reader") {
			t.Errorf("工具 %s 应绑定 reader，got %v", name, row.Agents)
		}
		if contains(row.Agents, "planner") {
			t.Errorf("工具 %s 不应再绑定 planner，got %v", name, row.Agents)
		}
	}
}

// TestTaskIntelToolOwnershipMigration 守存量库迁移：V7 曾把三件绑给 planner，
// 新 seed 必须能把旧绑定改掉（不能只首插）。
func TestTaskIntelToolOwnershipMigration(t *testing.T) {
	s, pg := newInsightTestPG(t)
	// 先造「存量库」：三件工具以 planner 绑定入库。
	for _, name := range []string{"request_reader_links", "adopt_related_task", "dismiss_related_task"} {
		agents, _ := json.Marshal([]string{"planner"})
		schema, _ := json.Marshal(map[string]any{"type": "object"})
		if err := pg.SeedTool(name, "旧描述", schema, agents); err != nil {
			t.Fatal(err)
		}
		if err := pg.SetSystemToolAgents(name, agents); err != nil { // 覆盖可能存在的旧行
			t.Fatal(err)
		}
	}
	// 跑 seed：归属必须迁到 reader。
	s.seedProjectTools()
	for _, name := range []string{"request_reader_links", "adopt_related_task", "dismiss_related_task"} {
		row, err := pg.GetTool(name)
		if err != nil || row == nil {
			t.Fatalf("工具 %s 未入库: err=%v", name, err)
		}
		if len(row.Agents) != 1 || row.Agents[0] != "reader" {
			t.Errorf("存量库迁移后 %s 应只绑 reader，got %v", name, row.Agents)
		}
	}
}

// TestReaderLinkFlow 覆盖工具逻辑（临时 PG）：
//   - A 有 2 endpoint + 1 credential，B 的 surface 命中 1 条 → 返回 A 且命中
//     明细正确、finding/意图计数正确；
//   - 从 A 自己申请则 A 被排除；
//   - scope=cross 且对方项目未开 reader_enabled → 不返回；开启后才返回；
//   - adopt 写 adopted + hint，重复 adopt 幂等；dismiss 写 dismissed 无 hint；
//   - reader 的 link_tasks 不覆盖已 adopted 的行。
func TestReaderLinkFlow(t *testing.T) {
	s, pg := newInsightTestPG(t)
	ctx := context.Background()

	pid := intelLinkProject(t, pg, "link-p", true)
	taskA, idA := intelLinkTask(t, s, pg, pid, "link-a")
	taskB, idB := intelLinkTask(t, s, pg, pid, "link-b")
	pidC := intelLinkProject(t, pg, "link-c-p", false) // 未开 reader_enabled
	_, idC := intelLinkTask(t, s, pg, pidC, "link-c")

	epKey := "get /api/user/{id}"
	rowsA := []db.TaskIntel{
		{Kind: db.IntelKindEndpoint, Key: epKey, Value: "https://a.example.com/api/user/9", Source: "finding"},
		{Kind: db.IntelKindEndpoint, Key: "post /api/login", Value: "https://a.example.com/api/login", Source: "finding"},
		{Kind: db.IntelKindCredential, Key: "password|admin|a.example.com:443", Value: "password for admin@a.example.com:443", Source: "fact"},
		// V9-SCOPE：被勾连任务的资产（带端口，落库时归一成 host）。
		{Kind: db.IntelKindAsset, Key: "10.0.0.9:8080", Value: "10.0.0.9:8080", Source: "asset"},
	}
	if _, err := pg.UpsertTaskIntel(ctx, pid, idA, rowsA); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.UpsertTaskIntel(ctx, pidC, idC, []db.TaskIntel{
		{Kind: db.IntelKindEndpoint, Key: epKey, Value: "https://c.example.com/api/user/1", Source: "finding"},
		{Kind: db.IntelKindAsset, Key: "10.0.0.10:80", Value: "10.0.0.10:80", Source: "asset"},
	}); err != nil {
		t.Fatal(err)
	}
	// A 的价值计数：1 finding + 1 意图。
	var assetID int64
	if err := pg.QueryRow(`INSERT INTO assets(type, domain) VALUES ('root_domain','a.example.com') RETURNING id`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Exec(`DELETE FROM assets WHERE id=$1`, assetID) }) //nolint:errcheck
	if _, err := pg.AddFinding(idA, 0, "rce", "x", "high", "s", "e", "w", []int64{assetID}); err != nil {
		t.Fatal(err)
	}
	if _, err := taskA.Store.AddIntent(map[string]any{"summary": "打 A"}, 1, nil, "planner"); err != nil {
		t.Fatal(err)
	}

	// ---------- request_reader_links ----------
	req := s.toolRequestReaderLinks()
	call := func(c context.Context, raw json.RawMessage) (string, bool) {
		r, err := req.Call(c, raw, nil)
		if err != nil {
			t.Fatalf("tool call: %v", err)
		}
		return r.Flatten(), r.IsError
	}
	// V9-READER：阅读者按项目视野找候选，显式传 project_id + 排除发起方任务。
	var out struct {
		Candidates []readerLinkCandidate `json:"candidates"`
		Note       string                `json:"note"`
	}
	callToolJSON(t, "request_reader_links", call, ctx, map[string]any{
		"surface": "GET /api/user/123", "project_id": pid, "exclude_task_id": idB,
	}, &out)

	if len(out.Candidates) != 1 || out.Candidates[0].TaskID != idA {
		t.Fatalf("候选应只有任务 A(%d)，got %+v", idA, out.Candidates)
	}
	cand := out.Candidates[0]
	if cand.HitCount != 1 || len(cand.Hits) != 1 || cand.Hits[0].Kind != db.IntelKindEndpoint || cand.Hits[0].Key != epKey {
		t.Errorf("命中明细不对: %+v", cand.Hits)
	}
	if cand.FindingCount != 1 || cand.IntentCount != 1 {
		t.Errorf("价值计数应为 finding=1/intent=1，got %d/%d", cand.FindingCount, cand.IntentCount)
	}
	if !strings.Contains(out.Note, "以下为候选") || !strings.Contains(out.Note, "adopt") || !strings.Contains(out.Note, "dismiss") {
		t.Errorf("返回必须带「候选须下钻」提示: %q", out.Note)
	}

	// 排除 A 自己：A 必须被排除。
	out.Candidates = nil
	callToolJSON(t, "request_reader_links", call, ctx, map[string]any{
		"surface": "GET /api/user/123", "project_id": pid, "exclude_task_id": idA,
	}, &out)
	for _, c := range out.Candidates {
		if c.TaskID == idA {
			t.Fatalf("发起方任务 A 不应作为自己的候选: %+v", out.Candidates)
		}
	}

	// scope=cross：C 未开 reader_enabled → 不返回；开启后才返回。
	out.Candidates = nil
	callToolJSON(t, "request_reader_links", call, ctx, map[string]any{
		"surface": "GET /api/user/123", "project_id": pid, "exclude_task_id": idB, "scope": "cross",
	}, &out)
	if len(out.Candidates) != 0 {
		t.Fatalf("C 未开 reader_enabled，cross 不应返回任何候选，got %+v", out.Candidates)
	}
	if _, err := pg.Exec(`UPDATE projects SET reader_enabled=true WHERE id=$1`, pidC); err != nil {
		t.Fatal(err)
	}
	out.Candidates = nil
	callToolJSON(t, "request_reader_links", call, ctx, map[string]any{
		"surface": "GET /api/user/123", "project_id": pid, "exclude_task_id": idB, "scope": "cross",
	}, &out)
	if len(out.Candidates) != 1 || out.Candidates[0].TaskID != idC {
		t.Fatalf("C 开启 reader_enabled 后应被 cross 命中，got %+v", out.Candidates)
	}

	// ---------- adopt（阅读者判定相关，暴露给发起方 B 的规划者） ----------
	if _, err := taskA.Store.AddNode(db.KindFact, map[string]any{
		"summary": "A 任务已验证 /api/user/{id} 存在越权",
	}, 0, "confirmed", "worker", nil); err != nil {
		t.Fatal(err)
	}
	var hintGraphEvents int
	ix := newProjectIndexer(pg)
	ix.Start(ctx)
	t.Cleanup(ix.Stop)
	prevHook := taskB.Store.OnGraphChange
	taskB.Store.OnGraphChange = func(ev db.GraphChange) {
		if ev.Kind == db.KindHint {
			hintGraphEvents++
			ix.Enqueue(idB, ev) // 走生产同款投影/事件落库路径
		}
	}
	defer func() { taskB.Store.OnGraphChange = prevHook }()

	adopt := s.toolAdoptRelatedTask()
	adoptCall := func(c context.Context, in map[string]any) string {
		raw, _ := json.Marshal(in)
		r, err := adopt.Call(c, raw, nil)
		if err != nil {
			t.Fatalf("adopt: %v", err)
		}
		if r.IsError {
			t.Fatalf("adopt 返回错误: %s", r.Flatten())
		}
		return r.Flatten()
	}
	adoptCall(ctx, map[string]any{
		"task_id": idB, "related_task_id": idA, "reason": "两边都命中 /api/user/{id}，A 已验证越权",
		"strength": "strong",
		"matched":  []map[string]any{{"kind": db.IntelKindEndpoint, "key": epKey, "value": "https://a.example.com/api/user/9"}},
	})
	var decision, reason, matched, decidedBy string
	if err := pg.QueryRow(`SELECT decision, reason, matched::text, decided_by FROM task_intel_links WHERE task_id=$1 AND related_task_id=$2`, idB, idA).
		Scan(&decision, &reason, &matched, &decidedBy); err != nil {
		t.Fatal(err)
	}
	if decision != "adopted" || decidedBy != "reader" || !strings.Contains(reason, "/api/user/{id}") || !strings.Contains(matched, epKey) {
		t.Errorf("adopt 落库不对: decision=%q decided_by=%q reason=%q matched=%s", decision, decidedBy, reason, matched)
	}
	hintCount := func() int {
		var n int
		if err := pg.QueryRow(`SELECT COUNT(*) FROM exploration_nodes WHERE exploration_id=$1 AND kind='hint'`, taskB.ExpID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := hintCount(); n != 1 {
		t.Fatalf("adopt 应写 1 条 hint，got %d", n)
	}
	var payloadRaw []byte
	if err := pg.QueryRow(`SELECT payload FROM exploration_nodes WHERE exploration_id=$1 AND kind='hint' ORDER BY id DESC LIMIT 1`, taskB.ExpID).Scan(&payloadRaw); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		t.Fatal(err)
	}
	hintText, _ := payload["text"].(string)
	if !strings.Contains(hintText, fmt.Sprintf("任务#%d", idA)) || !strings.Contains(hintText, epKey) || !strings.Contains(hintText, "直接采信") {
		t.Errorf("hint 正文缺少来源任务/要点/直接采信: %q", hintText)
	}
	if got := int64(floatOf(payload["source_task_id"])); got != idA {
		t.Errorf("hint payload.source_task_id=%d want %d", got, idA)
	}
	if got, _ := payload["source_task_name"].(string); strings.TrimSpace(got) == "" {
		t.Errorf("hint payload.source_task_name 不应为空: %+v", payload)
	}
	if got := int64(floatOf(payload["source_project_id"])); got != pid {
		t.Errorf("hint payload.source_project_id=%d want %d", got, pid)
	}
	if got, _ := payload["strength"].(string); got != "strong" {
		t.Errorf("hint payload.strength=%q want strong", got)
	}
	points, _ := payload["reusable_points"].([]any)
	if len(points) == 0 {
		t.Fatalf("hint payload 应含可复用要点: %+v", payload)
	}
	foundEP := false
	for _, p := range points {
		if strings.Contains(fmt.Sprint(p), epKey) {
			foundEP = true
		}
	}
	if !foundEP {
		t.Errorf("可复用要点应含接口 %q: %+v", epKey, points)
	}
	if facts, _ := payload["key_facts"].([]any); len(facts) == 0 {
		t.Errorf("hint payload 应含关键事实摘要: %+v", payload)
	}
	// V9-SCOPE：hint 必须自我声明只是经验参考，并列出外部任务资产 host。
	if ref, _ := payload["reference_only"].(bool); !ref {
		t.Errorf("hint payload 必须 reference_only=true: %+v", payload)
	}
	foreign := fmt.Sprint(payload["foreign_hosts"])
	if !strings.Contains(foreign, "10.0.0.9") || strings.Contains(foreign, "8080") {
		t.Errorf("hint payload.foreign_hosts 应为归一 host（去端口），got %v", payload["foreign_hosts"])
	}
	if !strings.Contains(hintText, "禁止对以下地址") || !strings.Contains(hintText, "10.0.0.9") {
		t.Errorf("hint 正文应列出禁止地址: %q", hintText)
	}
	// 落库：幂等一行，host 已归一去端口。
	var foreignSource int64
	var foreignCount int
	if err := pg.QueryRow(`SELECT COUNT(*) FROM task_foreign_assets WHERE task_id=$1`, idB).Scan(&foreignCount); err != nil {
		t.Fatal(err)
	}
	if foreignCount != 1 {
		t.Fatalf("adopt 应写 1 条外部资产，got %d", foreignCount)
	}
	var host string
	if err := pg.QueryRow(`SELECT host, source_task_id FROM task_foreign_assets WHERE task_id=$1`, idB).
		Scan(&host, &foreignSource); err != nil {
		t.Fatal(err)
	}
	if host != "10.0.0.9" || foreignSource != idA {
		t.Fatalf("外部资产应为 host=10.0.0.9 source=%d，got host=%s source=%d", idA, host, foreignSource)
	}
	// 采纳必须触发图变更（生产链=project_graph_events）并唤醒规划者。
	if hintGraphEvents == 0 {
		t.Error("adopt 写 hint 后应触发图变更回调（规划者会被唤醒）")
	}
	// 生产链是 OnGraphChange → ProjectIndexer → project_graph_events；等异步
	// 消费者落库，确认事件真的新增（reader 触发器/审计都靠它）。
	var graphEvents int
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := pg.QueryRow(`SELECT COUNT(*) FROM project_graph_events WHERE task_id=$1 AND kind='hint'`, idB).Scan(&graphEvents); err != nil {
			t.Fatal(err)
		}
		if graphEvents > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if graphEvents == 0 {
		t.Error("project_graph_events 应有 hint 事件（规划者由图变更唤醒）")
	}
	taskB.trigMu.Lock()
	var hintTriggers int
	for _, ev := range taskB.pendingTriggers {
		if ev.Kind == "hint" {
			hintTriggers++
		}
	}
	taskB.trigMu.Unlock()
	if hintTriggers == 0 {
		t.Error("adopt 后发起方任务应有 hint 触发事件（NotifyHint 唤醒规划者）")
	}

	// 重复 adopt 幂等：hint 不重复写。
	adoptCall(ctx, map[string]any{"task_id": idB, "related_task_id": idA, "reason": "同一用户接口（复核）"})
	if n := hintCount(); n != 1 {
		t.Errorf("重复 adopt 不应重复写 hint，got %d", n)
	}
	if n, _ := pg.CountTaskForeignAssets(ctx, idB); n != 1 {
		t.Errorf("重复 adopt 不应重复写外部资产，got %d", n)
	}

	// ---------- dismiss（只留 links，无 hint、无事件、无唤醒） ----------
	eventsBefore := hintGraphEvents
	hintsBefore := hintCount()
	var pgEventsBefore int
	if err := pg.QueryRow(`SELECT COUNT(*) FROM project_graph_events WHERE task_id=$1 AND kind='hint'`, idB).Scan(&pgEventsBefore); err != nil {
		t.Fatal(err)
	}
	dismiss := s.toolDismissRelatedTask()
	rawDismiss, _ := json.Marshal(map[string]any{"task_id": idB, "related_task_id": idC, "reason": "不同资产，读完两边无复用点"})
	rd, err := dismiss.Call(ctx, rawDismiss, nil)
	if err != nil || rd.IsError {
		t.Fatalf("dismiss: err=%v res=%+v", err, rd)
	}
	if err := pg.QueryRow(`SELECT decision, decided_by FROM task_intel_links WHERE task_id=$1 AND related_task_id=$2`, idB, idC).
		Scan(&decision, &decidedBy); err != nil {
		t.Fatal(err)
	}
	if decision != "dismissed" || decidedBy != "reader" {
		t.Errorf("dismiss 决策应为 dismissed/reader，got %q/%q", decision, decidedBy)
	}
	// V9-SCOPE：dismiss 不写外部资产（C 有资产情报，也不得进负向清单）。
	if n, _ := pg.CountTaskForeignAssets(ctx, idB); n != 1 {
		t.Errorf("dismiss 不应写外部资产，task_foreign_assets=%d", n)
	}
	if n := hintCount(); n != hintsBefore {
		t.Errorf("dismiss 不应写 hint，hint 数=%d (before %d)", n, hintsBefore)
	}
	if hintGraphEvents != eventsBefore {
		t.Errorf("dismiss 不应触发图变更，events=%d (before %d)", hintGraphEvents, eventsBefore)
	}
	// 留一点时间让可能的异步投影落库，再确认事件数没涨。
	time.Sleep(100 * time.Millisecond)
	var pgEventsAfter int
	if err := pg.QueryRow(`SELECT COUNT(*) FROM project_graph_events WHERE task_id=$1 AND kind='hint'`, idB).Scan(&pgEventsAfter); err != nil {
		t.Fatal(err)
	}
	if pgEventsAfter != pgEventsBefore {
		t.Errorf("dismiss 不应新增 project_graph_events，got %d (before %d)", pgEventsAfter, pgEventsBefore)
	}
	taskB.trigMu.Lock()
	hintTriggersAfterDismiss := 0
	for _, ev := range taskB.pendingTriggers {
		if ev.Kind == "hint" {
			hintTriggersAfterDismiss++
		}
	}
	taskB.trigMu.Unlock()
	if hintTriggersAfterDismiss != hintTriggers {
		t.Errorf("dismiss 不应唤醒规划者，hint 触发数=%d (before %d)", hintTriggersAfterDismiss, hintTriggers)
	}

	// ---------- reader link_tasks 不覆盖 adopted ----------
	link := s.toolLinkTasks()
	rawLink, _ := json.Marshal(map[string]any{
		"task_id": idB, "related_task_id": idA, "reason": "阅读者候选",
	})
	rl, err := link.Call(ctx, rawLink, nil)
	if err != nil || rl.IsError {
		t.Fatalf("link_tasks: err=%v res=%+v", err, rl)
	}
	if err := pg.QueryRow(`SELECT decision FROM task_intel_links WHERE task_id=$1 AND related_task_id=$2`, idB, idA).Scan(&decision); err != nil {
		t.Fatal(err)
	}
	if decision != "adopted" {
		t.Errorf("link_tasks 不得覆盖 adopted，got %q（返回 %s）", decision, rl.Flatten())
	}
	if !strings.Contains(rl.Flatten(), "未覆盖") {
		t.Errorf("被保护时应如实回报: %s", rl.Flatten())
	}
}

// TestReaderLinkMatchKeyHitPG 复现实网缺陷（任务 #51 → 0 候选）：precise key
// 三个维度全不同（GET vs POST / 带 query vs 不带 / mariadb 10.1 vs 10.3），
// 但按 match_key 必须命中。
//
//	预置 A: endpoint|get /vulnerabilities/sqli/?id + component|mariadb@10.1
//	surface: POST /vulnerabilities/sqli/ SQL 注入 MariaDB 10.3
//	→ A 必须返回，hits 里 endpoint(match_key=/vulnerabilities/sqli/)、
//	  component(match_key=mariadb) 各一条。
//
// 负例：POST /vulnerabilities/upload/ + nginx 1.18 不得返回 A。
func TestReaderLinkMatchKeyHitPG(t *testing.T) {
	s, pg := newInsightTestPG(t)
	ctx := context.Background()
	pid := intelLinkProject(t, pg, "matchkey-p", true)
	_, idA := intelLinkTask(t, s, pg, pid, "matchkey-a")
	_, idB := intelLinkTask(t, s, pg, pid, "matchkey-b")

	if _, err := pg.UpsertTaskIntel(ctx, pid, idA, []db.TaskIntel{
		{Kind: db.IntelKindEndpoint, Key: "get /vulnerabilities/sqli/?id", Value: "http://dvwa/vulnerabilities/sqli/?id=1", Source: "finding"},
		{Kind: db.IntelKindComponent, Key: "mariadb@10.1", Value: "mariadb 10.1", Source: "asset"},
	}); err != nil {
		t.Fatal(err)
	}

	req := s.toolRequestReaderLinks()
	call := func(c context.Context, raw json.RawMessage) (string, bool) {
		r, err := req.Call(c, raw, nil)
		if err != nil {
			t.Fatalf("tool call: %v", err)
		}
		return r.Flatten(), r.IsError
	}
	var out struct {
		Candidates []readerLinkCandidate `json:"candidates"`
		Keys       []db.IntelKeyRef      `json:"keys"`
		Debug      struct {
			SurfaceKeys      []readerLinkSurfaceKey `json:"surface_keys"`
			QueriedProjectID int64                  `json:"queried_project_id"`
			Scope            string                 `json:"scope"`
		} `json:"debug"`
	}
	callToolJSON(t, "request_reader_links", call, ctx, map[string]any{
		"surface": "POST /vulnerabilities/sqli/ SQL 注入 MariaDB 10.3", "project_id": pid, "exclude_task_id": idB,
	}, &out)

	if len(out.Candidates) != 1 || out.Candidates[0].TaskID != idA {
		t.Fatalf("方法/query/版本都不同也必须命中原任务 A(%d)，got %+v", idA, out.Candidates)
	}
	hits := map[string]readerLinkHit{}
	for _, h := range out.Candidates[0].Hits {
		hits[h.Kind] = h
	}
	ep, ok := hits[db.IntelKindEndpoint]
	if !ok || ep.Key != "get /vulnerabilities/sqli/?id" || ep.MatchKey != "/vulnerabilities/sqli/" {
		t.Errorf("endpoint 命中不对: %+v", hits)
	}
	comp, ok := hits[db.IntelKindComponent]
	if !ok || comp.Key != "mariadb@10.1" || comp.MatchKey != "mariadb" {
		t.Errorf("component 命中不对: %+v", hits)
	}
	if out.Debug.QueriedProjectID != pid || out.Debug.Scope != "project" || len(out.Debug.SurfaceKeys) == 0 {
		t.Errorf("debug 面不完整: %+v", out.Debug)
	}
	var sawEPQuery bool
	for _, sk := range out.Debug.SurfaceKeys {
		if sk.Kind == db.IntelKindEndpoint && sk.MatchKey == "/vulnerabilities/sqli/" {
			sawEPQuery = true
		}
	}
	if !sawEPQuery {
		t.Errorf("debug.surface_keys 应含 endpoint 的匹配键 /vulnerabilities/sqli/: %+v", out.Debug.SurfaceKeys)
	}

	// 负例：不同接口 + 不同组件 → 不得把 A 连进来。
	out.Candidates = nil
	callToolJSON(t, "request_reader_links", call, ctx, map[string]any{
		"surface": "POST /vulnerabilities/upload/ nginx 1.18", "project_id": pid, "exclude_task_id": idB,
	}, &out)
	for _, c := range out.Candidates {
		if c.TaskID == idA {
			t.Fatalf("不同接口/组件不应命中 A: %+v", out.Candidates)
		}
	}
}

// TestReadTaskIntelTool 守 read_task_intel：按项目增量读、按 kind 分组、
// 返回 next_since_id（下一轮水位）。
func TestReadTaskIntelTool(t *testing.T) {
	s, pg := newInsightTestPG(t)
	ctx := context.Background()
	pid := intelLinkProject(t, pg, "intel-read-p", true)
	_, idA := intelLinkTask(t, s, pg, pid, "intel-read")

	if _, err := pg.UpsertTaskIntel(ctx, pid, idA, []db.TaskIntel{
		{Kind: db.IntelKindEndpoint, Key: "get /api/a", Value: "https://a/api/a", Source: "finding"},
		{Kind: db.IntelKindEndpoint, Key: "get /api/b", Value: "https://a/api/b", Source: "finding"},
		{Kind: db.IntelKindCredential, Key: "password|admin|a:443", Value: "password for admin@a:443", Source: "fact"},
	}); err != nil {
		t.Fatal(err)
	}

	tool := s.toolReadTaskIntel()
	raw, _ := json.Marshal(map[string]any{"project_id": pid, "since_id": 0})
	res, err := tool.Call(ctx, raw, nil)
	if err != nil || res.IsError {
		t.Fatalf("read_task_intel: err=%v res=%+v", err, res)
	}
	var out struct {
		NextSinceID int64 `json:"next_since_id"`
		Projects    []struct {
			ProjectID int64               `json:"project_id"`
			Total     int                 `json:"total"`
			Groups    []intelSummaryGroup `json:"groups"`
		} `json:"projects"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("返回体不是 JSON: %v（%s）", err, res.Flatten())
	}
	if out.NextSinceID <= 0 {
		t.Errorf("next_since_id 应前进，got %d", out.NextSinceID)
	}
	if len(out.Projects) != 1 || out.Projects[0].Total != 3 {
		t.Fatalf("应读到 1 个项目 3 条情报，got %+v", out.Projects)
	}
	counts := map[string]int{}
	for _, g := range out.Projects[0].Groups {
		counts[g.Kind] = g.Count
	}
	if counts[db.IntelKindEndpoint] != 2 || counts[db.IntelKindCredential] != 1 {
		t.Errorf("分组计数不对: %+v", counts)
	}
	// 水位之后无新增 → 0 条。
	raw, _ = json.Marshal(map[string]any{"project_id": pid, "since_id": out.NextSinceID})
	res, err = tool.Call(ctx, raw, nil)
	if err != nil || res.IsError {
		t.Fatalf("read_task_intel(增量): err=%v res=%+v", err, res)
	}
	var out2 struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &out2); err != nil {
		t.Fatal(err)
	}
	if out2.Total != 0 {
		t.Errorf("水位之后应为 0 条，got %d", out2.Total)
	}
}

// TestReaderLinkScopeSwitches 守「同一类、两个视角、各自开关」（V6-DUAL）：
//   - 跨任务（scope=project）受本项目 observer_enabled 控制，关了就 0 候选并说明原因；
//   - 跨项目（scope=cross）受目标项目 reader_enabled 控制（既有用例已覆盖）；
//   - reader 的 read_task_intel 显式指定项目时，两把开关都关才 skipped。
func TestReaderLinkScopeSwitches(t *testing.T) {
	s, pg := newInsightTestPG(t)
	ctx := context.Background()

	pid := intelLinkProject(t, pg, "scope-p", false) // observer=true, reader=false
	_, idA := intelLinkTask(t, s, pg, pid, "scope-a")
	_, idB := intelLinkTask(t, s, pg, pid, "scope-b")

	if _, err := pg.UpsertTaskIntel(ctx, pid, idA, []db.TaskIntel{
		{Kind: db.IntelKindEndpoint, Key: "post /vulnerabilities/sqli/", Value: "http://t/vulnerabilities/sqli/", Source: "finding"},
	}); err != nil {
		t.Fatal(err)
	}

	link := s.toolRequestReaderLinks()
	callLink := func(c context.Context, raw json.RawMessage) (string, bool) {
		r, err := link.Call(c, raw, nil)
		if err != nil {
			t.Fatalf("tool call: %v", err)
		}
		return r.Flatten(), r.IsError
	}
	type linkOut struct {
		Candidates []readerLinkCandidate `json:"candidates"`
		Note       string                `json:"note"`
	}

	// 1) observer 开 → 跨任务视角可用。
	var out linkOut
	callToolJSON(t, "request_reader_links", callLink, ctx, map[string]any{
		"surface": "POST /vulnerabilities/sqli/", "project_id": pid, "exclude_task_id": idB,
	}, &out)
	if len(out.Candidates) != 1 || out.Candidates[0].TaskID != idA {
		t.Fatalf("observer_enabled=true 时应命中任务 A，got %+v", out.Candidates)
	}

	// 2) 关掉 observer_enabled → 跨任务候选必须消失，且说明是开关原因。
	if _, err := pg.Exec(`UPDATE projects SET observer_enabled=false WHERE id=$1`, pid); err != nil {
		t.Fatal(err)
	}
	out.Candidates = nil
	out.Note = ""
	callToolJSON(t, "request_reader_links", callLink, ctx, map[string]any{
		"surface": "POST /vulnerabilities/sqli/", "project_id": pid, "exclude_task_id": idB,
	}, &out)
	if len(out.Candidates) != 0 {
		t.Fatalf("observer_enabled=false 时不应有跨任务候选，got %+v", out.Candidates)
	}
	if !strings.Contains(out.Note, "observer_enabled") || !strings.Contains(out.Note, "跨任务") {
		t.Errorf("0 候选时必须说明是跨任务视角未开启，got %q", out.Note)
	}

	// 3) 两把开关全关 → read_task_intel 显式指定项目进 skipped。
	read := s.toolReadTaskIntel()
	callRead := func(c context.Context, raw json.RawMessage) (string, bool) {
		r, err := read.Call(c, raw, nil)
		if err != nil {
			t.Fatalf("tool call: %v", err)
		}
		return r.Flatten(), r.IsError
	}
	var readOut struct {
		Total   int              `json:"total"`
		Skipped []map[string]any `json:"skipped"`
	}
	callToolJSON(t, "read_task_intel", callRead, ctx, map[string]any{"project_id": pid}, &readOut)
	if readOut.Total != 0 || len(readOut.Skipped) != 1 {
		t.Fatalf("两把开关全关应 skipped 且 0 条，got total=%d skipped=%+v", readOut.Total, readOut.Skipped)
	}

	// 4) 只开 reader_enabled（跨项目视角）→ 显式读该项目即可用。
	if _, err := pg.Exec(`UPDATE projects SET reader_enabled=true WHERE id=$1`, pid); err != nil {
		t.Fatal(err)
	}
	readOut.Total, readOut.Skipped = 0, nil // 复位，避免上一步的 skipped 残留
	callToolJSON(t, "read_task_intel", callRead, ctx, map[string]any{"project_id": pid}, &readOut)
	if len(readOut.Skipped) != 0 || readOut.Total == 0 {
		t.Fatalf("reader_enabled=true 时应可读该项目，got total=%d skipped=%+v", readOut.Total, readOut.Skipped)
	}
}

// TestIntelSurfaceKeysHighFreqComponents 守受控产品表：Shiro/WebLogic/fastjson
// 这类 CVE 密集组件必须能被 surface 抽出，否则「同组件版本且有在野利用」这条
// 强信号在实战里永远触发不了。
func TestIntelSurfaceKeysHighFreqComponents(t *testing.T) {
	cases := []struct{ surface, wantKey string }{
		{"识别组件 Apache Shiro 1.7.0，登录返回 user_token", "shiro@1.7"},
		{"fastjson 1.2.47 反序列化可打", "fastjson@1.2"},
		{"WebLogic 12.2.1.3 控制台暴露", "weblogic@12.2"},
	}
	for _, c := range cases {
		keys := intelSurfaceKeys(c.surface)
		found := false
		for _, k := range keys {
			if k.Kind == db.IntelKindComponent && k.Key == c.wantKey {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("surface %q 未抽出组件 %q，实际 keys=%+v", c.surface, c.wantKey, keys)
		}
	}
}

// TestReaderLinkScoringTwoTier 守 V11-READER3 的两级评分第一级：
// 精确 1.0 / 模糊 0.6 / 凭据 1.2 / 资产 0.8 / 组件 0.3；
// Σ≥2.0 strong、Σ≥1.0 medium、Σ<1.0 weak（weak 不进候选）。
func TestReaderLinkScoringTwoTier(t *testing.T) {
	matches := []db.IntelTaskMatch{
		// task 1：1 精确 + 1 模糊 = 1.65 → medium
		{TaskIntel: db.TaskIntel{TaskID: 1, Kind: db.IntelKindEndpoint, Key: "get /api/user/list", MatchKey: "/api/user/list"}},
		{TaskIntel: db.TaskIntel{TaskID: 1, Kind: db.IntelKindEndpoint, Key: "get /api/user/info", MatchKey: "/api/user/info"}, MatchScore: 0.65, MatchKind: "fuzzy"},
		// task 2：单条模糊 0.6 → weak，不进候选
		{TaskIntel: db.TaskIntel{TaskID: 2, Kind: db.IntelKindEndpoint, Key: "get /api/order/list", MatchKey: "/api/order/list"}, MatchScore: 0.6, MatchKind: "fuzzy"},
		// task 3：两条精确 = 2.0 → strong
		{TaskIntel: db.TaskIntel{TaskID: 3, Kind: db.IntelKindEndpoint, Key: "get /a", MatchKey: "/a"}},
		{TaskIntel: db.TaskIntel{TaskID: 3, Kind: db.IntelKindEndpoint, Key: "post /b", MatchKey: "/b"}},
		// task 4：可复用凭据 1.2 → medium
		{TaskIntel: db.TaskIntel{TaskID: 4, Kind: db.IntelKindCredential, Key: "password|admin|ssh", MatchKey: "password|admin"}},
	}
	out, _ := aggregateReaderLinkCandidates(matches, 10)
	if len(out) != 3 {
		t.Fatalf("应剩 3 个候选（task1/3/4），得到 %d: %+v", len(out), out)
	}
	if out[0].TaskID != 3 || out[0].MatchStrength != "strong" {
		t.Errorf("第一名应是 task3/strong，得到 %+v", out[0])
	}
	if out[1].TaskID != 1 || out[1].MatchStrength != "medium" {
		t.Errorf("第二名应是 task1/medium，得到 %+v", out[1])
	}
	if out[2].TaskID != 4 || out[2].MatchStrength != "medium" {
		t.Errorf("第三名应是 task4/medium（凭据），得到 %+v", out[2])
	}
	for _, c := range out {
		if c.TaskID == 2 {
			t.Errorf("单条模糊 task2 不应进候选")
		}
	}
}

// TestReaderLinkWeakComponentOnlyDropped 守 V8-SIG：只有组件命中的候选必须被丢弃。
func TestReaderLinkWeakComponentOnlyDropped(t *testing.T) {
	matches := []db.IntelTaskMatch{
		{TaskIntel: db.TaskIntel{TaskID: 1, Kind: db.IntelKindComponent, Key: "mariadb@10.1", MatchKey: "mariadb", Value: "MariaDB 10.1"}},
		{TaskIntel: db.TaskIntel{TaskID: 2, Kind: db.IntelKindComponent, Key: "dvwa@1.10", MatchKey: "dvwa", Value: "DVWA 1.10"}},
		{TaskIntel: db.TaskIntel{TaskID: 2, Kind: db.IntelKindEndpoint, Key: "post /vulnerabilities/sqli/", MatchKey: "/vulnerabilities/sqli/", Value: "http://t/x"}},
	}
	out, _ := aggregateReaderLinkCandidates(matches, 10)
	if len(out) != 1 || out[0].TaskID != 2 {
		t.Fatalf("只应有接口命中的任务 2，得到 %+v", out)
	}
	if out[0].HitCount != 2 {
		t.Errorf("强信号候选应保留全部命中（含组件旁证），got %d", out[0].HitCount)
	}
}

// TestRenderReaderAdoptHintIsDirectionOnly 守 V11-READER4：hint 只给方向，
// 不再携带可复用要点/关键事实/凭据掩码——否则执行者照 hint 就能复述结论，
// ask_reader 没人调（实测一轮 3 次下钻全靠人工注入）。
func TestRenderReaderAdoptHintIsDirectionOnly(t *testing.T) {
	text := renderReaderAdoptHint(readerAdoptHint{
		SourceTaskID: 136, SourceTaskName: "任务D", SourceProjectID: 58,
		Strength: "strong", Score: 72,
		Overlap:      []string{"GET /api/sso/userinfo", "POST /api/sso/login"},
		ForeignHosts: []string{"10.0.0.9"},
	})
	for _, banned := range []string{"可复用要点", "关键事实", "掩码", "secret", "cookie for"} {
		if strings.Contains(text, banned) {
			t.Errorf("hint 不应包含 %q：\n%s", banned, text)
		}
	}
	for _, want := range []string{"#136", "72/100", "GET /api/sso/userinfo", "两段", "自主验证", "只复现"} {
		if !strings.Contains(text, want) {
			t.Errorf("hint 缺少 %q：\n%s", want, text)
		}
	}
}

// TestOverlapEndpoints 守 hint 的重合接口：只取 endpoint、去重、保序、截断。
func TestOverlapEndpoints(t *testing.T) {
	hits := []readerLinkHit{
		{Kind: db.IntelKindCredential, Key: "cookie|admin|h:80"},
		{Kind: db.IntelKindEndpoint, Key: "GET /a"},
		{Kind: db.IntelKindEndpoint, Key: "GET /a"},
		{Kind: db.IntelKindAsset, Key: "h:80"},
		{Kind: db.IntelKindEndpoint, Key: "POST /b"},
		{Kind: db.IntelKindEndpoint, Key: "GET /c"},
	}
	got := overlapEndpoints(hits, 2)
	if len(got) != 2 || got[0] != "GET /a" || got[1] != "POST /b" {
		t.Fatalf("overlapEndpoints = %#v, want [GET /a POST /b]", got)
	}
}
