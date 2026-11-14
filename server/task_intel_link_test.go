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

	"github.com/Autumn-27/artex/agent"
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
// 装配，否则运行时不出现。
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
	if n := len(s.taskIntelPlannerTools()); n != 3 {
		t.Errorf("planner 勾连工具应为 3 件，got %d", n)
	}
	if n := len(s.taskIntelReaderTools()); n != 2 {
		t.Errorf("reader 勾连工具应为 2 件，got %d", n)
	}
	// seed 绑定：工具行必须存在且只绑对应 agent（planner 三件 / reader 两件）。
	s.seedProjectTools()
	for name, agentKey := range map[string]string{
		"request_reader_links": "planner", "adopt_related_task": "planner", "dismiss_related_task": "planner",
		"read_task_intel": "reader", "link_tasks": "reader",
	} {
		row, err := s.m.pg.GetTool(name)
		if err != nil || row == nil {
			t.Errorf("工具 %s 未入库: err=%v", name, err)
			continue
		}
		if !contains(row.Agents, agentKey) {
			t.Errorf("工具 %s 应绑定 %s，got %v", name, agentKey, row.Agents)
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
	}
	if _, err := pg.UpsertTaskIntel(ctx, pid, idA, rowsA); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.UpsertTaskIntel(ctx, pidC, idC, []db.TaskIntel{
		{Kind: db.IntelKindEndpoint, Key: epKey, Value: "https://c.example.com/api/user/1", Source: "finding"},
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
	bCtx := agent.WithRunInfo(ctx, agent.RunInfo{TaskID: idB})
	var out struct {
		Candidates []readerLinkCandidate `json:"candidates"`
		Note       string                `json:"note"`
	}
	callToolJSON(t, "request_reader_links", call, bCtx, map[string]any{
		"surface": "GET /api/user/123",
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

	// 从 A 自己申请：A 必须被排除。
	aCtx := agent.WithRunInfo(ctx, agent.RunInfo{TaskID: idA})
	out.Candidates = nil
	callToolJSON(t, "request_reader_links", call, aCtx, map[string]any{
		"surface": "GET /api/user/123",
	}, &out)
	for _, c := range out.Candidates {
		if c.TaskID == idA {
			t.Fatalf("当前任务 A 不应作为自己的候选: %+v", out.Candidates)
		}
	}

	// scope=cross：C 未开 reader_enabled → 不返回；开启后才返回。
	out.Candidates = nil
	callToolJSON(t, "request_reader_links", call, bCtx, map[string]any{
		"surface": "GET /api/user/123", "scope": "cross",
	}, &out)
	if len(out.Candidates) != 0 {
		t.Fatalf("C 未开 reader_enabled，cross 不应返回任何候选，got %+v", out.Candidates)
	}
	if _, err := pg.Exec(`UPDATE projects SET reader_enabled=true WHERE id=$1`, pidC); err != nil {
		t.Fatal(err)
	}
	out.Candidates = nil
	callToolJSON(t, "request_reader_links", call, bCtx, map[string]any{
		"surface": "GET /api/user/123", "scope": "cross",
	}, &out)
	if len(out.Candidates) != 1 || out.Candidates[0].TaskID != idC {
		t.Fatalf("C 开启 reader_enabled 后应被 cross 命中，got %+v", out.Candidates)
	}

	// ---------- adopt ----------
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
	adoptCall(bCtx, map[string]any{
		"related_task_id": idA, "reason": "同一用户接口",
		"matched": []map[string]any{{"kind": db.IntelKindEndpoint, "key": epKey, "value": "https://a.example.com/api/user/9"}},
	})
	var decision, reason, matched string
	if err := pg.QueryRow(`SELECT decision, reason, matched::text FROM task_intel_links WHERE task_id=$1 AND related_task_id=$2`, idB, idA).
		Scan(&decision, &reason, &matched); err != nil {
		t.Fatal(err)
	}
	if decision != "adopted" || reason != "同一用户接口" || !strings.Contains(matched, epKey) {
		t.Errorf("adopt 落库不对: decision=%q reason=%q matched=%s", decision, reason, matched)
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
	var hintText string
	if err := pg.QueryRow(`SELECT payload->>'text' FROM exploration_nodes WHERE exploration_id=$1 AND kind='hint' ORDER BY id DESC LIMIT 1`, taskB.ExpID).Scan(&hintText); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hintText, fmt.Sprintf("任务#%d", idA)) || !strings.Contains(hintText, epKey) {
		t.Errorf("hint 正文缺少任务/命中项: %q", hintText)
	}

	// 重复 adopt 幂等：hint 不重复写。
	adoptCall(bCtx, map[string]any{"related_task_id": idA, "reason": "同一用户接口（复核）"})
	if n := hintCount(); n != 1 {
		t.Errorf("重复 adopt 不应重复写 hint，got %d", n)
	}

	// ---------- dismiss ----------
	dismiss := s.toolDismissRelatedTask()
	rawDismiss, _ := json.Marshal(map[string]any{"related_task_id": idC, "reason": "不同资产"})
	rd, err := dismiss.Call(bCtx, rawDismiss, nil)
	if err != nil || rd.IsError {
		t.Fatalf("dismiss: err=%v res=%+v", err, rd)
	}
	if err := pg.QueryRow(`SELECT decision FROM task_intel_links WHERE task_id=$1 AND related_task_id=$2`, idB, idC).Scan(&decision); err != nil {
		t.Fatal(err)
	}
	if decision != "dismissed" {
		t.Errorf("dismiss 决策应为 dismissed，got %q", decision)
	}
	if n := hintCount(); n != 1 {
		t.Errorf("dismiss 不应写 hint，hint 数=%d", n)
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
