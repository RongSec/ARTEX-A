package server

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

// V9-SCOPE 实验（临时 PG + 假工具调用）：
//
//	A：任务 A 采纳任务 B（B 资产 10.0.0.9），对 10.0.0.9 发 curl → deny；
//	B：A 对自己的资产 127.0.0.1:9081 发同样命令 → allow（不误伤）；
//	C：任务 C 未采纳任何任务 → 任意 host 放行（回归）；
//	D：hint payload 带 reference_only=true 与 foreign_hosts。
//
// 这里用真实 Guard + 真实 task_foreign_assets / assets 表；工具调用是
// PreToolUse 级的假 Bash 调用（不真发网络请求）。
func TestForeignScopeExperimentPG(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	pg := m.PG()
	ctx := context.Background()
	s := &Server{m: m}

	pid := intelLinkProject(t, pg, "scope-p", true)
	taskA, idA := intelLinkTask(t, s, pg, pid, "scope-a")
	_, idB := intelLinkTask(t, s, pg, pid, "scope-b")
	taskC, idC := intelLinkTask(t, s, pg, pid, "scope-c")

	// B 的资产情报（小结表）：10.0.0.9:80 → 归一成 10.0.0.9。
	if _, err := pg.UpsertTaskIntel(ctx, pid, idB, []db.TaskIntel{
		{Kind: db.IntelKindAsset, Key: "10.0.0.9:80", Value: "10.0.0.9:80", Source: "asset"},
	}); err != nil {
		t.Fatal(err)
	}
	// A 自己的资产 127.0.0.1:9081（走生产登记路径：assets.task_ids + task_scope）。
	if _, err := pg.Assets().RegisterTaskAssetScopes(idA, []db.ScopeInput{{Kind: "ip", Value: "127.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pg.Exec(`UPDATE assets SET task_ids=array_remove(task_ids,$1) WHERE type='ip' AND ip='127.0.0.1'`, idA) //nolint:errcheck
	})

	// A 采纳 B（走生产工具，落 link + 外部资产 + hint）。
	adopt := s.toolAdoptRelatedTask()
	raw, _ := json.Marshal(map[string]any{
		"task_id": idA, "related_task_id": idB, "reason": "同一攻击面可复用打法",
	})
	res, err := adopt.Call(ctx, raw, nil)
	if err != nil || res.IsError {
		t.Fatalf("adopt: err=%v res=%+v", err, res)
	}

	run := func(task *Task, taskID int64, cmd string) (bool, string, []byte) {
		evCtx := intercept.WithTaskContext(ctx, strconv.FormatInt(taskID, 10), "worker", nil)
		return task.Guard.Hooks().PreToolUse(evCtx, "Bash", json.RawMessage(`{"command":`+strconv.Quote(cmd)+`}`))
	}

	// A：外部任务资产 → deny。
	blocked, msg, _ := run(taskA, idA, "curl http://10.0.0.9/x")
	if !blocked {
		t.Fatal("A：对采纳任务 B 的资产 10.0.0.9 应 deny")
	}
	if !strings.Contains(msg, "不在本任务授权范围") {
		t.Fatalf("A：deny 消息应含「不在本任务授权范围」，got %q", msg)
	}
	t.Logf("A: blocked=%v msg=%q", blocked, msg)

	// B：本任务资产 → allow。
	blockedB, msgB, _ := run(taskA, idA, "curl http://127.0.0.1:9081/x")
	if blockedB {
		t.Fatalf("B：本任务资产不得误伤: %s", msgB)
	}
	t.Logf("B: blocked=%v msg=%q", blockedB, msgB)

	// C：未采纳任何任务 → 任意 host 放行。
	blockedC, msgC, _ := run(taskC, idC, "curl http://10.0.0.9/x")
	if blockedC {
		t.Fatalf("C：未采纳任务不应拦截: %s", msgC)
	}
	t.Logf("C: blocked=%v msg=%q", blockedC, msgC)

	// 留痕：decision_source=builtin_foreign_scope。
	var source, reason string
	if err := pg.QueryRow(`SELECT decision_source, reason FROM intercept_pending
WHERE task_id=$1 AND tool_name='Bash' ORDER BY id DESC LIMIT 1`, strconv.FormatInt(idA, 10)).Scan(&source, &reason); err != nil {
		t.Fatalf("读取拦截留痕失败: %v", err)
	}
	if source != "builtin_foreign_scope" {
		t.Fatalf("decision_source=%q want builtin_foreign_scope", source)
	}
	if !strings.Contains(reason, "不在本任务授权范围") {
		t.Fatalf("留痕 reason=%q", reason)
	}

	// D：hint payload 必须声明经验参考 + 列出外部 host。
	var payloadRaw []byte
	if err := pg.QueryRow(`SELECT payload FROM exploration_nodes
WHERE exploration_id=$1 AND kind='hint' ORDER BY id DESC LIMIT 1`, taskA.ExpID).Scan(&payloadRaw); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		t.Fatal(err)
	}
	if ref, _ := payload["reference_only"].(bool); !ref {
		t.Fatalf("D：hint payload 缺 reference_only=true: %+v", payload)
	}
	hosts := fmtHosts(payload["foreign_hosts"])
	if len(hosts) != 1 || hosts[0] != "10.0.0.9" {
		t.Fatalf("D：hint foreign_hosts=%v want [10.0.0.9]", payload["foreign_hosts"])
	}
	ref, _ := payload["reference_only"].(bool)
	t.Logf("D: reference_only=%v foreign_hosts=%v", ref, hosts)
}

func fmtHosts(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}
