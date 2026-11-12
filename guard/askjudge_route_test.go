package guard

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

// ============================================================================
// V4-D 修复1 的 guard 路由面（DB 版，无库跳过，与 askburst/judge 测试同款）：
// 路由代码在 applyIntercept 的 !matched/ask 分支里，无法脱离 Interceptor.Match
// （DB 规则加载）做纯函数测试，故这里跑真实拦截链。
// 交裁语义本体（allow/deny/故障回落）已在 intercept/askjudge_test.go 纯函数钉住。
// ============================================================================

func openRouteTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("无数据库配置 (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("打开库失败: %v", err)
	}
	return d
}

// routeFixture 建一条 tool_name 命中的规则并配好 enabled tools / judge 开关，
// 返回 guard 与还原钩子。taskID 供各用例清理 intercept_pending。
func routeFixture(t *testing.T, d *db.DB, ruleName, action, probeTool string, judgeEnabled bool) *intercept.Interceptor {
	t.Helper()
	ic := intercept.New(d)
	priorTools, err := ic.GetEnabledTools()
	if err != nil {
		t.Fatal(err)
	}
	priorCfg := ic.GetJudgeConfig()
	t.Cleanup(func() { _ = ic.SetEnabledTools(priorTools); _ = ic.SetJudgeConfig(priorCfg) })
	rule, err := d.CreateInterceptRule(ruleName, "tool_name", "string", probeTool, action, "路由测试", 100, true, false, 0, "deny")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_rules WHERE id=$1`, rule.ID) })
	if err := ic.SetEnabledTools([]string{probeTool}); err != nil {
		t.Fatal(err)
	}
	if err := ic.SetJudgeConfig(intercept.JudgeConfig{Enabled: judgeEnabled}); err != nil {
		t.Fatal(err)
	}
	return ic
}

// 测例5：deny 规则命中 + 判官开启 → 仍拒，且【判官根本不被调用】
// （硬规则不因模型翻案）。判官故意配成必返 allow —— 若误送判官会被放行，测试即炸。
func TestRouteDenyRuleNeverCallsJudge(t *testing.T) {
	d := openRouteTestDB(t)
	defer d.Close()
	ic := routeFixture(t, d, "路由测试·deny", "deny", "RouteDenyProbe", true)
	called := false
	ic.SetReviewer(func(context.Context, int64, string, intercept.ReviewInput) (intercept.Decision, error) {
		called = true
		return intercept.Decision{Action: "allow", Message: "should-never-be-asked"}, nil
	})
	g := NewWithInterceptor(ic)
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id='route-deny'`) })
	ctx := intercept.WithTaskContext(context.Background(), "route-deny", "route-agent", nil)
	blocked, _, _ := g.Hooks().PreToolUse(ctx, "RouteDenyProbe", json.RawMessage(`{"probe":1}`))
	if !blocked {
		t.Fatal("deny 规则命中必须拦截")
	}
	if called {
		t.Fatal("deny 命中不得送判官（硬规则不因模型翻案）")
	}
}

// ask 规则命中 + 判官开启 + 模型 allow → 放行且 decision_source=model 留痕，
// 不进 pending 等待（回归点：此前直接进人工、60s 超时 deny）。
func TestRouteAskRuleJudgeAllowPassesWithAudit(t *testing.T) {
	d := openRouteTestDB(t)
	defer d.Close()
	ic := routeFixture(t, d, "路由测试·ask", "ask", "RouteAskProbe", true)
	asked := false
	ic.SetReviewer(func(context.Context, int64, string, intercept.ReviewInput) (intercept.Decision, error) {
		asked = true
		return intercept.Decision{Action: "allow", Message: "只读，放行"}, nil
	})
	g := NewWithInterceptor(ic)
	taskID := "route-ask-allow"
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id=$1`, taskID) })
	ctx := intercept.WithTaskContext(context.Background(), taskID, "route-agent", nil)
	blocked, _, _ := g.Hooks().PreToolUse(ctx, "RouteAskProbe", json.RawMessage(`{"probe":1}`))
	if blocked {
		t.Fatal("判官 allow 后不得阻塞进人工等待")
	}
	if !asked {
		t.Fatal("ask 命中 + 判官开启必须送判官")
	}
	rows, err := d.ListTaskIntercepts(taskID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("应恰好一条审计留痕，rows=%d err=%v", len(rows), err)
	}
	row := rows[0]
	if row.Status != "allowed" || row.DecisionSource != "model" {
		t.Fatalf("留痕应为 allowed/model，得到 %+v", row)
	}
}

// 基线不变：ask 规则命中 + 判官关闭 → 不送判官、照常进人工 pending，
// 人工放行后通过（emit 回调里 Decide，同 capture_approval_test 范式）。
func TestRouteAskRuleJudgeOffGoesToHuman(t *testing.T) {
	d := openRouteTestDB(t)
	defer d.Close()
	ic := routeFixture(t, d, "路由测试·ask关", "ask", "RouteAskOffProbe", false)
	asked := false
	ic.SetReviewer(func(context.Context, int64, string, intercept.ReviewInput) (intercept.Decision, error) {
		asked = true
		return intercept.Decision{Action: "allow", Message: "不该被调用"}, nil
	})
	g := NewWithInterceptor(ic)
	taskID := "route-ask-off"
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id=$1`, taskID) })
	// emit 回调收到 intercept_request 即"已进入人工审批"，当场人工放行解阻塞。
	reachedHuman := false
	ctx := intercept.WithTaskContext(context.Background(), taskID, "route-agent", func(a db.Activity) {
		if a.Kind != "intercept_request" {
			return
		}
		reachedHuman = true
		var detail struct {
			ID int64 `json:"pending_id"`
		}
		if json.Unmarshal([]byte(a.Detail), &detail) == nil {
			if err := ic.Decide(detail.ID, true); err != nil {
				t.Error(err)
			}
		}
	})
	blocked, _, _ := g.Hooks().PreToolUse(ctx, "RouteAskOffProbe", json.RawMessage(`{"probe":1}`))
	if asked {
		t.Fatal("判官关闭时不得送判官（基线不变）")
	}
	if !reachedHuman {
		t.Fatal("判官关闭的 ask 必须进人工审批")
	}
	if blocked {
		t.Fatal("人工放行后不应阻塞")
	}
	rows, err := d.ListTaskIntercepts(taskID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("人工审批应留一条记录，rows=%d err=%v", len(rows), err)
	}
	if rows[0].DecisionSource != "rule" {
		t.Fatalf("判官关闭时的留痕来源仍应是 rule（未交模型），得到 %q", rows[0].DecisionSource)
	}
}
