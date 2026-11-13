package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

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

// V6-AUTO：判官自己给 ask + policy=auto → 按规则 timeout_action 立即 deny，
// 【不进 pending】。回归点：旧行为会回落人工等 60s，人不在线就按 deny 拦掉。
func TestRouteAskRuleJudgeAskAutoPolicyNoPending(t *testing.T) {
	d := openRouteTestDB(t)
	defer d.Close()
	ic := routeFixture(t, d, "路由测试·ask自主", "ask", "RouteAskAutoProbe", true)
	// 显式钉住 auto，避免同库其它用例留下的设置影响本用例。
	cfg := ic.GetJudgeConfig()
	cfg.AskPolicy = "auto"
	if err := ic.SetJudgeConfig(cfg); err != nil {
		t.Fatal(err)
	}
	ic.SetReviewer(func(context.Context, int64, string, intercept.ReviewInput) (intercept.Decision, error) {
		return intercept.Decision{Action: "ask", Message: "拿不准是否影响业务"}, nil
	})
	g := NewWithInterceptor(ic)
	// taskID 带纳秒后缀：route 测试用 defer d.Close()，t.Cleanup 的删除在
	// 关库后执行会静默失败；唯一 ID 让本用例在持久库上重复跑也不串行。
	taskID := fmt.Sprintf("route-ask-auto-%d", time.Now().UnixNano())
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id=$1`, taskID) })
	ctx := intercept.WithTaskContext(context.Background(), taskID, "route-agent", nil)
	blocked, msg, _ := g.Hooks().PreToolUse(ctx, "RouteAskAutoProbe", json.RawMessage(`{"probe":1}`))
	if !blocked {
		t.Fatal("规则 timeout_action=deny 时，判官 ask 应自主 deny")
	}
	if !strings.Contains(msg, "[自主]") {
		t.Fatalf("拦截消息应带 [自主] 留痕，得到 %q", msg)
	}
	var pending int
	if err := d.QueryRow(`SELECT count(*) FROM intercept_pending WHERE task_id=$1 AND status='pending'`, taskID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("自主落定不得创建 pending 记录，实际 %d 条", pending)
	}
	rows, err := d.ListTaskIntercepts(taskID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("应恰好一条审计留痕（denied/model），rows=%d err=%v", len(rows), err)
	}
	if rows[0].Status != "denied" || rows[0].DecisionSource != "model" {
		t.Fatalf("留痕应为 denied/model，得到 %+v", rows[0])
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

// V5-E：内置规则 #1「[内置] 递归强制删除 rm -rf」由 deny 降为 ask 后，这条
// v1 规则（tool_input 正则、priority 100）命中也必须走 V4-D 的「ask 交判官」
// 路由——不能是「只有短路口和 tool_name 型 ask 才交判官」。这里不做桩规则，
// 直接用库里种子出来的那条规则打 Bash 命令，锁死真实链路的两个分支：
// 判官开启 → 交裁；判官关闭 → 人工审批（不送判官）。
func TestRouteRmRecursiveBuiltinRuleIsAskRouted(t *testing.T) {
	d := openRouteTestDB(t)
	defer d.Close()

	const ruleName = "[内置] 递归强制删除 rm -rf"
	var action string
	var timeout bool
	var timeoutSecs int
	if err := d.QueryRow(`SELECT action, timeout_enabled, timeout_seconds FROM intercept_rules WHERE name=$1`,
		ruleName).Scan(&action, &timeout, &timeoutSecs); err != nil {
		t.Fatalf("库中应有种子规则 %q: %v", ruleName, err)
	}
	if action != "ask" {
		t.Fatalf("种子规则 %q 的动作应为 ask（V5-E），得到 %q", ruleName, action)
	}
	// ask 落地人工时必须有时限：v1 出厂是 deny+timeout_enabled=false，漏了这一步
	// 判官未启用/故障回落时 HandleAsk 会无限等人工，一条 rm -rf 挂死整个 task。
	// V6-AUTO：超时收紧到 15s（判官 ask 已自主落定，只有故障时才用这 15s）。
	if !timeout {
		t.Fatalf("种子规则 %q 的审批超时必须是打开的（15s→deny）", ruleName)
	}
	if timeoutSecs != 15 {
		t.Fatalf("种子规则 %q 的审批超时应为 15s（V6-AUTO），得到 %d", ruleName, timeoutSecs)
	}

	ic := intercept.New(d)
	priorTools, err := ic.GetEnabledTools()
	if err != nil {
		t.Fatal(err)
	}
	priorCfg := ic.GetJudgeConfig()
	t.Cleanup(func() { _ = ic.SetEnabledTools(priorTools); _ = ic.SetJudgeConfig(priorCfg) })
	if err := ic.SetEnabledTools([]string{"Bash"}); err != nil {
		t.Fatal(err)
	}
	g := NewWithInterceptor(ic)
	input := json.RawMessage(`{"command":"rm -rf /tmp/sqlmap-out"}`)

	t.Run("判官开启 → 交判官，allow 放行", func(t *testing.T) {
		if err := ic.SetJudgeConfig(intercept.JudgeConfig{Enabled: true}); err != nil {
			t.Fatal(err)
		}
		asked := false
		ic.SetReviewer(func(_ context.Context, _ int64, _ string, in intercept.ReviewInput) (intercept.Decision, error) {
			asked = true
			return intercept.Decision{Action: "allow", Message: "清理本次扫描产物，不影响业务"}, nil
		})
		taskID := "route-rm-recursive-judge"
		t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id=$1`, taskID) })
		ctx := intercept.WithTaskContext(context.Background(), taskID, "route-agent", nil)
		blocked, _, _ := g.Hooks().PreToolUse(ctx, "Bash", input)
		if !asked {
			t.Fatal("规则 #1 命中 ask 时必须送判官（v1 规则同样走 V4-D 路由）")
		}
		if blocked {
			t.Fatal("判官 allow 后不应阻塞")
		}
	})

	t.Run("判官关闭 → 进人工审批，不送判官", func(t *testing.T) {
		if err := ic.SetJudgeConfig(intercept.JudgeConfig{Enabled: false}); err != nil {
			t.Fatal(err)
		}
		asked := false
		ic.SetReviewer(func(_ context.Context, _ int64, _ string, _ intercept.ReviewInput) (intercept.Decision, error) {
			asked = true
			return intercept.Decision{Action: "allow", Message: "不该被调用"}, nil
		})
		taskID := "route-rm-recursive-human"
		t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id=$1`, taskID) })
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
		blocked, _, _ := g.Hooks().PreToolUse(ctx, "Bash", input)
		if asked {
			t.Fatal("判官关闭时不得送判官")
		}
		if !reachedHuman {
			t.Fatal("判官关闭的 ask 必须进人工审批（fail-closed 兜底）")
		}
		if blocked {
			t.Fatal("人工放行后不应阻塞")
		}
	})
}
