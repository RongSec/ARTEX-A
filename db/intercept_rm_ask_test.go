package db

import (
	"database/sql"
	"errors"
	"regexp"
	"testing"
)

// V5-E：规则 #1「[内置] 递归强制删除 rm -rf」从 deny 降为 ask，交判官按
// 「可逆性 × 作用对象」裁决（rm 的目标归属正则判不了）。存量库靠
// downgradeRmRecursiveToAsk 幂等迁移。这里锁死迁移的三种情形：只降出厂行，
// 用户改过的规则与已降过的行都不碰。
func TestDowngradeRmRecursiveToAsk(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	// 必须用 Cleanup 而非 defer：t.Cleanup 在 defer 之后执行，defer d.Close()
	// 会先关库，让下面的还原清理静默失败（Exec 报 database is closed 被忽略）。
	t.Cleanup(func() { d.Close() })

	// 记下出厂行的原值并还原，避免污染同库其它用例。规则被用户删过时
	// 临时造一行，结束后删除。
	var origAction, origPattern string
	var origTimeout bool
	err = d.QueryRow(`SELECT action, pattern, timeout_enabled FROM intercept_rules WHERE name=$1 ORDER BY id LIMIT 1`,
		rmRecursiveRuleName).Scan(&origAction, &origPattern, &origTimeout)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message)
VALUES ($1, true, 100, 'tool_input', 'regex', $2, 'deny', 'v5e test')`,
			rmRecursiveRuleName, rmRecursivePattern); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = d.Exec(`DELETE FROM intercept_rules WHERE name=$1 AND message='v5e test'`, rmRecursiveRuleName)
		})
	case err != nil:
		t.Fatal(err)
	default:
		t.Cleanup(func() {
			_, _ = d.Exec(`UPDATE intercept_rules SET action=$1, pattern=$2, timeout_enabled=$3 WHERE name=$4`,
				origAction, origPattern, origTimeout, rmRecursiveRuleName)
		})
	}

	// set 把规则摆回指定形态；factoryTimeout=false 模拟 v1 出厂行（deny 用不上
	// 审批超时，timeout_enabled=false）。
	set := func(t *testing.T, action, pattern string, factoryTimeout bool) {
		t.Helper()
		if _, err := d.Exec(`UPDATE intercept_rules SET action=$1, pattern=$2, timeout_enabled=$3, timeout_action='deny' WHERE name=$4`,
			action, pattern, factoryTimeout, rmRecursiveRuleName); err != nil {
			t.Fatal(err)
		}
	}
	state := func(t *testing.T) (action, pattern string, timeout bool) {
		t.Helper()
		if err := d.QueryRow(`SELECT action, pattern, timeout_enabled FROM intercept_rules WHERE name=$1 ORDER BY id LIMIT 1`,
			rmRecursiveRuleName).Scan(&action, &pattern, &timeout); err != nil {
			t.Fatal(err)
		}
		return action, pattern, timeout
	}

	t.Run("旧 deny 且仍是出厂 pattern → 改 ask 并打开审批超时", func(t *testing.T) {
		set(t, "deny", rmRecursivePattern, false)
		if err := d.downgradeRmRecursiveToAsk(); err != nil {
			t.Fatal(err)
		}
		action, pattern, timeout := state(t)
		if action != "ask" || pattern != rmRecursivePattern {
			t.Fatalf("want action=ask 且 pattern 不变, got action=%q pattern=%q", action, pattern)
		}
		// 超时必须同时打开：否则 HandleAsk 无超时分支会无限等人工，判官没开时
		// 一条 rm -rf 能把 task 挂死。
		if !timeout {
			t.Fatal("降 ask 必须打开审批超时（无人处理 → deny）")
		}
	})

	t.Run("已是 ask → 不动", func(t *testing.T) {
		set(t, "ask", rmRecursivePattern, true)
		if err := d.downgradeRmRecursiveToAsk(); err != nil {
			t.Fatal(err)
		}
		if action, _, _ := state(t); action != "ask" {
			t.Fatalf("want action 保持 ask, got %q", action)
		}
	})

	t.Run("pattern 被用户改过 → 不动", func(t *testing.T) {
		const custom = `(?i)\brm\b\s+-rf\s+/var/www\b`
		set(t, "deny", custom, false)
		if err := d.downgradeRmRecursiveToAsk(); err != nil {
			t.Fatal(err)
		}
		action, pattern, timeout := state(t)
		if action != "deny" || pattern != custom || timeout {
			t.Fatalf("用户改过的规则不该被迁移, got action=%q pattern=%q timeout=%t", action, pattern, timeout)
		}
	})
}

// V6-AUTO：规则 #1 的审批超时从 60s 收紧到 15s（判官 ask 已自主落定，
// 15s 只在判官故障回落人工时生效）。迁移守卫与降 ask 同款：只动仍是出厂
// 形态的行，用户改过超时/正则的不覆盖。
func TestShortenRmRecursiveAskTimeout(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	var origAction, origPattern string
	var origEnabled bool
	var origSecs int
	err = d.QueryRow(`SELECT action, pattern, timeout_enabled, timeout_seconds FROM intercept_rules WHERE name=$1 ORDER BY id LIMIT 1`,
		rmRecursiveRuleName).Scan(&origAction, &origPattern, &origEnabled, &origSecs)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, true, 100, 'tool_input', 'regex', $2, 'ask', 'v6auto test', true, 60, 'deny')`,
			rmRecursiveRuleName, rmRecursivePattern); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = d.Exec(`DELETE FROM intercept_rules WHERE name=$1 AND message='v6auto test'`, rmRecursiveRuleName)
		})
	case err != nil:
		t.Fatal(err)
	default:
		t.Cleanup(func() {
			_, _ = d.Exec(`UPDATE intercept_rules SET action=$1, pattern=$2, timeout_enabled=$3, timeout_seconds=$4 WHERE name=$5`,
				origAction, origPattern, origEnabled, origSecs, rmRecursiveRuleName)
		})
	}

	set := func(t *testing.T, action, pattern string, enabled bool, secs int) {
		t.Helper()
		if _, err := d.Exec(`UPDATE intercept_rules SET action=$1, pattern=$2, timeout_enabled=$3, timeout_seconds=$4, timeout_action='deny' WHERE name=$5`,
			action, pattern, enabled, secs, rmRecursiveRuleName); err != nil {
			t.Fatal(err)
		}
	}
	secs := func(t *testing.T) int {
		t.Helper()
		var n int
		if err := d.QueryRow(`SELECT timeout_seconds FROM intercept_rules WHERE name=$1 ORDER BY id LIMIT 1`,
			rmRecursiveRuleName).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	t.Run("出厂 ask+60s → 15s", func(t *testing.T) {
		set(t, "ask", rmRecursivePattern, true, 60)
		if err := d.shortenRmRecursiveAskTimeout(); err != nil {
			t.Fatal(err)
		}
		if got := secs(t); got != 15 {
			t.Fatalf("want timeout_seconds=15, got %d", got)
		}
	})

	t.Run("用户改过超时值 → 不动", func(t *testing.T) {
		set(t, "ask", rmRecursivePattern, true, 30)
		if err := d.shortenRmRecursiveAskTimeout(); err != nil {
			t.Fatal(err)
		}
		if got := secs(t); got != 30 {
			t.Fatalf("用户配置不应被覆盖，want 30, got %d", got)
		}
	})

	t.Run("action 非 ask → 不动", func(t *testing.T) {
		set(t, "deny", rmRecursivePattern, false, 60)
		if err := d.shortenRmRecursiveAskTimeout(); err != nil {
			t.Fatal(err)
		}
		if got := secs(t); got != 60 {
			t.Fatalf("非 ask 行不应被迁移，want 60, got %d", got)
		}
	})

	t.Run("pattern 被用户改过 → 不动", func(t *testing.T) {
		const custom = `(?i)\brm\b\s+-rf\s+/var/www\b`
		set(t, "ask", custom, true, 60)
		if err := d.shortenRmRecursiveAskTimeout(); err != nil {
			t.Fatal(err)
		}
		if got := secs(t); got != 60 {
			t.Fatalf("用户改过的正则不应被迁移，want 60, got %d", got)
		}
	})
}

// V5-E 只改 action，正则不动：两条对照命令仍然都命中规则 #1（于是都进判官），
// 极端样本（根目录、--no-preserve-root）也仍在覆盖内。
func TestRmRecursiveSeedPatternUnchanged(t *testing.T) {
	re := regexp.MustCompile(rmRecursivePattern)
	for _, cmd := range []string{
		`rm -rf /tmp/sqlmap-out`, // 清理本次扫描产物 → 判官 A2 allow
		`rm -rf /var/www/html`,   // 删目标生产文件 → 判官 D4 deny
		`rm -rf /`,               // 极端样本仍命中
		`rm --recursive /tmp/x`,
		`rm -fr /tmp/x`,
		`rm -rf --no-preserve-root /`,
	} {
		if !re.MatchString(cmd) {
			t.Errorf("规则 #1 正则应当命中 %q（改 ask 不等于放宽匹配面）", cmd)
		}
	}
	for _, cmd := range []string{`rm /tmp/x`, `rm -f /tmp/x.log`, `rmdir /tmp/x`} {
		if re.MatchString(cmd) {
			t.Errorf("非递归删除 %q 不该命中规则 #1", cmd)
		}
	}
}
