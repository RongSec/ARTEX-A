package db

import (
	"fmt"
	"testing"
	"time"
)

// seedSetting 的语义是「只填空缺」：已有非空值不覆盖，空值才写。
// 这是「.env 导入」不会把页面里改过的配置改回去的唯一保证。
func TestSeedSettingOnlyFillsGaps(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	key := fmt.Sprintf("test.seed_secret.%d", time.Now().UnixNano())
	defer func() { _, _ = d.Exec(`DELETE FROM settings WHERE key=$1`, key) }()

	// 库里没有 → 写入
	if !d.seedSetting(key, "from-env") {
		t.Fatal("空值时应写入")
	}
	if v, ok, _ := d.GetSetting(key); !ok || v != "from-env" {
		t.Fatalf("写入后应为 from-env，实际 %q ok=%v", v, ok)
	}

	// 已有非空值 → 不覆盖
	if d.seedSetting(key, "newer-env") {
		t.Fatal("已有非空值时应跳过")
	}
	if v, _, _ := d.GetSetting(key); v != "from-env" {
		t.Fatalf("不应被覆盖，实际 %q", v)
	}

	// 空环境变量 → 连「缺省填充」都不该发生
	key2 := key + ".empty"
	defer func() { _, _ = d.Exec(`DELETE FROM settings WHERE key=$1`, key2) }()
	if d.seedSetting(key2, "   ") {
		t.Fatal("空值不应写入")
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "  ", "k"); got != "k" {
		t.Fatalf("got %q", got)
	}
	if got := firstNonEmpty(" ", ""); got != "" {
		t.Fatalf("got %q", got)
	}
}
