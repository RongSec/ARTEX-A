package vulnintel

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestEnsureTemplatesRepoSwitch 验证「库配置里换了模板源」会真的重建模板树。
//
// 为什么必须测:origin 还指旧地址时,`git pull` 只会拉旧仓库,页面显示
// 「同步成功、模板数不变」,用户以为换源生效了。这里用两个本地仓库模拟
// 镜像切换,断言第二次 clone 来自新仓库。
func TestEnsureTemplatesRepoSwitch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git 不在 PATH")
	}
	tmp := t.TempDir()
	mkrepo := func(name, marker string) string {
		dir := filepath.Join(tmp, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		write := func(rel, body string) {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		write("http/test.yaml", "id: "+marker+"\n")
		write("README.md", marker+"\n")
		for _, args := range [][]string{
			{"init", "-q"},
			{"config", "user.email", "t@t"},
			{"config", "user.name", "t"},
			{"add", "."},
			{"commit", "-qm", marker},
		} {
			cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v %s", args, err, out)
			}
		}
		return dir
	}
	repoA := mkrepo("repo-a", "from-a")
	repoB := mkrepo("repo-b", "from-b")
	target := filepath.Join(tmp, "checkout")

	ctx := context.Background()
	if err := EnsureTemplates(ctx, target, "", repoA); err != nil {
		t.Fatalf("首次 clone A: %v", err)
	}
	if n := CountTemplates(target); n != 1 {
		t.Fatalf("A 模板数 = %d, 期望 1", n)
	}
	// 换源:应删掉旧树、从 B 重建。
	if err := EnsureTemplates(ctx, target, "", repoB); err != nil {
		t.Fatalf("换源 clone B: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(target, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) == "from-a\n" {
		t.Fatal("换源后内容仍来自旧仓库 —— origin 没换")
	}
	// 同源再跑一次走 pull 分支,不应失败。
	if err := EnsureTemplates(ctx, target, "", repoB); err != nil {
		t.Fatalf("同源 pull: %v", err)
	}
}
