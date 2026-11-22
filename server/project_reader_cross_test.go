package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// V4-E reader「资产优先」输入面：prompt 升级判定（纯函数）与工具返回结构。

// readerPromptUpgradeFor 的三分支必须互斥且覆盖：空=播种、旧默认=升级、
// 用户编辑过=不动（升级默认正文绝不能冲掉用户手写内容）。
func TestReaderPromptUpgradeFor(t *testing.T) {
	cases := []struct {
		desc string
		cur  string
		want readerPromptUpgrade
	}{
		{"空 prompt", "", readerPromptSeed},
		{"空白 prompt", "  \n\t", readerPromptSeed},
		{"旧默认", readerPromptV1, readerPromptReplace},
		{"旧默认带尾随空白", readerPromptV1 + "\n\n", readerPromptReplace},
		{"V4-E 资产优先旧默认", readerPrompt, readerPromptReplace}, // V6-U3 起也是旧默认，升到统一版
		{"V6 统一版旧默认", readerUnifiedPromptV6, readerPromptReplace},
		{"V7-LINK 旧默认", readerUnifiedPrompt, readerPromptReplace},      // V8-NAME 起升级到新称谓版
		{"V8-NAME 旧默认", readerUnifiedPromptNames, readerPromptReplace}, // V9-READER 起升级到下钻判定版
		{"V9-READER 旧默认", readerUnifiedPromptV9, readerPromptReplace}, // V11 起升级到评分版
		{"V10-READER 旧默认", readerUnifiedPromptV10, readerPromptReplace}, // V11 起升级到评分版
		{"V11-READER3 旧默认", readerUnifiedPromptV11, readerPromptReplace}, // V11-READER7 起升级到独立判官版
		{"V12 当前默认", readerUnifiedPromptV12, readerPromptKeep},
		{"用户编辑过", readerPromptV1 + "\n补充：只看 443 端口。", readerPromptKeep},
		{"用户全新正文", "自定义阅读者", readerPromptKeep},
	}
	for _, c := range cases {
		if got := readerPromptUpgradeFor(c.cur); got != c.want {
			t.Fatalf("%s：readerPromptUpgradeFor 得到 %v，期望 %v", c.desc, got, c.want)
		}
	}
	// 新默认正文必须与旧默认不同（否则「升级」是空操作，测试上面的 replace 分支
	// 也就失去意义）。
	if readerPrompt == readerPromptV1 {
		t.Fatal("readerPrompt 与 readerPromptV1 相同：默认正文升级无从发生")
	}
	if readerUnifiedPromptNames == readerUnifiedPrompt {
		t.Fatal("新称谓默认正文与 V7 默认相同：V8-NAME 升级无从发生")
	}
	if readerUnifiedPromptV9 == readerUnifiedPromptNames {
		t.Fatal("V9-READER 默认正文与 V8 默认相同：下钻判定升级无从发生")
	}
	if !strings.Contains(readerUnifiedPromptV9, "不要把未判定的候选丢给规划者") ||
		!strings.Contains(readerUnifiedPromptV9, "最多判定 3 个候选") {
		t.Fatal("V9-READER 默认正文缺少下钻判定工作流关键约束")
	}
	if readerUnifiedPromptV11 == readerUnifiedPromptV10 {
		t.Fatal("V11 默认正文与 V10 相同：两级评分升级无从发生")
	}
	for _, want := range []string{"relevance_score", "chains", "match_score", "since_rev"} {
		if !strings.Contains(readerUnifiedPromptV11, want) {
			t.Fatalf("V11 默认正文缺少关键字段 %q", want)
		}
	}
	if readerUnifiedPromptV12 == readerUnifiedPromptV11 {
		t.Fatal("V12 默认正文与 V11 相同：独立判官升级无从发生")
	}
	for _, want := range []string{"judge_related_tasks", "独立上下文", "candidate_ids"} {
		if !strings.Contains(readerUnifiedPromptV12, want) {
			t.Fatalf("V12 默认正文缺少关键字段 %q", want)
		}
	}
}

// 工具返回结构：cross_project_assets 与 projects 并存；cross_project_assets
// 必须按 reader_enabled 可见集裁剪（未开闸项目不得出现在行里）。
func TestReadAllProjectInsightsCrossProjectAssets(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	n := time.Now().UnixNano()
	suffix := strconv.FormatInt(n%1000000, 10)
	sharedIP := fmt.Sprintf("10.97.%d.%d", n%256, (n/256)%256)

	projA, err := pg.CreateProject(db.CreateProjectInput{Name: "reader-a-" + suffix, ReaderEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	projB, err := pg.CreateProject(db.CreateProjectInput{Name: "reader-b-" + suffix, ReaderEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	projC, err := pg.CreateProject(db.CreateProjectInput{Name: "reader-c-" + suffix}) // 未开 reader_enabled
	if err != nil {
		t.Fatal(err)
	}
	pidA, pidB, pidC := projA.ID, projB.ID, projC.ID
	taskA, err := pg.CreateTaskWithOptions("reader a", "goal", db.TaskCreateOptions{ProjectID: &pidA})
	if err != nil {
		t.Fatal(err)
	}
	taskB, err := pg.CreateTaskWithOptions("reader b", "goal", db.TaskCreateOptions{ProjectID: &pidB})
	if err != nil {
		t.Fatal(err)
	}
	taskC, err := pg.CreateTaskWithOptions("reader c", "goal", db.TaskCreateOptions{ProjectID: &pidC})
	if err != nil {
		t.Fatal(err)
	}
	var assetID int64
	if err := pg.QueryRow(`INSERT INTO assets(type, ip) VALUES ('ip', $1) RETURNING id`, sharedIP).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, tid := range []int64{taskA.ID, taskB.ID, taskC.ID} {
			_, _ = pg.DeleteTaskCascade(tid, false, true)
		}
		_, _ = pg.Exec(`DELETE FROM assets WHERE id=$1`, assetID)
		for _, pid := range []int64{pidA, pidB, pidC} {
			_ = pg.DeleteProject(pid)
		}
	}()

	for _, tid := range []int64{taskA.ID, taskB.ID, taskC.ID} {
		if _, err := pg.AddFinding(tid, 0, "rce", "x", "high", "s", "e", "w", []int64{assetID}); err != nil {
			t.Fatal(err)
		}
	}

	s := &Server{m: &Manager{pg: pg}}
	tool := s.toolReadCrossProjectAssets()
	res, err := tool.Call(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("工具调用失败: err=%v res=%+v", err, res)
	}
	if len(res.Content) == 0 {
		t.Fatal("工具返回空内容")
	}
	var out struct {
		CrossProjectAssets []db.CrossProjectAssetRow `json:"cross_project_assets"`
	}
	text := res.Content[0].Text
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("返回体不是预期对象结构: %v（原文 %s）", err, text)
	}
	var hit *db.CrossProjectAssetRow
	for i := range out.CrossProjectAssets {
		if out.CrossProjectAssets[i].AssetID == assetID {
			hit = &out.CrossProjectAssets[i]
		}
	}
	if hit == nil {
		t.Fatalf("共享资产 %d 应出现在 cross_project_assets，得到 %+v", assetID, out.CrossProjectAssets)
	}
	// C 未开 reader_enabled：行里只应剩 A/B 两个项目。
	if hit.ProjectCount != 2 || len(hit.Projects) != 2 {
		t.Fatalf("reader_enabled 裁剪后应剩 2 个项目，得到 %+v", hit)
	}
	for _, p := range hit.Projects {
		if p.ID == pidC {
			t.Fatalf("未开 reader_enabled 的项目 %d 不应出现在 cross_project_assets", pidC)
		}
	}
}
