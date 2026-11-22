package db

// V5-A 洞察生命周期与跨项目注入原料的单测：
//   - DeriveAssetKeys：纯函数（无库），钉死「正文反查已知资产键」的召回边界；
//   - PG 集成（无库自动 skip，照仓库 testDSN 范式）：同资产新洞察覆盖旧行
//     （superseded_by 正确）、ListInsights 排除 rejected、RejectInsight 的
//     幂等/不存在语义、RejectInsight 后跨项目注入不再返回该行。

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"
)

func TestDeriveAssetKeys(t *testing.T) {
	cands := []string{
		"canal.example.com",
		"10.0.0.8",
		"ab",          // 短于阈值：不参与匹配
		"dup.example", // 与下面重复（大小写不同）
		"DUP.example",
		"",
	}
	content := "在 CANAL.example.com 与 10.0.0.8 上同版本组件可复用；ab 这种短串不算。"
	got := DeriveAssetKeys(content, cands)
	want := []string{"10.0.0.8", "canal.example.com"}
	if len(got) != len(want) {
		t.Fatalf("DeriveAssetKeys = %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("DeriveAssetKeys = %v want %v", got, want)
		}
	}

	// 没命中任何已知键 → 空（该条洞察永不注入，只能人工看）。
	if got := DeriveAssetKeys("只写了组件名 canal v1.1.5，没有资产键", cands); len(got) != 0 {
		t.Errorf("no-hit must return empty, got %v", got)
	}
	// 边界：空正文/空候选 → nil，不 panic。
	if got := DeriveAssetKeys("", cands); got != nil {
		t.Errorf("empty content must return nil, got %v", got)
	}
	if got := DeriveAssetKeys(content, nil); got != nil {
		t.Errorf("empty candidates must return nil, got %v", got)
	}
	// 去重：同一个键在正文出现多次只算一次。
	dup := DeriveAssetKeys("dup.example 与 Dup.Example 都是同一台", []string{"dup.example", "DUP.example"})
	if len(dup) != 1 {
		t.Errorf("dedupe failed: %v", dup)
	}
}

// TestGlobalInsightSupersede 验同资产覆盖：写新洞察后旧行置 superseded、
// superseded_by=新 id，且注入查询只返回新行。
func TestGlobalInsightSupersede(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	key := fmt.Sprintf("insight-supersede-%d.example.com", time.Now().UnixNano())
	oldIns, err := d.WriteGlobalInsight(ctx, "旧结论：该资产可用打法等", []int64{1}, []string{key})
	if err != nil {
		t.Fatal(err)
	}
	newIns, err := d.WriteGlobalInsight(ctx, "新结论：该资产版本已升级，旧打法失效", []int64{1, 2}, []string{key})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		d.Exec(`DELETE FROM global_insights WHERE id = ANY($1::bigint[])`, marshalInt64Array([]int64{oldIns.ID, newIns.ID})) //nolint:errcheck
	}()

	if newIns.Status != InsightStatusActive || len(newIns.AssetKeys) != 1 || newIns.AssetKeys[0] != key {
		t.Fatalf("new row shape wrong: %+v", newIns)
	}
	var status string
	var supersededBy int64
	if err := d.QueryRow(`SELECT status, COALESCE(superseded_by,0) FROM global_insights WHERE id=$1`, oldIns.ID).
		Scan(&status, &supersededBy); err != nil {
		t.Fatal(err)
	}
	if status != InsightStatusSuperseded {
		t.Errorf("旧行 status = %q want %q", status, InsightStatusSuperseded)
	}
	if supersededBy != newIns.ID {
		t.Errorf("superseded_by = %d want %d", supersededBy, newIns.ID)
	}

	// 注入查询只应看到新行（旧行不再 active）。
	list, err := d.ListCrossProjectInsights(ctx, []string{key}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != newIns.ID {
		t.Fatalf("injectable = %+v want only id %d", globalIDs(list), newIns.ID)
	}

	// 无交集键 → 空；空键集 → 空（永不注入的兜底语义）。
	if l, err := d.ListCrossProjectInsights(ctx, []string{"no-such-key.example"}, 10); err != nil || len(l) != 0 {
		t.Errorf("non-intersecting keys must return empty, got %v err=%v", globalIDs(l), err)
	}
	if l, err := d.ListCrossProjectInsights(ctx, nil, 10); err != nil || len(l) != 0 {
		t.Errorf("nil keys must return empty, got %v err=%v", globalIDs(l), err)
	}
}

// TestInsightRejectLifecycle 验 ListInsights 只取 active，以及 RejectInsight
// 的幂等/不存在语义（project 与 global 两类）。
func TestInsightRejectLifecycle(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	suffix := strconv.FormatInt(time.Now().UnixNano()%1000000, 10)
	p, err := d.CreateProject(CreateProjectInput{Name: "insight-reject-" + suffix, ReaderEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM projects WHERE id=$1`, p.ID) //nolint:errcheck // project_insights 级联删

	in, err := d.WriteInsight(ctx, p.ID, "待否决的项目洞察", 0, []string{"canal.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	list, err := d.ListInsights(ctx, p.ID, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if n := findInsight(list, in.ID); n == nil {
		t.Fatalf("刚写的 active 洞察不在 ListInsights 里: %+v", list)
	}

	changed, err := d.RejectInsight(ctx, "project", in.ID, "版本不同，本目标不成立")
	if err != nil || !changed {
		t.Fatalf("reject: changed=%v err=%v", changed, err)
	}
	if list, err = d.ListInsights(ctx, p.ID, nil, 10); err != nil {
		t.Fatal(err)
	} else if findInsight(list, in.ID) != nil {
		t.Errorf("rejected 洞察不应再出现在 ListInsights: %+v", list)
	}
	var status, reason string
	if err := d.QueryRow(`SELECT status, rejected_reason FROM project_insights WHERE id=$1`, in.ID).
		Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != InsightStatusRejected || reason != "版本不同，本目标不成立" {
		t.Errorf("rejected 落库 status=%q reason=%q", status, reason)
	}

	// 幂等：再拒一次 → changed=false 且不报错；空 reason 不抹掉已有留痕。
	changed, err = d.RejectInsight(ctx, "project", in.ID, "")
	if err != nil || changed {
		t.Fatalf("重复否决应幂等: changed=%v err=%v", changed, err)
	}
	if err := d.QueryRow(`SELECT rejected_reason FROM project_insights WHERE id=$1`, in.ID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "版本不同，本目标不成立" {
		t.Errorf("幂等重复否决不该改写 reason, got %q", reason)
	}

	// 不存在 → ErrInsightNotFound（工具侧转成「未找到」文本，不报错）。
	if _, err := d.RejectInsight(ctx, "global", 999999999, "x"); !errors.Is(err, ErrInsightNotFound) {
		t.Errorf("missing id err = %v want ErrInsightNotFound", err)
	}
	// kind 非法 → ErrInsightKindInvalid。
	if _, err := d.RejectInsight(ctx, "insight", in.ID, "x"); !errors.Is(err, ErrInsightKindInvalid) {
		t.Errorf("bad kind err = %v want ErrInsightKindInvalid", err)
	}

	// global：否决后不再是注入候选。
	key := fmt.Sprintf("insight-reject-global-%d.example.com", time.Now().UnixNano())
	g, err := d.WriteGlobalInsight(ctx, "跨项目洞察待否决", []int64{p.ID}, []string{key})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM global_insights WHERE id=$1`, g.ID) //nolint:errcheck
	if changed, err := d.RejectInsight(ctx, "global", g.ID, "来源项目上下文不适用"); err != nil || !changed {
		t.Fatalf("reject global: changed=%v err=%v", changed, err)
	}
	if l, err := d.ListCrossProjectInsights(ctx, []string{key}, 10); err != nil || len(l) != 0 {
		t.Errorf("rejected 跨项目洞察仍被注入: %v err=%v", globalIDs(l), err)
	}
}

func findInsight(list []Insight, id int64) *Insight {
	for i := range list {
		if list[i].ID == id {
			return &list[i]
		}
	}
	return nil
}

// TestListInsightsKeywordOrdering 守「命中数降序 → 时间降序」的注入排序。
// 回归点：早期实现用 text[] 的 `&` 交集运算符，PG 里并不存在（只 intarray
// 的 int[] 有），带关键词时整条查询 42883 报错 → 注入静默全空。此测用真实
// PG 跑带 matchKeywords 的路径，确保命中排序是「算出来的」而不是「报错退化的」。
func TestListInsightsKeywordOrdering(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	suffix := strconv.FormatInt(time.Now().UnixNano()%1000000, 10)
	p, err := d.CreateProject(CreateProjectInput{Name: "insight-order-" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM projects WHERE id=$1`, p.ID) //nolint:errcheck // 级联删

	noHit, err := d.WriteInsight(ctx, p.ID, "不相交，靠时间补位", 0, []string{"other.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	oneHit, err := d.WriteInsight(ctx, p.ID, "命中一个键", 0, []string{"canal.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	twoHit, err := d.WriteInsight(ctx, p.ID, "命中两个键", 0, []string{"canal.example.com", "10.0.0.8"})
	if err != nil {
		t.Fatal(err)
	}

	list, err := d.ListInsights(ctx, p.ID, []string{"canal.example.com", "10.0.0.8"}, 10)
	if err != nil {
		t.Fatalf("带 matchKeywords 的查询不该报错: %v", err)
	}
	if len(list) < 3 {
		t.Fatalf("want ≥3 行, got %+v", list)
	}
	// 两个键都命中 > 一个键命中 > 不相交。
	if list[0].ID != twoHit.ID || list[1].ID != oneHit.ID || list[2].ID != noHit.ID {
		t.Errorf("命中排序错误: got %d,%d,%d want %d,%d,%d",
			list[0].ID, list[1].ID, list[2].ID, twoHit.ID, oneHit.ID, noHit.ID)
	}
}

// TestListInsightsMatchNoBackfill 钉死 V11-INSIGHT9 的核心语义：
// ListInsightsMatch 只返回 keywords 与 matchKeys 有交集的行，【不做时间补位】；
// 而 ListInsights（管理面/读全量）保持旧行为，两者不能互相污染。
func TestListInsightsMatchNoBackfill(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	suffix := strconv.FormatInt(time.Now().UnixNano()%1000000, 10)
	p, err := d.CreateProject(CreateProjectInput{Name: "insight-no-backfill-" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM projects WHERE id=$1`, p.ID) //nolint:errcheck // 级联删

	hit, err := d.WriteInsight(ctx, p.ID, "同组件可复用", 0, []string{"canal.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	// 不命中的行故意最后写：旧 ListInsights 会把它按 created_at DESC 补到最前，
	// 正是不该再发生的「无差别广播」。
	if _, err := d.WriteInsight(ctx, p.ID, "完全无关的另一套系统", 0, []string{"other.example.com"}); err != nil {
		t.Fatal(err)
	}

	got, err := d.ListInsightsMatch(ctx, p.ID, []string{"canal.example.com", "10.0.0.8"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != hit.ID {
		t.Fatalf("ListInsightsMatch 应只返回命中的 1 条(id=%d)，got %+v", hit.ID, got)
	}

	// 无交集 / 空键集 → 空（不是「拿最近的顶上」）。
	if l, err := d.ListInsightsMatch(ctx, p.ID, []string{"no-such.example"}, 10); err != nil || len(l) != 0 {
		t.Errorf("无交集必须为空, got %d err=%v", len(l), err)
	}
	if l, err := d.ListInsightsMatch(ctx, p.ID, nil, 10); err != nil || len(l) != 0 {
		t.Errorf("空键集必须为空, got %d err=%v", len(l), err)
	}

	// 全量视图不受影响：两条都在（管理面/跨项目阅读输入仍要看得见）。
	all, err := d.ListInsights(ctx, p.ID, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("ListInsights 应仍返回 2 条, got %d", len(all))
	}
}

func globalIDs(list []GlobalInsight) []int64 {
	out := make([]int64, 0, len(list))
	for _, g := range list {
		out = append(out, g.ID)
	}
	return out
}
