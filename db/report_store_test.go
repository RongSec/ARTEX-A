package db

// T15(1/2) 纯函数单测：报告 job 状态迁移矩阵全覆盖 + skeleton 校验正误例。
// 无 PG 依赖，任何环境都跑（与 FindingsByTask 式带库测区分开）。

import (
	"encoding/json"
	"testing"
)

func TestCanAdvanceReportMatrix(t *testing.T) {
	states := []string{ReportPending, ReportRunning, ReportDone, ReportFailed, "bogus", ""}
	// 合法矩阵：仅这三条边。
	legal := map[[2]string]bool{
		{ReportPending, ReportRunning}: true,
		{ReportRunning, ReportDone}:    true,
		{ReportRunning, ReportFailed}:  true,
	}
	for _, from := range states {
		for _, to := range states {
			got := CanAdvanceReport(from, to)
			want := legal[[2]string{from, to}]
			if got != want {
				t.Errorf("CanAdvanceReport(%q,%q)=%v want %v", from, to, got, want)
			}
		}
	}
	// 显式钉死关键非法边（防矩阵被误改）：跳级、自环、终态外出。
	for _, pair := range [][2]string{
		{ReportPending, ReportDone},   // 不允许跳级 pending→done
		{ReportPending, ReportFailed}, // 不允许跳级 pending→failed
		{ReportDone, ReportRunning},   // 终态不可复活
		{ReportFailed, ReportRunning},
		{ReportDone, ReportDone},
		{ReportFailed, ReportFailed},
		{ReportPending, ReportPending},
		{ReportRunning, ReportRunning},
	} {
		if CanAdvanceReport(pair[0], pair[1]) {
			t.Errorf("transition %s->%s must be illegal", pair[0], pair[1])
		}
	}
}

func TestValidateSkeletonOK(t *testing.T) {
	ok := []ReportSection{
		{Key: SectionCover, Title: "封面", Enabled: true},
		{Key: SectionVulnDetail, Title: "漏洞明细", Enabled: true},
		{Key: SectionConclusion, Title: "", Enabled: false},
	}
	if err := ValidateSkeleton(ok); err != nil {
		t.Fatalf("valid skeleton rejected: %v", err)
	}
	// 单元素、全 disabled 也合法（顺序与开关由渲染端尊重）。
	if err := ValidateSkeleton([]ReportSection{{Key: SectionStatement, Enabled: false}}); err != nil {
		t.Fatalf("single-section skeleton rejected: %v", err)
	}
}

func TestValidateSkeletonErrors(t *testing.T) {
	cases := []struct {
		name string
		in   []ReportSection
	}{
		{"empty", nil},
		{"empty slice", []ReportSection{}},
		{"unknown key", []ReportSection{{Key: "nonexistent_chapter", Enabled: true}}},
		{"empty key", []ReportSection{{Key: "", Enabled: true}}},
		{"duplicate key", []ReportSection{
			{Key: SectionSummary, Title: "A", Enabled: true},
			{Key: SectionSummary, Title: "B", Enabled: true},
		}},
		{"unknown among known", []ReportSection{
			{Key: SectionCover, Enabled: true},
			{Key: "appendix", Enabled: true},
		}},
	}
	for _, c := range cases {
		if err := ValidateSkeleton(c.in); err == nil {
			t.Errorf("%s: invalid skeleton accepted", c.name)
		} else if !errorsIsInvalid(err) {
			t.Errorf("%s: wrong error type: %v", c.name, err)
		}
	}
}

// errorsIsInvalid 是 errors.Is(err, ErrReportSkeletonInvalid) 的薄封装，
// 避免测试文件多引一个包。
func errorsIsInvalid(err error) bool {
	target := ErrReportSkeletonInvalid
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestNormalizeSkeletonTitles(t *testing.T) {
	in := []ReportSection{
		{Key: SectionCover, Title: "  公家   封面  ", Enabled: true},
		{Key: SectionTargets, Title: "", Enabled: true},
	}
	out := NormalizeSkeleton(in)
	if out[0].Title != "公家 封面" {
		t.Errorf("title whitespace collapse failed: %q", out[0].Title)
	}
	if out[1].Title != "检测目标" {
		t.Errorf("empty title should fall back to default: %q", out[1].Title)
	}
	// 原切片不被修改（返回副本）。
	if in[1].Title != "" {
		t.Error("NormalizeSkeleton mutated input")
	}
}

func TestParseSkeletonJSON(t *testing.T) {
	// 合法数组：解析+归一化。
	raw, _ := json.Marshal([]ReportSection{{Key: SectionSummary, Enabled: true}})
	got := ParseSkeletonJSON(raw)
	if len(got) != 1 || got[0].Key != SectionSummary || got[0].Title != "风险等级汇总" {
		t.Fatalf("parse valid skeleton failed: %+v", got)
	}
	// 历史默认 '{}' / 空 / 脏值 → 默认全章节骨架（6 章节、全 enabled、按默认序）。
	for _, dirty := range [][]byte{[]byte("{}"), nil, []byte("[]"), []byte("garbage")} {
		got := ParseSkeletonJSON(dirty)
		if len(got) != len(DefaultSectionKeys) {
			t.Fatalf("dirty input %q: want %d default sections, got %d", dirty, len(DefaultSectionKeys), len(got))
		}
		for i, s := range got {
			if s.Key != DefaultSectionKeys[i] || !s.Enabled {
				t.Fatalf("default skeleton order/enabled broken at %d: %+v", i, s)
			}
		}
	}
}

func TestUnmarshalInt64Array(t *testing.T) {
	cases := map[string][]int64{
		"[1,2,3]": {1, 2, 3},
		"[]":      {},
		"null":    {},
		"":        {},
		"[42]":    {42},
	}
	for in, want := range cases {
		got := unmarshalInt64Array([]byte(in))
		if len(got) != len(want) {
			t.Errorf("unmarshalInt64Array(%q)=%v want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("unmarshalInt64Array(%q)[%d]=%d want %d", in, i, got[i], want[i])
			}
		}
	}
}
