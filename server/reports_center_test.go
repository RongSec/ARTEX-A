package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func int64p(v int64) *int64 { return &v }

func TestGroupReportTree(t *testing.T) {
	rows := []*db.ReportTreeRow{
		{ProjectID: int64p(10), ProjectName: "项目 A", TaskName: "任务一",
			Report: &db.Report{ID: 1, Scope: db.ReportScopeTask, TaskID: int64p(100), Status: db.ReportDone}},
		{ProjectID: int64p(10), ProjectName: "项目 A", TaskName: "任务一",
			Report: &db.Report{ID: 2, Scope: db.ReportScopeTask, TaskID: int64p(100), Status: db.ReportFailed}},
		{ProjectID: int64p(10), ProjectName: "项目 A",
			Report: &db.Report{ID: 3, Scope: db.ReportScopeProject, ProjectID: int64p(10), Status: db.ReportDone}},
		{ProjectID: int64p(20), ProjectName: "项目 B", TaskName: "任务二",
			Report: &db.Report{ID: 4, Scope: db.ReportScopeTask, TaskID: int64p(200), Status: db.ReportRunning}},
		{Report: &db.Report{ID: 5, Scope: db.ReportScopeTask, TaskID: int64p(300), Status: db.ReportDone}},
	}
	tree := groupReportTree(rows)
	if len(tree.Projects) != 2 {
		t.Fatalf("projects=%d", len(tree.Projects))
	}
	p := tree.Projects[0]
	if p.ID != 10 || p.Counts.Total != 3 || p.Counts.Done != 2 || p.Counts.Failed != 1 {
		t.Fatalf("项目 A 统计错误: %+v", p.Counts)
	}
	if len(p.Reports) != 1 || len(p.Tasks) != 1 || p.Tasks[0].ID != 100 || p.Tasks[0].Counts.Total != 2 {
		t.Fatalf("项目 A 分组错误: %+v", p)
	}
	if len(tree.Orphans) != 1 || tree.Orphans[0].ID != 300 {
		t.Fatalf("孤儿分组错误: %+v", tree.Orphans)
	}
}

func TestUniqueArchiveEntry(t *testing.T) {
	used := map[string]bool{}
	got := []string{
		uniqueArchiveEntry("报告.docx", used),
		uniqueArchiveEntry("报告.docx", used),
		uniqueArchiveEntry("报告.docx", used),
	}
	want := []string{"报告.docx", "报告 (2).docx", "报告 (3).docx"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 个名字=%q, want %q", i+1, got[i], want[i])
		}
	}
}

func TestSanitizeArchiveName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a/b\\c:d.docx", "a_b_c_d.docx"},
		{"  ../报告.docx ", "_报告.docx"},
		{"", "report"},
	}
	for _, c := range cases {
		if got := sanitizeArchiveName(c.in); got != c.want {
			t.Errorf("sanitizeArchiveName(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}
