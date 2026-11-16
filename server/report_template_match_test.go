package server

import (
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestTemplateNameKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"渗透测试报告.docx", "渗透测试报告"},
		{"渗透测试报告.MD", "渗透测试报告"},
		{" 渗透 测试（报告） ", "渗透测试报告"},
		{"Acme-Report_v2.markdown", "acmereportv2"},
		{"报告模板.txt", "报告模板"},
	}
	for _, c := range cases {
		if got := templateNameKey(c.in); got != c.want {
			t.Errorf("templateNameKey(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}

func TestMatchReportTemplateByName(t *testing.T) {
	older := &db.ReportTemplate{ID: 1, Name: "渗透测试报告", UpdatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	newer := &db.ReportTemplate{ID: 2, Name: "渗透 测试报告", UpdatedAt: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)}
	other := &db.ReportTemplate{ID: 3, Name: "应急响应报告", UpdatedAt: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)}
	list := []*db.ReportTemplate{older, other, newer}

	got := matchReportTemplateByName("渗透测试报告.docx", list)
	if got == nil || got.ID != newer.ID {
		t.Fatalf("同名多行应取最近更新，got %+v", got)
	}
	if got := matchReportTemplateByName("不存在的文档.docx", list); got != nil {
		t.Fatalf("无同名应返回 nil，got %+v", got)
	}
	if got := matchReportTemplateByName("", list); got != nil {
		t.Fatalf("空文件名应返回 nil，got %+v", got)
	}
}

func TestDiffReportSkeletons(t *testing.T) {
	old := []db.ReportSection{
		{Key: db.SectionCover, Title: "封面", Enabled: true},
		{Key: db.SectionSummary, Title: "汇总", Enabled: true},
		{Key: db.SectionVulnDetail, Title: "漏洞明细", Enabled: true},
	}
	next := []db.ReportSection{
		{Key: db.SectionCover, Title: "报告封面", Enabled: true},
		{Key: db.SectionSummary, Title: "汇总", Enabled: false},
		{Key: db.SectionConclusion, Title: "结论", Enabled: true},
	}
	d := diffReportSkeletons(old, next)
	if !d.Major {
		t.Fatal("key 集合不同应标 Major")
	}
	if len(d.Added) != 1 || d.Added[0] != "conclusion" {
		t.Fatalf("added=%v", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0] != "vuln_detail" {
		t.Fatalf("removed=%v", d.Removed)
	}
	if len(d.Retitled) != 1 || d.Retitled[0] != "cover" {
		t.Fatalf("retitled=%v", d.Retitled)
	}
	if len(d.Toggled) != 1 || d.Toggled[0] != "summary" {
		t.Fatalf("toggled=%v", d.Toggled)
	}

	same := diffReportSkeletons(old, old)
	if same.Major || len(same.Added)+len(same.Removed)+len(same.Retitled)+len(same.Toggled) != 0 {
		t.Fatalf("相同骨架应无差异，got %+v", same)
	}
}
