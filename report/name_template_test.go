package report

import (
	"strings"
	"testing"
	"time"
)

func TestRenderReportName(t *testing.T) {
	at := timeAt("2026-11-17T10:05:09+08:00")
	cases := []struct {
		name string
		tmpl string
		data ReportNameData
		want string
	}{
		{
			name: "task 无资产用任务ID",
			tmpl: "",
			data: ReportNameData{TaskID: 13, TaskName: "很长的任务目标整句"},
			want: "任务13渗透测试报告-2026-11-17",
		},
		{
			name: "识别出 host",
			tmpl: DefaultReportNameTemplate,
			data: ReportNameData{TaskID: 7, System: "mall.example.com"},
			want: "mall.example.com渗透测试报告-2026-11-17",
		},
		{
			name: "project 用项目ID",
			tmpl: "{system}-{project}-{project_id}",
			data: ReportNameData{ProjectID: 9, ProjectName: "验收项目"},
			want: "项目9-验收项目-9",
		},
		{
			name: "自定义中文日期",
			tmpl: "{system}报告-{date:YYYY年M月D日}-{date:HHmm}",
			data: ReportNameData{TaskID: 3},
			want: "任务3报告-2026年11月17日-1005",
		},
		{
			name: "未知占位符原样保留",
			tmpl: "{system}-{unknown}-{date:QQ}",
			data: ReportNameData{TaskID: 4},
			want: "任务4-{unknown}-QQ",
		},
		{
			name: "文件名非法字符清理",
			tmpl: `{system}-报告`,
			data: ReportNameData{System: "a/b:c*d?e\"f<g>h|i"},
			want: "a_b_c_d_e_f_g_h_i-报告.docx",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "文件名非法字符清理" {
				got := ReportFileName(c.tmpl, c.data, at, "docx")
				if got != c.want {
					t.Fatalf("got %q want %q", got, c.want)
				}
				return
			}
			if got := RenderReportName(c.tmpl, c.data, at); got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestRenderReportNameMonthAndMinute(t *testing.T) {
	at := timeAt("2026-03-04T05:06:07+08:00")
	got := RenderReportName("{MM}-{mm}-{M}-{D}-{HH}-{ss}", ReportNameData{}, at)
	want := "03-06-3-4-05-07"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSanitizeReportFileNameLength(t *testing.T) {
	got := SanitizeReportFileName(strings.Repeat("长", 200))
	if n := len([]rune(got)); n != 120 {
		t.Fatalf("length=%d want 120", n)
	}
}

func timeAt(s string) time.Time {
	tt, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return tt
}
