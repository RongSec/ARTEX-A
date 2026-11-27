package report

// T15(2/2) 纯函数单测：去重合并 / URL 模板提取 / 伪资产反向校验 /
// CandidateTargets 候选抽取 / ReportBaseName。无库断言。

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func reproJSON(t *testing.T, rp Reproduction) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(rp)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func finding(id, taskID int64, vulnclass, name, severity, url string, assetIDs ...int64) *db.DBFinding {
	tid := taskID
	return &db.DBFinding{
		ID: id, TaskID: &tid, VulnClass: vulnclass, Name: name, Severity: severity, AssetIDs: assetIDs,
	}
}

// ---------- MergeVulns ----------

func TestMergeVulnsSameVulnAcrossTasks(t *testing.T) {
	// 两个任务、同资产同 URL 同类别 = 同一漏洞：合并为一条，severity 取最高，
	// 来源任务号全保留。
	a := VulnSection{FindingID: 1, Name: "SQL注入", Severity: "high", VulnClass: "sqli", Asset: "www.a.com", URLTemplate: "www.a.com/login", SourceTasks: []int64{7}}
	b := VulnSection{FindingID: 2, Name: "SQL 注入（重复报告）", Severity: "critical", VulnClass: "sqli", Asset: "www.a.com", URLTemplate: "www.a.com/login", SourceTasks: []int64{9}}
	c := VulnSection{FindingID: 3, Name: "XSS", Severity: "low", VulnClass: "xss", Asset: "www.a.com", URLTemplate: "www.a.com/search", SourceTasks: []int64{9}}
	out := MergeVulns([]VulnSection{a, b, c})
	if len(out) != 2 {
		t.Fatalf("want 2 merged sections, got %d: %+v", len(out), out)
	}
	// 排序：critical 最前。
	sql := out[0]
	if sql.Severity != "critical" {
		t.Errorf("severity should take max: got %q", sql.Severity)
	}
	if len(sql.SourceTasks) != 2 || sql.SourceTasks[0] != 7 || sql.SourceTasks[1] != 9 {
		t.Errorf("source tasks not merged: %+v", sql.SourceTasks)
	}
	if sql.Name != "SQL注入" {
		t.Errorf("first-in wins name: got %q", sql.Name)
	}
	if out[1].Severity != "low" {
		t.Errorf("xss untouched: %+v", out[1])
	}
}

func TestMergeVulnsEmptyAssetDedup(t *testing.T) {
	// 未关联资产（空键）同 URL 同类别也合并。
	a := VulnSection{FindingID: 1, Severity: "medium", VulnClass: "infoleak", Asset: "", URLTemplate: "h/p", SourceTasks: []int64{3}}
	b := VulnSection{FindingID: 2, Severity: "low", VulnClass: "infoleak", Asset: "", URLTemplate: "h/p", SourceTasks: []int64{4}}
	out := MergeVulns([]VulnSection{a, b})
	if len(out) != 1 || out[0].Severity != "medium" {
		t.Fatalf("empty-asset dedup failed: %+v", out)
	}
}

func TestMergeVulnsDifferentURLNotMerged(t *testing.T) {
	a := VulnSection{FindingID: 1, Severity: "high", VulnClass: "sqli", Asset: "x", URLTemplate: "x/a", SourceTasks: []int64{1}}
	b := VulnSection{FindingID: 2, Severity: "high", VulnClass: "sqli", Asset: "x", URLTemplate: "x/b", SourceTasks: []int64{1}}
	if out := MergeVulns([]VulnSection{a, b}); len(out) != 2 {
		t.Fatalf("different url templates must not merge: %+v", out)
	}
}

// ---------- ExtractURLTemplate ----------

func TestExtractURLTemplate(t *testing.T) {
	cases := []struct {
		name string
		rp   Reproduction
		want string
	}{
		{"origin-form", Reproduction{Steps: []ReproStep{{Request: "POST /api/user/login?from=app HTTP/1.1\r\nHost: mall.example.com:8443\r\n\r\n{}"}}}, "mall.example.com:8443/api/user/login"},
		{"http default port stripped", Reproduction{Steps: []ReproStep{{Request: "GET /admin HTTP/1.1\r\nHost: www.a.com:80\r\n"}}}, "www.a.com/admin"},
		{"absolute curl", Reproduction{Steps: []ReproStep{{Request: "curl -s 'https://api.a.com/v1/ping?x=1' -H 'Token: abc'"}}}, "api.a.com/v1/ping"},
		{"entry point fallback", Reproduction{EntryPoint: "PUT /config", Steps: nil}, ""}, // 无 Host → 提不出模板（宁缺毋滥）
		{"entry point with host", Reproduction{EntryPoint: "https://e.a.com/login"}, "e.a.com/login"},
		{"no repro", Reproduction{}, ""},
	}
	for _, c := range cases {
		got := ExtractURLTemplate(reproJSON(t, c.rp))
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

// ---------- 伪资产反向校验（红线） ----------

func TestFilterPseudoTargets(t *testing.T) {
	candidates := []string{"mall.example.com", "10.0.0.1", "10.0.0.10", "admin.example.com", "v1.example.com", "1.2.3.4"}
	// 证据：只真打了 mall（Host 头）、10.0.0.10（IP 直连）、admin.example.com 的
	// 请求里带路径。注意 1.2.3.4 只出现在响应体里（不算证据——evidence 调用方
	// 只喂 request 文本，这里直接体现函数语义）。
	evidence := []string{
		"GET /index.html HTTP/1.1\r\nHost: mall.example.com\r\n\r\n",
		"POST /login HTTP/1.1\r\nHost: 10.0.0.10:8080\r\n\r\nuser=1",
		"curl http://admin.example.com/api",
	}
	kept, removed := FilterPseudoTargets(candidates, evidence)
	keptSet := map[string]bool{}
	for _, k := range kept {
		keptSet[k] = true
	}
	removedSet := map[string]bool{}
	for _, r := range removed {
		removedSet[r] = true
	}
	// 命中保留。
	for _, want := range []string{"mall.example.com", "10.0.0.10", "admin.example.com"} {
		if !keptSet[want] {
			t.Errorf("%s should be kept, kept=%v removed=%v", want, kept, removed)
		}
	}
	// 10.0.0.1 不得被 10.0.0.10 证据误命中（版本/前缀串不误判）。
	if keptSet["10.0.0.1"] {
		t.Errorf("10.0.0.1 must NOT be kept via 10.0.0.10 evidence")
	}
	// 无任何证据的目标剔除。
	for _, want := range []string{"10.0.0.1", "v1.example.com", "1.2.3.4"} {
		if !removedSet[want] {
			t.Errorf("%s should be removed, kept=%v", want, kept)
		}
	}
}

func TestFilterPseudoTargetsSubdomainBoundary(t *testing.T) {
	// 证据打了 v1.example.com，候选 example.com（根域）不得算命中——边界字符
	// 校验只允许「完整 host」出现；example.com 嵌在 v1.example.com 前面被 '.'
	// 粘连，判为不同主机。
	kept, removed := FilterPseudoTargets([]string{"example.com"}, []string{"GET / HTTP/1.1\r\nHost: v1.example.com\r\n"})
	if len(kept) != 0 || len(removed) != 1 {
		t.Errorf("root domain must not hit via subdomain evidence: kept=%v removed=%v", kept, removed)
	}
	// 反之候选 v1.example.com 命中自身证据。
	kept, _ = FilterPseudoTargets([]string{"v1.example.com"}, []string{"Host: V1.Example.com"})
	if len(kept) != 1 {
		t.Errorf("case-insensitive host hit failed: %v", kept)
	}
}

func TestFilterPseudoTargetsEmptyEvidence(t *testing.T) {
	// 空证据集 → 全部剔除（伪资产硬闸门：无漏洞证据的目标一行都不进表）。
	kept, removed := FilterPseudoTargets([]string{"a.com", "b.com"}, nil)
	if len(kept) != 0 {
		t.Errorf("empty evidence must remove all, kept=%v", kept)
	}
	if len(removed) != 2 {
		t.Errorf("want 2 removed, got %v", removed)
	}
}

// ---------- CandidateTargets ----------

func TestCandidateTargetsExtractAndDedupe(t *testing.T) {
	goals := []string{
		"对 https://Mall.Example.com:8443/portal 与 http://mall.example.com 进行渗透测试，旁站 10.1.2.3",
		"目标：api.example.com，后台 admin.example.com/admin",
	}
	anchors := []string{"www.example.com", "MALL.EXAMPLE.COM"}
	got := CandidateTargets(goals, anchors)
	want := map[string]bool{"mall.example.com": true, "10.1.2.3": true, "api.example.com": true, "admin.example.com": true, "www.example.com": true}
	if len(got) != len(want) {
		t.Fatalf("candidate set wrong: %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected candidate %q in %v", g, got)
		}
	}
	// 已排序且去重（大小写归一后 mall 只出现一次）。
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("not sorted/deduped: %v", got)
		}
	}
}

// ---------- VulnFromFinding + input fixture ----------

func TestVulnFromFindingAndProjectGrouping(t *testing.T) {
	f := finding(101, 7, "sqli", "SQL注入", "high", "", 5)
	rp := Reproduction{EntryPoint: "https://mall.example.com/login", Steps: []ReproStep{{Request: "POST /login HTTP/1.1\r\nHost: mall.example.com\r\n\r\n", Response: "200"}}}
	f.Reproduction = reproJSON(t, rp)
	label := func(id int64) string {
		if id == 5 {
			return "mall.example.com"
		}
		return "asset#" + string(rune('0'+byte(id)))
	}
	v := VulnFromFinding(f, label)
	if v.Asset != "mall.example.com" || v.URLTemplate != "mall.example.com/login" || v.Name != "SQL注入" {
		t.Fatalf("mapping wrong: %+v", v)
	}
	if len(v.SourceTasks) != 1 || v.SourceTasks[0] != 7 {
		t.Errorf("source task wrong: %+v", v.SourceTasks)
	}

	// 项目级 input fixture：两任务两资产，合并后按资产分章节。
	in := &ReportInput{
		Title: "示例项目", Scope: "project", Locale: "zh-CN", GeneratedAt: time.Now(),
		Chapters: db.ParseSkeletonJSON(nil),
		Findings: []VulnSection{
			{FindingID: 1, Name: "SQL注入", Severity: "high", VulnClass: "sqli", Asset: "mall.example.com", URLTemplate: "mall.example.com/login", SourceTasks: []int64{7}},
			{FindingID: 2, Name: "命令执行", Severity: "critical", VulnClass: "rce", Asset: "10.1.2.3", URLTemplate: "10.1.2.3/shell", SourceTasks: []int64{8}},
			{FindingID: 3, Name: "XSS", Severity: "low", VulnClass: "xss", Asset: "mall.example.com", URLTemplate: "mall.example.com/search", SourceTasks: []int64{7, 8}},
		},
	}
	groups := GroupVulnsByAsset(in.Findings)
	if len(groups) != 2 {
		t.Fatalf("want 2 asset groups, got %d", len(groups))
	}
	if groups[0].Asset != "10.1.2.3" || len(groups[0].Sections) != 1 {
		t.Errorf("critical-asset group should be first: %+v", groups[0])
	}
	if groups[1].Asset != "mall.example.com" || len(groups[1].Sections) != 2 {
		t.Errorf("mall group should carry 2 sections: %+v", groups[1])
	}

	// Markdown 桩渲染：项目级出「资产：」章、多来源任务标注、无复现不崩。
	md := MarkdownFromInput(in)
	for _, want := range []string{"### 资产：10.1.2.3", "### 资产：mall.example.com", "（来源任务 #7、#8）", "## 检测目标"} {
		if !strings.Contains(md, want) {
			t.Errorf("project markdown missing %q:\n%s", want, md)
		}
	}
	// 关章骨架：enabled=false 的章节不渲染。
	in.Chapters = []db.ReportSection{{Key: db.SectionVulnDetail, Enabled: true}}
	md2 := MarkdownFromInput(in)
	if strings.Contains(md2, "## 检测目标") || !strings.Contains(md2, "## 漏洞明细") {
		t.Errorf("skeleton gating broken:\n%s", md2)
	}
}

// ---------- ReportBaseName ----------

func TestReportBaseName(t *testing.T) {
	day := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	if got := ReportBaseName("示例集团 门户渗透", day, "docx"); got != "示例集团_门户渗透-20261111.docx" {
		t.Errorf("name wrong: %q", got)
	}
	if got := ReportBaseName("../../evil/名", day, "MD"); !strings.HasPrefix(got, "evil_名-20261111.md") || strings.Contains(got, "/") || strings.Contains(got, "..") {
		t.Errorf("path traversal not sanitized: %q", got)
	}
	if got := ReportBaseName("   ", day, ""); !strings.HasPrefix(got, "渗透测试报告-20261111.docx") {
		t.Errorf("empty-title fallback wrong: %q", got)
	}
	long := strings.Repeat("漏", 200)
	if got := ReportBaseName(long, day, "md"); len([]rune(got)) > 80+len("-20261111.md") {
		t.Errorf("long title not truncated: len=%d", len([]rune(got)))
	}
}

// ---------- Markdown 章节抽取（影响/修复建议） ----------

func TestMarkdownSection(t *testing.T) {
	md := "# 标题\n\n## 概述\n一句话。\n\n## 影响与危害\n\n- **加密失效**：全部接口可解密。\n- 可伪造请求。\n\n### 补充\n细节。\n\n## 修复建议\n\n1. 升级到 3.2.0。\n2. 密钥改为服务端下发。\n\n## 参考\n链接。"
	if got := markdownSection(md, "影响与危害", "影响", "危害"); !strings.Contains(got, "加密失效") || !strings.Contains(got, "可伪造请求") || !strings.Contains(got, "细节") {
		t.Errorf("harm section wrong: %q", got)
	}
	if strings.Contains(markdownSection(md, "影响与危害"), "修复建议") {
		t.Error("harm section leaked into next chapter")
	}
	got := markdownSection(md, "修复建议", "修复方案")
	if !strings.Contains(got, "升级到 3.2.0") || !strings.Contains(got, "密钥改为服务端下发") {
		t.Errorf("remediation section wrong: %q", got)
	}
	// 无章节 → 空串（调用方回退「暂无」）。
	if got := markdownSection(md, "不存在的章节"); got != "" {
		t.Errorf("missing section should be empty, got %q", got)
	}
	// 加粗标题形态也能识别。
	if got := markdownSection("**修复建议**\n打补丁。", "修复建议"); got != "打补丁。" {
		t.Errorf("bold heading not recognized: %q", got)
	}
	// 章节内的加粗小标题（**短期**）不是章节边界，不能把正文截空。
	bold := "## 修复建议\n\n**短期（可立即落地）**\n- 轮换密钥。\n\n**中期**\n- 改 AES-GCM。\n\n## 参考\n链接。"
	if got := markdownSection(bold, "修复建议"); !strings.Contains(got, "轮换密钥") || !strings.Contains(got, "AES-GCM") || strings.Contains(got, "链接") {
		t.Errorf("bold subheading should stay inside section: %q", got)
	}
}
