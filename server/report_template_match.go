package server

// R1（V9-RPT）报告模板「重复上传」识别：导入文档后按**文件名（去扩展名）**与
// 现有模板名做归一比较，命中则返回 matched_template 供前端默认走「更新现有
// 模板」（PATCH 复用 id，保留对话/历史，版本号 +1），而不是无脑新建。
//
// 本文件只有纯函数（无 DB/HTTP），便于单测覆盖归一化与骨架差异口径。

import (
	"strings"
	"time"
	"unicode"

	"github.com/Autumn-27/artex/db"
)

// reportTemplateMatchInfo 是 import-docx 响应里的 matched_template 形状。
type reportTemplateMatchInfo struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

// reportSkeletonDiff 是「新文档骨架 vs 现有模板骨架」的差异提示。Major=true
// 表示 key 集合发生变化（结构差异极大）；前端仍默认「更新」，但把差异章节亮出来。
type reportSkeletonDiff struct {
	Added    []string `json:"added"`
	Removed  []string `json:"removed"`
	Retitled []string `json:"retitled"`
	Toggled  []string `json:"toggled"`
	Major    bool     `json:"major"`
}

// templateNameKey 把模板名/文件名归一成比较键：去扩展名（.docx/.md/.markdown/
// .txt）、小写、去所有空白与常见分隔符/括号。中文命名差异（空格/连字符/全角
// 括号）是重复上传最常见的误判来源，这里统一抹平。
func templateNameKey(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	for _, ext := range []string{".docx", ".markdown", ".md", ".txt"} {
		s = strings.TrimSuffix(s, ext)
	}
	var b strings.Builder
	for _, r := range s {
		if unicode.IsSpace(r) || strings.ContainsRune(`-_—·.。()（）[]【】{}《》<>`, r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// matchReportTemplateByName 在现有模板里找归一名称相同的一行；多个同名取最近
// 更新（再以 id 大者兜底），无命中返回 nil。fileStem 可带扩展名，内部会剥掉。
func matchReportTemplateByName(fileStem string, list []*db.ReportTemplate) *db.ReportTemplate {
	key := templateNameKey(fileStem)
	if key == "" {
		return nil
	}
	var best *db.ReportTemplate
	for _, t := range list {
		if t == nil || templateNameKey(t.Name) != key {
			continue
		}
		if best == nil || t.UpdatedAt.After(best.UpdatedAt) || (t.UpdatedAt.Equal(best.UpdatedAt) && t.ID > best.ID) {
			best = t
		}
	}
	return best
}

// diffReportSkeletons 对比两套骨架的章节 key 集合/标题/启用态。Major=key 集合
// 不同（新增或缺失章节）——前端据此提示「结构差异极大」但仍默认更新。
func diffReportSkeletons(old, next []db.ReportSection) reportSkeletonDiff {
	d := reportSkeletonDiff{Added: []string{}, Removed: []string{}, Retitled: []string{}, Toggled: []string{}}
	oldMap := make(map[db.ReportSectionKey]db.ReportSection, len(old))
	for _, s := range old {
		oldMap[s.Key] = s
	}
	seen := map[db.ReportSectionKey]bool{}
	for _, s := range next {
		seen[s.Key] = true
		prev, ok := oldMap[s.Key]
		if !ok {
			d.Added = append(d.Added, string(s.Key))
			continue
		}
		if strings.TrimSpace(prev.Title) != strings.TrimSpace(s.Title) {
			d.Retitled = append(d.Retitled, string(s.Key))
		}
		if prev.Enabled != s.Enabled {
			d.Toggled = append(d.Toggled, string(s.Key))
		}
	}
	for _, s := range old {
		if !seen[s.Key] {
			d.Removed = append(d.Removed, string(s.Key))
		}
	}
	d.Major = len(d.Added) > 0 || len(d.Removed) > 0
	return d
}
