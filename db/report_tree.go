package db

// R6（V9-RPT）报告归档树取数：reports LEFT JOIN tasks/projects，一次把「报告
// + 所属任务/项目名」取回，供 /api/reports/tree 分组展示。分组/计数在 server
// 端是纯函数（groupReportTree），本文件只负责 SQL 与扫描。

import (
	"database/sql"
	"fmt"
	"strings"
)

// ReportTreeRow 是一条报告 + 其归属任务/项目名（任务级报告的任务可能已删，
// 名称回退空串由调用方补「任务#id」）。
type ReportTreeRow struct {
	Report          *Report
	TaskName        string
	TaskDescription string
	ProjectName     string
	// ProjectID 是报告实际归属项目（项目级报告取 r.project_id；任务级取任务
	// 当前 project_id 的 COALESCE 结果）。
	ProjectID *int64
}

const reportTreeSelect = `r.id, r.scope, r.task_ids, r.project_id, r.template_id, r.locale, r.format, r.status,
	COALESCE(r.file_path, ''), COALESCE(r.error, ''), COALESCE(r.warning, ''),
	array_to_json(COALESCE(r.finding_ids, '{}'))::text, r.created_at, r.started_at, r.finished_at,
	COALESCE(t.name, ''), COALESCE(t.description, ''), COALESCE(p.name, ''),
	COALESCE(r.project_id, t.project_id)`

// ListReportTreeRows 返回报告归档树的行（新→旧）。status 为空=全部；q 非空时
// 按任务名/描述/项目名模糊过滤（大小写不敏感）。
func (d *DB) ListReportTreeRows(status, q string) ([]*ReportTreeRow, error) {
	status = strings.TrimSpace(status)
	q = strings.TrimSpace(q)
	query := `SELECT ` + reportTreeSelect + `
		FROM reports r
		LEFT JOIN tasks t ON t.id = r.task_ids AND r.scope = 'task'
		LEFT JOIN projects p ON p.id = COALESCE(r.project_id, t.project_id)
		WHERE ($1 = '' OR r.status = $1)
		  AND ($2 = '' OR t.name ILIKE '%'||$2||'%' OR t.description ILIKE '%'||$2||'%' OR p.name ILIKE '%'||$2||'%')
		ORDER BY r.created_at DESC, r.id DESC`
	rows, err := d.Query(query, status, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ReportTreeRow{}
	for rows.Next() {
		row := &ReportTreeRow{Report: &Report{}}
		var aid []byte
		var started, finished sql.NullTime
		if err := rows.Scan(
			&row.Report.ID, &row.Report.Scope, &row.Report.TaskID, &row.Report.ProjectID,
			&row.Report.TemplateID, &row.Report.Locale, &row.Report.Format, &row.Report.Status,
			&row.Report.FilePath, &row.Report.Error, &row.Report.Warning, &aid,
			&row.Report.CreatedAt, &started, &finished,
			&row.TaskName, &row.TaskDescription, &row.ProjectName, &row.ProjectID,
		); err != nil {
			return out, fmt.Errorf("scan report tree row: %w", err)
		}
		row.Report.FindingIDs = unmarshalInt64Array(aid)
		if started.Valid {
			row.Report.StartedAt = started.Time
		}
		if finished.Valid {
			row.Report.FinishedAt = finished.Time
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
