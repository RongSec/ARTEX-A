package db

// T16(3/3) 发现证据截图 store：finding_evidence_images 表。发现详情页逐复现步骤
// 上传的截图（png/jpg/…）。filename 存相对 dataDir 的路径（由 server 层落盘 +
// 静态服务），本层只管行读写与排序。句柄键=findings.id（见 schema §Q 注释）。

import (
	"database/sql"
	"time"
)

// FindingEvidenceImage 是 finding_evidence_images 一行。
type FindingEvidenceImage struct {
	ID        int64     `json:"id"`
	FindingID int64     `json:"finding_id"`
	StepIndex int       `json:"step_index"` // 复现步骤下标(从1计)；0=漏洞级
	Filename  string    `json:"filename"`   // 相对 dataDir 存储路径
	URL       string    `json:"url"`        // 绝对访问路径（server 层填 /api/findings/{fid}/evidence/{id}）
	Caption   string    `json:"caption"`
	SortOrder int       `json:"sort_order"`
	CreatedAt time.Time `json:"created_at"`
}

const findingEvidenceImageCols = `id, finding_id, step_index, filename, COALESCE(caption,''), sort_order, created_at`

func scanFindingEvidenceImage(row interface{ Scan(...any) error }) (FindingEvidenceImage, error) {
	var e FindingEvidenceImage
	err := row.Scan(&e.ID, &e.FindingID, &e.StepIndex, &e.Filename, &e.Caption, &e.SortOrder, &e.CreatedAt)
	return e, err
}

// AddFindingEvidenceImage 插入一张证据图并返回新行。stepIndex<0 归 0。
func (d *DB) AddFindingEvidenceImage(findingID int64, stepIndex int, filename, caption string, sortOrder int) (*FindingEvidenceImage, error) {
	if stepIndex < 0 {
		stepIndex = 0
	}
	e, err := scanFindingEvidenceImage(d.QueryRow(`
INSERT INTO finding_evidence_images(finding_id, step_index, filename, caption, sort_order)
VALUES ($1,$2,$3,$4,$5)
RETURNING `+findingEvidenceImageCols, findingID, stepIndex, filename, caption, sortOrder))
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// ListFindingEvidenceImages 返回某发现的全部证据图（按 step_index, sort_order, id 升序）。
func (d *DB) ListFindingEvidenceImages(findingID int64) ([]FindingEvidenceImage, error) {
	rows, err := d.Query(`SELECT `+findingEvidenceImageCols+`
		FROM finding_evidence_images WHERE finding_id=$1
		ORDER BY step_index, sort_order, id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FindingEvidenceImage{}
	for rows.Next() {
		e, err := scanFindingEvidenceImage(rows)
		if err != nil {
			return out, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetFindingEvidenceImage 按 id 取一行（并校验归属 findingID 防越权）；不存在/
// 归属不符返回 nil。静态服务用它反查 filename。
func (d *DB) GetFindingEvidenceImage(id, findingID int64) (*FindingEvidenceImage, error) {
	e, err := scanFindingEvidenceImage(d.QueryRow(`SELECT `+findingEvidenceImageCols+`
		FROM finding_evidence_images WHERE id=$1 AND finding_id=$2`, id, findingID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// UpdateFindingEvidenceImageCaption 改一张证据图的图注 + 可选重排 step_index/
// sort_order（三值都传；调用方先 Get 回填不改的值）。返回更新后行。
func (d *DB) UpdateFindingEvidenceImage(id, findingID int64, caption string, stepIndex, sortOrder int) (*FindingEvidenceImage, error) {
	if stepIndex < 0 {
		stepIndex = 0
	}
	e, err := scanFindingEvidenceImage(d.QueryRow(`UPDATE finding_evidence_images
SET caption=$3, step_index=$4, sort_order=$5
WHERE id=$1 AND finding_id=$2
RETURNING `+findingEvidenceImageCols, id, findingID, caption, stepIndex, sortOrder))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// DeleteFindingEvidenceImage 删一行并返回其 filename（供调用方删盘上文件）；
// 不存在/归属不符返回 ("", false, nil)。
func (d *DB) DeleteFindingEvidenceImage(id, findingID int64) (filename string, ok bool, err error) {
	var f string
	scanErr := d.QueryRow(`DELETE FROM finding_evidence_images WHERE id=$1 AND finding_id=$2 RETURNING filename`, id, findingID).Scan(&f)
	if scanErr == sql.ErrNoRows {
		return "", false, nil
	}
	if scanErr != nil {
		return "", false, scanErr
	}
	return f, true, nil
}
