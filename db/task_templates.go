package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	MaxTaskTemplateNameRunes = 120
	MaxTaskTemplateTextRunes = 16000
)

var (
	ErrTaskTemplateInvalid      = errors.New("invalid task template")
	ErrTaskTemplateNameConflict = errors.New("task template name already exists")
	ErrTaskTemplateNotFound     = errors.New("task template not found")
)

// TaskTemplate is a reusable task preset (description/goal + optional category
// and task-level intercept/allow rules).
type TaskTemplate struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	NKey        string `json:"-"`
	Description string `json:"description"`
	// Targets 模板预置的资产清单（一行一个 URL/IP/域名/CIDR）。应用模板时
	// 原样填进任务创建的资产框，用户仍可增删后解析。
	Targets        string                   `json:"targets"`
	Goal           string                   `json:"goal"`
	CategoryID     *int64                   `json:"category_id"`
	InterceptRules []TaskInterceptRuleInput `json:"intercept_rules"`
	// Constraints 模板自带的操作约束；应用模板时原样带进创建表单。
	Constraints []ConstraintInput `json:"constraints"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// TaskTemplateInput is the create/update payload after normalization.
type TaskTemplateInput struct {
	Name           string
	Description    string
	Targets        string
	Goal           string
	CategoryID     *int64
	InterceptRules []TaskInterceptRuleInput
	Constraints    []ConstraintInput
}

// TaskTemplatePatch changes only fields flagged as set. Name/Description/Goal use
// non-nil pointers; CategoryID/InterceptRules use explicit Set flags (so a nil
// CategoryID can mean "clear" when SetCategoryID is true).
type TaskTemplatePatch struct {
	Name              *string
	Description       *string
	Targets           *string
	Goal              *string
	CategoryID        *int64
	SetCategoryID     bool
	InterceptRules    []TaskInterceptRuleInput
	SetInterceptRules bool
	Constraints       []ConstraintInput
	SetConstraints    bool
}

const taskTemplateCols = `id, name, nkey, description, targets, goal, category_id, intercept_rules, constraints, created_at, updated_at`

func scanTaskTemplate(row interface{ Scan(...any) error }) (TaskTemplate, error) {
	var t TaskTemplate
	var rulesRaw, constraintsRaw []byte
	if err := row.Scan(&t.ID, &t.Name, &t.NKey, &t.Description, &t.Targets, &t.Goal, &t.CategoryID, &rulesRaw, &constraintsRaw, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return t, err
	}
	t.Constraints = []ConstraintInput{}
	if len(constraintsRaw) > 0 {
		if err := json.Unmarshal(constraintsRaw, &t.Constraints); err != nil {
			return t, err
		}
		if t.Constraints == nil {
			t.Constraints = []ConstraintInput{}
		}
	}
	t.InterceptRules = []TaskInterceptRuleInput{}
	if len(rulesRaw) > 0 {
		if err := json.Unmarshal(rulesRaw, &t.InterceptRules); err != nil {
			return t, err
		}
		if t.InterceptRules == nil {
			t.InterceptRules = []TaskInterceptRuleInput{}
		}
	}
	return t, nil
}

// marshalTemplateRules serializes a template's rule snapshot to JSONB text,
// always producing a JSON array (never null).
func marshalTemplateRules(rules []TaskInterceptRuleInput) ([]byte, error) {
	if rules == nil {
		rules = []TaskInterceptRuleInput{}
	}
	return json.Marshal(rules)
}

// normalizeTemplateConstraints 校验并去重模板约束（kind allow/deny、text 非空，
// 去重按 kind+text；上限 100 条，防止把模板当约束仓库）。
func normalizeTemplateConstraints(items []ConstraintInput) ([]ConstraintInput, error) {
	out := make([]ConstraintInput, 0, len(items))
	seen := map[string]bool{}
	for _, it := range items {
		kind := strings.ToLower(strings.TrimSpace(it.Kind))
		text := strings.TrimSpace(it.Text)
		if kind != "allow" && kind != "deny" {
			return nil, fmt.Errorf("%w: constraint kind must be allow or deny", ErrTaskTemplateInvalid)
		}
		if text == "" {
			continue
		}
		if utf8.RuneCountInString(text) > 200 {
			return nil, fmt.Errorf("%w: constraint text exceeds 200 characters", ErrTaskTemplateInvalid)
		}
		key := kind + "\x00" + text
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ConstraintInput{Kind: kind, Text: text})
	}
	if len(out) > 100 {
		return nil, fmt.Errorf("%w: too many constraints (max 100)", ErrTaskTemplateInvalid)
	}
	return out, nil
}

func marshalTemplateConstraints(items []ConstraintInput) ([]byte, error) {
	if items == nil {
		items = []ConstraintInput{}
	}
	return json.Marshal(items)
}

// taskTemplateName normalizes display whitespace while preserving the user's case.
func taskTemplateName(name string) string { return strings.Join(strings.Fields(name), " ") }

// taskTemplateNKey is the case-insensitive identity used by the unique index.
func taskTemplateNKey(name string) string { return strings.ToLower(taskTemplateName(name)) }

func normalizeTaskTemplateInput(in TaskTemplateInput) (TaskTemplateInput, string, error) {
	in.Name = taskTemplateName(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	in.Goal = strings.TrimSpace(in.Goal)
	switch {
	case in.Name == "":
		return in, "", fmt.Errorf("%w: name is required", ErrTaskTemplateInvalid)
	case utf8.RuneCountInString(in.Name) > MaxTaskTemplateNameRunes:
		return in, "", fmt.Errorf("%w: name exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateNameRunes)
	case in.Description == "":
		return in, "", fmt.Errorf("%w: description is required", ErrTaskTemplateInvalid)
	case utf8.RuneCountInString(in.Description) > MaxTaskTemplateTextRunes:
		return in, "", fmt.Errorf("%w: description exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateTextRunes)
	// goal 是**可选**字段：UI 上标了「（可选）」，后端就不能强制。
	// 语义上它只是「更具体的可核验目标」，留空时应用模板会按资产生成。
	case utf8.RuneCountInString(in.Goal) > MaxTaskTemplateTextRunes:
		return in, "", fmt.Errorf("%w: goal exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateTextRunes)
	}
	constraints, err := normalizeTemplateConstraints(in.Constraints)
	if err != nil {
		return in, "", err
	}
	in.Constraints = constraints
	in.Targets = strings.TrimSpace(in.Targets)
	if utf8.RuneCountInString(in.Targets) > MaxTaskTemplateTextRunes {
		return in, "", fmt.Errorf("%w: targets exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateTextRunes)
	}
	return in, taskTemplateNKey(in.Name), nil
}

func normalizeTaskTemplatePatch(patch TaskTemplatePatch) (TaskTemplatePatch, *string, error) {
	if patch.Name == nil && patch.Description == nil && patch.Goal == nil && !patch.SetCategoryID && !patch.SetInterceptRules && !patch.SetConstraints {
		return patch, nil, fmt.Errorf("%w: no fields supplied", ErrTaskTemplateInvalid)
	}
	var nkey *string
	if patch.Name != nil {
		name := taskTemplateName(*patch.Name)
		if name == "" {
			return patch, nil, fmt.Errorf("%w: name is required", ErrTaskTemplateInvalid)
		}
		if utf8.RuneCountInString(name) > MaxTaskTemplateNameRunes {
			return patch, nil, fmt.Errorf("%w: name exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateNameRunes)
		}
		key := taskTemplateNKey(name)
		patch.Name = &name
		nkey = &key
	}
	if patch.SetConstraints {
		constraints, err := normalizeTemplateConstraints(patch.Constraints)
		if err != nil {
			return patch, nil, err
		}
		patch.Constraints = constraints
	}
	if patch.Targets != nil {
		targets := strings.TrimSpace(*patch.Targets)
		if utf8.RuneCountInString(targets) > MaxTaskTemplateTextRunes {
			return patch, nil, fmt.Errorf("%w: targets exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateTextRunes)
		}
		patch.Targets = &targets
	}
	if patch.Description != nil {
		description := strings.TrimSpace(*patch.Description)
		if description == "" {
			return patch, nil, fmt.Errorf("%w: description is required", ErrTaskTemplateInvalid)
		}
		if utf8.RuneCountInString(description) > MaxTaskTemplateTextRunes {
			return patch, nil, fmt.Errorf("%w: description exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateTextRunes)
		}
		patch.Description = &description
	}
	if patch.Goal != nil {
		// 目标说明可空：留空时任务侧按资产生成，与任务创建口径一致。
		goal := strings.TrimSpace(*patch.Goal)
		if utf8.RuneCountInString(goal) > MaxTaskTemplateTextRunes {
			return patch, nil, fmt.Errorf("%w: goal exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateTextRunes)
		}
		patch.Goal = &goal
	}
	return patch, nkey, nil
}

func taskTemplateUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// CreateTaskTemplate inserts one globally reusable preset.
func (d *DB) CreateTaskTemplate(in TaskTemplateInput) (*TaskTemplate, error) {
	in, nkey, err := normalizeTaskTemplateInput(in)
	if err != nil {
		return nil, err
	}
	rulesJSON, err := marshalTemplateRules(in.InterceptRules)
	if err != nil {
		return nil, err
	}
	constraintsJSON, err := marshalTemplateConstraints(in.Constraints)
	if err != nil {
		return nil, err
	}
	t, err := scanTaskTemplate(d.QueryRow(`
INSERT INTO task_templates(name, nkey, description, targets, goal, category_id, intercept_rules, constraints)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (nkey) DO NOTHING
RETURNING `+taskTemplateCols, in.Name, nkey, in.Description, in.Targets, in.Goal, in.CategoryID, rulesJSON, constraintsJSON))
	if err == sql.ErrNoRows {
		return nil, ErrTaskTemplateNameConflict
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ListTaskTemplates returns the most recently maintained templates first.
func (d *DB) ListTaskTemplates() ([]*TaskTemplate, error) {
	rows, err := d.Query(`SELECT ` + taskTemplateCols + ` FROM task_templates ORDER BY updated_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*TaskTemplate{}
	for rows.Next() {
		t, err := scanTaskTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

// GetTaskTemplate returns nil when id does not exist.
func (d *DB) GetTaskTemplate(id int64) (*TaskTemplate, error) {
	t, err := scanTaskTemplate(d.QueryRow(`SELECT `+taskTemplateCols+` FROM task_templates WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// UpdateTaskTemplate replaces the editable fields of one preset.
func (d *DB) UpdateTaskTemplate(id int64, in TaskTemplateInput) (*TaskTemplate, error) {
	in, _, err := normalizeTaskTemplateInput(in)
	if err != nil {
		return nil, err
	}
	return d.PatchTaskTemplate(id, TaskTemplatePatch{
		Name: &in.Name, Description: &in.Description, Targets: &in.Targets, Goal: &in.Goal,
		Constraints: in.Constraints, SetConstraints: true,
	})
}

// PatchTaskTemplate atomically changes only the supplied fields. Keeping the
// merge in one UPDATE prevents concurrent disjoint PATCH requests from losing
// each other's changes.
func (d *DB) PatchTaskTemplate(id int64, patch TaskTemplatePatch) (*TaskTemplate, error) {
	patch, nkey, err := normalizeTaskTemplatePatch(patch)
	if err != nil {
		return nil, err
	}
	rulesJSON, err := marshalTemplateRules(patch.InterceptRules)
	if err != nil {
		return nil, err
	}
	constraintsJSON, err := marshalTemplateConstraints(patch.Constraints)
	if err != nil {
		return nil, err
	}
	t, err := scanTaskTemplate(d.QueryRow(`UPDATE task_templates
SET name=CASE WHEN $2 THEN $3::text ELSE name END,
    nkey=CASE WHEN $2 THEN $4::text ELSE nkey END,
    description=CASE WHEN $5 THEN $6::text ELSE description END,
    goal=CASE WHEN $7 THEN $8::text ELSE goal END,
    category_id=CASE WHEN $9 THEN $10::bigint ELSE category_id END,
    intercept_rules=CASE WHEN $11 THEN $12::jsonb ELSE intercept_rules END,
    constraints=CASE WHEN $13 THEN $14::jsonb ELSE constraints END,
    targets=CASE WHEN $15 THEN $16::text ELSE targets END
WHERE id=$1
RETURNING `+taskTemplateCols,
		id,
		patch.Name != nil, patch.Name, nkey,
		patch.Description != nil, patch.Description,
		patch.Goal != nil, patch.Goal,
		patch.SetCategoryID, patch.CategoryID,
		patch.SetInterceptRules, rulesJSON,
		patch.SetConstraints, constraintsJSON,
		patch.Targets != nil, patch.Targets,
	))
	if err == sql.ErrNoRows {
		return nil, ErrTaskTemplateNotFound
	}
	if taskTemplateUniqueViolation(err) {
		return nil, ErrTaskTemplateNameConflict
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// DeleteTaskTemplate deletes one preset and reports whether it existed.
func (d *DB) DeleteTaskTemplate(id int64) (bool, error) {
	result, err := d.Exec(`DELETE FROM task_templates WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n > 0, err
}
