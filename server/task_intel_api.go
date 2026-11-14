package server

// 任务情报表 API（V7-INTEL 第一层 / V8-INTEL3 任务小结）。
//
//   GET  /api/tasks/{id}/intel           任务小结：summary + 五类结构化分组
//   GET  /api/tasks/{id}/intel/coverage  覆盖率审计：正文见过的接口 vs 已入表
//   POST /api/tasks/{id}/intel/rebuild   立即重建（同步；管理员=登录态，见 auth.go
//        单管理员模型：/api/* 全部过 JWT，没有更细的角色维度）
//
// GET 只读不生成：情报表的生成时机是任务终态（或显式 rebuild），避免打开面板
// 就触发写库+发信号。
//
// 向后兼容：groups 在本版由「数组」改为「按 kind 的映射」（前端直接按组取值），
// 旧数组结构原样保留在 legacy_groups，字段与排序都不变。

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// IntelGroup 是旧版情报表的一个 kind 分组（legacy_groups 用，顺序固定：
// endpoint/credential/component/asset/vuln）。
type IntelGroup struct {
	Kind  string         `json:"kind"`
	Label string         `json:"label"`
	Count int            `json:"count"`
	Items []db.TaskIntel `json:"items"`
}

// intelGroupOrder 是分组展示顺序（与事件摘要同序）。
var intelGroupOrder = []string{
	db.IntelKindEndpoint, db.IntelKindCredential, db.IntelKindComponent,
	db.IntelKindAsset, db.IntelKindVuln,
}

// groupTaskIntel 纯函数：平铺行 → 按 kind 分组（空 kind 也保留分组，前端
// 渲染五张固定表头更稳；组内保持输入序=DB 的 kind,key 序）。
func groupTaskIntel(rows []db.TaskIntel) []IntelGroup {
	byKind := map[string][]db.TaskIntel{}
	for _, r := range rows {
		byKind[r.Kind] = append(byKind[r.Kind], r)
	}
	out := make([]IntelGroup, 0, len(intelGroupOrder))
	for _, k := range intelGroupOrder {
		items := byKind[k]
		if items == nil {
			items = []db.TaskIntel{}
		}
		out = append(out, IntelGroup{Kind: k, Label: db.IntelKindLabel(k), Count: len(items), Items: items})
	}
	return out
}

// ---------------------------------------------------------------------------
// 结构化条目（任务小结页直接用）
// ---------------------------------------------------------------------------

// intelEvidence 是一条情报的来源指针。同一次命中可能同时来自 finding 与
// fact（按序号对齐合并，单条来源时只出现一个字段）。
type intelEvidence struct {
	FindingID  *int64 `json:"finding_id,omitempty"`
	FactNodeID *int64 `json:"fact_node_id,omitempty"`
	AssetID    *int64 `json:"asset_id,omitempty"`
}

// intelEndpointItem 是一条接口情报：不只"打哪里"，还带用途/参数/状态码/鉴权。
type intelEndpointItem struct {
	Key          string          `json:"key"`
	Method       string          `json:"method"`
	Path         string          `json:"path"`
	Hosts        []string        `json:"hosts"`
	Purpose      string          `json:"purpose"`
	Params       []string        `json:"params"`
	StatusCodes  []int           `json:"status_codes"`
	AuthRequired bool            `json:"auth_required"`
	HitCount     int             `json:"hit_count"`
	Evidence     []intelEvidence `json:"evidence"`
}

// intelCredentialItem 是一条凭据：value 恒为脱敏描述，密文只出现在
// secret_masked（前 2 后 2）。
type intelCredentialItem struct {
	Key            string   `json:"key"`
	CredentialType string   `json:"credential_type"`
	Username       string   `json:"username"`
	Service        string   `json:"service"`
	Value          string   `json:"value"`
	SecretMasked   string   `json:"secret_masked"`
	WhereUsed      []string `json:"where_used"`
	Source         string   `json:"source"`
}

type intelComponentItem struct {
	Key     string `json:"key"`
	Product string `json:"product"`
	Version string `json:"version"`
	Value   string `json:"value"`
}

type intelAssetItem struct {
	Key   string `json:"key"`
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Value string `json:"value"`
}

type intelVulnItem struct {
	Key       string `json:"key"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Asset     string `json:"asset"`
	FindingID int64  `json:"finding_id"`
}

// intelGroups 是五组固定键（空组返回 []，不返回 null）。
type intelGroups struct {
	Endpoint   []intelEndpointItem   `json:"endpoint"`
	Credential []intelCredentialItem `json:"credential"`
	Component  []intelComponentItem  `json:"component"`
	Asset      []intelAssetItem      `json:"asset"`
	Vuln       []intelVulnItem       `json:"vuln"`
}

// taskIntelSummary 是任务小结的头部（任务口径 + 各类计数）。
type taskIntelSummary struct {
	Name            string         `json:"name"`
	Goal            string         `json:"goal"`
	Status          string         `json:"status"`
	ProjectID       int64          `json:"project_id"`
	ProjectName     string         `json:"project_name"`
	StartedAt       *time.Time     `json:"started_at,omitempty"`
	EndedAt         *time.Time     `json:"ended_at,omitempty"`
	DurationSeconds int64          `json:"duration_seconds"`
	Counts          map[string]int `json:"counts"`
}

// taskIntelResp 是 GET /api/tasks/{id}/intel 的响应体。
type taskIntelResp struct {
	TaskID       int64             `json:"task_id"`
	Total        int               `json:"total"`
	Summary      *taskIntelSummary `json:"summary"`
	Groups       intelGroups       `json:"groups"`
	LegacyGroups []IntelGroup      `json:"legacy_groups"`
	Hint         string            `json:"hint,omitempty"`
}

// intelRowDetail 是 task_intel.detail 的解码投影（缺字段即零值）。
type intelRowDetail struct {
	Count        int      `json:"count"`
	Methods      []string `json:"methods"`
	Hosts        []string `json:"hosts"`
	Purpose      string   `json:"purpose"`
	Params       []string `json:"params"`
	StatusCodes  []int    `json:"status_codes"`
	AuthRequired bool     `json:"auth_required"`
	FindingIDs   []int64  `json:"finding_ids"`
	FactNodeIDs  []int64  `json:"fact_node_ids"`
	AssetIDs     []int64  `json:"asset_ids"`
	SecretMasked string   `json:"secret_masked"`
	Patterns     []string `json:"patterns"`
	WhereUsed    []string `json:"where_used"`
	Versions     []string `json:"versions"`
	Severity     string   `json:"severity"`
	VulnClass    string   `json:"vulnclass"`
	Title        string   `json:"title"`
	AssetType    string   `json:"asset_type"`
	URL          string   `json:"url"`
}

func decodeIntelDetail(raw json.RawMessage) intelRowDetail {
	var d intelRowDetail
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &d)
	}
	return d
}

// splitEndpointKey 拆 "method /path?params"：方法小写、路径去掉 query。
func splitEndpointKey(key string) (method, path string) {
	key = strings.TrimSpace(key)
	method = "get"
	if i := strings.IndexByte(key, ' '); i > 0 {
		method = strings.ToLower(strings.TrimSpace(key[:i]))
		key = strings.TrimSpace(key[i+1:])
	}
	if i := strings.IndexByte(key, '?'); i >= 0 {
		key = key[:i]
	}
	return method, key
}

// buildIntelEvidence 把来源 id 列表按序号对齐合并：
// 一条 finding + 一条 fact → [{finding_id, fact_node_id}]，与小结页的证据链一致。
func buildIntelEvidence(d intelRowDetail) []intelEvidence {
	n := len(d.FindingIDs)
	if len(d.FactNodeIDs) > n {
		n = len(d.FactNodeIDs)
	}
	if len(d.AssetIDs) > n {
		n = len(d.AssetIDs)
	}
	out := make([]intelEvidence, 0, n)
	for i := 0; i < n; i++ {
		var e intelEvidence
		if i < len(d.FindingIDs) {
			v := d.FindingIDs[i]
			e.FindingID = &v
		}
		if i < len(d.FactNodeIDs) {
			v := d.FactNodeIDs[i]
			e.FactNodeID = &v
		}
		if i < len(d.AssetIDs) {
			v := d.AssetIDs[i]
			e.AssetID = &v
		}
		out = append(out, e)
	}
	return out
}

func emptyIfNil[T any](in []T) []T {
	if in == nil {
		return []T{}
	}
	return in
}

// buildIntelGroups 纯函数：平铺行 → 五组结构化条目（空组是 []，顺序稳定）。
func buildIntelGroups(rows []db.TaskIntel) intelGroups {
	g := intelGroups{
		Endpoint:   []intelEndpointItem{},
		Credential: []intelCredentialItem{},
		Component:  []intelComponentItem{},
		Asset:      []intelAssetItem{},
		Vuln:       []intelVulnItem{},
	}
	for _, r := range rows {
		d := decodeIntelDetail(r.Detail)
		switch r.Kind {
		case db.IntelKindEndpoint:
			method, path := splitEndpointKey(r.Key)
			hit := d.Count
			if hit <= 0 {
				hit = 1
			}
			g.Endpoint = append(g.Endpoint, intelEndpointItem{
				Key: r.Key, Method: method, Path: path,
				Hosts:        emptyIfNil(d.Hosts),
				Purpose:      d.Purpose,
				Params:       emptyIfNil(d.Params),
				StatusCodes:  makeIntSlice(d.StatusCodes),
				AuthRequired: d.AuthRequired,
				HitCount:     hit,
				Evidence:     emptyIfNil(buildIntelEvidence(d)),
			})
		case db.IntelKindCredential:
			parts := strings.SplitN(r.Key, "|", 3)
			ctype, user, svc := "", "", ""
			if len(parts) > 0 {
				ctype = parts[0]
			}
			if len(parts) > 1 && parts[1] != "-" {
				user = parts[1]
			}
			if len(parts) > 2 && parts[2] != "-" {
				svc = parts[2]
			}
			g.Credential = append(g.Credential, intelCredentialItem{
				Key: r.Key, CredentialType: ctype, Username: user, Service: svc,
				Value: r.Value, SecretMasked: d.SecretMasked,
				WhereUsed: emptyIfNil(d.WhereUsed), Source: r.Source,
			})
		case db.IntelKindComponent:
			product, version := r.Key, ""
			if i := strings.IndexByte(r.Key, '@'); i >= 0 {
				product = r.Key[:i]
				if v := r.Key[i+1:]; v != "*" {
					version = v
				}
			}
			g.Component = append(g.Component, intelComponentItem{
				Key: r.Key, Product: product, Version: version, Value: r.Value,
			})
		case db.IntelKindAsset:
			host, port := r.Key, 0
			if i := strings.LastIndex(r.Key, ":"); i > 0 {
				host = r.Key[:i]
				port = atoiSafe(r.Key[i+1:])
			}
			g.Asset = append(g.Asset, intelAssetItem{
				Key: r.Key, Host: host, Port: port, Value: r.Value,
			})
		case db.IntelKindVuln:
			key := r.Key
			asset := ""
			if i := strings.LastIndex(key, "|"); i >= 0 {
				asset = key[i+1:]
				key = key[:i]
			}
			title := d.Title
			if title == "" {
				title = key
			}
			var fid int64
			if len(d.FindingIDs) > 0 {
				fid = d.FindingIDs[0]
			}
			g.Vuln = append(g.Vuln, intelVulnItem{
				Key: r.Key, Title: title, Severity: d.Severity, Asset: asset, FindingID: fid,
			})
		}
	}
	return g
}

func makeIntSlice(in []int) []int {
	if in == nil {
		return []int{}
	}
	return in
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// buildTaskIntelSummary 组装任务小结头部。project_name 取不到就留空（任务
// 未挂项目或项目已删），不阻断整个响应。
func (s *Server) buildTaskIntelSummary(ctx context.Context, t *db.Task, groups intelGroups) *taskIntelSummary {
	sum := &taskIntelSummary{
		Name:   t.Name,
		Goal:   t.Goal,
		Status: t.Status,
		Counts: map[string]int{
			db.IntelKindEndpoint:   len(groups.Endpoint),
			db.IntelKindCredential: len(groups.Credential),
			db.IntelKindComponent:  len(groups.Component),
			db.IntelKindAsset:      len(groups.Asset),
			db.IntelKindVuln:       len(groups.Vuln),
			"finding":              0,
			"intent":               0,
		},
	}
	if t.ProjectID != nil && *t.ProjectID > 0 {
		sum.ProjectID = *t.ProjectID
		if p, err := s.m.pg.GetProject(*t.ProjectID); err == nil && p != nil {
			sum.ProjectName = p.Name
		}
	}
	start := t.FirstRunAt
	if start == nil {
		created := t.CreatedAt
		start = &created
	}
	sum.StartedAt = start
	sum.EndedAt = t.CompletedAt
	end := time.Now()
	if t.CompletedAt != nil {
		end = *t.CompletedAt
	}
	if d := end.Sub(*start); d > 0 {
		sum.DurationSeconds = int64(d / time.Second)
	}
	if findings, intents, err := s.m.pg.TaskIntelScopeCounts(ctx, t.ID); err == nil {
		sum.Counts["finding"] = findings
		sum.Counts["intent"] = intents
	}
	return sum
}

// taskIntelList GET /api/tasks/{id}/intel。
func (s *Server) taskIntelList(w http.ResponseWriter, r *http.Request) {
	taskID, ok := pathInt(r, "id")
	if !ok || taskID <= 0 {
		writeErr(w, 400, "任务 id 无效")
		return
	}
	t, err := s.m.pg.GetTask(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if t == nil {
		writeErr(w, 404, "任务不存在")
		return
	}
	rows, err := s.m.pg.TaskIntelForTask(r.Context(), taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	groups := buildIntelGroups(rows)
	resp := taskIntelResp{
		TaskID:       taskID,
		Total:        len(rows),
		Summary:      s.buildTaskIntelSummary(r.Context(), t, groups),
		Groups:       groups,
		LegacyGroups: groupTaskIntel(rows),
	}
	if t.ProjectID == nil || *t.ProjectID <= 0 {
		resp.Hint = "该任务未挂项目：情报表只在项目内生成（跨任务比对需要项目范围）。"
	} else if len(rows) == 0 {
		resp.Hint = "暂无情报：任务收官时自动生成，也可点「重建」立即抽取。"
	}
	writeJSON(w, 200, resp)
}

// taskIntelRebuild POST /api/tasks/{id}/intel/rebuild —— 同步重建。终态钩子
// 是异步尽力而为，这里是可重试的确定性入口：先删本任务由抽取生成的旧行再重建
// （source=manual 保留），因此历史上抽错的噪声行会在这里被清掉；重复调用行数
// 与 key 集合一致（幂等），只有相对旧表真正新增的 key 才发图变更信号。
func (s *Server) taskIntelRebuild(w http.ResponseWriter, r *http.Request) {
	taskID, ok := pathInt(r, "id")
	if !ok || taskID <= 0 {
		writeErr(w, 400, "任务 id 无效")
		return
	}
	st, err := s.rebuildTaskIntel(r.Context(), taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, st)
}
