package server

// V9-READER：勾连判定从规划者移到阅读者。
//
// 背景（用户规格）：规划者上下文宝贵，不应自己下钻旧任务。任务图变更通常意味着
// 小结表（task_intel）产生增量；阅读者拿增量与库内其它任务比对，读【当前任务】
// 与【被勾连任务】两边上下文判定相关性：
//
//	reader : read_task_intel（增量）→ get_task_graph_digest（两边摘要）
//	         → adopt_related_task（相关：写 hint 暴露被勾连任务图给发起方规划者）
//	         / dismiss_related_task（不相关：只留审计）
//	备用   : request_reader_links（按 surface 找候选）
//
// 规划者不再持有任何勾连工具，也不再读旧任务；它被 hint 唤醒后直接采信 hint
// 里的来源任务、理由与可复用要点。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	// readerLinkDefaultLimit 是 request_reader_links 默认返回的候选任务数。
	readerLinkDefaultLimit = 5
	// readerLinkMaxLimit 防模型一次要太多候选把上下文撑爆。
	readerLinkMaxLimit = 20
	// readerLinkHintMaxHits 是 adopt 写进 hint 的命中明细上限。
	readerLinkHintMaxHits = 6
	// readerLinkHintMaxRows 是无 matched 入参时从被采纳任务情报表取的行数上限。
	readerLinkHintMaxRows = 8
	// readerLinkHintMaxOverlap 是 hint 里「重合接口」的条数上限。
	readerLinkHintMaxOverlap = 4
	// readerLinkDecidedBy 是 V9-READER 起勾连决策的决策者标记。
	readerLinkDecidedBy = "reader"
)

// readerLinkCandidateNote 是 request_reader_links 返回里必须带的一句提示
// （用户规格：候选不等于结论，必须由阅读者读完两边上下文再判定）。
const readerLinkCandidateNote = "以下为候选，须由你判断相关性；拿到后直接调 judge_related_tasks(task_id, candidate_ids=[...]) 一次判完（每个候选独立上下文，互不影响）；score≥40 的 adopt、<40 的 dismiss；未判定的候选不要丢给规划者"

// ---------------------------------------------------------------------------
// surface → (kind,key)
// ---------------------------------------------------------------------------

var (
	// 带方法的裸路径：POST /api/user/123。
	reSurfaceMethodPath = regexp.MustCompile(`(?i)\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+(/[A-Za-z0-9_\-./%{}@+~:]+)`)
	// 裸路径（不含方法）：/api/user/list。前置要求行首或分隔符，避免从 URL
	// 主机名后面截一段路径（https://h/api/x 的 /api 前面是 'h'，不会命中）。
	reSurfaceBarePath = regexp.MustCompile(`(?:^|[\s"'（(【\[,，;；])(/[A-Za-z0-9_\-./%{}@+~:]{1,})`)
	// host:port（IPv4 或域名）。
	reSurfaceHostPort = regexp.MustCompile(`(?i)\b((?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}):(\d{1,5})\b`)
	// 产品/版本 token：nginx/1.18.0、Canal/1.1.5。版本至少一个点，避免把
	// 路径片段 "users/123" 误当产品版本。
	reSurfaceProdVer = regexp.MustCompile(`(?i)\b([A-Za-z][A-Za-z0-9._+\-]{1,30})/([vV]?\d+(?:\.\d+)+)\b`)
)

// intelSurfaceKeys 是纯函数：从一段新攻击面描述里抽候选 (kind,key)。
//
// 规则（与情报表的归一化口径对齐）：
//   - 绝对 URL → endpoint（NormalizeEndpoint，方法缺省 GET）+ asset（host:port，
//     端口缺省按 scheme 补 80/443）；
//   - 带方法/不带方法的裸路径（/api/...）→ endpoint；
//   - host:port → asset；
//   - 已知产品 + 版本、Product/1.2.3 → component（product@major.minor）。
//
// 去重、保序（endpoint → asset → component）。空输入返回 nil。
func intelSurfaceKeys(surface string) []db.IntelKeyRef {
	text := strings.TrimSpace(surface)
	if text == "" {
		return nil
	}
	var out []db.IntelKeyRef
	seen := map[string]bool{}
	add := func(kind, key string) {
		kind = strings.ToLower(strings.TrimSpace(kind))
		key = strings.TrimSpace(key)
		if kind == "" || key == "" {
			return
		}
		id := kind + "\x00" + key
		if seen[id] {
			return
		}
		seen[id] = true
		out = append(out, db.IntelKeyRef{Kind: kind, Key: key})
	}

	// 1) 绝对 URL：endpoint + asset。
	methodPath := map[string]bool{}
	for _, raw := range reIntelAbsURL.FindAllString(text, -1) {
		if k, _ := db.NormalizeEndpoint("", raw); k != "" {
			add(db.IntelKindEndpoint, k)
		}
		if a := intelAssetKeyFromURL(raw); a != "" {
			add(db.IntelKindAsset, a)
		}
	}
	// 2) 显式方法 + 路径。
	for _, m := range reSurfaceMethodPath.FindAllStringSubmatch(text, -1) {
		p := trimSurfacePath(m[2])
		if p == "" {
			continue
		}
		methodPath[p] = true
		if k, _ := db.NormalizeEndpoint(m[1], p); k != "" {
			add(db.IntelKindEndpoint, k)
		}
	}
	// 3) 裸路径（已带方法的路径不重复抽）。
	for _, m := range reSurfaceBarePath.FindAllStringSubmatch(text, -1) {
		p := trimSurfacePath(m[1])
		if p == "" || methodPath[p] {
			continue
		}
		if k, _ := db.NormalizeEndpoint("", p); k != "" {
			add(db.IntelKindEndpoint, k)
		}
	}
	// 4) host:port → asset。端口越界只丢该条（文本里其它面继续抽）。
	for _, m := range reSurfaceHostPort.FindAllStringSubmatch(text, -1) {
		port, err := strconv.Atoi(m[2])
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		host := strings.ToLower(m[1])
		if !validGoalHost(host) {
			continue
		}
		add(db.IntelKindAsset, net.JoinHostPort(host, strconv.Itoa(port)))
	}
	// 5) 产品 + 版本 → component。先走已知产品表（含 "nginx 1.18.0" 这种
	// 空格分隔），再走 Product/1.2.3 token。
	for _, m := range reIntelProductVer.FindAllStringSubmatch(text, -1) {
		prod := m[1]
		if c, ok := intelCanonicalProduct(prod); ok {
			prod = c
		}
		if k, _ := db.NormalizeComponent(prod, m[2]); k != "" {
			add(db.IntelKindComponent, k)
		}
	}
	for _, loc := range reSurfaceProdVer.FindAllStringSubmatchIndex(text, -1) {
		// 左侧紧跟 "/" 说明是路径片段（/api/1.2），不是产品/版本。
		if loc[0] > 0 && text[loc[0]-1] == '/' {
			continue
		}
		prod := text[loc[2]:loc[3]]
		// HTTP/1.1 这类协议版本不是组件。
		if intelSurfaceProdNoise[strings.ToLower(prod)] {
			continue
		}
		if k, _ := db.NormalizeComponent(prod, text[loc[4]:loc[5]]); k != "" {
			add(db.IntelKindComponent, k)
		}
	}
	return out
}

// intelSurfaceProdNoise 是 Product/Version 形态里不该当组件的协议/通用词。
var intelSurfaceProdNoise = map[string]bool{
	"http": true, "https": true, "ws": true, "wss": true, "ftp": true,
	"tcp": true, "udp": true, "socks": true, "socks5": true,
}

// trimSurfacePath 清理裸路径尾部常见标点，并挡掉 "/"、"//" 与纯符号片段。
func trimSurfacePath(p string) string {
	p = strings.TrimRight(p, `.,;:!?。，；：！？)`+"'\"》】]")
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || len(p) < 2 {
		return ""
	}
	body := p[1:]
	if body == "" {
		return ""
	}
	hasWord := false
	for _, r := range body {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			hasWord = true
			break
		}
	}
	if !hasWord {
		return ""
	}
	return p
}

// intelAssetKeyFromURL 取 URL 的 asset 键：host + 显式端口，缺省按 scheme 补
// 80/443（与 server/task_intel_build.go 的 intelAssetKey 同口径）。
func intelAssetKeyFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	if p := u.Port(); p != "" {
		return host + ":" + p
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "wss":
		return host + ":443"
	case "http", "ws":
		return host + ":80"
	}
	return host
}

// ---------------------------------------------------------------------------
// 阅读者勾连工具
// ---------------------------------------------------------------------------

// readerLinkHit 是一条命中明细（同时作为 task_intel_links.matched 的元素形状）。
// Key 是命中行的精确键（供下钻复核），MatchKey 是本次据以连上的粗粒度键
// （planner 据此知道"是按接口路径还是按组件产品名连上的"）。
type readerLinkHit struct {
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	MatchKey string `json:"match_key,omitempty"`
	Value    string `json:"value"`
	// Score 是本条命中对候选总分的贡献：精确 1.0 / 模糊 0.6 / 凭据 1.2 /
	// 资产 0.8 / 组件 0.3。审计里据此解释"为什么它在候选里"。
	Score float64 `json:"score,omitempty"`
	// Match 标记命中方式：exact=归一化后完全相等 / fuzzy=路径相似。
	Match string `json:"match,omitempty"`
}

// readerLinkSurfaceKey 是 debug.surface_keys 的元素：surface 抽出的精确键 +
// 它换算出的匹配键。线上核对"为什么 0 候选"时，一眼能看出比对口径。
type readerLinkSurfaceKey struct {
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	MatchKey string `json:"match_key"`
}

// readerLinkCandidate 是 request_reader_links 返回的候选任务。
//
// 两级评分的第一级在这里：MatchScore 是 SQL 侧命中打分，MatchStrength 是
// 它映射出的档位。规则（用户认可）：Σ≥2.0 strong / Σ≥1.0 medium / Σ>0 weak；
// **weak 不进候选**（单条模糊或仅组件同名不足以让阅读者去读两张图）。
type readerLinkCandidate struct {
	TaskID        int64           `json:"task_id"`
	TaskName      string          `json:"task_name"`
	ProjectID     int64           `json:"project_id"`
	Hits          []readerLinkHit `json:"hits"`
	HitCount      int             `json:"hit_count"`
	ExactHits     int             `json:"exact_hits,omitempty"`
	FuzzyHits     int             `json:"fuzzy_hits,omitempty"`
	MatchScore    float64         `json:"match_score"`
	MatchStrength string          `json:"match_strength"`
	FindingCount  int             `json:"finding_count"`
	IntentCount   int             `json:"intent_count"`
}

// taskIntelLinkTarget 取勾连决策的「发起方任务」上下文：即被暴露情报给其规划者
// 的那个任务（图变更消息里的 task_id）。阅读者是全局视角、没有任务上下文，
// 因此 task_id 必须显式传入。
func (s *Server) taskIntelLinkTarget(ctx context.Context, raw json.RawMessage) (int64, *db.TaskInsightContext, error) {
	taskID := parseProfileID(raw)
	if taskID <= 0 {
		return 0, nil, fmt.Errorf("task_id 必填：填本轮图变更消息里的 task_id（发起方任务）")
	}
	if s == nil || s.m == nil || s.m.pg == nil {
		return 0, nil, fmt.Errorf("情报表存储不可用")
	}
	tctx, err := s.m.pg.TaskInsightContext(ctx, taskID)
	if err != nil {
		return 0, nil, fmt.Errorf("读取发起方任务失败（可能已删除）: %w", err)
	}
	if tctx.ProjectID <= 0 {
		return 0, nil, fmt.Errorf("发起方任务未挂项目：情报表只在项目内生成，无法勾连")
	}
	return taskID, tctx, nil
}

// toolRequestReaderLinks 是阅读者的备用入口：按一段新攻击面找候选任务。
// 常规入口是 read_task_intel 的增量，本工具用于已知 surface、需要按它反查时。
func (s *Server) toolRequestReaderLinks() actool.CoreTool {
	return roTool("request_reader_links",
		"备用入口：把一段攻击面描述（URL/裸路径/host:port/组件版本，可混合自由文本）交给情报表，找出命中同一接口/凭据/组件的其它任务。"+
			"返回候选任务的 task_id、名称、命中明细与该任务的 finding/意图数量；这只是候选，须由你（阅读者）读完两边上下文判断相关性，相关的用 adopt_related_task 暴露给发起方规划者、无关的用 dismiss_related_task 舍弃。"+
			"scope=project 是【跨任务阅读者】视角，只看同项目，需本项目 observer_enabled=true；"+
			"scope=cross 是【跨项目阅读者】视角，只看其它项目，需目标项目 reader_enabled=true。",
		objSchema(map[string]any{
			"surface":         strParam("攻击面描述（可含 URL、/api/... 路径、host:port、产品/版本，或一段自然语言）"),
			"project_id":      map[string]any{"type": "integer", "description": "检索锚定项目 id（scope=project 时即该项目；scope=cross 时排除该项目、查其它项目）"},
			"exclude_task_id": map[string]any{"type": "integer", "description": "可选：排除的发起方任务 id（通常是本轮图变更的 task_id）"},
			"scope":           map[string]any{"type": "string", "enum": []any{"project", "cross"}, "description": "检索范围：project=同项目(默认) / cross=已开启 reader_enabled 的其它项目"},
			"limit":           map[string]any{"type": "integer", "description": "候选任务数上限（默认 5，最大 20）"},
		}, "surface", "project_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Surface       string          `json:"surface"`
				ProjectID     json.RawMessage `json:"project_id"`
				ExcludeTaskID json.RawMessage `json:"exclude_task_id"`
				Scope         string          `json:"scope"`
				Limit         int             `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Surface) == "" {
				return actool.Errorf("surface 不能为空（描述攻击面，含 URL/路径/host:port/组件版本均可）"), nil
			}
			pid := parseProfileID(a.ProjectID)
			if pid <= 0 {
				return actool.Errorf("project_id 必填（阅读者按项目视野找候选）"), nil
			}
			excludeID := parseProfileID(a.ExcludeTaskID)
			scope := strings.ToLower(strings.TrimSpace(a.Scope))
			if scope == "" {
				scope = "project"
			}
			if scope != "project" && scope != "cross" {
				return actool.Errorf("scope 必须是 project 或 cross"), nil
			}
			// V7-SCOPE：两个视角各自一把开关（V6-DUAL 语义），拉取侧同样要过闸。
			//   scope=project（跨任务/项目内）→ 锚定项目 observer_enabled
			//   scope=cross （跨项目）        → 目标项目 reader_enabled（在 SQL 内过滤）
			if scope == "project" {
				if proj, perr := s.m.pg.GetProject(pid); perr == nil && proj != nil && !proj.ObserverEnabled {
					return jsonResult(map[string]any{
						"surface":    a.Surface,
						"scope":      scope,
						"keys":       []db.IntelKeyRef{},
						"candidates": []readerLinkCandidate{},
						"debug":      map[string]any{"missing_switch": "observer_enabled", "queried_project_id": pid},
						"note":       "该项目未开启【跨任务】视角（observer_enabled=false），项目内任务情报不可勾连。" + readerLinkCandidateNote,
					})
				}
			}
			limit := a.Limit
			if limit <= 0 {
				limit = readerLinkDefaultLimit
			}
			if limit > readerLinkMaxLimit {
				limit = readerLinkMaxLimit
			}
			keys := intelSurfaceKeys(a.Surface)
			// debug 面：把 surface → 精确键 → 匹配键的换算结果一并回给模型/
			// 运维，线上排查"为什么 0 候选"时不必再猜比对口径。
			surfaceKeys := make([]readerLinkSurfaceKey, 0, len(keys))
			for _, k := range keys {
				surfaceKeys = append(surfaceKeys, readerLinkSurfaceKey{
					Kind: k.Kind, Key: k.Key, MatchKey: db.IntelMatchKey(k.Kind, k.Key),
				})
			}
			debug := map[string]any{
				"surface_keys":       surfaceKeys,
				"queried_project_id": pid,
				"exclude_task_id":    excludeID,
				"scope":              scope,
			}
			if len(keys) == 0 {
				return jsonResult(map[string]any{
					"surface":    a.Surface,
					"scope":      scope,
					"keys":       []db.IntelKeyRef{},
					"candidates": []readerLinkCandidate{},
					"debug":      debug,
					"note":       "未能从 surface 中抽出可比对的键（URL/路径/host:port/产品版本）；可改用更具体的接口或资产描述重试。" + readerLinkCandidateNote,
				})
			}
			matches, err := s.m.pg.MatchTaskIntel(ctx, pid, keys, excludeID, scope == "cross")
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			// V11：精确 match_key 只认「归一化后完全相等」，同 controller 的
			// /api/user/list 与 /api/user/info 会漏。这里补一层路径模糊匹配，
			// 按 (task_id,kind,key) 与精确结果合并（精确优先，不重复计分）。
			exactCount := len(matches)
			if fuzzy, ferr := s.m.pg.MatchTaskIntelFuzzy(ctx, pid, keys, excludeID, scope == "cross", 0.6); ferr == nil {
				matches = mergeIntelMatches(matches, fuzzy)
			} else {
				debug["fuzzy_error"] = ferr.Error()
			}
			debug["exact_rows"] = exactCount
			debug["fuzzy_rows"] = len(matches) - exactCount
			cands, weakDropped := aggregateReaderLinkCandidates(matches, limit)
			debug["weak_dropped"] = weakDropped
			// 候选落库：审计要能列出「所有候选的评分与是否采纳」。只落不给
			// 规划者——暴露门槛在 adopt（阅读者读完两张图后的 relevance 评分）。
			// 已有 adopted/dismissed 的对会被 SaveCandidateIntelLink 保护，不覆盖。
			if excludeID > 0 {
				for _, c := range cands {
					raw, _ := json.Marshal(c.Hits)
					_, _, _ = s.m.pg.SaveCandidateIntelLink(ctx, db.TaskIntelLink{
						ProjectID: pid, TaskID: excludeID, RelatedTaskID: c.TaskID,
						Reason: fmt.Sprintf("SQL 命中 %d 条（%.2f/%s），待阅读者读图判定",
							c.HitCount, c.MatchScore, c.MatchStrength),
						Matched: raw, MatchStrength: c.MatchStrength,
						MatchScore: c.MatchScore, MatchHits: c.HitCount,
					})
				}
			}
			out := map[string]any{
				"surface":    a.Surface,
				"scope":      scope,
				"keys":       keys,
				"candidates": cands,
				"debug":      debug,
				"note":       readerLinkCandidateNote,
			}
			if len(cands) == 0 {
				out["note"] = "没有其它任务命中这些键。" + readerLinkCandidateNote
			}
			return jsonResult(out)
		})
}

// mergeIntelMatches 把精确 JOIN 与模糊补漏的命中行合并，按
// (task_id, kind, key) 去重——精确行先入，模糊行只有在没被精确命中时才补进来。
// 这样同一个接口不会既算 1.0 又算 0.6。
func mergeIntelMatches(exact, fuzzy []db.IntelTaskMatch) []db.IntelTaskMatch {
	if len(fuzzy) == 0 {
		return exact
	}
	key := func(m db.IntelTaskMatch) string {
		return fmt.Sprintf("%d\x00%s\x00%s", m.TaskID, m.Kind, m.Key)
	}
	seen := make(map[string]bool, len(exact)+len(fuzzy))
	out := make([]db.IntelTaskMatch, 0, len(exact)+len(fuzzy))
	for _, m := range exact {
		seen[key(m)] = true
		out = append(out, m)
	}
	for _, m := range fuzzy {
		if seen[key(m)] {
			continue
		}
		seen[key(m)] = true
		out = append(out, m)
	}
	return out
}

// aggregateReaderLinkCandidates 是纯函数：命中行 → 候选任务（按累计分降序），
// 并截断到 limit。
//
// 打分（用户认可的口径）：精确接口 1.0 / 模糊接口 0.6 / 凭据 1.2 / 资产 0.8 /
// 组件 0.3。Σ≥2.0 strong、Σ≥1.0 medium、Σ>0 weak。
// **weak 不进候选**：单条模糊路径或仅组件同名，不足以让阅读者去读两张完整图。
// 组件仍然随强信号返回（作为旁证），只是不能单独成候选。
func aggregateReaderLinkCandidates(matches []db.IntelTaskMatch, limit int) ([]readerLinkCandidate, int) {
	if len(matches) == 0 {
		return []readerLinkCandidate{}, 0
	}
	byTask := map[int64]*readerLinkCandidate{}
	hitSeen := map[int64]map[string]bool{}
	for _, m := range matches {
		c := byTask[m.TaskID]
		if c == nil {
			c = &readerLinkCandidate{
				TaskID:       m.TaskID,
				TaskName:     m.TaskName,
				ProjectID:    m.ProjectID,
				FindingCount: m.FindingCount,
				IntentCount:  m.IntentCount,
			}
			byTask[m.TaskID] = c
			hitSeen[m.TaskID] = map[string]bool{}
		}
		id := m.Kind + "\x00" + m.Key
		if hitSeen[m.TaskID][id] {
			continue
		}
		// 精确 JOIN 的行没有 MatchScore，按 kind 取固定分；模糊补漏的行带相似度。
		score, how := m.MatchScore, m.MatchKind
		if score <= 0 {
			score, how = db.EndpointHitScore(m.Kind), "exact"
		}
		if score <= 0 {
			continue // vuln 等不可比类型
		}
		hitSeen[m.TaskID][id] = true
		c.Hits = append(c.Hits, readerLinkHit{
			Kind: m.Kind, Key: m.Key, MatchKey: m.MatchKey, Value: m.Value,
			Score: score, Match: how,
		})
		c.MatchScore += score
		if how == "fuzzy" {
			c.FuzzyHits++
		} else {
			c.ExactHits++
		}
	}
	out := make([]readerLinkCandidate, 0, len(byTask))
	dropped := 0
	for _, c := range byTask {
		c.MatchScore = math.Round(c.MatchScore*100) / 100
		c.MatchStrength = db.MatchStrengthOf(c.MatchScore)
		if c.MatchStrength == "" || c.MatchStrength == "weak" {
			dropped++ // weak 不进候选（见函数注释），但计数回给调用方做 debug
			continue
		}
		c.HitCount = c.ExactHits + c.FuzzyHits // 只数计分命中：vuln 等 0 分项不算「命中 N 条」
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].MatchScore != out[j].MatchScore {
			return out[i].MatchScore > out[j].MatchScore
		}
		if out[i].HitCount != out[j].HitCount {
			return out[i].HitCount > out[j].HitCount
		}
		return out[i].TaskID < out[j].TaskID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, dropped
}

// toolAdoptRelatedTask 阅读者判定两个任务相关后调用：落
// task_intel_links(decision=adopted) 并把被勾连任务的可复用要点以结构化 hint
// 写进【发起方任务】，同时唤醒其规划者（复用 add_hint 的图变更 + NotifyHint
// 路径）。重复 adopt 幂等（不重复写 hint）。
func (s *Server) toolAdoptRelatedTask() actool.CoreTool {
	return wrTool("adopt_related_task",
		"阅读者专用：你读完【发起方任务】与【被勾连任务】两边上下文（get_task_graph_digest，读摘要不读全文）后，判定两者相关（同一攻击面/同一资产可复用/同一利用链）时调用。"+
			"记 decision=adopted，并写一条【方向提示】hint（来源任务+相关性分+重合接口）唤醒发起方规划者。"+
			"注意：hint 不承载测法（不写请求/参数/凭据），只在发起方一轮上下文里有效；细节由规划者/执行者用 ask_reader 向你下钻。"+
			"必须给 relevance_score（1-100，读完两张完整图后的判断），没有分数不接受采纳。"+
			"无关的候选请用 dismiss_related_task；重复采纳同一对任务是幂等的（不重复写 hint）。",
		objSchema(map[string]any{
			"task_id":         strParam("发起方任务 id：本轮图变更消息里的 task_id（要被暴露情报、被唤醒规划者的任务）"),
			"related_task_id": strParam("被勾连任务 id：情报来源任务（读到的旧任务）"),
			"reason":          strParam("判定相关的理由：必须写「读到了什么」（如两边都有未授权 /api/user/{id} 且旧任务已验证越权），不能只写「键相同」"),
			"relevance_score": map[string]any{"type": "integer", "description": "必填：读完两边完整图后的相关性评分 1-100（≥60 strong / 40-59 medium / <40 不采纳）。没有分数就不许采纳——档位兜底会把分数写成固定值，审计会失真"},
			"chains": map[string]any{"type": "array", "description": "读到并确认可迁移的利用链摘要（最多 6 条）。规划者靠它判断值不值得迁移，不靠原始边 id", "items": objSchema(map[string]any{
				"entry":    strParam("入口，如 GET /api/sso/userinfo"),
				"steps":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "中间结论，2-4 条短句"},
				"outcome":  strParam("终点/影响，如 越权读取任意用户信息"),
				"verified": map[string]any{"type": "boolean", "description": "对方任务里是否已验证"},
				"node_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "出处节点 id（read_task_graph 返回的整数 id，如 537；不确定就留空数组，不要填 0）"},
			})},
			"matched": map[string]any{"type": "array", "items": objSchema(map[string]any{
				"kind":  strParam("endpoint/credential/component/asset/vuln"),
				"key":   strParam("归一化键"),
				"value": strParam("人类可读原文"),
			}), "description": "可选：本次采纳依据的命中明细（缺省用被勾连任务情报表前若干行）"},
		}, "task_id", "related_task_id", "reason", "chains"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID        json.RawMessage `json:"task_id"`
				RelatedTaskID json.RawMessage `json:"related_task_id"`
				Reason        string          `json:"reason"`
				// 第二级评分：阅读者读完两张完整图后的相关性判断。这是暴露门槛，
				// 必填——不再接受从 strength 档位反推（那会把分数写成 70/50/30 的固定值）。
				RelevanceScore int              `json:"relevance_score"`
				Chains         []db.ReaderChain `json:"chains"`
				Matched        []readerLinkHit  `json:"matched"`
			}
			_ = json.Unmarshal(in, &a)
			taskID, tctx, err := s.taskIntelLinkTarget(ctx, a.TaskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			relatedID := parseProfileID(a.RelatedTaskID)
			if relatedID <= 0 || relatedID == taskID {
				return actool.Errorf("related_task_id 无效（必须是被勾连任务，不能等于 task_id）"), nil
			}
			reason := strings.TrimSpace(a.Reason)
			if reason == "" {
				return actool.Errorf("reason 必填：写清读到了什么（不能只写键相同）"), nil
			}
			score := a.RelevanceScore
			if score <= 0 {
				// 不接受「读完图但说不出相关性」的采纳，也不再用档位兜底：旧逻辑
				// 会把 strong 写成固定 70，审计里看起来像真打了分（实测 3 条采纳
				// 只有 1 条真给分）。
				return actool.Errorf("必须给 relevance_score（1-100）：读完两张完整图后的相关性评分。≥60 才暴露；40-59 可采纳但需说明；<40 请用 dismiss_related_task。档位（strength）不再兜底分数"), nil
			}
			if score > 100 {
				score = 100
			}
			if score < 40 {
				return actool.Errorf(fmt.Sprintf("relevance_score=%d 低于暴露门槛（medium=40）：不要 adopt。请用 dismiss_related_task 并写明「还缺什么证据」", score)), nil
			}
			relStrength := "medium"
			if score >= 60 {
				relStrength = "strong"
			}
			strength := relStrength
			chains := a.Chains
			if len(chains) == 0 {
				// 链摘要是规划者判断「值不值得迁移」的唯一依据（它看不到原始边）。
				// 不给就等于只暴露了一个接口名，跟旧版没区别，所以这里硬拦。
				return actool.Errorf("chains 必填：至少 1 条，从 read_task_graph 的 edges/nodes 整理——entry（接口 method+path）、steps（中间结论）、outcome（终点）、verified、node_ids。不要只写接口名"), nil
			}
			if len(chains) > 6 {
				chains = chains[:6]
			}
			chainRaw, _ := json.Marshal(chains)
			rt, err := s.m.pg.GetTask(relatedID)
			if err != nil || rt == nil {
				return actool.Errorf(fmt.Sprintf("被勾连任务不存在: %d", relatedID)), nil
			}
			rctx, err := s.m.pg.TaskInsightContext(ctx, relatedID)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("读取被勾连任务上下文失败: %v", err)), nil
			}
			prev, err := s.m.pg.TaskIntelLinkFor(ctx, taskID, relatedID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			matched := a.Matched
			if prev != nil && len(prev.Matched) > 0 {
				// 审计的 matched 必须与 match_score 同源：用候选阶段的 SQL 命中，
				// 不用模型在 adopt 参数里自己归纳的「命中」——后者会和分数对不上账
				// （实测出现过「分数 2.6 / 命中 4 条，明细列的是另一组」）。
				matched = nil
				_ = json.Unmarshal(prev.Matched, &matched)
			}
			if len(matched) == 0 {
				matched = s.intelHitsForTask(ctx, relatedID, readerLinkHintMaxRows)
			}
			raw, _ := json.Marshal(matched)
			linkID, err := s.m.pg.SaveTaskIntelLink(ctx, db.TaskIntelLink{
				ProjectID: tctx.ProjectID, TaskID: taskID, RelatedTaskID: relatedID,
				Decision: "adopted", Reason: reason, Matched: raw, DecidedBy: readerLinkDecidedBy,
				RelevanceScore: score, RelevanceStrength: relStrength, Chains: chainRaw,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			// V9-SCOPE：把被勾连任务的资产 host 记到发起方名下（负向清单）。
			// 幂等（UNIQUE(task_id,host)），重复 adopt 也会补齐；失败只记日志，
			// 不影响采纳本身 —— 执行层的匹配查不到就放行（宁漏不误伤）。
			foreignHosts := s.foreignAssetHostsForTask(ctx, relatedID)
			if _, ferr := s.m.pg.RecordTaskForeignAssets(ctx, taskID, relatedID, foreignHosts); ferr != nil {
				log.Printf("[reader] 记录任务#%d 的外部资产失败（source=#%d）: %v", taskID, relatedID, ferr)
			}
			if prev != nil && prev.Decision == "adopted" {
				s.noteReaderDecision(ctx, "adopted", fmt.Sprintf("%d:%d", taskID, relatedID))
				return actool.Text(fmt.Sprintf("任务#%d ↔ #%d 已是 adopted，决策与明细已更新；hint 不重复写入", taskID, relatedID)), nil
			}
			srcName := strings.TrimSpace(rt.Name)
			if srcName == "" {
				srcName = strings.TrimSpace(rt.Description)
			}
			overlap := overlapEndpoints(matched, readerLinkHintMaxOverlap)
			hintID, err := s.writeReaderAdoptHint(ctx, taskID, readerAdoptHint{
				SourceTaskID: relatedID, SourceTaskName: srcName,
				SourceProjectID: rctx.ProjectID, SourceProjectName: rctx.ProjectName,
				Strength: strength, Score: score, Overlap: overlap,
				// 给可直接下钻的节点 id（比让模型拼 query 少一轮）；
				// 给本任务已测证据（规划者据此决定「首次覆盖」还是「复测」）。
				DrillNodes:   s.drillNodeIDs(ctx, relatedID, chains, 4),
				SelfHits:     s.selfOverlapEvidence(ctx, taskID, overlap, 3),
				ForeignHosts: foreignHosts, LinkID: linkID,
			})
			s.noteReaderDecision(ctx, "adopted", fmt.Sprintf("%d:%d", taskID, relatedID))
			if err != nil {
				return actool.Text(fmt.Sprintf("已采纳任务#%d，但写 hint/唤醒规划者失败（不影响决策）：%v", relatedID, err)), nil
			}
			return actool.Text(fmt.Sprintf("已采纳任务#%d（decision=adopted），其可复用要点已写入任务#%d 的 hint#%d 并唤醒规划者", relatedID, taskID, hintID)), nil
		})
}

// toolDismissRelatedTask 阅读者判定候选与发起方无关时调用：只落
// decision=dismissed，不写 hint、不唤醒规划者。
func (s *Server) toolDismissRelatedTask() actool.CoreTool {
	return wrTool("dismiss_related_task",
		"阅读者专用：读完两边上下文后判定某个候选与发起方任务无关时调用。记 decision=dismissed（含一句话理由），不写 hint、不唤醒规划者。"+
			"相关的候选请用 adopt_related_task。",
		objSchema(map[string]any{
			"task_id":         strParam("发起方任务 id（本轮图变更消息里的 task_id）"),
			"related_task_id": strParam("被舍弃的候选任务 id"),
			"reason":          strParam("舍弃理由（一句话，说明读完两边后为什么不相关）"),
			"matched": map[string]any{"type": "array", "items": objSchema(map[string]any{
				"kind":  strParam("endpoint/credential/component/asset/vuln"),
				"key":   strParam("归一化键"),
				"value": strParam("人类可读原文"),
			}), "description": "可选：命中明细（留档复盘为什么看过又舍弃）"},
		}, "task_id", "related_task_id", "reason"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID        json.RawMessage `json:"task_id"`
				RelatedTaskID json.RawMessage `json:"related_task_id"`
				Reason        string          `json:"reason"`
				Matched       []readerLinkHit `json:"matched"`
			}
			_ = json.Unmarshal(in, &a)
			taskID, tctx, err := s.taskIntelLinkTarget(ctx, a.TaskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			relatedID := parseProfileID(a.RelatedTaskID)
			if relatedID <= 0 || relatedID == taskID {
				return actool.Errorf("related_task_id 无效（必须是被勾连任务，不能等于 task_id）"), nil
			}
			reason := strings.TrimSpace(a.Reason)
			if reason == "" {
				return actool.Errorf("reason 必填：一句话说明为什么不相关"), nil
			}
			raw, _ := json.Marshal(a.Matched)
			if len(a.Matched) == 0 {
				raw = json.RawMessage(`[]`)
			}
			if _, err := s.m.pg.SaveTaskIntelLink(ctx, db.TaskIntelLink{
				ProjectID: tctx.ProjectID, TaskID: taskID, RelatedTaskID: relatedID,
				Decision: "dismissed", Reason: reason, Matched: raw, DecidedBy: readerLinkDecidedBy,
			}); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			s.noteReaderDecision(ctx, "dismissed", fmt.Sprintf("%d:%d", taskID, relatedID))
			return actool.Text(fmt.Sprintf("已舍弃任务#%d（decision=dismissed，不写 hint、不唤醒）", relatedID)), nil
		})
}

// readerAdoptHint 是写进发起方任务图的结构化 hint 内容。
//
// V11-READER4（用户口径）：hint 只是「往哪看」的方向提示，**不承载测法**。
// 早期版本把被勾连任务的可复用要点、关键事实、凭据掩码都塞进 hint，结果是
// 执行者照 hint 就能复述结论，ask_reader 反而没人调（实测一轮里 3 次下钻全是
// 人工注入）。细节应当由执行者按意图下钻，且下钻后必须做本任务自己的验证。
type readerAdoptHint struct {
	SourceTaskID      int64
	SourceTaskName    string
	SourceProjectID   int64
	SourceProjectName string
	Strength          string
	// Score 是阅读者读完两张完整图后的相关性评分（暴露门槛，不再是档位兜底）。
	Score int
	// Overlap 是两边撞上的接口（METHOD /path，已脱敏），最多 4 条。
	// 规划者靠它把「本轮要测的端点」和「参考任务测过的端点」对上。
	Overlap []string
	// DrillNodes 是可以直接按 id 下钻的节点（chains.node_ids 优先，其次参考
	// 任务情报表的 source_id），最多 4 个。给 id 比让模型自己拼 query 少一轮。
	DrillNodes []int64
	// SelfHits 是本任务【已经测过】同一接口的证据（"GET /api/x — fact#650 …"），
	// 最多 3 条。规划者据此把「复测 + 借鉴」合成一条意图；为空表示首次覆盖。
	SelfHits []string
	// ForeignHosts 是被勾连任务情报表（task_intel kind=asset）里的资产 host。
	// 它们只是经验参考的对象，不属于发起方任务授权范围（V9-SCOPE）。
	ForeignHosts []string
	LinkID       int64
}

// writeReaderAdoptHint 把 adopted 结论写进发起方任务图（与 add_hint 同形态：
// kind=hint + 图变更事件），并调用 NotifyHint 唤醒其规划者。规划者不再自己
// 下钻：hint 里已给出来源任务、关联强度和可复用要点。
func (s *Server) writeReaderAdoptHint(ctx context.Context, taskID int64, h readerAdoptHint) (int64, error) {
	// 不能用 s.m.Task：那只查「运行表」（引擎里活着的任务）。用户暂停的任务、
	// 或刚好在两次唤醒之间的任务都不在表里，hint 会被静默丢掉——而 hint 是
	// 阅读者暴露给规划者的唯一通道，丢了等于这次采纳白做。直接写 PG。
	var expID, projectID int64
	if err := s.m.pg.QueryRowContext(ctx, `
SELECT exploration_id, COALESCE(project_id,0) FROM tasks WHERE id=$1 AND deleted_at IS NULL`, taskID).
		Scan(&expID, &projectID); err != nil {
		return 0, fmt.Errorf("发起方任务#%d 不存在或已删除: %w", taskID, err)
	}
	text := renderReaderAdoptHint(h)
	payload := map[string]any{
		"text":                text,
		"decided_by":          readerLinkDecidedBy,
		"reference_only":      true,
		"foreign_host_count":  len(h.ForeignHosts),
		"source_task_id":      h.SourceTaskID,
		"source_task_name":    h.SourceTaskName,
		"source_project_id":   h.SourceProjectID,
		"source_project_name": h.SourceProjectName,
		"strength":            h.Strength,
		"relevance_score":     h.Score,
		"overlap_endpoints":   h.Overlap,
		"link_id":             h.LinkID,
	}
	id, err := s.m.pg.Exploration(expID).AddNode(db.KindHint, payload, 0, "active", "reader", nil)
	if err != nil {
		return 0, err
	}
	// 图变更事件：让项目级阅读者水位看到这条 hint（也让审计能追到）。
	if projectID > 0 {
		_ = s.m.pg.InsertGraphEvent(ctx, projectID, taskID, id, db.KindHint,
			fmt.Sprintf("阅读者采纳任务#%d（%s，相关性 %d）：重合接口 %s",
				h.SourceTaskID, h.Strength, h.Score, strings.Join(h.Overlap, "、")))
	}
	// 任务在跑就立刻唤醒规划者；暂停的任务只落图，恢复后第一轮就能读到。
	if t, ok := s.m.Task(strconv.FormatInt(taskID, 10)); ok && t != nil {
		t.NotifyHint([]string{text})
		// 光唤醒规划者不够：worker 是长 run，它的 system prompt 在启动时就固定了，
		// 采纳完成时它可能已经跑了几十秒（实测 17:57:23 的 ask_reader(136) 被拒，
		// 17:58:14 才 adopt）。adopt 的瞬间给所有 running 意图排一条纠正消息，
		// worker 下一步就能拿到下钻入口，不用等下一轮或人工注入。
		s.steerWorkersOnAdopt(ctx, expID, h)
	}
	return id, nil
}

// steerWorkersOnAdopt 在采纳落库后，给本任务所有 running 意图注入一条「可以下钻了」
// 的指令。只做通知，不改意图：worker 仍按自己的意图走，只是知道了入口和两段要求。
func (s *Server) steerWorkersOnAdopt(ctx context.Context, expID int64, h readerAdoptHint) {
	if s.engine == nil || expID <= 0 || h.SourceTaskID <= 0 {
		return
	}
	nodes, err := s.m.pg.Exploration(expID).ListByKind(db.KindIntent, 50)
	if err != nil {
		return
	}
	overlap := strings.Join(h.Overlap, "、")
	if overlap == "" {
		return // 没有重合接口 = 没什么可借的，别拿噪音打扰 worker
	}
	// 只通知「可能用得上」的意图：summary 里出现任一重合接口的路径。否则一次采纳
	// 会给所有 running 意图都塞一条无关消息，5 条采纳就是 5 条噪音。
	paths := make([]string, 0, len(h.Overlap))
	for _, ep := range h.Overlap {
		if i := strings.IndexByte(ep, ' '); i > 0 {
			ep = strings.TrimSpace(ep[i+1:])
		}
		if ep = strings.ToLower(strings.TrimSpace(ep)); ep != "" {
			paths = append(paths, ep)
		}
	}
	msg := fmt.Sprintf("阅读者已采纳任务#%d（相关性 %d/100，重合接口 %s）。现在可以 ask_reader(%d, query=\"/api/...\") 下钻；返回的凭据仅作低置信参考（可能过期、属于参考环境），在本任务资产上验证成功才算数。下钻后仍须「借鉴复现 + 自主验证」两段，只复现 = 未完成。",
		h.SourceTaskID, h.Score, overlap, h.SourceTaskID)
	for _, n := range nodes {
		if n.State != "running" {
			continue
		}
		var p struct {
			Summary string `json:"summary"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		summary := strings.ToLower(p.Summary)
		hit := len(paths) == 0
		for _, path := range paths {
			if strings.Contains(summary, path) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		if err := s.engine.SteerWork(n.ID, msg); err != nil {
			log.Printf("[reader] adopt 后 steer 意图#%d 失败（不影响采纳）: %v", n.ID, err)
		}
	}
}

// renderReaderAdoptHint 是纯函数：规划者读到的 hint 正文。
//
// V11-READER7（用户口径）：hint 只留四件事——来源与分数、重合接口、本任务覆盖
// 情况、下钻入口。两段式要求、授权边界、持久化说明全部删掉：
//   - 两段式在 workerReaderSpec / ask_reader 的 required_next 里已有，hint 重复
//     一遍只是噪音（实测每条约 900 字，占 planner 上下文的大头）；
//   - 授权边界在 plannerLinkGuidance 的硬规则里已有，执行层还会硬拦；
//   - hint 的持久性由 reader_refs.borrow_state 账本保证，不需要在正文里解释。
func renderReaderAdoptHint(h readerAdoptHint) string {
	var b strings.Builder
	b.WriteString("【阅读者·可借鉴】#")
	b.WriteString(strconv.FormatInt(h.SourceTaskID, 10))
	if n := strings.TrimSpace(h.SourceTaskName); n != "" {
		b.WriteString("「")
		b.WriteString(n)
		b.WriteString("」")
	}
	if h.Score > 0 {
		b.WriteString(" ")
		b.WriteString(strconv.Itoa(h.Score))
		b.WriteString("/100")
	}
	if len(h.Overlap) > 0 {
		b.WriteString("\n重合：")
		b.WriteString(strings.Join(h.Overlap, "、"))
	}
	if len(h.SelfHits) > 0 {
		b.WriteString("\n本任务已测：")
		b.WriteString(strings.Join(h.SelfHits, "；"))
	}
	b.WriteString("\n下钻：ask_reader(")
	b.WriteString(strconv.FormatInt(h.SourceTaskID, 10))
	if len(h.DrillNodes) > 0 {
		b.WriteString(", node_ids=[")
		for i, id := range h.DrillNodes {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(strconv.FormatInt(id, 10))
		}
		b.WriteString("])")
	} else if len(h.Overlap) > 0 {
		// 没有可定位的节点时才退化成 query：取第一条路径即可。
		path := h.Overlap[0]
		if i := strings.IndexByte(path, ' '); i > 0 {
			path = strings.TrimSpace(path[i+1:])
		}
		b.WriteString(", query=\"")
		b.WriteString(path)
		b.WriteString("\")")
	} else {
		b.WriteString(")")
	}
	return b.String()
}

// selfOverlapEvidence 查本任务情报表里与参考任务重合的接口，返回
// 「METHOD /path — fact#650 摘要」形态的证据行。用于让规划者知道这个端点
// 是「首次覆盖」还是「复测」——复测要把既有结论和借鉴一起带进意图。
func (s *Server) selfOverlapEvidence(ctx context.Context, taskID int64, overlap []string, n int) []string {
	if s.m.pg == nil || taskID <= 0 || len(overlap) == 0 || n <= 0 {
		return nil
	}
	keys := make([]string, 0, len(overlap))
	for _, ep := range overlap {
		if ep = strings.TrimSpace(ep); ep != "" {
			keys = append(keys, ep)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	// pgx stdlib 不把 []string 自动映射成 text[]，这里显式展开 IN（keys ≤4）。
	args := []any{taskID}
	marks := make([]string, 0, len(keys))
	for _, k := range keys {
		args = append(args, strings.ToLower(k))
		marks = append(marks, "$"+strconv.Itoa(len(args)))
	}
	args = append(args, n)
	rows, err := s.m.pg.QueryContext(ctx, `
SELECT ti.key, ti.value, COALESCE(ti.source_id,0), COALESCE(n.kind,'')
FROM task_intel ti
LEFT JOIN exploration_nodes n ON n.id = ti.source_id
WHERE ti.task_id=$1 AND ti.kind='endpoint' AND COALESCE(n.state,'') <> 'origin' AND lower(ti.key) IN (`+strings.Join(marks, ",")+`)
ORDER BY ti.id DESC LIMIT $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		log.Printf("[reader] 查任务#%d 本任务覆盖失败: %v", taskID, err)
		return nil
	}
	defer rows.Close()
	out := make([]string, 0, n)
	for rows.Next() {
		var key, val, nk string
		var src int64
		if err := rows.Scan(&key, &val, &src, &nk); err != nil {
			continue
		}
		line := strings.TrimSpace(key)
		if src > 0 {
			if nk == "" {
				nk = "node"
			}
			line += " — " + nk + "#" + strconv.FormatInt(src, 10)
		}
		if v := clipText(val, 80); v != "" {
			line += " " + v
		}
		out = append(out, line)
	}
	return out
}

// drillNodeIDs 从 chains 与参考任务情报表里选可下钻的节点 id（去重、保序、截断）。
func (s *Server) drillNodeIDs(ctx context.Context, relatedID int64, chains []db.ReaderChain, n int) []int64 {
	if n <= 0 {
		return nil
	}
	out := make([]int64, 0, n)
	seen := map[int64]bool{}
	add := func(id int64) {
		if id <= 0 || seen[id] || len(out) >= n {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	for _, c := range chains {
		for _, id := range c.NodeIDs {
			add(id)
		}
	}
	if len(out) < n {
		if rows, err := s.m.pg.TaskIntelForTask(ctx, relatedID); err == nil {
			for _, r := range rows {
				if r.SourceID != nil {
					add(*r.SourceID)
				}
				if len(out) >= n {
					break
				}
			}
		}
	}
	return out
}

// foreignAssetHostsForTask 从被勾连任务的小结表（task_intel）取资产 host。
// 只认 kind=asset（接口/凭据里出现的 IP 不在此列 —— 那些是打法素材，不是
// 被勾连任务的授权资产），归一化后去重排序，供 task_foreign_assets 落库。
func (s *Server) foreignAssetHostsForTask(ctx context.Context, taskID int64) []string {
	rows, err := s.m.pg.TaskIntelForTask(ctx, taskID)
	if err != nil {
		log.Printf("[reader] 读取任务#%d 资产情报失败（外部资产不记录）: %v", taskID, err)
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.Kind != db.IntelKindAsset {
			continue
		}
		h := guard.NormalizeHost(r.Key)
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// overlapEndpoints 是纯函数：从候选命中里取两边撞上的接口键（METHOD /path），
// 去重保序并截断到 n。它是 hint 里唯一允许出现的「参考任务内容」——路径不带
// host，规划者据此判断本轮要测的端点是否值得借鉴；其余细节一律走下钻。
func overlapEndpoints(hits []readerLinkHit, n int) []string {
	if n <= 0 {
		return nil
	}
	out := make([]string, 0, n)
	seen := map[string]bool{}
	for _, h := range hits {
		if h.Kind != db.IntelKindEndpoint {
			continue
		}
		k := strings.TrimSpace(h.Key)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
		if len(out) >= n {
			break
		}
	}
	return out
}

// clipRunes 按 rune 截断，给 hint / 参考图摘要限长。
func clipRunes(s string, max int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= max {
		return string(r)
	}
	return string(r[:max]) + "…"
}

// intelHitsForTask 读某任务情报表的前 n 行，转成 hint 用的命中明细。
func (s *Server) intelHitsForTask(ctx context.Context, taskID int64, n int) []readerLinkHit {
	rows, err := s.m.pg.TaskIntelForTask(ctx, taskID)
	if err != nil {
		return nil
	}
	out := make([]readerLinkHit, 0, n)
	for _, r := range rows {
		if len(out) >= n {
			break
		}
		out = append(out, readerLinkHit{Kind: r.Kind, Key: r.Key, MatchKey: r.MatchKey, Value: r.Value})
	}
	return out
}

// ---------------------------------------------------------------------------
// reader 两工具
// ---------------------------------------------------------------------------

// intelSummaryItem 是 read_task_intel 的条目（不带 detail，避免把情报表
// 全量明细灌进阅读者上下文）。
type intelSummaryItem struct {
	ID     int64  `json:"id"`
	TaskID int64  `json:"task_id"`
	Kind   string `json:"kind"`
	Key    string `json:"key"`
	Value  string `json:"value"`
	// Rev 是变更序列；同一行被更新（接口细节变丰富）时会以新 rev 再出现。
	Rev int64 `json:"rev,omitempty"`
}

// intelSummaryGroup 是按 kind 分组的增量摘要。
type intelSummaryGroup struct {
	Kind  string             `json:"kind"`
	Label string             `json:"label"`
	Count int                `json:"count"`
	Items []intelSummaryItem `json:"items"`
}

// toolReadTaskIntel 按 since_rev 水位增量读情报表，按 kind 分组返回摘要。
// project_id 缺省=全部开启 reader_enabled 的 active 项目（阅读者的常规视野）。
func (s *Server) toolReadTaskIntel() actool.CoreTool {
	return roTool("read_task_intel",
		"按变更序列增量读任务情报表（每个任务终态生成的接口/凭据/组件/资产/漏洞表），用于判断「哪些任务可以互相比对」。"+
			"since_rev 传上一轮返回的 next_since_rev（首轮 0）；它是全局变更序列，接口细节变丰富也会重新下发（不是只增不改的 id）。"+
			"project_id 缺省=全部已开启 reader_enabled 的项目（跨项目视野）。"+
			"显式指定 project_id 时，该项目需 observer_enabled 或 reader_enabled 至少一项开启，否则进 skipped。返回按 kind 分组的条目与任务归属，以及 next_since_rev（下次传回）。",
		objSchema(map[string]any{
			"project_id": map[string]any{"type": "integer", "description": "可选：只读某个项目；缺省=全部开启 reader_enabled 的项目"},
			"since_rev":  map[string]any{"type": "integer", "description": "可选：上次读到的最大 rev（首轮 0）"},
			// 兼容旧参数：V10 提示词里写的是 since_id，传进来按 rev 处理并回显提示。
			"since_id": map[string]any{"type": "integer", "description": "已废弃：等同 since_rev（保留兼容）"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ProjectID json.RawMessage `json:"project_id"`
				SinceRev  json.RawMessage `json:"since_rev"`
				SinceID   json.RawMessage `json:"since_id"`
			}
			_ = json.Unmarshal(in, &a)
			if s == nil || s.m == nil || s.m.pg == nil {
				return actool.Errorf("情报表存储不可用"), nil
			}
			since := parseProfileID(a.SinceRev)
			if since <= 0 {
				since = parseProfileID(a.SinceID)
			}
			pid := parseProfileID(a.ProjectID)
			var pids []int64
			skipped := []map[string]any{}
			if pid > 0 {
				// V7-SCOPE：显式指定项目也要过视角开关——任一视角开着就可读：
				// 跨任务看 observer_enabled，跨项目看 reader_enabled。
				if proj, perr := s.m.pg.GetProject(pid); perr != nil || proj == nil ||
					(!proj.ObserverEnabled && !proj.ReaderEnabled) {
					skipped = append(skipped, map[string]any{
						"project_id": pid,
						"reason":     "该项目未开启任何阅读视角（observer_enabled=false 且 reader_enabled=false）",
					})
				} else {
					pids = []int64{pid}
				}
			} else {
				visible, _, err := s.readerVisibleProjects(nil)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				pids = visible
			}
			projects := make([]map[string]any, 0, len(pids))
			total := 0
			next := since
			for _, p := range pids {
				rows, watermark, err := s.m.pg.IntelSince(ctx, p, since)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if watermark > next {
					next = watermark
				}
				total += len(rows)
				projects = append(projects, map[string]any{
					"project_id":     p,
					"since_rev":      since,
					"next_since_rev": watermark,
					"has_more":       len(rows) >= 500,
					"total":          len(rows),
					"groups":         groupIntelSummary(rows),
					"tasks":          intelTaskCounts(rows),
				})
			}
			out := map[string]any{
				"since_rev":      since,
				"next_since_rev": next,
				"total":          total,
				"projects":       projects,
			}
			if len(skipped) > 0 {
				out["skipped"] = skipped
			}
			if total == 0 {
				out["note"] = "自该水位后没有新增情报，本轮无需勾连。"
			} else {
				out["note"] = "同一 kind/key 出现在多个任务即为候选勾连信号；发现可用 link_tasks 标成候选关联，不要用自由文本洞察代替结构化链接。"
			}
			return jsonResult(out)
		})
}

// groupIntelSummary 是纯函数：平铺情报行 → 按 kind 分组（固定顺序，未知
// kind 追加在后），组内保持输入序（DB 的 id 序=增量顺序）。
func groupIntelSummary(rows []db.TaskIntel) []intelSummaryGroup {
	byKind := map[string][]intelSummaryItem{}
	for _, r := range rows {
		byKind[r.Kind] = append(byKind[r.Kind], intelSummaryItem{
			ID: r.ID, TaskID: r.TaskID, Kind: r.Kind, Key: r.Key, Value: r.Value, Rev: r.Rev,
		})
	}
	out := make([]intelSummaryGroup, 0, len(intelGroupOrder))
	seen := map[string]bool{}
	for _, k := range intelGroupOrder {
		seen[k] = true
		items := byKind[k]
		if items == nil {
			items = []intelSummaryItem{}
		}
		out = append(out, intelSummaryGroup{Kind: k, Label: db.IntelKindLabel(k), Count: len(items), Items: items})
	}
	var extra []string
	for k := range byKind {
		if !seen[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		out = append(out, intelSummaryGroup{Kind: k, Label: db.IntelKindLabel(k), Count: len(byKind[k]), Items: byKind[k]})
	}
	return out
}

// intelTaskCounts 是纯函数：每任务的情报条数（阅读者据此挑「信息最多的
// 任务」优先比对）。
func intelTaskCounts(rows []db.TaskIntel) []map[string]any {
	order := make([]int64, 0, 4)
	counts := map[int64]int{}
	for _, r := range rows {
		if _, ok := counts[r.TaskID]; !ok {
			order = append(order, r.TaskID)
		}
		counts[r.TaskID]++
	}
	out := make([]map[string]any, 0, len(order))
	for _, id := range order {
		out = append(out, map[string]any{"task_id": id, "count": counts[id]})
	}
	return out
}

// toolLinkTasks 写 reader 的结构化候选关联（decision=candidate）。
// 幂等：UNIQUE(task_id,related_task_id) 上 upsert；已有 adopted/dismissed 的
// 行不被 candidate 覆盖（阅读者下钻后的决策优先）。
func (s *Server) toolLinkTasks() actool.CoreTool {
	return wrTool("link_tasks",
		"把两个任务标成【候选关联】（task_intel_links.decision=candidate），供阅读者后续判定。"+
			"task_id 与 related_task_id 用 read_task_intel 返回的 task_id；reason 写清命中项（如同一接口/同一凭据/同组件版本）；matched 可选，填命中的 {kind,key,value}。"+
			"幂等：重复标同一对不重复；阅读者已 adopted/dismissed 的关联不会被覆盖。不要用自由文本洞察代替本工具。",
		objSchema(map[string]any{
			"task_id":         strParam("发起关联的任务 id"),
			"related_task_id": strParam("被关联的任务 id"),
			"reason":          strParam("关联理由（命中项说明）"),
			"matched": map[string]any{"type": "array", "items": objSchema(map[string]any{
				"kind":  strParam("endpoint/credential/component/asset/vuln"),
				"key":   strParam("归一化键"),
				"value": strParam("人类可读原文"),
			}), "description": "可选：命中明细"},
		}, "task_id", "related_task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID        json.RawMessage `json:"task_id"`
				RelatedTaskID json.RawMessage `json:"related_task_id"`
				Reason        string          `json:"reason"`
				Matched       []readerLinkHit `json:"matched"`
			}
			_ = json.Unmarshal(in, &a)
			if s == nil || s.m == nil || s.m.pg == nil {
				return actool.Errorf("情报表存储不可用"), nil
			}
			taskID := parseProfileID(a.TaskID)
			relatedID := parseProfileID(a.RelatedTaskID)
			if taskID <= 0 || relatedID <= 0 || taskID == relatedID {
				return actool.Errorf("task_id / related_task_id 必须是两个不同的任务 id"), nil
			}
			t, err := s.m.pg.GetTask(taskID)
			if err != nil || t == nil {
				return actool.Errorf(fmt.Sprintf("任务不存在: %d", taskID)), nil
			}
			if t.ProjectID == nil || *t.ProjectID <= 0 {
				return actool.Errorf(fmt.Sprintf("任务 %d 未挂项目，无法建立勾连", taskID)), nil
			}
			rt, err := s.m.pg.GetTask(relatedID)
			if err != nil || rt == nil {
				return actool.Errorf(fmt.Sprintf("任务不存在: %d", relatedID)), nil
			}
			raw, _ := json.Marshal(a.Matched)
			if len(a.Matched) == 0 {
				raw = json.RawMessage(`[]`)
			}
			id, applied, err := s.m.pg.SaveCandidateIntelLink(ctx, db.TaskIntelLink{
				ProjectID: *t.ProjectID, TaskID: taskID, RelatedTaskID: relatedID,
				Decision: "candidate", Reason: strings.TrimSpace(a.Reason), Matched: raw,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if !applied {
				return actool.Text(fmt.Sprintf("任务#%d ↔ #%d 已有阅读者决策（adopted/dismissed），candidate 未覆盖（link#%d）", taskID, relatedID, id)), nil
			}
			return actool.Text(fmt.Sprintf("已标候选关联 任务#%d ↔ #%d（link#%d）", taskID, relatedID, id)), nil
		})
}

// readerDecisionStat 是一轮阅读者会话的勾连判定累计。
type readerDecisionStat struct {
	total     int
	adopted   int
	dismissed int
	seen      map[string]bool // 同一 (task,related) 重复决策只计一次
}

// noteReaderDecision 累计本轮判定并打印「判定了 N 个候选：adopt x / dismiss y」。
// 以 chat 会话 id 为轮次标识（reader 触发会话由 runTriggeredRun 创建）；同一
// 候选的重复决策（如重复 adopt）不重复计数。
func (s *Server) noteReaderDecision(ctx context.Context, decision, pair string) {
	key := agent.RunInfoFrom(ctx).SessionID
	s.readerDecisionMu.Lock()
	if s.readerDecisions == nil {
		s.readerDecisions = map[string]*readerDecisionStat{}
	}
	st := s.readerDecisions[key]
	if st == nil {
		st = &readerDecisionStat{seen: map[string]bool{}}
		s.readerDecisions[key] = st
	}
	if pair == "" || !st.seen[pair] {
		if pair != "" {
			st.seen[pair] = true
		}
		st.total++
		switch decision {
		case "adopted":
			st.adopted++
		case "dismissed":
			st.dismissed++
		}
	}
	total, adopted, dismissed := st.total, st.adopted, st.dismissed
	s.readerDecisionMu.Unlock()
	log.Printf("[reader] 判定了 %d 个候选：adopt %d / dismiss %d", total, adopted, dismissed)
}

// clearReaderDecisions 清理一轮阅读者会话的计数（会话结束后调用）。
func (s *Server) clearReaderDecisions(sessionID string) {
	s.readerDecisionMu.Lock()
	delete(s.readerDecisions, sessionID)
	s.readerDecisionMu.Unlock()
}

// taskIntelReaderTools 是阅读者的勾连工具集（seed 绑定与装配共用同一列表，
// 口径单源）。规划者不再持有任何勾连工具。
func (s *Server) taskIntelReaderTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolReadTaskIntel(),
		s.toolLinkTasks(),
		s.toolRequestReaderLinks(),
		// 读双方完整图：判相关性时不能只看投影摘要（V10-READER-2）。
		s.toolReadTaskGraph(),
		// V11-READER7：每候选独立上下文的批量判官（避免 N 个候选互相污染上下文）。
		s.toolJudgeRelatedTasks(),
		s.toolAdoptRelatedTask(),
		s.toolDismissRelatedTask(),
	}
}
