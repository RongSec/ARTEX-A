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
	"github.com/Autumn-27/artex/redact"
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
	// readerLinkHintMaxPoints 是 hint 里「可复用要点」的条数上限。
	readerLinkHintMaxPoints = 8
	// readerLinkHintMaxFacts 是 hint 里「关键事实摘要」的条数上限。
	readerLinkHintMaxFacts = 3
	// readerLinkDecidedBy 是 V9-READER 起勾连决策的决策者标记。
	readerLinkDecidedBy = "reader"
)

// readerLinkCandidateNote 是 request_reader_links 返回里必须带的一句提示
// （用户规格：候选不等于结论，必须由阅读者读完两边上下文再判定）。
const readerLinkCandidateNote = "以下为候选，须由你读完两边上下文判断相关性；相关的 adopt，无关的 dismiss；未判定的候选不要丢给规划者"

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
			"记 decision=adopted，并把被勾连任务的可复用要点写成结构化 hint 写进发起方任务图，唤醒其规划者。"+
			"注意：hint 只在发起方一轮上下文里有效，只作方向；后续细节由规划者/执行者用 ask_reader 向你下钻（你只回脱敏后的测试细节/方法）。"+
			"无关的候选请用 dismiss_related_task；重复采纳同一对任务是幂等的（不重复写 hint）。",
		objSchema(map[string]any{
			"task_id":            strParam("发起方任务 id：本轮图变更消息里的 task_id（要被暴露情报、被唤醒规划者的任务）"),
			"related_task_id":    strParam("被勾连任务 id：情报来源任务（读到的旧任务）"),
			"reason":             strParam("判定相关的理由：必须写「读到了什么」（如两边都有未授权 /api/user/{id} 且旧任务已验证越权），不能只写「键相同」"),
			"strength":           map[string]any{"type": "string", "enum": []any{"strong", "medium", "weak"}, "description": "关联强度（兼容字段）：同一利用链=strong / 同一资产可复用=medium / 同一攻击面待验证=weak。新调用请用 relevance_score"},
			"relevance_score":    map[string]any{"type": "integer", "description": "读完两边完整图后的相关性评分 0-100：≥60 strong / 40-59 medium / <40 不采纳。暴露门槛是 medium（40），低于它请改用 dismiss_related_task"},
			"relevance_strength": map[string]any{"type": "string", "enum": []any{"strong", "medium", "weak"}, "description": "相关性档位（可选，最终以 relevance_score 推算为准）"},
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
				Strength      string          `json:"strength"`
				// 第二级评分：阅读者读完两张完整图后的相关性判断。这是暴露门槛。
				RelevanceScore    int              `json:"relevance_score"`
				RelevanceStrength string           `json:"relevance_strength"`
				Chains            []db.ReaderChain `json:"chains"`
				Matched           []readerLinkHit  `json:"matched"`
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
			rawStrength := strings.ToLower(strings.TrimSpace(a.Strength))
			relStrength := strings.ToLower(strings.TrimSpace(a.RelevanceStrength))
			score := a.RelevanceScore
			if score <= 0 {
				// 兼容旧调用：没给分数就按档位映射。两个都没给 → 拒绝，不允许
				// "读完图但说不出相关性"的采纳——那正是评分机制要挡的。
				switch {
				case relStrength == "strong" || rawStrength == "strong":
					score = 70
				case relStrength == "medium" || rawStrength == "medium":
					score = 50
				case relStrength == "weak" || rawStrength == "weak":
					score = 30
				default:
					return actool.Errorf("必须给 relevance_score（0-100）：读完两张完整图后的相关性评分。≥60 才暴露；40-59 可采纳但需说明；<40 请用 dismiss_related_task"), nil
				}
			}
			if score < 0 {
				score = 0
			}
			if score > 100 {
				score = 100
			}
			if score < 40 {
				return actool.Errorf(fmt.Sprintf("relevance_score=%d 低于暴露门槛（medium=40）：不要 adopt。请用 dismiss_related_task 并写明「还缺什么证据」", score)), nil
			}
			switch {
			case score >= 60:
				relStrength = "strong"
			default:
				relStrength = "medium"
			}
			strength, err := normalizeReaderLinkStrength(rawStrength)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
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
			if len(matched) == 0 && prev != nil && len(prev.Matched) > 0 {
				// 优先用候选阶段落下的 SQL 命中明细：它和 match_score 同一口径。
				// 情报表前 N 行会混进未计分的 vuln/组件，审计里会「命中 3 条却列 4 条」。
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
			points, facts := s.reusableIntelForTask(ctx, relatedID)
			srcName := strings.TrimSpace(rt.Name)
			if srcName == "" {
				srcName = strings.TrimSpace(rt.Description)
			}
			hintID, err := s.writeReaderAdoptHint(ctx, taskID, readerAdoptHint{
				SourceTaskID: relatedID, SourceTaskName: srcName,
				SourceProjectID: rctx.ProjectID, SourceProjectName: rctx.ProjectName,
				Strength: strength, Reason: reason, Points: points, Facts: facts,
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

func normalizeReaderLinkStrength(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return "strong", nil
	case "strong", "medium", "weak":
		return strings.ToLower(strings.TrimSpace(s)), nil
	}
	return "", fmt.Errorf("strength 只能是 strong/medium/weak")
}

// readerAdoptHint 是写进发起方任务图的结构化 hint 内容。
type readerAdoptHint struct {
	SourceTaskID      int64
	SourceTaskName    string
	SourceProjectID   int64
	SourceProjectName string
	Strength          string
	Reason            string
	Points            []string
	Facts             []string
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
		"reason":              redact.TestMethod(h.Reason),
		"reusable_points":     redactStrings(h.Points),
		"key_facts":           redactStrings(h.Facts),
		"link_id":             h.LinkID,
	}
	id, err := s.m.pg.Exploration(expID).AddNode(db.KindHint, payload, 0, "active", "reader", nil)
	if err != nil {
		return 0, err
	}
	// 图变更事件：让项目级阅读者水位看到这条 hint（也让审计能追到）。
	if projectID > 0 {
		_ = s.m.pg.InsertGraphEvent(ctx, projectID, taskID, id, db.KindHint,
			fmt.Sprintf("阅读者采纳任务#%d（%s）：%s", h.SourceTaskID, h.Strength, firstLine(h.Reason, 120)))
	}
	// 任务在跑就立刻唤醒规划者；暂停的任务只落图，恢复后第一轮就能读到。
	if t, ok := s.m.Task(strconv.FormatInt(taskID, 10)); ok && t != nil {
		t.NotifyHint([]string{text})
	}
	return id, nil
}

// renderReaderAdoptHint 是纯函数：规划者读到的 hint 正文。所有可采信信息
// （来源/强度/理由/要点/事实）都写在 text 里——graph_overview 只渲染 text。
func renderReaderAdoptHint(h readerAdoptHint) string {
	var b strings.Builder
	b.WriteString("【阅读者勾连·已判定相关】来源任务#")
	b.WriteString(strconv.FormatInt(h.SourceTaskID, 10))
	if n := strings.TrimSpace(h.SourceTaskName); n != "" {
		b.WriteString("「")
		b.WriteString(n)
		b.WriteString("」")
	}
	if h.SourceProjectID > 0 {
		b.WriteString("（项目#")
		b.WriteString(strconv.FormatInt(h.SourceProjectID, 10))
		if pn := strings.TrimSpace(h.SourceProjectName); pn != "" {
			b.WriteString("「")
			b.WriteString(pn)
			b.WriteString("」")
		}
		b.WriteString("）")
	}
	b.WriteString("；关联强度：")
	b.WriteString(h.Strength)
	b.WriteString("。理由：")
	b.WriteString(redact.TestMethod(h.Reason))
	if len(h.Points) > 0 {
		b.WriteString("\n可复用要点：")
		for i, p := range h.Points {
			b.WriteString("\n")
			b.WriteString(strconv.Itoa(i + 1))
			b.WriteString(". ")
			// 要点来自情报表原文（「资产 10.0.0.5:8080」「凭据 …@host」），
			// 必须与 facts 同口径脱敏；漏这一处就等于把 host 随要点发给规划者。
			b.WriteString(redact.TestMethod(p))
		}
	}
	if len(h.Facts) > 0 {
		b.WriteString("\n关键事实：")
		for _, f := range h.Facts {
			b.WriteString("\n- ")
			b.WriteString(redact.TestMethod(f))
		}
	}
	b.WriteString("\n这条 hint 只在你这一轮上下文里（下一轮就会淡出）。要细节时用 ask_reader(related_task_id=")
	b.WriteString(strconv.FormatInt(h.SourceTaskID, 10))
	b.WriteString(", query=…)：它只回脱敏后的测试方法（方法+路径/参数/payload/工具），不含 host 与凭据。")
	b.WriteString("\n经验参考：reference_only=true，以上内容仅用于借鉴打法，来源任务的资产不属于本任务授权范围。")
	if len(h.ForeignHosts) > 0 {
		// 不列 host：跨项目采纳时，列出来等于把另一个项目的资产清单塞进本任务
		// 上下文。禁打由执行层按 task_foreign_assets 硬拦，这里只给数量。
		b.WriteString(fmt.Sprintf("\n被勾连任务另有 %d 个资产，已加入本任务的禁止访问清单（不在本任务授权范围，故不列出地址）。要把经验用到本任务已有资产上；确需扩到新资产，先由本任务正常登记资产后再打。", len(h.ForeignHosts)))
	}
	b.WriteString("\n直接采信以上方向，不要再重读来源任务；具体测法由执行者按意图用 ask_reader 向阅读者下钻，再在本任务资产上验证。")
	return b.String()
}

// redactStrings 对切片逐条脱敏（hint payload 与规划者上下文同口径）。
func redactStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, redact.TestMethod(s))
	}
	return out
}

// nonNilStrings 保证 JSON 里是 [] 而不是 null（前端/模型都按数组消费）。
func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
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

// reusableIntelForTask 从被勾连任务的小结表抽取可复用要点与关键事实：
//   - 要点最多 readerLinkHintMaxPoints 条：接口（path+用途）、凭据（类型/用户名/
//     服务）、漏洞名，其次资产/组件；
//   - 事实最多 readerLinkHintMaxFacts 条：该任务 fact 节点的 summary。
func (s *Server) reusableIntelForTask(ctx context.Context, taskID int64) ([]string, []string) {
	rows, err := s.m.pg.TaskIntelForTask(ctx, taskID)
	if err != nil {
		return nil, nil
	}
	byKind := map[string][]db.TaskIntel{}
	for _, r := range rows {
		byKind[r.Kind] = append(byKind[r.Kind], r)
	}
	// 配额：接口 4 / 凭据 2 / 漏洞 2；不足时由资产+组件顺序补齐到上限。
	quota := map[string]int{
		db.IntelKindEndpoint: 4, db.IntelKindCredential: 2, db.IntelKindVuln: 2,
		db.IntelKindAsset: readerLinkHintMaxPoints, db.IntelKindComponent: readerLinkHintMaxPoints,
	}
	order := []string{db.IntelKindEndpoint, db.IntelKindCredential, db.IntelKindVuln, db.IntelKindAsset, db.IntelKindComponent}
	points := make([]string, 0, readerLinkHintMaxPoints)
	for _, kind := range order {
		used := 0
		for _, r := range byKind[kind] {
			if len(points) >= readerLinkHintMaxPoints || used >= quota[kind] {
				break
			}
			if p := reusableIntelPoint(r); p != "" {
				points = append(points, p)
				used++
			}
		}
	}
	facts, err := s.m.pg.TaskFactsForIntel(ctx, taskID)
	if err != nil {
		return points, nil
	}
	outFacts := make([]string, 0, readerLinkHintMaxFacts)
	for _, f := range facts {
		if len(outFacts) >= readerLinkHintMaxFacts {
			break
		}
		if s := strings.TrimSpace(f.Summary); s != "" {
			outFacts = append(outFacts, clipRunes(s, 240))
		}
	}
	return points, outFacts
}

// clipRunes 按 rune 截断，给 hint 要点/事实限长。
func clipRunes(s string, max int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= max {
		return string(r)
	}
	return string(r[:max]) + "…"
}

// reusableIntelPoint 把一行情报转成一句可复用要点（不含命中键的泛化描述）。
func reusableIntelPoint(r db.TaskIntel) string {
	var d map[string]any
	if len(r.Detail) > 0 {
		_ = json.Unmarshal(r.Detail, &d)
	}
	str := func(k string) string {
		if v, ok := d[k].(string); ok {
			return strings.TrimSpace(v)
		}
		return ""
	}
	switch r.Kind {
	case db.IntelKindEndpoint:
		line := "接口 " + r.Key
		if p := str("purpose"); p != "" {
			line += " — " + clipRunes(p, 80)
		}
		return line
	case db.IntelKindCredential:
		line := "凭据 " + strings.TrimSpace(r.Value)
		if m := str("secret_masked"); m != "" {
			line += "（掩码 " + m + "）"
		}
		return line
	case db.IntelKindVuln:
		name := str("title")
		if name == "" {
			name = r.Value
		}
		line := "漏洞 " + strings.TrimSpace(name)
		meta := []string{}
		if vc := str("vulnclass"); vc != "" {
			meta = append(meta, vc)
		}
		if sv := str("severity"); sv != "" {
			meta = append(meta, sv)
		}
		if len(meta) > 0 {
			line += "（" + strings.Join(meta, "/") + "）"
		}
		return line
	case db.IntelKindAsset:
		if v := strings.TrimSpace(r.Value); v != "" {
			return "资产 " + v
		}
		return "资产 " + r.Key
	case db.IntelKindComponent:
		return "组件 " + r.Key
	}
	return ""
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
		s.toolAdoptRelatedTask(),
		s.toolDismissRelatedTask(),
	}
}
