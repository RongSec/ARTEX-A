package server

// V7-LINK：阅读者机制的「按需勾连」。
//
// 背景（用户规格）：每个任务终态都有一份可直接比对的情报表（task_intel：
// 接口/凭据/组件/资产/漏洞），情报表新增即一次图变更信号。planner 形成新的
// 攻击面时，不再由 resolver 按 URL/资产键自动往 prompt 里塞别的任务的经验，
// 而是**主动申请阅读者帮忙找相关任务**，再自己下钻判断保留/舍弃：
//
//	planner: request_reader_links(surface) → 候选（task/命中明细/价值计数）
//	         → adopt_related_task（保留 + 写 hint）/ dismiss_related_task（舍弃）
//	reader : read_task_intel（增量情报表）→ link_tasks（candidate 关联）
//
// 这一单同时拆掉了 server/project_insight.go 的跨项目自动注入：项目内洞察
// （observer_enabled）照旧注入，跨项目情报改走「申请-下钻-决策」这条显式链，
// reader_enabled 退化为 scope=cross 的闸门（独立于 observer_enabled）。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
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
)

// readerLinkCandidateNote 是 request_reader_links 返回里必须带的一句提示
// （用户规格原话：候选不等于结论，必须 planner 自己下钻判断）。
const readerLinkCandidateNote = "以下为候选，须由你下钻判断相关性；有关的 adopt，无关的 dismiss"

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
// planner 三工具
// ---------------------------------------------------------------------------

// readerLinkHit 是一条命中明细（同时作为 task_intel_links.matched 的元素形状）。
// Key 是命中行的精确键（供下钻复核），MatchKey 是本次据以连上的粗粒度键
// （planner 据此知道"是按接口路径还是按组件产品名连上的"）。
type readerLinkHit struct {
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	MatchKey string `json:"match_key,omitempty"`
	Value    string `json:"value"`
}

// readerLinkSurfaceKey 是 debug.surface_keys 的元素：surface 抽出的精确键 +
// 它换算出的匹配键。线上核对"为什么 0 候选"时，一眼能看出比对口径。
type readerLinkSurfaceKey struct {
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	MatchKey string `json:"match_key"`
}

// readerLinkCandidate 是 request_reader_links 返回的候选任务。
type readerLinkCandidate struct {
	TaskID       int64           `json:"task_id"`
	TaskName     string          `json:"task_name"`
	ProjectID    int64           `json:"project_id"`
	Hits         []readerLinkHit `json:"hits"`
	HitCount     int             `json:"hit_count"`
	FindingCount int             `json:"finding_count"`
	IntentCount  int             `json:"intent_count"`
}

// taskIntelLinkContext 取当前 planner 轮的任务与项目上下文。RunInfo 由
// Plan() 的 WithRunInfo 注入；不在任务轮（主 agent/chat）时明确报错而不是
// 静默返回空——模型需要知道「这个工具只在任务规划里可用」。
func (s *Server) taskIntelLinkContext(ctx context.Context) (int64, *db.TaskInsightContext, error) {
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID <= 0 {
		return 0, nil, fmt.Errorf("request/adopt/dismiss 只能在任务规划轮中使用（当前没有任务上下文）")
	}
	if s == nil || s.m == nil || s.m.pg == nil {
		return 0, nil, fmt.Errorf("情报表存储不可用")
	}
	tctx, err := s.m.pg.TaskInsightContext(ctx, ri.TaskID)
	if err != nil {
		return 0, nil, fmt.Errorf("读取当前任务失败（可能已删除）: %w", err)
	}
	if tctx.ProjectID <= 0 {
		return 0, nil, fmt.Errorf("当前任务未挂项目：情报表只在项目内生成，无法勾连")
	}
	return ri.TaskID, tctx, nil
}

// toolRequestReaderLinks 让 planner 用一段新攻击面申请阅读者勾连候选。
//
// 返回是【候选】而非 prompt 注入：planner 必须逐条下钻，用 adopt/dismiss 决策。
func (s *Server) toolRequestReaderLinks() actool.CoreTool {
	return roTool("request_reader_links",
		"当你形成新的攻击面（准备产出意图）时调用：把这段攻击面描述（URL/裸路径/host:port/组件版本，可混合自由文本）交给情报表，找出命中同一接口/凭据/组件的其它任务。"+
			"返回候选任务的 task_id、名称、命中明细与该任务的 finding/意图数量；这只是候选，须由你下钻判断相关性，有关的用 adopt_related_task 保留、无关的用 dismiss_related_task 舍弃。"+
			"scope=project 是【跨任务阅读者】视角，只看同项目，需本项目 observer_enabled=true；"+
			"scope=cross 是【跨项目阅读者】视角，只看其它项目，需目标项目 reader_enabled=true。",
		objSchema(map[string]any{
			"surface": strParam("新攻击面描述（可含 URL、/api/... 路径、host:port、产品/版本，或一段自然语言）"),
			"scope":   map[string]any{"type": "string", "enum": []any{"project", "cross"}, "description": "检索范围：project=同项目(默认) / cross=已开启 reader_enabled 的其它项目"},
			"limit":   map[string]any{"type": "integer", "description": "候选任务数上限（默认 5，最大 20）"},
		}, "surface"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Surface string `json:"surface"`
				Scope   string `json:"scope"`
				Limit   int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Surface) == "" {
				return actool.Errorf("surface 不能为空（描述新攻击面，含 URL/路径/host:port/组件版本均可）"), nil
			}
			taskID, tctx, err := s.taskIntelLinkContext(ctx)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			scope := strings.ToLower(strings.TrimSpace(a.Scope))
			if scope == "" {
				scope = "project"
			}
			if scope != "project" && scope != "cross" {
				return actool.Errorf("scope 必须是 project 或 cross"), nil
			}
			// V7-SCOPE：两个视角各自一把开关（V6-DUAL 语义），拉取侧同样要过闸。
			//   scope=project（跨任务/项目内）→ 当前项目 observer_enabled
			//   scope=cross （跨项目）        → 目标项目 reader_enabled（在 SQL 内过滤）
			// 不过闸的后果是「关了开关仍能拿到候选」，等于开关只关了旧注入路径。
			if scope == "project" {
				if proj, perr := s.m.pg.GetProject(tctx.ProjectID); perr == nil && proj != nil && !proj.ObserverEnabled {
					return jsonResult(map[string]any{
						"surface":    a.Surface,
						"scope":      scope,
						"keys":       []db.IntelKeyRef{},
						"candidates": []readerLinkCandidate{},
						"debug":      map[string]any{"missing_switch": "observer_enabled", "queried_project_id": tctx.ProjectID},
						"note":       "本项目未开启【跨任务】视角（observer_enabled=false），项目内任务情报不可勾连。" + readerLinkCandidateNote,
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
				"queried_project_id": tctx.ProjectID,
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
			matches, err := s.m.pg.MatchTaskIntel(ctx, tctx.ProjectID, keys, taskID, scope == "cross")
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cands := aggregateReaderLinkCandidates(matches, limit)
			for i := range cands {
				cands[i].HitCount = len(cands[i].Hits)
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

// aggregateReaderLinkCandidates 是纯函数：命中行 → 候选任务（按命中条数降序，
// 同数按 task_id 升序保证稳定），并截断到 limit。
func aggregateReaderLinkCandidates(matches []db.IntelTaskMatch, limit int) []readerLinkCandidate {
	if len(matches) == 0 {
		return []readerLinkCandidate{}
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
		hitSeen[m.TaskID][id] = true
		c.Hits = append(c.Hits, readerLinkHit{Kind: m.Kind, Key: m.Key, MatchKey: m.MatchKey, Value: m.Value})
	}
	out := make([]readerLinkCandidate, 0, len(byTask))
	for _, c := range byTask {
		c.HitCount = len(c.Hits)
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Hits) != len(out[j].Hits) {
			return len(out[i].Hits) > len(out[j].Hits)
		}
		return out[i].TaskID < out[j].TaskID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// toolAdoptRelatedTask 保留一个候选任务：落 task_intel_links(decision=adopted)
// 并把被采纳任务的关键情报以 add_hint 同形态写进当前任务图，供 planner 下一轮
// 引用。重复 adopt 幂等（不重复写 hint）。
func (s *Server) toolAdoptRelatedTask() actool.CoreTool {
	return wrTool("adopt_related_task",
		"采纳 request_reader_links 返回的某个候选任务：记 decision=adopted（含命中明细与理由），并把该任务的关键情报以提示(hint)形式写进当前任务图，供你下一轮规划引用。"+
			"只对下钻后确认相关的候选使用；无关的请用 dismiss_related_task。重复采纳同一任务是幂等的（不会重复写 hint）。",
		objSchema(map[string]any{
			"related_task_id": strParam("被采纳的候选任务 id（request_reader_links 返回的 task_id）"),
			"reason":          strParam("采纳理由（一句话，说明与当前攻击面哪里相关）"),
			"matched": map[string]any{"type": "array", "items": objSchema(map[string]any{
				"kind":  strParam("endpoint/credential/component/asset/vuln"),
				"key":   strParam("归一化键"),
				"value": strParam("人类可读原文"),
			}), "description": "可选：本次采纳依据的命中明细（缺省用该任务情报表前若干行）"},
		}, "related_task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				RelatedTaskID json.RawMessage `json:"related_task_id"`
				Reason        string          `json:"reason"`
				Matched       []readerLinkHit `json:"matched"`
			}
			_ = json.Unmarshal(in, &a)
			taskID, tctx, err := s.taskIntelLinkContext(ctx)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			relatedID := parseProfileID(a.RelatedTaskID)
			if relatedID <= 0 || relatedID == taskID {
				return actool.Errorf("related_task_id 无效（必须是候选任务，不能是当前任务）"), nil
			}
			rt, err := s.m.pg.GetTask(relatedID)
			if err != nil || rt == nil {
				return actool.Errorf(fmt.Sprintf("候选任务不存在: %d", relatedID)), nil
			}
			reason := strings.TrimSpace(a.Reason)
			matched := a.Matched
			if len(matched) == 0 {
				matched = s.intelHitsForTask(ctx, relatedID, readerLinkHintMaxRows)
			}
			raw, _ := json.Marshal(matched)
			prev, err := s.m.pg.TaskIntelLinkFor(ctx, taskID, relatedID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if _, err := s.m.pg.SaveTaskIntelLink(ctx, db.TaskIntelLink{
				ProjectID: tctx.ProjectID, TaskID: taskID, RelatedTaskID: relatedID,
				Decision: "adopted", Reason: reason, Matched: raw,
			}); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if prev != nil && prev.Decision == "adopted" {
				return actool.Text(fmt.Sprintf("任务#%d 已是 adopted，决策与明细已更新；hint 不重复写入", relatedID)), nil
			}
			hintID, err := s.writeAdoptHint(taskID, relatedID, rt.Name, reason, matched)
			if err != nil {
				return actool.Text(fmt.Sprintf("已采纳任务#%d，但写 hint 失败（不影响决策）：%v", relatedID, err)), nil
			}
			return actool.Text(fmt.Sprintf("已采纳任务#%d（decision=adopted），关键情报已写入当前任务图 hint#%d", relatedID, hintID)), nil
		})
}

// toolDismissRelatedTask 舍弃一个候选任务：只落 decision=dismissed，不写 hint。
func (s *Server) toolDismissRelatedTask() actool.CoreTool {
	return wrTool("dismiss_related_task",
		"舍弃 request_reader_links 返回的某个候选任务：记 decision=dismissed（含理由），不写 hint。"+
			"只在下钻确认与当前攻击面无关时使用；有关联的请用 adopt_related_task。",
		objSchema(map[string]any{
			"related_task_id": strParam("被舍弃的候选任务 id（request_reader_links 返回的 task_id）"),
			"reason":          strParam("舍弃理由（一句话，说明为什么不相关）"),
			"matched": map[string]any{"type": "array", "items": objSchema(map[string]any{
				"kind":  strParam("endpoint/credential/component/asset/vuln"),
				"key":   strParam("归一化键"),
				"value": strParam("人类可读原文"),
			}), "description": "可选：命中明细（留档复盘为什么看过又舍弃）"},
		}, "related_task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				RelatedTaskID json.RawMessage `json:"related_task_id"`
				Reason        string          `json:"reason"`
				Matched       []readerLinkHit `json:"matched"`
			}
			_ = json.Unmarshal(in, &a)
			taskID, tctx, err := s.taskIntelLinkContext(ctx)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			relatedID := parseProfileID(a.RelatedTaskID)
			if relatedID <= 0 || relatedID == taskID {
				return actool.Errorf("related_task_id 无效（必须是候选任务，不能是当前任务）"), nil
			}
			raw, _ := json.Marshal(a.Matched)
			if len(a.Matched) == 0 {
				raw = json.RawMessage(`[]`)
			}
			if _, err := s.m.pg.SaveTaskIntelLink(ctx, db.TaskIntelLink{
				ProjectID: tctx.ProjectID, TaskID: taskID, RelatedTaskID: relatedID,
				Decision: "dismissed", Reason: strings.TrimSpace(a.Reason), Matched: raw,
			}); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("已舍弃任务#%d（decision=dismissed，不写 hint）", relatedID)), nil
		})
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

// writeAdoptHint 把采纳的情报写进当前任务探索图（与 add_hint 同形态：
// kind=hint、payload={"text": ...}）。刻意不触发 planner 唤醒——当前就是
// planner 自己在跑这一轮，hint 供它下一轮读取即可。
func (s *Server) writeAdoptHint(taskID, relatedID int64, taskName, reason string, hits []readerLinkHit) (int64, error) {
	t, ok := s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok || t == nil || t.Store == nil {
		return 0, fmt.Errorf("当前任务不在运行表")
	}
	text := renderAdoptHint(relatedID, taskName, reason, hits)
	return t.Store.AddNode(db.KindHint, map[string]any{"text": text}, 0, "active", "reader", nil)
}

// renderAdoptHint 是纯函数：采纳提示正文（带命中的 kind/key，便于下一轮
// planner 直接引用；上限 readerLinkHintMaxHits 条）。
func renderAdoptHint(relatedID int64, taskName, reason string, hits []readerLinkHit) string {
	var b strings.Builder
	b.WriteString("【跨任务/跨项目阅读者勾连·采纳】任务#")
	b.WriteString(strconv.FormatInt(relatedID, 10))
	if n := strings.TrimSpace(taskName); n != "" {
		b.WriteString("「")
		b.WriteString(n)
		b.WriteString("」")
	}
	b.WriteString("的情报与当前攻击面相关")
	if len(hits) > 0 {
		b.WriteString("（命中：")
		for i, h := range hits {
			if i >= readerLinkHintMaxHits {
				b.WriteString(" 等")
				break
			}
			if i > 0 {
				b.WriteString("；")
			}
			b.WriteString(db.IntelKindLabel(h.Kind))
			b.WriteString(" ")
			b.WriteString(h.Key)
		}
		b.WriteString("）")
	}
	if r := strings.TrimSpace(reason); r != "" {
		b.WriteString("。理由：")
		b.WriteString(r)
	}
	b.WriteString("。可下钻其情报表复用接口/凭据/组件线索，结论仍需在本任务验证。")
	return b.String()
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
}

// intelSummaryGroup 是按 kind 分组的增量摘要。
type intelSummaryGroup struct {
	Kind  string             `json:"kind"`
	Label string             `json:"label"`
	Count int                `json:"count"`
	Items []intelSummaryItem `json:"items"`
}

// toolReadTaskIntel 按 since_id 水位增量读情报表，按 kind 分组返回摘要。
// project_id 缺省=全部开启 reader_enabled 的 active 项目（阅读者的常规视野）。
func (s *Server) toolReadTaskIntel() actool.CoreTool {
	return roTool("read_task_intel",
		"按水位增量读任务情报表（每个任务终态生成的接口/凭据/组件/资产/漏洞表），用于判断「哪些任务可以互相比对」。"+
			"since_id 传上一轮返回的 next_since_id（首轮 0）；project_id 缺省=全部已开启 reader_enabled 的项目（跨项目视野）。"+
			"显式指定 project_id 时，该项目需 observer_enabled 或 reader_enabled 至少一项开启，否则进 skipped。返回按 kind 分组的条目与任务归属，以及 next_since_id（下次传回）。",
		objSchema(map[string]any{
			"project_id": map[string]any{"type": "integer", "description": "可选：只读某个项目；缺省=全部开启 reader_enabled 的项目"},
			"since_id":   map[string]any{"type": "integer", "description": "可选：上次读到的最大 id（首轮 0）"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ProjectID json.RawMessage `json:"project_id"`
				SinceID   json.RawMessage `json:"since_id"`
			}
			_ = json.Unmarshal(in, &a)
			if s == nil || s.m == nil || s.m.pg == nil {
				return actool.Errorf("情报表存储不可用"), nil
			}
			since := parseProfileID(a.SinceID)
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
					"project_id":    p,
					"since_id":      since,
					"next_since_id": watermark,
					"has_more":      len(rows) >= 500,
					"total":         len(rows),
					"groups":        groupIntelSummary(rows),
					"tasks":         intelTaskCounts(rows),
				})
			}
			out := map[string]any{
				"since_id":      since,
				"next_since_id": next,
				"total":         total,
				"projects":      projects,
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
			ID: r.ID, TaskID: r.TaskID, Kind: r.Kind, Key: r.Key, Value: r.Value,
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
// 行不被 candidate 覆盖（规划者下钻后的决策优先）。
func (s *Server) toolLinkTasks() actool.CoreTool {
	return wrTool("link_tasks",
		"把两个任务标成【候选关联】（task_intel_links.decision=candidate），供规划者下钻判断。"+
			"task_id 与 related_task_id 用 read_task_intel 返回的 task_id；reason 写清命中项（如同一接口/同一凭据/同组件版本）；matched 可选，填命中的 {kind,key,value}。"+
			"幂等：重复标同一对不重复；规划者已 adopted/dismissed 的关联不会被覆盖。不要用自由文本洞察代替本工具。",
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
				return actool.Text(fmt.Sprintf("任务#%d ↔ #%d 已有规划者决策（adopted/dismissed），candidate 未覆盖（link#%d）", taskID, relatedID, id)), nil
			}
			return actool.Text(fmt.Sprintf("已标候选关联 任务#%d ↔ #%d（link#%d）", taskID, relatedID, id)), nil
		})
}

// taskIntelPlannerTools / taskIntelReaderTools 是两个 agent 的工具集（seed
// 绑定与装配共用同一列表，口径单源）。
func (s *Server) taskIntelPlannerTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolRequestReaderLinks(),
		s.toolAdoptRelatedTask(),
		s.toolDismissRelatedTask(),
	}
}

func (s *Server) taskIntelReaderTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolReadTaskIntel(),
		s.toolLinkTasks(),
	}
}
