package db

// 阅读者暴露面（V10-READER）：采纳之后，被勾连任务对当前任务「有限可见」。
//
// 设计口径（用户拍板）：
//   - 可见的只有：任务概述、情报表计数、**接口表的 method+path**（不含 host）、
//     以及可下钻的节点 id + 一句话摘要。
//   - 不可见：host / IP / URL 主机部分、凭据值、资产范围、对方正在跑的过程。
//   - 细节一律走 ask_reader：按 id 取节点后由服务端脱敏，只回「测试方法」。
//
// 为什么不并进 DirectSourceStores：静态关联会把对方整张图（含 scope 与资产
// 锚点）持续暴露给规划者，两个任务同时在跑时还会互相干扰；采纳是「参考」，
// 不是「继承」。这里只提供一份收窄的只读索引。

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/redact"
)

// ReaderEndpointRef 是一条可借鉴的接口：只有方法/路径/用途/参数，没有 host。
type ReaderEndpointRef struct {
	Method  string   `json:"method"`
	Path    string   `json:"path"`
	Purpose string   `json:"purpose,omitempty"`
	Params  []string `json:"params,omitempty"`
	Status  []int    `json:"status,omitempty"`
}

// ReaderNodeRef 是一个可下钻的节点：id + 类型 + 一句话摘要。
type ReaderNodeRef struct {
	ID      int64  `json:"id"`
	Kind    string `json:"kind"`
	Summary string `json:"summary"`
	State   string `json:"state,omitempty"`
}

// ReaderTaskRef 是被采纳任务在当前任务视角下的全部可见信息。
type ReaderTaskRef struct {
	TaskID    int64               `json:"related_task_id"`
	Name      string              `json:"name"`
	Goal      string              `json:"goal"`
	Status    string              `json:"status"`
	Reason    string              `json:"reason"`            // 阅读者给出的关联理由
	Overlap   []string            `json:"overlap,omitempty"` // 撞上的接口键（METHOD /path），不含 host
	Counts    map[string]int      `json:"counts"`            // 情报表五类计数
	Endpoints []ReaderEndpointRef `json:"endpoints,omitempty"`
	Nodes     []ReaderNodeRef     `json:"drillable,omitempty"` // 可按 id 下钻的 finding/fact
	// Intents 是对方「跑过的工作」入口：给 id 就能用 ask_reader 看它的执行过程
	// （activity：工具 + 摘要，已脱敏）。接口测试方法多数在这里，不在 finding 里。
	Intents []ReaderNodeRef `json:"intents,omitempty"`
}

const (
	readerRefMaxEndpoints = 20
	readerRefMaxNodes     = 10
)

// ReaderRefs 返回当前任务被采纳的参考任务（adopted），**不按项目过滤**：
// 用户口径是「跨项目也要能返回」——同一个组件/同一类接口出现在别的项目里，
// 恰恰是阅读者最该发现的东西。是否外溢由阅读者的判定（adopt）控制，不在这里
// 再按 project_id 拦一道；host 仍在字段层脱敏。
func (s *ExplorationStore) ReaderRefs(limit int) ([]ReaderTaskRef, error) {
	owner, err := s.TaskID()
	if err != nil || owner <= 0 {
		return nil, err
	}
	if limit <= 0 || limit > 8 {
		limit = 4
	}
	rows, err := s.db.Query(`
SELECT link.related_task_id, COALESCE(t.name,''), COALESCE(t.goal,''), COALESCE(t.status,''),
       COALESCE(link.reason,''), COALESCE(link.matched::text,'[]')
FROM task_intel_links link
JOIN tasks t ON t.id = link.related_task_id AND t.deleted_at IS NULL
JOIN tasks owner ON owner.id = link.task_id AND owner.deleted_at IS NULL -- 发起方已删则 refs 为空
WHERE link.task_id = $1 AND link.decision = 'adopted'
ORDER BY link.created_at DESC, link.id DESC
LIMIT $2`, owner, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReaderTaskRef{}
	type row struct {
		id                         int64
		name, goal, status, reason string
		matched                    string
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.name, &r.goal, &r.status, &r.reason, &r.matched); err != nil {
			return nil, err
		}
		pending = append(pending, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, r := range pending {
		ref := ReaderTaskRef{
			// 概览也不能带 host：任务名/目标/理由都是 agent 或人写的原文，
			// 一行 "对 oa.example.com 做测试" 就把资产漏了。
			TaskID: r.id, Name: truncRunes(redact.TestMethod(r.name), 80),
			Goal:   truncRunes(redact.TestMethod(r.goal), 300),
			Status: r.status, Reason: truncRunes(redact.TestMethod(r.reason), 200),
			Overlap: overlapEndpoints(r.matched),
			Counts:  map[string]int{},
		}
		ref.Counts, ref.Endpoints = s.readerIntelSnapshot(r.id)
		ref.Nodes = s.readerDrillableNodes(r.id)
		if intents, err := s.ReaderTaskLastIntents(r.id, 8); err == nil {
			ref.Intents = intents
		}
		out = append(out, ref)
	}
	return out, nil
}

// readerIntelSnapshot 读被采纳任务的情报表：五类计数 + 接口表（不含 host）。
func (s *ExplorationStore) readerIntelSnapshot(taskID int64) (map[string]int, []ReaderEndpointRef) {
	counts := map[string]int{}
	rows, err := s.db.Query(`
SELECT kind, count(*) FROM task_intel WHERE task_id=$1 GROUP BY 1`, taskID)
	if err == nil {
		for rows.Next() {
			var k string
			var n int
			if rows.Scan(&k, &n) == nil {
				counts[k] = n
			}
		}
		rows.Close()
	}
	eps := []ReaderEndpointRef{}
	rows2, err := s.db.Query(`
SELECT key, COALESCE(detail::text,'{}')
FROM task_intel WHERE task_id=$1 AND kind='endpoint'
ORDER BY key LIMIT $2`, taskID, readerRefMaxEndpoints)
	if err != nil {
		return counts, eps
	}
	defer rows2.Close()
	for rows2.Next() {
		var key, detail string
		if rows2.Scan(&key, &detail) != nil {
			continue
		}
		method, path := endpointMethodPath(key)
		if path == "" {
			continue
		}
		var d struct {
			Purpose     string   `json:"purpose"`
			Params      []string `json:"params"`
			StatusCodes []int    `json:"status_codes"`
		}
		_ = json.Unmarshal([]byte(detail), &d)
		ep := ReaderEndpointRef{Method: method, Path: path, Purpose: truncRunes(redact.TestMethod(d.Purpose), 60), Status: d.StatusCodes}
		for _, p := range d.Params {
			if len(ep.Params) >= 12 {
				break
			}
			ep.Params = append(ep.Params, truncRunes(redact.TestMethod(p), 40))
		}
		eps = append(eps, ep)
	}
	return counts, eps
}

// readerDrillableNodes 取被采纳任务里可下钻的节点（只给 id + 摘要，不给 payload）。
func (s *ExplorationStore) readerDrillableNodes(taskID int64) []ReaderNodeRef {
	var expID int64
	if err := s.db.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1 AND deleted_at IS NULL`, taskID).Scan(&expID); err != nil {
		return nil
	}
	rows, err := s.db.Query(`
SELECT id, kind, state, COALESCE(payload->>'summary','')
FROM exploration_nodes
WHERE exploration_id=$1 AND kind IN ('finding','fact')
ORDER BY (kind='finding') DESC, id DESC
LIMIT $2`, expID, readerRefMaxNodes)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []ReaderNodeRef{}
	for rows.Next() {
		var n ReaderNodeRef
		if rows.Scan(&n.ID, &n.Kind, &n.State, &n.Summary) != nil {
			continue
		}
		n.Summary = truncRunes(redact.TestMethod(n.Summary), 160)
		out = append(out, n)
	}
	return out
}

// ReaderTaskNode 按 id 取被采纳任务的一个节点。调用前会校验「这个任务确实被
// 采纳过」——否则任意 id 都成了跨任务读取的后门。
func (s *ExplorationStore) ReaderTaskNode(relatedTaskID, nodeID int64) (*Node, error) {
	expID, err := s.adoptedExploration(relatedTaskID)
	if err != nil || expID == 0 {
		return nil, err
	}
	return s.db.Exploration(expID).GetNode(nodeID)
}

// ReaderTaskTrace 取被采纳任务某个意图的执行过程（activity）。
// 只返回 kind != thinking/usage 的步骤；由调用方再做脱敏。
func (s *ExplorationStore) ReaderTaskTrace(relatedTaskID, intentID int64, limit int) ([]Activity, error) {
	expID, err := s.adoptedExploration(relatedTaskID)
	if err != nil || expID == 0 {
		return nil, err
	}
	return s.db.Exploration(expID).ActivityTrace(intentID, limit)
}

// ReaderTaskLastIntents 取被采纳任务最近结束的意图（给「看测试过程」一个入口）。
func (s *ExplorationStore) ReaderTaskLastIntents(relatedTaskID int64, limit int) ([]ReaderNodeRef, error) {
	expID, err := s.adoptedExploration(relatedTaskID)
	if err != nil || expID == 0 {
		return nil, err
	}
	if limit <= 0 || limit > 30 {
		limit = 10
	}
	rows, err := s.db.Query(`
SELECT id, state, COALESCE(payload->>'summary','')
FROM exploration_nodes
WHERE exploration_id=$1 AND kind='intent'
  AND state IN ('done','blocked','exhausted','stopped')
ORDER BY id DESC LIMIT $2`, expID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReaderNodeRef{}
	for rows.Next() {
		var n ReaderNodeRef
		n.Kind = KindIntent
		if rows.Scan(&n.ID, &n.State, &n.Summary) != nil {
			continue
		}
		n.Summary = truncRunes(redact.TestMethod(n.Summary), 160)
		out = append(out, n)
	}
	return out, rows.Err()
}

// ReaderSearchNodes 在被采纳任务的 finding/fact 摘要里按关键词检索，返回 id + 摘要。
// 只查 payload->>'summary'，不读 detail/evidence（那是下钻时才脱敏给的）。
func (s *ExplorationStore) ReaderSearchNodes(relatedTaskID int64, q string, limit int) ([]ReaderNodeRef, error) {
	expID, err := s.adoptedExploration(relatedTaskID)
	if err != nil || expID == 0 {
		return nil, err
	}
	if limit <= 0 || limit > 20 {
		limit = 8
	}
	like := "%" + strings.TrimSpace(q) + "%"
	rows, err := s.db.Query(`
SELECT id, kind, state, COALESCE(payload->>'summary','')
FROM exploration_nodes
WHERE exploration_id=$1 AND kind IN ('finding','fact')
  AND COALESCE(payload->>'summary','') ILIKE $2
ORDER BY (kind='finding') DESC, id DESC LIMIT $3`, expID, like, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReaderNodeRef{}
	for rows.Next() {
		var n ReaderNodeRef
		if rows.Scan(&n.ID, &n.Kind, &n.State, &n.Summary) != nil {
			continue
		}
		n.Summary = truncRunes(redact.TestMethod(n.Summary), 160)
		out = append(out, n)
	}
	return out, rows.Err()
}

// adoptedExploration 校验 owner → related 是 adopted，返回对方的 exploration_id。
func (s *ExplorationStore) adoptedExploration(relatedTaskID int64) (int64, error) {
	owner, err := s.TaskID()
	if err != nil || owner <= 0 {
		return 0, err
	}
	var expID int64
	err = s.db.QueryRow(`
SELECT t.exploration_id
FROM task_intel_links link
JOIN tasks t ON t.id = link.related_task_id AND t.deleted_at IS NULL
WHERE link.task_id=$1 AND link.related_task_id=$2 AND link.decision='adopted'`,
		owner, relatedTaskID).Scan(&expID)
	if err != nil {
		return 0, nil // 未采纳：调用方按「无权限/不存在」处理，不区分
	}
	return expID, nil
}

// overlapEndpoints 从 matched JSON 里挑出接口类键（METHOD /path）。资产/凭据
// 的键里带 host 或口令，不外泄。
func overlapEndpoints(matchedJSON string) []string {
	var items []struct {
		Kind string `json:"kind"`
		Key  string `json:"key"`
	}
	if json.Unmarshal([]byte(matchedJSON), &items) != nil {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, it := range items {
		if it.Kind != IntelKindEndpoint {
			continue
		}
		method, path := endpointMethodPath(it.Key)
		if path == "" {
			continue
		}
		k := method + " " + path
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

func truncRunes(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// endpointMethodPath 拆 "method /path?params"：方法转大写（给人看），路径去掉 query。
// 与 server 侧 splitEndpointKey 同口径，只是展示时大写。
func endpointMethodPath(key string) (method, path string) {
	key = strings.TrimSpace(key)
	method = "GET"
	if i := strings.IndexByte(key, ' '); i > 0 {
		method = strings.ToUpper(strings.TrimSpace(key[:i]))
		key = strings.TrimSpace(key[i+1:])
	}
	if i := strings.IndexByte(key, '?'); i >= 0 {
		key = key[:i]
	}
	return method, key
}
