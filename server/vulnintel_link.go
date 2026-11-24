package server

// 资产图联动：同步进来的 CVE 反向匹配 service 资产的 technologies 指纹，
// 给受影响任务挂一条聚合 hint。放独立文件，不混进 manager.go。
//
// 为什么要做：情报库自己「有数据」不等于「任务能用上」。跑着的任务不会主动
// 遍历 4000 条资产去查库；把命中结果推进它的探索图，planner 下一轮才看得到。
//
// 防抖：每轮同步都会命中同一批资产，同一资产 24 小时内只挂一次。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/vulnintel"
)

// intelHintPrefix 是联动 hint 的判重前缀（FormatHint 正文也以它开头）。
const intelHintPrefix = "[情报联动]"

// assetTag 返回 FormatHint 为单个资产写的标记串，用于判重。
func assetTag(assetID int64) string {
	return fmt.Sprintf("资产(id=%d)", assetID)
}

// linkVulnIntelAssets 在每轮同步后执行：新同步的 CVE × service 资产指纹 →
// 按 (任务, 资产) 聚合成一条 hint，锚定到资产节点。best-effort，错误只记日志。
func (s *Server) linkVulnIntelAssets() {
	if s == nil || s.vuln == nil || s.m == nil || s.m.pg == nil {
		return
	}
	ctx := context.Background()
	since := time.Now().Add(-7 * 24 * time.Hour) // 与增量窗口重叠，防漏
	res, err := s.vuln.store.LinkAssetsToVulns(ctx, since)
	if err != nil {
		log.Printf("[vulnintel] 资产联动查询失败: %v", err)
		return
	}
	if len(res.Matches) == 0 {
		return
	}

	// task → asset → matches
	perTask := map[int64]map[int64][]vulnintel.AssetVulnMatch{}
	taskIDs := []int64{}
	seenTask := map[int64]bool{}
	for _, mt := range res.Matches {
		if mt.TaskID <= 0 {
			continue
		}
		if !seenTask[mt.TaskID] {
			seenTask[mt.TaskID] = true
			taskIDs = append(taskIDs, mt.TaskID)
		}
		if perTask[mt.TaskID] == nil {
			perTask[mt.TaskID] = map[int64][]vulnintel.AssetVulnMatch{}
		}
		perTask[mt.TaskID][mt.AssetID] = append(perTask[mt.TaskID][mt.AssetID], mt)
	}

	// 一次性取任务的探索图 id（没有图的任务跳过：没地方挂）。
	expOf := map[int64]int64{}
	rows, err := s.m.pg.Query(`SELECT id, exploration_id FROM tasks WHERE id = ANY($1)`, taskIDs)
	if err != nil {
		log.Printf("[vulnintel] 资产联动取任务失败: %v", err)
		return
	}
	for rows.Next() {
		var id, exp int64
		if err := rows.Scan(&id, &exp); err == nil {
			expOf[id] = exp
		}
	}
	rows.Close()

	added := 0
	for taskID, perAsset := range perTask {
		exp, ok := expOf[taskID]
		if !ok || exp <= 0 {
			continue
		}
		ts := s.m.pg.Exploration(exp)
		recent, err := ts.ListByKind(db.KindHint, 500)
		if err != nil {
			log.Printf("[vulnintel] 任务 %d 读 hint 失败（跳过防抖）: %v", taskID, err)
			recent = nil
		}
		alerted := map[int64]bool{}
		dayAgo := time.Now().Add(-24 * time.Hour)
		for _, n := range recent {
			var p struct {
				Text string `json:"text"`
			}
			_ = json.Unmarshal(n.Payload, &p)
			if !strings.HasPrefix(p.Text, intelHintPrefix) {
				continue
			}
			if !n.CreatedAt.IsZero() && n.CreatedAt.Before(dayAgo) {
				continue
			}
			for _, mt := range res.Matches {
				if strings.Contains(p.Text, assetTag(mt.AssetID)) {
					alerted[mt.AssetID] = true
				}
			}
		}
		for assetID, ms := range perAsset {
			if alerted[assetID] {
				continue
			}
			text := intelHintPrefix + vulnintel.FormatHint(ms, assetID)
			// origin="human" = 平台注入的提示，与 UI 手工 add_hint 同源可见。
			if _, err := ts.AddNode(db.KindHint, map[string]any{"text": text}, 0, "active", "human", []int64{assetID}); err != nil {
				log.Printf("[vulnintel] 任务 %d 挂情报 hint 失败: %v", taskID, err)
				continue
			}
			added++
		}
	}
	log.Printf("[vulnintel] 资产联动: 命中资产 %d，挂 hint %d 条（任务 %d 个）",
		res.MatchedAssets, added, len(perTask))
}
