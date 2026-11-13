package server

// 统一阅读者的宿主工具与一次性 seed（artex-hs T11 / V6-U3）。
//
// V6-U3 把 observer（项目内跨任务观察）与 reader（跨项目串联）两条独立链合成
// 一套：一个 agent（主 key=reader，收官 nudge 硬编码）、一条 trigger
// （OnProjectGraph + IntervalSec 双条件）、一份 prompt（按触发前缀判别作用域）。
// observer agent 行保留作只读别名，但不再新建触发（seedObserverAgent 早退）。
//
// 六工具名不变：observer 四件（query_project_index / get_task_graph_digest /
// write_project_insight / push_task_hint）+ reader 两件（read_all_project_insights /
// write_global_insight）。两个聚合出口 projectObserverTools()/
// projectReaderTools() 保持原样（装配单测按数量断言），统一绑定用
// unifiedReaderToolKeys（六件全绑到 reader）。
//
// 工具经 SeedTool 入库 + AddAgentToToolBinding 绑定到 reader；触发运行策略
// serial+merge=all（整波合并）；tool_base='none'（只读红线，两 key 都保留）。
// 两个尺度各自独立开关（V6-DUAL）：projects.observer_enabled 管跨任务/项目内
// 那一路（write_project_insight / on_project_graph / 项目段注入），
// projects.reader_enabled 管跨项目那一路（read_all_project_insights /
// write_global_insight / 跨项目段注入）。同一个 agent、两把闸。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// ---------- observer / reader 工具 ----------

// toolQueryProjectIndex 读某项目的节点投影（T09 project_index 表的查询面）。
// observer 用它总览全项目：同 kind/severity/asset_keys/关键词过滤都是投影列
// 上的谓词，成本与任务数×节点数线性（几百行量级）。
func (s *Server) toolQueryProjectIndex() actool.CoreTool {
	return roTool("query_project_index",
		"读指定项目的【全任务节点投影索引】(跨任务总览用)：每行=某任务探索图一个节点的摘要(kind/state/summary/severity/关联资产键/task_id/node_id)。"+
			"\n过滤全可选：kinds(如 finding/fact/goal)、severities(如 high/critical)、asset_keys(资产键交集命中，如 [\"10.0.0.8:8080\",\"canal.example.com\"])、q(summary 关键词大小写不敏感)。默认新在前。",
		objSchema(map[string]any{
			"project_id": map[string]any{"type": "integer", "description": "项目 id"},
			"kinds":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "按节点类型过滤(可选)"},
			"severities": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "按严重度过滤(可选，只对 finding 有意义)"},
			"asset_keys": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "资产键交集过滤(可选)：任一命中即返回"},
			"q":          strParam("summary 关键词(可选，大小写不敏感子串)"),
			"limit":      map[string]any{"type": "integer", "description": "返回条数上限(可选，默认 200)"},
		}, "project_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ProjectID  json.RawMessage `json:"project_id"`
				Kinds      []string        `json:"kinds"`
				Severities []string        `json:"severities"`
				AssetKeys  []string        `json:"asset_keys"`
				Q          string          `json:"q"`
				Limit      int             `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			pid := parseProfileID(a.ProjectID) // 复用「数字或数字字符串」解析
			if pid <= 0 {
				return actool.Errorf("project_id 无效"), nil
			}
			rows, err := s.m.pg.QueryProjectIndex(ctx, pid, db.ProjectIndexFilter{
				Kinds: a.Kinds, Severities: a.Severities, AssetKeys: a.AssetKeys, Query: a.Q, Limit: a.Limit,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out := make([]map[string]any, 0, len(rows))
			for _, r := range rows {
				out = append(out, map[string]any{
					"task_id": r.TaskID, "node_id": r.NodeID, "kind": r.Kind, "state": r.State,
					"summary": r.Summary, "severity": r.Severity, "asset_keys": r.AssetKeys,
				})
			}
			return jsonResult(out)
		})
}

// toolGetTaskGraphDigest 按任务下钻读探索图总览。复用原版 graph_overview 的
// 宿主委托路径（delegateToTask + GraphOverviewTool，与 get_task_graph 同一
// 实现——只读、按 task 限域、planner 所见即所得）。独立命名+描述是给 observer
// 的语义入口；实现零复制。
func (s *Server) toolGetTaskGraphDigest() actool.CoreTool {
	return roTool("get_task_graph_digest",
		"下钻读指定任务的探索图总览(目标/意图/事实/发现/提示与关系，与任务内 graph_overview 同构，只读)。投影清单(query_project_index)里定位到可疑 task_id 后用它看全貌。",
		objSchema(map[string]any{"task_id": strParam("任务 id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).GraphOverviewTool)
		})
}

// toolWriteProjectInsight 写一条项目级洞察（observer 的产出面）。keywords
// 必填至少 1 个——planner 侧注入靠 keywords ∩ 任务锚定 asset_keys 命中，
// 无关键词的洞察永远不会被复用（拒写防垃圾行，与 content 必填同理由）。
func (s *Server) toolWriteProjectInsight() actool.CoreTool {
	return wrTool("write_project_insight",
		"给指定项目写一条【跨任务可借鉴洞察】(project_insights)：短、事实性、可执行，"+
			"格式如「N任务 canal v1.1.5 未认证RCE已验证，可借鉴至 M任务 10.x:8080」。keywords=组件名/版本/IP/域名等命中键（至少 1 个，注入时与任务锚定资产求交集）。宁少勿滥：没有真发现就别写。",
		objSchema(map[string]any{
			"project_id":     map[string]any{"type": "integer", "description": "项目 id"},
			"content":        strParam("洞察正文(短、事实性、可执行)"),
			"keywords":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "命中关键词(组件名/版本/IP/域名…，≥1)"},
			"source_task_id": map[string]any{"type": "integer", "description": "可选：本洞察主要来源任务 id"},
		}, "project_id", "content", "keywords"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ProjectID    json.RawMessage `json:"project_id"`
				Content      string          `json:"content"`
				Keywords     []string        `json:"keywords"`
				SourceTaskID int64           `json:"source_task_id"`
			}
			_ = json.Unmarshal(in, &a)
			pid := parseProfileID(a.ProjectID)
			if pid <= 0 {
				return actool.Errorf("project_id 无效"), nil
			}
			if len(a.Keywords) == 0 {
				return actool.Errorf("keywords 至少 1 个(无关键词的洞察永远不会被注入命中)"), nil
			}
			ins, err := s.m.pg.WriteInsight(ctx, pid, a.Content, a.SourceTaskID, a.Keywords)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("project insight %d written (project#%d)", ins.ID, pid)), nil
		})
}

// toolPushTaskHint 给目标任务注入战略提示并唤醒其 planner。实现=委托
// add_task_hint（原版人工插话同一路径：hint 落探索图 + NotifyHint 记「人新
// 增了提示」触发 planner），保证目标任务 planner 下轮真的读到。每轮 ≤2 条
// 的节制由 prompt 约束（seed prompt 第 5 步），工具层不硬拦（与原版一致）。
func (s *Server) toolPushTaskHint() actool.CoreTool {
	return wrTool("push_task_hint",
		"给指定任务注入一条战略提示并唤醒其规划者(等价人工插话 add_task_hint；planner 下轮生成意图时读到)。仅当该任务【当下正需要】这条信息时用，每轮 ≤2 条、宁少勿滥。",
		objSchema(map[string]any{
			"task_id":   strParam("目标任务 id"),
			"text":      strParam("提示内容(引用借鉴来源 task/节点 id，简洁可执行)"),
			"asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "可选：锚定该任务内的资产 id"},
		}, "task_id", "text"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			// add_task_hint 的批量形态（hints 数组）这里不透传：observer 单条
			// 语义清晰，批量留原版入口。
			var a struct {
				TaskID   string            `json:"task_id"`
				Text     string            `json:"text"`
				AssetIDs []json.RawMessage `json:"asset_ids"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Text) == "" {
				return actool.Errorf("text 不能为空"), nil
			}
			return s.delegateToTask(ctx, in, (*agent.ToolSet).AddHintTool)
		})
}

// toolReadAllProjectInsights 读跨项目的项目洞察池（reader 的输入面）。
// project_ids 可选：空=全部【已开 reader_enabled 的 active 项目】。limit
// 默认 100（串联是"读一遍再归纳"，不该吞全表）。
//
// T18 reader_enabled=项目级 opt-in：未开启的项目不进 reader 视野（读面收窄，
// 双闸的全局侧由 reader 触发器 enabled，项目侧由此处过滤）。显式传入的
// project_ids 同样过滤——只保留开了 reader_enabled 的；被剔除的在返回体里
// 如实标注 skipped_projects，不静默吞掉（agent 需要知道哪些项目不在视野内，
// 免得对着空结果反复重试）。
//
// V4-E「资产优先」：返回体从「纯项目洞察数组」升级为对象，新增
// cross_project_assets——同一资产出现在 ≥2 个项目里的聚合行（项目数/项目
// 列表/finding 数/最近出现）。跨项目最强信号是资产重叠，这是 SQL join 的活，
// 不该让模型从散文里猜；projects/insights 原字段形状不变（向后兼容）。
// cross_project_assets 同样按 reader_enabled 可见集裁剪（否则会绕过项目级
// opt-in 把未开闸项目的情报漏给 reader）。
func (s *Server) toolReadAllProjectInsights() actool.CoreTool {
	return roTool("read_all_project_insights",
		"读跨项目阅读输入，两段：① cross_project_assets＝同一资产出现在 ≥2 个项目里的聚合行"+
			"(资产标签/类型/涉及项目[id+名称]/发现数/最近出现，按项目数降序，最多 20 行)——跨项目信号先看这段；"+
			"② projects＝各项目的项目洞察(project_insights，observer 产出)。"+
			"仅覆盖【开启阅读者开关(reader_enabled)】的 active 项目；project_ids 空=读全部已开启项目。"+
			"cross_project_assets 为空即无跨项目信号，不必再逐条翻 insights。",
		objSchema(map[string]any{
			"project_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "可选：限定项目 id；空=全部已开启项目"},
			"limit":       map[string]any{"type": "integer", "description": "每项目条数上限(可选，默认 50)"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ProjectIDs []int64 `json:"project_ids"`
				Limit      int     `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			ids, skipped, err := s.readerVisibleProjects(a.ProjectIDs)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.Limit <= 0 {
				a.Limit = 50
			}
			visible := make(map[int64]bool, len(ids))
			for _, pid := range ids {
				visible[pid] = true
			}
			projects := make([]map[string]any, 0, len(ids))
			for _, pid := range ids {
				list, err := s.m.pg.ListInsights(ctx, pid, nil, a.Limit)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				items := make([]map[string]any, 0, len(list))
				for _, it := range list {
					items = append(items, map[string]any{"id": it.ID, "content": it.Content, "keywords": it.Keywords, "source_task_id": it.SourceTaskID, "created_at": it.CreatedAt})
				}
				projects = append(projects, map[string]any{"project_id": pid, "insights": items})
			}
			cross, err := s.m.pg.CrossProjectAssetRows(ctx, 0)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cross = db.FilterCrossProjectAssetsByProjects(cross, visible)
			out := map[string]any{
				"cross_project_assets": cross,
				"projects":             projects,
			}
			if len(skipped) > 0 {
				// 被 reader_enabled 闸剔除的项目如实回报（照 warn 不拒纪律）。
				out["skipped_projects"] = skipped
				out["note"] = "这些项目未开启 reader_enabled 或不是 active 项目，不在跨项目阅读视野内"
			}
			return jsonResult(out)
		})
}

// readerVisibleProjects 计算 reader 可见项目集：projectIDs 空=全部 active 且
// reader_enabled=true 的项目；非空=逐个过滤（不存在/非 active/未开启的进
// skipped）。返回的 skipped 是字符串描述数组，供工具返回体如实标注。
func (s *Server) readerVisibleProjects(projectIDs []int64) (visible []int64, skipped []string, err error) {
	pg := s.m.pg
	if len(projectIDs) == 0 {
		ps, err := pg.ListProjects("active")
		if err != nil {
			return nil, nil, err
		}
		for _, p := range ps {
			if p.ReaderEnabled {
				visible = append(visible, p.ID)
			}
		}
		return visible, nil, nil
	}
	seen := map[int64]bool{}
	for _, pid := range projectIDs {
		if pid <= 0 || seen[pid] {
			continue
		}
		seen[pid] = true
		p, err := pg.GetProject(pid)
		if errors.Is(err, db.ErrProjectNotFound) {
			skipped = append(skipped, fmt.Sprintf("%d(不存在)", pid))
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		switch {
		case p.Status != "active":
			skipped = append(skipped, fmt.Sprintf("%d(非 active)", pid))
		case !p.ReaderEnabled:
			skipped = append(skipped, fmt.Sprintf("%d(未开 reader_enabled)", pid))
		default:
			visible = append(visible, pid)
		}
	}
	return visible, skipped, nil
}

// toolWriteGlobalInsight 写一条跨项目全局洞察（reader 产出）。进
// global_insights；source_projects=串联涉及的项目集，供展示回链。
//
// V5-A：asset_keys 是注入 planner 的唯一命中依据（与任务 open 意图锚定资产的
// 归一化键求交集）。入参缺省时刻意做一次「从正文反查已知资产键」的推导——
// 候选集=来源项目下出现过的资产键（AssetKeysForProjects，归一化规则与注入侧
// AssetKeysForIDs 同源），命中=正文里出现该键（大小写不敏感子串）。推导不出
// 就落空数组 → 该条永不注入（只能人工看），绝不硬塞无关键去骗命中。
func (s *Server) toolWriteGlobalInsight() actool.CoreTool {
	return wrTool("write_global_insight",
		"写一条【跨项目全局洞察】(global_insights)：多个项目里重复出现的同类面（同组件/同类入口/同一打法跨项目可迁移）。source_projects 填涉及的每个项目 id。"+
			"asset_keys 填洞察点名的资产键（域名/IP/URL，如 [\"canal.example.com\",\"10.0.0.8\"]）——planner 靠它把这条读回正在打该资产的任务；不填则从正文自动匹配来源项目的已知资产，匹配不到就不会被注入。"+
			"宁少勿滥；单项目内部的事写 write_project_insight，别写这里。",
		objSchema(map[string]any{
			"content":         strParam("洞察正文(跨项目证据链式陈述，指明各项目 task/资产)"),
			"source_projects": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "涉及的项目 id(≥1)"},
			"asset_keys":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可选：命中资产键(域名/IP/URL)；缺省从正文匹配来源项目的已知资产"},
		}, "content", "source_projects"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Content        string   `json:"content"`
				SourceProjects []int64  `json:"source_projects"`
				AssetKeys      []string `json:"asset_keys"`
			}
			_ = json.Unmarshal(in, &a)
			if len(a.SourceProjects) == 0 {
				return actool.Errorf("source_projects 至少 1 个"), nil
			}
			// T18：source_projects 剔除未 opt-in（reader_enabled 关/非 active/
			// 不存在）的项目——warn 不拒，洞察宁少勿滥的纪律不变，但也不因某
			// 个项目没开开关就把整条合法的全局洞察打回。全被剔除才报错。
			visible, skipped, err := s.readerVisibleProjects(a.SourceProjects)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if len(skipped) > 0 {
				log.Printf("[reader] write_global_insight 剔除未开启 reader_enabled 的项目: %v", skipped)
			}
			if len(visible) == 0 {
				return actool.Errorf("source_projects 全部未开启 reader_enabled 或不可见，无有效来源项目"), nil
			}
			// V5-A：入参缺省 → 从正文推导。候选集查库失败按「推导失败=空」处理
			// （洞察照写，只是不参与注入；不因一次旁路查询抖动丢掉 reader 的产出）。
			var derivedNote string
			if len(a.AssetKeys) == 0 {
				if cands, err := s.m.pg.AssetKeysForProjects(ctx, visible); err == nil {
					a.AssetKeys = db.DeriveAssetKeys(a.Content, cands)
					if len(a.AssetKeys) == 0 {
						derivedNote = "；正文未匹配到已知资产键，本条不会被注入 planner"
					}
				} else {
					derivedNote = fmt.Sprintf("；资产键推导失败(%v)，本条不会被注入 planner", err)
				}
			}
			g, err := s.m.pg.WriteGlobalInsight(ctx, a.Content, visible, a.AssetKeys)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("global insight %d written (projects %v, asset_keys %v)%s", g.ID, visible, g.AssetKeys, derivedNote)), nil
		})
}

// projectObserverTools / projectReaderTools 是两 agent 的工具集（seed 注册与
// seed 绑定共用同一列表，口径单源）。
func (s *Server) projectObserverTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolQueryProjectIndex(),
		s.toolGetTaskGraphDigest(),
		s.toolWriteProjectInsight(),
		s.toolPushTaskHint(),
	}
}

func (s *Server) projectReaderTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolReadAllProjectInsights(),
		s.toolWriteGlobalInsight(),
	}
}

// unifiedReaderToolKeys 是统一阅读者 agent（key=reader）绑定的全部六工具
// （V6-U3）：observer 四件 + reader 两件，工具名一律不变。两个聚合出口
// projectObserverTools()/projectReaderTools() 仍需按原数量分别服务装配链，
// 故合并只发生在「绑定集合」这一层，不动那两个函数。
var unifiedReaderToolKeys = []string{
	"query_project_index", "get_task_graph_digest", "write_project_insight", "push_task_hint",
	"read_all_project_insights", "write_global_insight",
}

// ---------- seed（照 reporter 样板 orchestration.go:735） ----------

// observerPrompt 是观察者 system prompt 的默认正文（SeedPromptIfEmpty 播种，
// DB 里可编辑；要点全部保留：只读红线、五步工作流、insight 格式与克制）。
const observerPrompt = "你是本项目的【跨任务观察者】：只读与总结，禁止执行任何渗透动作（不调用扫描/请求/命令类工具，也没有它们）。\n" +
	"触发时机：本项目的探索图发生变更，触发消息里带本批变更清单（kind/摘要/task_id）。\n" +
	"工作步骤：\n" +
	"1) query_project_index 总览全项目投影（可按 kinds/severities/asset_keys 过滤），建立「这个项目里各任务都在做什么、发现了什么」的全貌；\n" +
	"2) 从触发清单里的 task_id/kind 定位变更点，必要时 get_task_graph_digest 下钻该任务的完整探索图；\n" +
	"3) 与其他任务的投影比对——同一 CMS/同组件同版本/同服务指纹/同类漏洞入口都是高价值借鉴信号（A 任务已验证的打法/入口/PoC 对 B 任务是现成的路）；\n" +
	"4) 确有可借鉴处用 write_project_insight 落库：短、事实性、可执行，格式如「N任务 canal v1.1.5 未认证RCE已验证，可借鉴至 M任务 10.x:8080」，keywords 必须带组件名/版本/IP/域名等命中键；\n" +
	"5) 仅当某目标任务【当下正需要】该信息时才 push_task_hint 直接提醒（每轮最多 2 条，宁少勿滥；hint 会唤醒对方 planner，滥用等于污染）。\n" +
	"没有真发现就直接结束本轮，绝不写空洞 insight 或客套 hint。跨项目的事不归你管（那是 reader）。"

// readerPromptV1 是上线时的默认正文（V4-E 之前）。存量库里未编辑过的 prompt
// 与它逐字节相同——upgradeReaderPrompt 据此判断「可以安全升级」，用户改过的
// 正文一律不覆盖。修改 readerPrompt 时必须同步把旧版文本迁到这里。
const readerPromptV1 = "你是【跨项目阅读者】：只读与总结，禁止执行任何渗透动作。\n" +
	"定时触发（每 30 分钟一轮）。工作步骤：\n" +
	"1) read_all_project_insights 读各项目观察者积累的洞察；\n" +
	"2) 串联跨项目的相似面——同一组件/同类入口/同一打法在多个项目重复出现（含同一资产出现在多项目）即为信号；\n" +
	"3) 确有串联价值才 write_global_insight：正文指明涉及的项目/任务/资产证据链，source_projects 填全涉及项目 id。\n" +
	"宁少勿滥：单项目内部的事已由观察者处理，没有跨项目信号就空转结束，不要复述单项目 insight、不要写空洞总结。"

// readerPrompt 是阅读者 system prompt 的默认正文（V4-E：资产优先输入）。
const readerPrompt = "你是【跨项目阅读者】：只读与总结，禁止执行任何渗透动作。\n" +
	"触发时机：项目收官时点亮一轮，另有定时兜底（每 30 分钟一轮）。工作步骤：\n" +
	"1) read_all_project_insights 拿本轮输入，【第一步先看 cross_project_assets】——它已经把「同一资产/同一组件出现在 ≥2 个项目」join 好了（资产标签/类型/涉及项目[id+名称]/发现数/最近出现）。" +
	"cross_project_assets 为空＝本轮没有跨项目信号，【直接空转结束】，不要再去逐条翻 projects 里的 insights 找感觉；\n" +
	"2) cross_project_assets 非空时，就围绕这些行写全局洞察：每条必须点名【是哪个资产、涉及哪几个项目】，说清结论——同一资产上的同类漏洞面该搬到哪个项目、同一组件版本问题在哪几个项目重复出现、同一入口/打法可怎么复用或去重。" +
	"需要背景细节时可回看对应项目的 insights 印证，但不要复述单项目内容；\n" +
	"3) 确有串联价值才 write_global_insight：正文按「资产 → 项目 → 证据」陈述，source_projects 填全涉及项目 id。\n" +
	"宁少勿滥：单项目内部的事已由观察者处理，没有跨项目资产信号就空转结束，不要写空洞总结。"

// observerGraphMessage 是 on_project_graph 触发器的用户消息模板（scheduler
// 会在其后追加渲染好的变更清单正文）。V6 起单 trigger 用下方带前缀的
// unifiedGraphMessage；本常量保留给 observer 别名 seed 的回退路径。
const observerGraphMessage = "项目探索图发生了新变更，请依职责观察。"

// V6-U3 统一阅读者：单 trigger 双条件的两个消息前缀。图变更触发带
// 【scope=project】，定时触发带【scope=cross】——readerUnifiedPrompt 据此判别
// 本轮做「项目内观察」还是「跨项目串联」。一条 trigger 同时开两条件，
// scheduler 的 fireProjectGraph/fireIntervals 各认 OnProjectGraph/IntervalSec
// （last_projgraph_id 水位与 last_fire 两套状态独立，不串）。
const unifiedGraphMessage = "【scope=project】项目探索图发生了新变更，请依职责观察。"
const unifiedIntervalMessage = "【scope=cross】定时跨项目阅读：读各项目洞察，串联跨项目相似面。"

// unifiedReaderTrigger 构造统一阅读者的【唯一】触发器行：双条件 + enabled=true。
// seedReaderAgent（全新库建行）与 unifyReaderAgent（存量库收敛）共用，口径单源。
func unifiedReaderTrigger() *db.AgentTrigger {
	return &db.AgentTrigger{
		AgentKey: "reader", Enabled: true, OnProjectGraph: true, IntervalSec: 1800,
		ProjectGraphMessage: unifiedGraphMessage,
		IntervalMessage:     unifiedIntervalMessage,
	}
}

// readerUnifiedPrompt 是统一阅读者（单 agent/单 trigger）的默认正文：把 observer
// 五步与 reader 跨项目三步合成一份，用触发消息前缀判别本轮作用域。
// 旧默认 readerPromptV1（V4-E 之前）与 readerPrompt（V4-E 资产优先版）保留作
// upgradeReaderPrompt 的「逐字节比对旧默认才升级」基准——用户手改的一律不覆盖。
const readerUnifiedPrompt = "你是【统一阅读者】：只读与总结，禁止执行任何渗透动作（不调用扫描/请求/命令类工具，也没有它们）。\n" +
	"触发时机：项目探索图变更（图变更触发）或定时兜底（每 30 分钟一轮）；一条触发器同时挂这两个条件。\n" +
	"【先看触发消息前缀判别本轮作用域】\n" +
	"· 【scope=project】（项目图变更，消息里还带本批变更清单）：做项目内跨任务观察——\n" +
	"  1) query_project_index 总览全项目投影（可按 kinds/severities/asset_keys 过滤）；\n" +
	"  2) 从变更清单里的 task_id/kind 定位变更点，必要时 get_task_graph_digest 下钻该任务完整探索图；\n" +
	"  3) 与其他任务投影比对——同 CMS/同组件同版本/同类漏洞入口都是高价值借鉴信号；\n" +
	"  4) 确有可借鉴处用 write_project_insight 落库（短、事实性、可执行，keywords 必带命中键）；\n" +
	"  5) 仅当某目标任务【当下正需要】该信息才 push_task_hint 提醒（每轮最多 2 条，宁少勿滥）。\n" +
	"· 【scope=cross】（定时触发）：做跨项目串联——\n" +
	"  1) read_all_project_insights 拿本轮输入，【先看 cross_project_assets】——它已 join 好「同一资产/组件出现在 ≥2 个项目」；为空即无跨项目信号，直接空转结束；\n" +
	"  2) cross_project_assets 非空时围绕这些行写全局洞察，点名是哪个资产、涉及哪几个项目、同一资产上的同类漏洞面该搬到哪；\n" +
	"  3) 确有串联价值才 write_global_insight：正文按「资产 → 项目 → 证据」陈述，source_projects 填全涉及项目 id。\n" +
	"没有真发现就直接结束本轮，绝不写空洞洞察或客套 hint；单项目内部的事只写 write_project_insight、跨项目的事只写 write_global_insight，别混。"

// seedObserverAgent 是 V6 之前的「跨任务观察者」seed（回退路径保留）。
// V6-U3 起 observer 退化为只读别名：收敛完成后（reader_unified_v1 置位）
// 一律早退，不再新建 agent/触发器；收官 nudge 硬编码的主 key 是 reader，
// 工具/触发器/prompt 全归它。存量库里已存在的 observer agent 行保留不动。
func (s *Server) seedObserverAgent() {
	if v, _, _ := s.m.pg.GetSetting(readerUnifiedFlag); v == "true" {
		return
	}
	const flag = "observer_agent_seed_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成败只尝试一次

	if exist, _ := s.m.pg.GetAgentByKey("observer"); exist != nil {
		return // key 已被占用（用户手建过）——不覆盖
	}
	a, err := s.m.pg.CreateAgent("observer", "跨任务观察者",
		"项目级跨任务观察：项目探索图变更时自动触发，读全项目投影，把可借鉴处写成项目洞察、必要时提醒相关任务。默认惰性（项目未开观察者开关时不触发）。")
	if err != nil {
		log.Printf("[observer] 创建 agent 失败: %v", err)
		return
	}
	if err := s.m.pg.SeedPromptIfEmpty(a.ID, observerPrompt); err != nil {
		log.Printf("[observer] seed prompt 失败: %v", err)
	}
	// 触发运行策略：serial + merge=all —— 一波图变更合并成【一次】观察会话
	// （天然 debounce；5s tick × 项目内多条事件=一条触发消息已在 scheduler 聚合，
	// merge=all 再把跨 tick 的余量并掉）。parallel 会被 nextTriggerRun 忽略 merge
	// （conversations.go:671），达不到整波合并——与 reporter（parallel+none 一漏
	// 一报）刻意相反。max_parallel=2：serial 下仅影响上限语义，与任务书对齐。
	if err := s.m.pg.SetAgentTriggerBehavior("observer", "serial", "all", 2); err != nil {
		log.Printf("[observer] 设置触发运行策略失败: %v", err)
	}
	if err := s.m.pg.AddAgentToToolBinding("observer", []string{
		"query_project_index", "get_task_graph_digest", "write_project_insight", "push_task_hint",
	}); err != nil {
		log.Printf("[observer] 绑定工具失败: %v", err)
	}
	// 全局唯一 observer 触发器行：on_project_graph=true、enabled=true
	// （真正开关在 projects.observer_enabled；用户可在系统→触发器页改）。
	if _, err := s.m.pg.CreateTrigger(&db.AgentTrigger{
		AgentKey: "observer", Enabled: true, OnProjectGraph: true,
		ProjectGraphMessage: observerGraphMessage,
	}); err != nil {
		log.Printf("[observer] 创建触发器失败: %v", err)
	}
	log.Printf("[observer] 已预置「跨任务观察者」agent + 项目图变更触发器")
}

// seedReaderAgent 预置「统一阅读者」自定义 agent（V6-U3）：绑定六工具 +
// 单条双条件触发器（OnProjectGraph + IntervalSec=1800 + enabled=true）。
// 一次性 flag 保护；存量库的旧 reader（只绑两工具/触发器 enabled=false）
// 由紧随其后的 unifyReaderAgent 收敛，本函数因自己的 flag 已置位会早退。
func (s *Server) seedReaderAgent() {
	const flag = "reader_agent_seed_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }()

	if exist, _ := s.m.pg.GetAgentByKey("reader"); exist != nil {
		return
	}
	a, err := s.m.pg.CreateAgent("reader", "统一阅读者",
		"统一阅读者：项目内观察(图变更触发)与跨项目串联(定时触发)共用一个 agent、一条双条件触发器。读全项目投影/单任务图、写项目洞察、必要时提醒任务；定时读跨项目资产信号、写跨项目洞察。")
	if err != nil {
		log.Printf("[reader] 创建 agent 失败: %v", err)
		return
	}
	if err := s.m.pg.SeedPromptIfEmpty(a.ID, readerUnifiedPrompt); err != nil {
		log.Printf("[reader] seed prompt 失败: %v", err)
	}
	// serial+merge=all：整波图变更合并成一次会话（observer 原策略），max_parallel=2。
	if err := s.m.pg.SetAgentTriggerBehavior("reader", "serial", "all", 2); err != nil {
		log.Printf("[reader] 设置触发运行策略失败: %v", err)
	}
	if err := s.m.pg.AddAgentToToolBinding("reader", unifiedReaderToolKeys); err != nil {
		log.Printf("[reader] 绑定工具失败: %v", err)
	}
	if _, err := s.m.pg.CreateTrigger(unifiedReaderTrigger()); err != nil {
		log.Printf("[reader] 创建双条件触发器失败: %v", err)
	}
	log.Printf("[reader] 已预置「统一阅读者」agent + 单条双条件触发器(on_project_graph+interval, enabled)")
}

// readerUnifiedFlag 是「统一阅读者收敛已完成」的一次性标记（settings 表）。
// 双重用途：unifyReaderAgent 自己只跑一次；seedObserverAgent 见它即早退
// （observer 不再新建 agent/触发器）。
const readerUnifiedFlag = "reader_unified_v1"

// unifyReaderAgent 把存量库的两条独立链收敛成一条（V6-U3），一次性执行：
//   - reader 补绑六工具（AddAgentToToolBinding 幂等 append）；
//   - 触发器：先去重（reader 名下只留一条），再执行裁决指定的
//     UPDATE agent_triggers SET agent_key='reader' WHERE agent_key='observer'，
//     最后合并成一条双条件 enabled=true 的 trigger，删掉多余行；
//   - prompt 升级交给 upgradeReaderPrompt（逐字节比对旧默认 + 新 flag）。
//
// 全新库里 seedReaderAgent 已建好双条件 trigger/六工具/unified prompt，
// 本函数跑起来是幂等 no-op 后置 flag；不覆盖用户手改。
func (s *Server) unifyReaderAgent() {
	pg := s.m.pg
	if pg == nil {
		return
	}
	if v, _, _ := pg.GetSetting(readerUnifiedFlag); v == "true" {
		return
	}
	defer func() { _ = pg.SetSetting(readerUnifiedFlag, "true") }()

	if err := pg.AddAgentToToolBinding("reader", unifiedReaderToolKeys); err != nil {
		log.Printf("[reader-unify] 补绑六工具失败: %v", err)
	}

	// ① 先去重：reader 名下只保留第一条，删掉多余重复触发行。
	rdr, err := pg.ListTriggersFor("reader")
	if err != nil {
		log.Printf("[reader-unify] 读 reader 触发器失败: %v", err)
		return
	}
	for i := 1; i < len(rdr); i++ {
		if err := pg.DeleteTrigger(rdr[i].ID); err != nil {
			log.Printf("[reader-unify] 删除重复 reader 触发器 %d 失败: %v", rdr[i].ID, err)
		}
	}
	// ② 裁决指定 SQL：observer 的触发行归到 reader 主 key。
	if _, err := pg.Exec(`UPDATE agent_triggers SET agent_key='reader' WHERE agent_key='observer'`); err != nil {
		log.Printf("[reader-unify] 迁移 observer 触发器失败: %v", err)
		return
	}
	// ③ 合并成唯一一条双条件 trigger（补齐消息/开关），删掉其余行。
	all, err := pg.ListTriggersFor("reader")
	if err != nil {
		log.Printf("[reader-unify] 复读 reader 触发器失败: %v", err)
		return
	}
	if len(all) == 0 {
		if _, err := pg.CreateTrigger(unifiedReaderTrigger()); err != nil {
			log.Printf("[reader-unify] 新建双条件触发器失败: %v", err)
		}
		return
	}
	keep := all[0]
	keep.Enabled = true
	keep.OnProjectGraph = true
	keep.IntervalSec = 1800
	// 前缀是双条件 trigger 判别作用域的功能必需：存量行的旧 message 不带前缀，
	// 这里保留用户可能写过的正文、只补前缀（不覆盖用户手改）；全新库已带前缀
	// 则原样保留，收敛本身幂等。
	if !strings.HasPrefix(strings.TrimSpace(keep.ProjectGraphMessage), "【scope=project】") {
		keep.ProjectGraphMessage = unifiedGraphMessage + " " + strings.TrimSpace(keep.ProjectGraphMessage)
	}
	if !strings.HasPrefix(strings.TrimSpace(keep.IntervalMessage), "【scope=cross】") {
		keep.IntervalMessage = unifiedIntervalMessage + " " + strings.TrimSpace(keep.IntervalMessage)
	}
	if err := pg.UpdateTrigger(keep); err != nil {
		log.Printf("[reader-unify] 更新双条件触发器失败: %v", err)
	}
	for _, t := range all[1:] {
		if err := pg.DeleteTrigger(t.ID); err != nil {
			log.Printf("[reader-unify] 删除多余触发器 %d 失败: %v", t.ID, err)
		}
	}
	log.Printf("[reader-unify] 已收敛为 reader 单 agent / 单条双条件触发器")
}

// seedProjectTools 把六工具 SeedTool 入库（首插生效），并跑统一阅读者的
// seed/收敛/升级。由 seedOrchestrationTools 末尾调用——agent 绑定要求工具行
// 先存在（reporter 同款顺序依赖）。绑定不给 auto/planner：跨任务读图+写 hint
// 是阅读者特权，最小暴露面。tool_base='none' 两 key 都保留（只读安全红线）。
func (s *Server) seedProjectTools() {
	emptyBindings, _ := json.Marshal([]string{})
	for _, t := range append(s.projectObserverTools(), s.projectReaderTools()...) {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, emptyBindings); err != nil {
			log.Printf("[project-tools] seed %s: %v", t.Name(), err)
		}
	}
	// V5-A：planner 的洞察否决工具。与 observer/reader 工具不同——它默认【只绑
	// planner】（首插生效：用户日后在工具页取消绑定也不会被重启复活）。旧库首次
	// 启动由这条 SeedTool 补行，随后 ToolResolve 按 agents 过滤，其他 agent 看不到。
	rt := s.toolRejectInsight()
	if schema, err := json.Marshal(rt.InputSchema()); err != nil {
		log.Printf("[project-tools] seed %s schema: %v", rt.Name(), err)
	} else if agents, err := json.Marshal([]string{"planner"}); err != nil {
		log.Printf("[project-tools] seed %s agents: %v", rt.Name(), err)
	} else if err := s.m.PG().SeedTool(rt.Name(), rt.Description(), schema, agents); err != nil {
		log.Printf("[project-tools] seed %s: %v", rt.Name(), err)
	}
	// V6-U3 顺序：先建 reader（全新库）→ 再收敛存量库双链（置 reader_unified_v1）
	// → observer 见 flag 早退 → 最后升级 prompt。
	s.seedReaderAgent()
	s.unifyReaderAgent()
	s.seedObserverAgent()

	// V6-U3：reader prompt 默认正文升级到统一阅读者版。seedReaderAgent 有
	// 一次性 flag 早退，SeedPromptIfEmpty 又是「已有任一版本就 no-op」，所以
	// 存量库里已建好的 reader 永远拿不到新正文——必须每次启动无条件收编
	// （动作本身幂等：逐字节比对旧默认才升级，见 upgradeReaderPrompt）。
	s.upgradeReaderPrompt()

	// V4 安全面：只读总结型 agent 剥离执行底座（tool_base='none'，装配层不再注入
	// DefaultTools，见 agent/chat.go chatBaseTools——reader 触发会话实测 21 次
	// Bash 直连 psql 越权侦查，conv#60 DB 明文密码进活动流）。
	// 刻意放在两 seed 之外、每次启动幂等执行：seed 函数有一次性 flag 早退，存量库
	// 里已建的 observer/reader 行若只写在 seed 内永远收编不到。其余 agent 不写此
	// 列，保持 schema 默认 'default'（worker/planner/mainagent/reporter 底座不变）。
	for _, key := range []string{"observer", "reader"} {
		if err := s.m.pg.SetAgentToolBase(key, "none"); err != nil {
			log.Printf("[project-tools] 设置 %s tool_base 失败: %v", key, err)
		}
	}
}

// readerPromptUpgradeFlag 是「统一阅读者默认正文已收编」的一次性标记
// （V6-U3 新 flag，替代 reader_prompt_asset_first_v4e——旧 flag 对已升级过
// V4-E 的存量库会早退，拿不到统一版正文）。与 seedReaderAgent 的 flag 不同：
// 这条只在真的处理过（播种/升级/确认已编辑）后置位，agent 尚不存在时留空，
// 下次启动再试。
const readerPromptUpgradeFlag = "reader_prompt_unified_v6"

// readerPromptUpgrade 是 upgradeReaderPrompt 的纯判定结果（无库可单测）。
type readerPromptUpgrade int

const (
	// readerPromptKeep：当前正文已被用户编辑——不覆盖。
	readerPromptKeep readerPromptUpgrade = iota
	// readerPromptSeed：当前为空（seed 曾失败）——直接播种新默认。
	readerPromptSeed
	// readerPromptReplace：当前与旧默认逐字节相同（用户没编辑过）——追加新版本。
	readerPromptReplace
)

// readerPromptUpgradeFor 是「能不能升级」的纯判定（V6-U3）：旧默认有两个
// ——readerPromptV1（V4-E 之前）与 readerPrompt（V4-E 资产优先版）。当前与
// 任一逐字节相同＝用户没编辑过，升到 readerUnifiedPrompt；已是统一版或用户
// 手改的正文一律 Keep，不覆盖。
func readerPromptUpgradeFor(cur string) readerPromptUpgrade {
	switch strings.TrimSpace(cur) {
	case "":
		return readerPromptSeed
	case readerPromptV1, readerPrompt:
		return readerPromptReplace
	default:
		return readerPromptKeep
	}
}

// upgradeReaderPrompt 把存量库 reader 的 system prompt 升到统一阅读者版：
//
//   - 当前 prompt 为空（seed 曾失败）→ 播种新默认；
//   - 当前 prompt 与任一旧默认（readerPromptV1 / readerPrompt）逐字节相同
//     ＝用户没编辑过 → 追加一个新版本（SavePrompt 保留历史，可在 UI 回滚）；
//   - 已是统一版或已被用户编辑 → 不覆盖，只记一行日志并置 flag。
//
// 用「逐字节比对旧默认」而不是无条件 ResetPromptToDefault：后者会把用户手写
// 的正文冲掉。这也是不能照搬 SetAgentToolBase「无脑写」的原因——tool_base 是
// 单选列，prompt 是版本历史，无条件写会每重启多一版垃圾版本。
func (s *Server) upgradeReaderPrompt() {
	pg := s.m.pg
	if pg == nil {
		return
	}
	if v, _, _ := pg.GetSetting(readerPromptUpgradeFlag); v == "true" {
		return
	}
	a, err := pg.GetAgentByKey("reader")
	if err != nil || a == nil {
		return // agent 还没建（被用户删掉/seed 未跑）→ 不置 flag，下次再试
	}
	cur, err := pg.CurrentPrompt(a.ID)
	if err != nil {
		log.Printf("[reader] 读取当前 prompt 失败: %v", err)
		return
	}
	switch readerPromptUpgradeFor(cur) {
	case readerPromptSeed:
		if err := pg.SeedPromptIfEmpty(a.ID, readerUnifiedPrompt); err != nil {
			log.Printf("[reader] 播种新默认 prompt 失败: %v", err)
			return
		}
		log.Printf("[reader] 已播种「统一阅读者」默认 prompt")
	case readerPromptReplace:
		if _, err := pg.SavePrompt(a.ID, readerUnifiedPrompt, "V6-U3 默认正文升级：统一阅读者单 agent/单 trigger", "system"); err != nil {
			log.Printf("[reader] 升级默认 prompt 失败: %v", err)
			return
		}
		log.Printf("[reader] 已把未编辑的默认 prompt 升级为「统一阅读者」版（历史版本保留）")
	default:
		log.Printf("[reader] 当前 prompt 已是统一版或被用户编辑，跳过默认正文升级（如需新流程请手动恢复内置默认）")
	}
	if err := pg.SetSetting(readerPromptUpgradeFlag, "true"); err != nil {
		log.Printf("[reader] 写入 prompt 升级标记失败: %v", err)
	}
}
