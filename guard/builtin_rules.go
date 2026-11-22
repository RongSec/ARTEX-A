package guard

// 仍留在代码里的判定项（V12-RULES 后只剩两条）。
//
// 三类规则（内置 / 短路 / DB）合并成 intercept_rules 一套之后，原来在这里
// 登记的「平台凭据 / 控制面 API / 本机凭据 / MCP 注册 / 删除资产」全部变成
// DB 规则行（见 db.seedDefaultInterceptRulesV5），页面可看可改可停用。
//
// 只有两项没法变成正则，继续硬编码：
//   - 外部任务资产范围：判定依赖「本任务授权了哪些资产」的任务上下文，
//     不是对命令文本做模式匹配；
//   - 审批防疲劳：ask 通道的限流保护，不是一条拦截规则。
//
// 名称必须与进审计链的 RuleName 完全一致（[代码常量]/[代码内置] 前缀是
// db.interceptSource 的跨包约定标记，勿改），页面上的条目才能和历史命中对上。

// 内置规则的审计链名称（[代码常量]/[代码内置] 前缀是 db.interceptSource 的
// 跨包约定标记，勿改）。
const (
	// 仍然留在代码里的两条：一条是「外部任务资产范围」（adopt 的安全边界，
	// 依赖任务上下文，无法表达成一条正则），一条是审批防疲劳（不是规则，
	// 是 ask 通道的保护）。
	builtinForeignScopeRuleName = "[代码内置] 外部任务资产范围"
	builtinAskBurstRuleName     = "[代码常量] 审批请求超阈值（同一 agent 重复请求）"
)


// BuiltinRule 是一条代码内置规则的元数据（只读展示用）。
// Action 目前恒为 deny：这里只收录「无人工放行路径」的硬拦项。
type BuiltinRule struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Action      string `json:"action"`
}

// BuiltinRules 返回仍由代码持有的判定项目录（只读展示，供管理页和历史
// 命中来源对照）。规则类红线已经全部落到 intercept_rules，这里只剩一条。
func BuiltinRules() []BuiltinRule {
	return []BuiltinRule{
		{
			Key:   "foreign_task_assets",
			Name:  builtinForeignScopeRuleName,
			Description: "阅读者采纳后，对方任务的资产地址不属于本任务授权范围，命中即拒绝，" +
				"提示先在本任务登记资产再由人工确认。",
			Action: "deny",
		},
	}
}
