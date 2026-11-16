package guard

// V9-UI 内置规则目录：供管理页「内置规则（代码内置，不可编辑）」只读展示。
//
// 这些规则硬编码在 guard 包里，不进 DB 规则表、不受 /api/settings 热改、也
// 没有运行期开关——持 JWT 的人能删掉 DB 规则，但删不掉这里的任何一条。
// 名称必须与进审计链的 RuleName 完全一致，页面上的条目才能和历史命中来源对上；
// 判定处一律引用下面的常量，避免「目录」与「实际判定」两处漂移。
//
// 新增内置规则时：先在这里登记 + 定义名称常量，再在判定处引用常量。

// 内置规则的审计链名称（[代码常量]/[代码内置] 前缀是 db.interceptSource 的
// 跨包约定标记，勿改）。
const (
	builtinControlPlaneRuleName = "[代码常量] 平台控制面 API"
	builtinPlatformCredRuleName = "[代码常量] 平台凭据/进程环境"
	builtinHostCredRuleName = "[代码常量] 本机系统凭据裸读"
	builtinMCPRegisterRuleName = "[代码常量] MCP 注册属凭据汇"
	builtinDeleteAssetsRuleName = "[代码常量] 删除业务资产属破坏性操作"
	builtinForeignScopeRuleName = "[代码内置] 外部任务资产范围"
	builtinFailClosedRuleName = "[代码常量] 短路规则配置非法（fail-closed）"
	builtinAskBurstRuleName = "[代码常量] 审批请求超阈值（同一 agent 重复请求）"
)

// BuiltinRule 是一条代码内置规则的元数据（只读展示用）。
// Action 目前恒为 deny：这里只收录「无人工放行路径」的硬拦项。
type BuiltinRule struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Action      string `json:"action"`
}

// BuiltinRules 返回内置规则目录（固定顺序，先数据面后平台面）。
//
// 只收录真正的红线；ask/allow 档由配置文件短路口径决定，不在此列。
func BuiltinRules() []BuiltinRule {
	return []BuiltinRule{
		{
			Key:   "foreign_task_assets",
			Name:  builtinForeignScopeRuleName,
			Description: "阅读者采纳后，对方任务的资产地址不属于本任务授权范围，命中即拒绝，" +
				"提示先在本任务登记资产再由人工确认。",
			Action: "deny",
		},
		{
			Key:         "platform_control_plane",
			Name:        builtinControlPlaneRuleName,
			Description: "对平台自身监听地址（127.0.0.1/localhost/<实际端口>）发起的管理接口请求一律拒绝，防止 agent 借 JWT 关掉规则。",
			Action:      "deny",
		},
		{
			Key:         "platform_credentials",
			Name:        builtinPlatformCredRuleName,
			Description: "读取平台凭据与密钥文件（jwt.key、.env、短路配置、MITM CA 等）一律拒绝，含运行时 dataDir 绝对路径与变形写法。",
			Action:      "deny",
		},
		{
			Key:         "host_system_credentials",
			Name:        builtinHostCredRuleName,
			Description: "以裸本地路径读取运行平台主机的系统凭据（/etc/shadow、/etc/sudoers、主机私钥）拒绝；对靶机的同类读取走 ssh 等远程指代，不受影响。",
			Action:      "deny",
		},
		{
			Key:         "mcp_registration",
			Name:        builtinMCPRegisterRuleName,
			Description: "运行期注册 MCP 会被当成凭据汇（可把任意命令注入执行面），一律拒绝，MCP 只能由管理员在配置里登记。",
			Action:      "deny",
		},
		{
			Key:         "delete_business_assets",
			Name:        builtinDeleteAssetsRuleName,
			Description: "删除业务资产属不可逆破坏性操作，一律拒绝，需人工在资产页处理。",
			Action:      "deny",
		},
	}
}
