package report

// Reproduction 是 report_finding 的结构化复现过程（artex-hs T14，架构 §4.1/§4.2）。
// agent 侧按【真实执行原文】填写：request/response 逐字取自实际发出的请求与
// 收到的响应（禁省略号/禁改写），这份复现过程直接决定 T16 的 docx 报告能否被
// 人工从零复现。ExchangeID 由落库时（T14(2/2) 的 reproResolver）按任务时间窗
// 自动关联流量回填（宁缺毋滥：多义/零命中留空，view-time 再兜底解析），也是
// T16 证据图穿插（step_index）的挂点。
type Reproduction struct {
	EntryPoint    string      `json:"entry_point"`    // 触发漏洞的关键接口（方法+URL）
	Prerequisites []string    `json:"prerequisites"`  // 前置：账号/角色/前序步骤（测试账号写清如何注册）
	Steps         []ReproStep `json:"steps"`          // 有序复现步骤
	Provenance    string      `json:"provenance"`     // 攻击链来源/依赖
}

// ReproStep 是一步复现：逐字请求 + 逐字响应 + 预期 + 证明了什么。
type ReproStep struct {
	Request    string `json:"request"`
	Response   string `json:"response"`
	Expected   string `json:"expected"`
	Proves     string `json:"proves"`
	ExchangeID string `json:"exchange_id,omitempty"` // 自动关联的真实流量 id；空=未关联
}
