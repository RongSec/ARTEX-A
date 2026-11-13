package guard

import "github.com/Autumn-27/artex/intercept"

// PreviewShortCircuit 是 shortCircuit 的只读导出，供
// POST /api/intercept/judge/test（试判）复用同一份红线判定。
//
// 只读语义由实现保证：shortCircuit 全部是正则/查表求值，不写库、不记审计、
// 不改任何状态（见 shortcircuit.go 的 shortCircuit 注释）。试判端点靠这条
// 导出与线上真实路径共用一份规则，避免"评估工具与生产线漂移"。
//
// 返回值与线上语义一致：nil 表示未命中；非 nil 时 Action ∈ allow|ask|deny，
// 调用方不应再跑 DB 规则（短路表在真实路径上是终局）。
func PreviewShortCircuit(toolName string, input []byte) *intercept.Decision {
	return shortCircuit(toolName, input)
}
