package guard

// 规则匹配的「执行面」收窄（V12-RULES）。
//
// 三类规则合并成 intercept_rules 一套之后，规则本身只剩正则，但**误报防护
// 不能跟着规则一起删**——这些逻辑不是规则，是「拿哪段文本去匹配」的判定，
// 每一条都是实战踩出来的：
//
//   - recordOnlyTools：record_fact / report_finding 等只写 DB 的工具，正文里
//     如实引用「曾尝试 cat /app/jwt.key」是审计刚需。把正文当命令扫，等于
//     逼 agent 改写证据措辞（任务 #49 实测）。
//   - 文件写入类工具：Write/Edit 的 content/new_string 是**内容**不是命令；
//     只有 file_path/path/command/args 是执行面。不分离的话，写一份报告
//     提到 jwt.key 就被硬拦（id=141 实测）。
//
// 这两条收窄只影响「tool_input 类规则看哪段文本」，不影响 tool_name 规则
// （工具名本身就是判定对象）。

import "encoding/json"

// recordOnlyTools 是纯记录类工具：只写数据库、不落盘、不执行命令。
//
// 它们照样要过 tool_name 规则（该禁的照禁），但 tool_input 规则不扫它们的
// 正文——「记录被拦命令的原文」是审计要求，不是越权尝试。
var recordOnlyTools = map[string]bool{
	"record_fact": true, "report_finding": true, "update_finding_report": true,
	"add_hint": true, "add_task_hint": true, "add_intent": true, "prove_goal": true,
	"goal_met": true, "set_goals": true, "set_constraints": true, "insert_assets": true,
	"bind_finding_traffic": true,
	// 阅读者的提示工具：只写 DB / 只推 hint，不执行、不读盘。
	"push_task_hint": true,
}

// isRecordOnlyTool 返回该工具是否只写 DB（内容不参与 tool_input 规则匹配）。
func isRecordOnlyTool(toolName string) bool { return recordOnlyTools[toolName] }

// platformWriteTools 是【会把正文文本写进文件】的工具名（已核对 norma tool 包：
// files.go 的 Write/Edit、multiedit.go 的 MultiEdit；TodoWrite 写内存，不算）。
var platformWriteTools = map[string]bool{
	"Write":     true,
	"Edit":      true,
	"MultiEdit": true,
}

// platformExecutionFields 是写入类工具里【执行面】的字段白名单：目标路径与
// （少数变体携带的）命令/参数。其余字段一律视为正文。
var platformExecutionFields = map[string]bool{
	"file_path": true,
	"path":      true,
	"command":   true,
	"args":      true,
}

// executionSurfaceInput 返回应当交给 tool_input 规则匹配的字节：
//   - 文件写入类工具 → 仅保留顶层执行面字段，重新序列化成 JSON；正文
//     （content/new_string/old_string/notes/description/edits…）整支丢弃。
//     保留 JSON 对象形态而不是拼纯文本，是为了让 intercept 的 JSON 深解码
//     分支（防 \u002f 转义绕过）照常工作。
//   - 其它工具 → 原样返回。
//
// 非 JSON 对象 / 解析失败 → 退回原始字节（宁可多扫，不可漏判）。
func executionSurfaceInput(toolName string, input []byte) []byte {
	if !platformWriteTools[toolName] {
		return input
	}
	if len(input) == 0 || input[0] != '{' {
		return input
	}
	var m map[string]any
	if err := json.Unmarshal(input, &m); err != nil {
		return input
	}
	exec := make(map[string]any, len(platformExecutionFields))
	for k, v := range m {
		if platformExecutionFields[k] {
			exec[k] = v
		}
	}
	out, err := json.Marshal(exec)
	if err != nil {
		return input
	}
	return out
}
