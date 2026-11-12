package db

import "regexp"

// V4 安全面（纵深防御，层2）：会话活动流落库前对凭据做脱敏。
//
// 背景：observer/reader 等只读型 agent 的触发会话曾出现模型自由裁量用 Bash 直连
// psql 的越权侦查（实网 conv#60），多条 activity 把 PGPASSWORD=<明文密码> 打进
// conversation_activities 并在 UI 可见。层1（agents.tool_base='none' 剥离执行底座）
// 是根治；这里是兜底——即使凭据经任何 agent/任何工具的输出通道回流到活动流
// （summary/detail），落库前也一律打码，对所有 agent 生效。
//
// 只处理文本形态的高置信凭据模式，宁可漏报不可误伤普通侦查输出（漏报还有
// guard/intercept 层拦命令本身）。
var (
	// PGPASSWORD=<value>：值到空白或引号为止（任务书原式）。
	rePgPassword = regexp.MustCompile(`(?i)(PGPASSWORD=)[^\s'"]+`)
	// 引号形态 PGPASSWORD='xxx' / PGPASSWORD="xxx"：引号保留、值打码
	// （RE2 无反向引用，故单/双引号各一条）。
	rePgPasswordSQ = regexp.MustCompile(`(?i)(PGPASSWORD=')[^']*(')`)
	rePgPasswordDQ = regexp.MustCompile(`(?i)(PGPASSWORD=")[^"]*(")`)
	// 连接串内嵌凭据：postgres://user:pass@ / postgresql://user:pass@ ——
	// 只打码 scheme 与 @ 之间的 userinfo，保留 host/path 供审计定位目标库。
	rePgURL = regexp.MustCompile(`(?i)postgres(ql)?://[^\s'"]*:[^\s'"]*@`)
	// HTTP 头里的 Bearer token：Authorization: Bearer <token>（≥20 字符才算
	// 真 token，避免打码 "Bearer 无效" 之类的中文说明文本）。
	reBearer = regexp.MustCompile(`(?i)(Authorization:\s*Bearer\s+)[A-Za-z0-9\-._~+/]{20,}`)
)

// sanitizeActivityText 打码文本中的明文凭据（PGPASSWORD / postgres(ql):// 连接串
// / Bearer token）。空串快路径。summary 与 detail 两个落库列都过它。
func sanitizeActivityText(s string) string {
	if s == "" {
		return s
	}
	s = rePgPassword.ReplaceAllString(s, "${1}***")
	s = rePgPasswordSQ.ReplaceAllString(s, "${1}***${2}")
	s = rePgPasswordDQ.ReplaceAllString(s, "${1}***${2}")
	s = rePgURL.ReplaceAllString(s, "postgres://***:***@")
	s = reBearer.ReplaceAllString(s, "${1}***")
	return s
}
