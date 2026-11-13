package intercept

import (
	"strings"
	"time"
)

// ============================================================================
// V5-B2：白名单外工具的「判官面」收敛。
//
// V5-B 把所有不在 intercept_enabled_tools 里的工具都送判官，本意是覆盖 MCP /
// 自定义工具，但连平台自带的 57 个内置工具（record_fact / graph_overview /
// list_tasks …）也一起送进去了 —— planner 每轮、worker 每条事实都要多付一次
// 判官调用（约 2-3k token + 1-3s），而它们既不能执行代码也不能影响外部系统，
// 判官对它们没有任何可拦的面。
//
// 这里是「送不送判官」的分类面：只有能执行代码 / 影响外部系统的工具才回 true。
// ============================================================================

// externalToolTTLCache 的分类结论 TTL。
//
// 分类来自 tools 表的一行（自定义工具的 kind 可在页面上改），60 秒足够让改动
// 生效，又不必每次工具调用都查库。Invalidate 会一并清空。
const externalToolTTL = 60 * time.Second

type externalToolVerdict struct {
	external bool
	expireAt time.Time
}

// toolKindExternal 把 tools.kind 映射为「是否必须送判官」（纯函数，无库可测）。
//
//   - builtin / 空：平台内置工具，不执行代码也不触外部系统 → 不判。
//   - command / script / http：自定义工具，会起进程或发请求 → 判。
//   - 其他未知 kind：按外部处理（fail-safe，宁可多判一次）。
func toolKindExternal(kind string) bool {
	switch kind {
	case "", "builtin":
		return false
	case "command", "script", "http":
		return true
	default:
		return true
	}
}

// IsToolExternal 报告一次工具调用是否必须送判官（即「白名单外」里真正需要
// 模型审查的那部分）。
//
//   - mcp__ 前缀：MCP 工具一律送判（它们不登记在 tools 表里，也能触外部系统）。
//   - tools 表有行：按 kind 分类（builtin → 不判；command/script/http → 判）。
//   - tools 表无行：未知工具名，fail-safe 送判。
//   - 查库失败 / 无库：同样 fail-safe 送判 —— 分类不明时不能替模型放行。
//
// 结果缓存 60 秒（见 externalToolTTL），Invalidate 时清空。
func (i *Interceptor) IsToolExternal(name string) bool {
	if name == "" {
		// 无工具名的调用判官无从审查，交给 shouldJudgeBeyondWhitelist 拦掉，
		// 这里不必查库、也不该被判为外部工具。
		return false
	}
	if i == nil || i.db == nil {
		return true
	}
	if strings.HasPrefix(name, "mcp__") {
		return true
	}

	now := time.Now()
	i.mu.RLock()
	if v, ok := i.externalTools[name]; ok && now.Before(v.expireAt) {
		external := v.external
		i.mu.RUnlock()
		return external
	}
	i.mu.RUnlock()

	i.mu.Lock()
	defer i.mu.Unlock()
	if v, ok := i.externalTools[name]; ok && now.Before(v.expireAt) {
		return v.external
	}
	external := i.lookupToolExternalLocked(name)
	if i.externalTools == nil {
		i.externalTools = map[string]externalToolVerdict{}
	}
	i.externalTools[name] = externalToolVerdict{external: external, expireAt: now.Add(externalToolTTL)}
	return external
}

// lookupToolExternalLocked 查 tools 表并分类。调用方须持有 i.mu 写锁。
func (i *Interceptor) lookupToolExternalLocked(name string) bool {
	t, err := i.db.GetTool(name)
	if err != nil || t == nil {
		return true // 查库失败或未登记：fail-safe 送判
	}
	return toolKindExternal(t.Kind)
}
