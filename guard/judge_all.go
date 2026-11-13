package guard

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/Autumn-27/artex/intercept"
)

// 判官结论缓存参数（白名单外工具专用，见 guard.judgeOutsideWhitelist）。
//
// 白名单外是 MCP / 自定义工具：它们的调用量远高于内置的 8 个工具，而输入
// 大多高度重复（同一次会话里同样的 list_files / read_file 参数会被反复调用）。
// 不缓存等于把「每工具调判官」的成本直接乘上调用次数。
const (
	judgeVerdictTTL      = 5 * time.Minute
	judgeVerdictCacheCap = 500
)

// shouldJudgeBeyondWhitelist 是白名单外分支的总闸（纯函数，无库可测）。
//
//   - enabled=false：管理员关了 intercept_judge_all_tools，退回改动前的语义
//     ——白名单外直接放行（省 token 的唯一开关）。此分支不查分类器。
//   - tool==""：事件不带工具名，判官无从审查，不送（避免一串空名判官调用）。
//   - external()==false：工具是平台内置（kind=builtin），既不执行代码也不触
//     外部系统，判官没有可拦的面 —— 送判纯属成本（V5-B2）。
//   - 其余：送判官。
//
// external 传函数而不是布尔值，是为了在前两个分支短路时完全不查库。
func shouldJudgeBeyondWhitelist(enabled bool, tool string, external func() bool) bool {
	if !enabled || tool == "" {
		return false
	}
	return external()
}

// toolIsExternal 报告某个工具是否必须送判官。
//
// 生产接线是 interceptor.IsToolExternal（查 tools 表按 kind 分类）；probe 字段
// 只用于让「内置不判 / MCP 判 / 未知判 / 自定义判」这组路由矩阵能在无库环境里
// 用假分类器钉住（见 judge_scope_test.go）。无 interceptor 时按外部处理：
// 没有分类信息就 fail-safe 送判。
func (g *Guard) toolIsExternal(name string) bool {
	if g.externalProbe != nil {
		return g.externalProbe(name)
	}
	if g.interceptor == nil {
		return true
	}
	return g.interceptor.IsToolExternal(name)
}

// cacheableJudgeVerdict 只缓存模型给出的确定性 allow/deny。
//
// 不缓存 ask：一条 ask 缓存下来会在 TTL 内反复复用同一份「等人工」语义，
// 而人工审批是即时交互，缓存没有收益。不缓存 ModelFallback：那是判官故障/
// 超时后按 fail_action 生成的兜底结论，把它缓存 5 分钟等于让一次瞬时故障
// 变成持续拦截/放行。
func cacheableJudgeVerdict(dec intercept.Decision) bool {
	return !dec.ModelFallback && (dec.Action == "allow" || dec.Action == "deny")
}

// judgeCacheKey 把一次调用折成缓存键：会话分区 + 工具名 + 输入摘要。
//
// 会话分区保证「同一次会话内复用」而不是跨会话复用：不同任务的上下文不同，
// 判官结论不该互相串用。同一会话里 (tool, sha256(input)) 相同即视为同一次
// 调用（判官输入契约本身也只含当前调用，不含历史，见 intercept.ReviewInput）。
func judgeCacheKey(ctx context.Context, tool string, input []byte) string {
	sum := sha256.Sum256(input)
	return intercept.SessionScope(ctx) + "\x00" + tool + "\x00" + hex.EncodeToString(sum[:])
}

// judgeFunc 是判官入口（生产上传 interceptor.Judge）。抽成参数是为了让白名单
// 外路由能在没有数据库的环境里用假判官验证：白名单外必送判官、开关 false
// 必不送、缓存命中不重复调模型。
type judgeFunc func(ctx context.Context, tool string, input json.RawMessage) (intercept.Decision, bool)

type judgeVerdict struct {
	dec      intercept.Decision
	expireAt time.Time
}

type judgeVerdictEntry struct {
	key string
	v   judgeVerdict
}

// judgeVerdictCache 是带 TTL 的 LRU：cap 上限 + 5 分钟过期。
//
// clock 注入（而非直接 time.Now）让过期/LRU 能在测试里确定性验证，不必 sleep。
type judgeVerdictCache struct {
	mu    sync.Mutex
	now   func() time.Time
	ttl   time.Duration
	limit int
	order *list.List // front = 最近使用
	items map[string]*list.Element
}

func newJudgeVerdictCache(now func() time.Time, ttl time.Duration, limit int) *judgeVerdictCache {
	if now == nil {
		now = time.Now
	}
	return &judgeVerdictCache{
		now:   now,
		ttl:   ttl,
		limit: limit,
		order: list.New(),
		items: map[string]*list.Element{},
	}
}

func (c *judgeVerdictCache) get(key string) (intercept.Decision, bool) {
	if c == nil {
		return intercept.Decision{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return intercept.Decision{}, false
	}
	entry := el.Value.(*judgeVerdictEntry)
	if !c.now().Before(entry.v.expireAt) {
		c.order.Remove(el)
		delete(c.items, key)
		return intercept.Decision{}, false
	}
	c.order.MoveToFront(el)
	return entry.v.dec, true
}

func (c *judgeVerdictCache) put(key string, dec intercept.Decision) {
	if c == nil || c.limit <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	expireAt := c.now().Add(c.ttl)
	if el, ok := c.items[key]; ok {
		entry := el.Value.(*judgeVerdictEntry)
		entry.v = judgeVerdict{dec: dec, expireAt: expireAt}
		c.order.MoveToFront(el)
		return
	}
	el := c.order.PushFront(&judgeVerdictEntry{key: key, v: judgeVerdict{dec: dec, expireAt: expireAt}})
	c.items[key] = el
	for c.order.Len() > c.limit {
		back := c.order.Back()
		if back == nil {
			break
		}
		c.order.Remove(back)
		delete(c.items, back.Value.(*judgeVerdictEntry).key)
	}
}

// len 供测试断言容量上限（LRU 淘汰）。
func (c *judgeVerdictCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
