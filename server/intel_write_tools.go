package server

// 三个「由 agent 主动调用」的登记/检索工具：
//
//	record_credential  发现真实可用凭据时登记（取代从散文/流量里正则猜凭据）
//	set_system_name    确认目标真实系统名时登记（报告封面/文件名用；未知则任务ID）
//	searxng_search     自建 SearXNG 联网检索（无 API 配额，DDG/Bing 等多引擎）
//
// 三者都挂在 hostTools()，再经 tools 表的 per-agent 绑定过滤；工具调用本身
// 会进 activity/tool_use，可审计。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// ---------- record_credential ----------

func (s *Server) toolRecordCredential() actool.CoreTool {
	return wrTool("record_credential",
		"发现【真实可用】的凭据时调用：账号口令、token、Cookie、hash、私钥。只登记你实际验证过或明确可用于登录/复用的凭据；不要把字段名（password/cmd/status）、HTTP 头名（X-Forwarded-Host）、nmap 输出（shown: 65532）当凭据。服务填 host 或 host:port，不要带 scheme/路径。明文只用于计算掩码，任务小结只显示前2后2。",
		objSchema(map[string]any{
			"kind":     map[string]any{"type": "string", "enum": []string{"password", "token", "cookie", "hash", "key"}, "description": "凭据类型"},
			"username": strParam("账号；hash/key 可为空；没有账号就留空"),
			"service":  strParam("归属服务，host 或 host:port（如 10.0.0.5:8080、crm.example.com）"),
			"secret":   strParam("凭据明文/密文原文；只用于计算掩码，不落明文"),
			"where_used": strParam("可选：该凭据可用的接口路径，逗号或换行分隔"),
			"evidence":   strParam("可选：一句话证据（登录成功/返回 200/可复用位置）"),
		}, "kind", "service", "secret"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Kind      string `json:"kind"`
				Username  string `json:"username"`
				Service   string `json:"service"`
				Secret    string `json:"secret"`
				WhereUsed string `json:"where_used"`
				Evidence  string `json:"evidence"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: %v", err), nil
			}
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 {
				return actool.Errorf("当前不在任务上下文中，无法登记凭据"), nil
			}
			t, err := s.m.pg.GetTask(ri.TaskID)
			if err != nil || t == nil {
				return actool.Errorf("任务 %d 不存在", ri.TaskID), nil
			}
			if t.ProjectID == nil || *t.ProjectID <= 0 {
				return actool.Errorf("任务未挂项目，情报表无法写入（先挂项目再登记）"), nil
			}
			kind := strings.ToLower(strings.TrimSpace(a.Kind))
			svc, ok := intelValidService(a.Service)
			if !ok {
				return actool.Errorf("service 必须是 host 或 host:port（不要带 http:// 或路径）: %q", a.Service), nil
			}
			user := strings.TrimSpace(a.Username)
			if user != "" {
				u, ok := intelValidUsername(user)
				if !ok {
					return actool.Errorf("username 不像账号（字段名/头名不算）: %q", user), nil
				}
				user = u
			}
			secret := strings.TrimSpace(a.Secret)
			if secret == "" {
				return actool.Errorf("secret 不能为空"), nil
			}
			if len([]rune(secret)) > 4096 {
				return actool.Errorf("secret 过长（>4096 字符）"), nil
			}
			masked := maskIntelSecret(secret)
			if masked == "" {
				if kind != "key" {
					return actool.Errorf("secret 不像可用凭据（散文/头部碎片不登记）"), nil
				}
				masked = "****"
			}
			key, value := db.NormalizeCredential(kind, user, svc)
			if key == "" {
				return actool.Errorf("kind 必须是 password/token/cookie/hash/key"), nil
			}
			var where []string
			for _, p := range strings.FieldsFunc(a.WhereUsed, func(r rune) bool { return r == ',' || r == '\n' || r == ';' }) {
				if p = strings.TrimSpace(p); p != "" {
					where = append(where, p)
				}
				if len(where) >= 8 {
					break
				}
			}
			detail, _ := json.Marshal(map[string]any{
				"count": 1, "patterns": []string{"tool"}, "secret_masked": masked,
				"where_used": where, "evidence": strings.TrimSpace(a.Evidence),
			})
			res, err := s.m.pg.UpsertTaskIntel(ctx, *t.ProjectID, int64(ri.TaskID), []db.TaskIntel{{
				Kind: db.IntelKindCredential, Key: key,
				MatchKey: db.IntelMatchKey(db.IntelKindCredential, key),
				Value:    value, Detail: detail, Source: "manual",
			}})
			if err != nil {
				return actool.Errorf("写入凭据失败: %v", err), nil
			}
			return actool.Text(fmt.Sprintf("credential recorded: %s（%s，掩码 %s；新增 %d / 更新 %d）",
				key, value, masked, res.Inserted, res.Updated)), nil
		})
}

// ---------- set_system_name ----------

func (s *Server) toolSetSystemName() actool.CoreTool {
	return wrTool("set_system_name",
		"当你在测试中【确认】了目标的真实系统名称（登录页标题、产品名、版权页、首页大标题）时调用，登记后报告封面/文件名使用它。禁止用域名、IP、端口、任务描述、页面 URL 当系统名；不确定就不要调用，报告会自动回退「任务ID」。同一任务重复调用以最后一次为准。",
		objSchema(map[string]any{
			"name":     strParam("系统名称，如「经销商门户」「XX考试系统」，2-40 字"),
			"evidence": strParam("可选：在哪里确认的（页面标题/版权/登录框文案）"),
		}, "name"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: %v", err), nil
			}
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 {
				return actool.Errorf("当前不在任务上下文中"), nil
			}
			name := strings.TrimSpace(a.Name)
			if len([]rune(name)) < 2 {
				return actool.Errorf("系统名至少 2 个字"), nil
			}
			if !isUsableSystemName(name) {
				return actool.Errorf("不像系统名（域名/IP/默认任务描述/过长文本都不行）: %q", name), nil
			}
			lower := strings.ToLower(name)
			if lower == "unknown" || name == "未知" || name == "未知系统" || name == "目标系统" {
				return actool.Errorf("不确定就不要登记；报告会用任务 ID"), nil
			}
			if _, err := s.m.pg.SetTaskSystemName(ri.TaskID, name); err != nil {
				return actool.Errorf("写入失败: %v", err), nil
			}
			return actool.Text(fmt.Sprintf("system name recorded: %s (task#%d)", name, ri.TaskID)), nil
		})
}

// ---------- searxng_search ----------

type searxngResult struct {
	Title         string `json:"title"`
	URL           string `json:"url"`
	Content       string `json:"content"`
	Engine        string `json:"engine"`
	PublishedDate string `json:"publishedDate"`
}

type searxngResponse struct {
	Results             []searxngResult `json:"results"`
	UnresponsiveEngines [][]string      `json:"unresponsive_engines"`
}

func (s *Server) toolSearxngSearch() actool.CoreTool {
	return wrTool("searxng_search",
		"联网检索（自建 SearXNG，聚合 DuckDuckGo/Bing 等，无 API 配额）。用于查 CVE/组件漏洞/PoC/绕过技巧/产品默认口令。返回标题、URL、摘要和来源引擎；结论必须再打开原文核对，不要把摘要当事实。",
		objSchema(map[string]any{
			"query": strParam("检索词；漏洞场景建议带组件名+版本+CVE/关键词"),
			"limit": map[string]any{"type": "integer", "description": "返回条数 1-10，默认 6"},
		}, "query"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Query string `json:"query"`
				Limit int    `json:"limit"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: %v", err), nil
			}
			q := strings.TrimSpace(a.Query)
			if q == "" {
				return actool.Errorf("query 不能为空"), nil
			}
			if a.Limit <= 0 || a.Limit > 10 {
				a.Limit = 6
			}
			base := strings.TrimSpace(settingString(s.m.pg, "searxng_url"))
			if base == "" {
				base = "http://127.0.0.1:18080"
			}
			base = strings.TrimRight(base, "/")
			u := base + "/search?" + url.Values{
				"q": {q}, "format": {"json"}, "language": {"zh-CN"}, "safesearch": {"0"},
			}.Encode()
			reqCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
			if err != nil {
				return actool.Errorf("构造搜索请求失败: %v", err), nil
			}
			// 只连本机 SearXNG，不走环境代理（SearXNG 自己配置出口代理）。
			client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 25 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				return actool.Errorf("SearXNG 请求失败（%s）: %v", base, err), nil
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
			if resp.StatusCode != http.StatusOK {
				return actool.Errorf("SearXNG 返回 HTTP %d: %s", resp.StatusCode, clipText(string(body), 200)), nil
			}
			var sr searxngResponse
			if err := json.Unmarshal(body, &sr); err != nil {
				return actool.Errorf("SearXNG 返回不是 JSON: %v", err), nil
			}
			if len(sr.Results) == 0 {
				return actool.Text("没有检索结果（上游引擎可能限流，换个关键词或稍后重试）"), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "SearXNG 检索「%s」，%d 条：\n", q, min(len(sr.Results), a.Limit))
			for i, r := range sr.Results {
				if i >= a.Limit {
					break
				}
				fmt.Fprintf(&b, "\n%d. %s\n   %s\n", i+1, clipText(r.Title, 160), r.URL)
				if c := clipText(r.Content, 320); c != "" {
					fmt.Fprintf(&b, "   %s\n", c)
				}
				meta := r.Engine
				if r.PublishedDate != "" {
					meta += " · " + clipText(r.PublishedDate, 32)
				}
				if meta != "" {
					fmt.Fprintf(&b, "   [%s]\n", meta)
				}
			}
			if len(sr.UnresponsiveEngines) > 0 {
				fmt.Fprintf(&b, "\n（%d 个引擎本轮无响应，不影响以上结果）", len(sr.UnresponsiveEngines))
			}
			return actool.Text(b.String()), nil
		})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// seedIntelWriteTools 把三个 host 工具注册进 tools 表（首次插入；之后页面可改）。
// 未绑定到某 agent 时 ToolResolve 会丢弃该工具，所以这里按角色给最小集合。
func (s *Server) seedIntelWriteTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	seed := func(t actool.CoreTool, agents []string) {
		schema, _ := json.Marshal(t.InputSchema())
		list, _ := json.Marshal(agents)
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, list); err != nil {
			log.Printf("[tools] seed %s 失败: %v", t.Name(), err)
		}
	}
	seed(s.toolRecordCredential(), []string{"worker", "mainagent", "pentest", "auto"})
	seed(s.toolSetSystemName(), []string{"worker", "planner", "mainagent", "pentest", "auto"})
	seed(s.toolSearxngSearch(), []string{"worker", "planner", "mainagent", "pentest", "auto", "retester"})
}
