// Package vulnintel 是漏洞情报同步：从公开源拉 CVE 条目入库，供资产指纹反查。
//
// 数据来源三个，都是互联网公开数据，没有任何私有仓库：
//   - NVD API 2.0（NIST，公开 REST，无 key 时限速 5 次/30s）
//   - CISA KEV（已知在野利用目录，单个 JSON）
//   - GitHub 公开搜索（按 CVE 编号匹配仓库名/描述，只存元数据，见 github.go）
//
// PoC 线索只保留仓库的元数据（repo / URL / star / 描述），平台不克隆、不执行、
// 不托管任何 PoC 代码；refs 里只保留 NVD 自己给出的参考 URL。
package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/artex/db"
	xproxy "golang.org/x/net/proxy"
)

const (
	settingLastKEV = "vulnintel.last_kev_sync"
	settingLastNVD = "vulnintel.last_nvd_sync"
	settingEnable  = "vulnintel.enabled"
	settingNVDKey  = "vulnintel.nvd_api_key"

	nvdEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	kevEndpoint = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// 无 key 时 NVD 限速 5 次/30 秒 = 每 6 秒一次；有 key 是 50 次/30 秒。
	nvdPageSize      = 2000
	nvdNoKeyInterval = 6 * time.Second
	nvdKeyInterval   = 700 * time.Millisecond
	nvdMaxWindowDays = 100 // NVD 单次查询窗口上限 120 天，留余量

	syncInterval = 30 * time.Minute
)

// Service 负责同步与状态查询。并发由 mu 串行化：同步是重 IO + 批量写库，
// 两轮重叠只会互相抢 NVD 配额。
type Service struct {
	pg     *db.DB
	client atomic.Pointer[http.Client]

	mu      sync.Mutex
	running string // "" | kev | nvd | full
	lastErr string
	lastRun time.Time
}

func New(pg *db.DB) *Service {
	s := &Service{pg: pg}
	c, err := intelHTTPClient("")
	if err != nil {
		c = &http.Client{Timeout: 90 * time.Second}
	}
	s.client.Store(c)
	return s
}

// httpClient 返回当前生效的抓取客户端（SetProxy 可热替换，无需重启服务）。
func (s *Service) httpClient() *http.Client {
	if c := s.client.Load(); c != nil {
		return c
	}
	return &http.Client{Timeout: 90 * time.Second}
}

// SetProxy 设置检索类出网代理（http/https/socks5），空字符串=直连。
// 只影响 NVD / CISA / GitHub 这些公开源抓取，不影响渗透测试流量。
func (s *Service) SetProxy(raw string) error {
	c, err := intelHTTPClient(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	s.client.Store(c)
	return nil
}

// intelHTTPClient 按代理串构造客户端。socks5 走 x/net/proxy 的拨号器，
// http/https 走 Transport.Proxy；空串=直连。
func intelHTTPClient(raw string) (*http.Client, error) {
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	tr := &http.Transport{DialContext: dialer.DialContext}
	client := &http.Client{Timeout: 90 * time.Second, Transport: tr}
	if raw == "" {
		return client, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("代理地址无效: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		tr.Proxy = http.ProxyURL(u)
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if u.User != nil {
			pass, _ := u.User.Password()
			auth = &xproxy.Auth{User: u.User.Username(), Password: pass}
		}
		d, err := xproxy.SOCKS5("tcp", u.Host, auth, dialer)
		if err != nil {
			return nil, fmt.Errorf("socks5 代理初始化失败: %w", err)
		}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.Dial(network, addr)
		}
	default:
		return nil, fmt.Errorf("不支持的代理协议 %q（支持 http/https/socks5）", u.Scheme)
	}
	return client, nil
}

// Start 起后台循环：首次延迟 30 秒（让服务先对外可用），之后每 30 分钟一轮快通道。
// 快通道 = KEV 全量（很小）+ NVD 最近 2 天增量。历史回填由用户点「全量同步」触发，
// 不在后台偷偷跑——首次启动就拉 400MB 会让磁盘和 NVD 配额都很难看。
func (s *Service) Start(ctx context.Context) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
		s.fastLane(ctx)
		t := time.NewTicker(syncInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.fastLane(ctx)
			}
		}
	}()
}

func (s *Service) fastLane(ctx context.Context) {
	if !s.enabled() {
		return
	}
	if _, err := s.SyncKEV(ctx); err != nil {
		log.Printf("[vulnintel] KEV 同步失败: %v", err)
	}
	since := time.Now().Add(-48 * time.Hour)
	if _, err := s.SyncNVD(ctx, since, time.Now()); err != nil {
		log.Printf("[vulnintel] NVD 增量同步失败: %v", err)
	}
	// PoC 聚合搭同一班车：每 30 分钟补一小批（认证 25 / 匿名 8），
	// 队列是「KEV 或 CVSS≥9 且没查过」，几千条靠日积月累而不是一次打爆配额。
	if n, added, err := s.SyncPoc(ctx, 0); err != nil {
		log.Printf("[vulnintel] PoC 聚合失败: %v", err)
	} else if n > 0 {
		log.Printf("[vulnintel] PoC 聚合：查了 %d 个 CVE，命中 %d 条线索", n, added)
	}
}

func (s *Service) enabled() bool {
	v, ok, err := s.pg.GetSetting(settingEnable)
	if err != nil || !ok {
		return true // 默认开：只读公开数据，没有副作用
	}
	return v != "false"
}

func (s *Service) nvdKey() string {
	v, _, _ := s.pg.GetSetting(settingNVDKey)
	return strings.TrimSpace(v)
}

func (s *Service) nvdInterval() time.Duration {
	if s.nvdKey() != "" {
		return nvdKeyInterval
	}
	return nvdNoKeyInterval
}

// Status 是前端状态卡与 API 的统一出口。
func (s *Service) Status(ctx context.Context) map[string]any {
	stats, err := s.pg.VulnIntelStats(ctx)
	if err != nil {
		stats = db.VulnIntelStats{}
	}
	kevAt, _, _ := s.pg.GetSetting(settingLastKEV)
	nvdAt, _, _ := s.pg.GetSetting(settingLastNVD)
	pocStats, err := s.pg.VulnPocStats(ctx)
	if err != nil {
		pocStats = db.VulnPocStats{}
	}
	s.mu.Lock()
	running, lastErr, lastRun := s.running, s.lastErr, s.lastRun
	s.mu.Unlock()
	return map[string]any{
		"stats":         stats,
		"poc":           pocStats,
		"github":        s.GitHubConfig(),
		"last_kev_sync": kevAt,
		"last_nvd_sync": nvdAt,
		"running":       running,
		"last_error":    lastErr,
		"last_run":      lastRun.Format(time.RFC3339),
		"enabled":       s.enabled(),
		"sources": []map[string]string{
			{"key": "nvd", "name": "NVD API 2.0", "url": nvdEndpoint, "note": "全量 CVE（含 CVSS / CPE / 参考链接）"},
			{"key": "kev", "name": "CISA KEV", "url": kevEndpoint, "note": "已知在野利用目录，含修复截止日"},
			{"key": "github", "name": "GitHub 公开搜索", "url": githubSearchAPI, "note": "按 CVE 编号匹配仓库名/描述，只存元数据不存代码"},
		},
	}
}

func (s *Service) begin(mode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running != "" {
		return fmt.Errorf("已有同步在进行（%s）", s.running)
	}
	s.running = mode
	s.lastErr = ""
	return nil
}

func (s *Service) finish(mode string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running == mode {
		s.running = ""
	}
	s.lastRun = time.Now()
	if err != nil {
		s.lastErr = err.Error()
	}
}

// SyncKEV 拉 CISA KEV 全量（约 1800 条，单个 JSON）。
func (s *Service) SyncKEV(ctx context.Context) (int, error) {
	if err := s.begin("kev"); err != nil {
		return 0, err
	}
	n, err := s.syncKEV(ctx)
	s.finish("kev", err)
	if err == nil {
		_ = s.pg.SetSetting(settingLastKEV, time.Now().Format(time.RFC3339))
	}
	return n, err
}

func (s *Service) syncKEV(ctx context.Context) (int, error) {
	var payload struct {
		Vulnerabilities []struct {
			CVEID          string `json:"cveID"`
			VendorProject  string `json:"vendorProject"`
			Product        string `json:"product"`
			Name           string `json:"vulnerabilityName"`
			Description    string `json:"shortDescription"`
			DateAdded      string `json:"dateAdded"`
			DueDate        string `json:"dueDate"`
			RansomwareUse  string `json:"knownRansomwareCampaignUse"`
			RequiredAction string `json:"requiredAction"`
		} `json:"vulnerabilities"`
	}
	if err := s.getJSON(ctx, kevEndpoint, &payload); err != nil {
		return 0, err
	}
	entries := make([]db.VulnIntelEntry, 0, len(payload.Vulnerabilities))
	for _, v := range payload.Vulnerabilities {
		if strings.TrimSpace(v.CVEID) == "" {
			continue
		}
		cpe := ""
		if v.VendorProject != "" && v.Product != "" {
			cpe = normalizeCPE(v.VendorProject) + ":" + normalizeCPE(v.Product)
		}
		e := db.VulnIntelEntry{
			CVEID:       strings.TrimSpace(v.CVEID),
			Source:      "kev",
			Title:       strings.TrimSpace(v.Name),
			Description: strings.TrimSpace(v.Description),
			Severity:    "HIGH", // KEV 不区分等级；保留 HIGH 以免被 CVSS 过滤漏掉
			KEV:         true,
			KEVDue:      strings.TrimSpace(v.DueDate),
			Ransomware:  strings.EqualFold(strings.TrimSpace(v.RansomwareUse), "Known"),
		}
		if cpe != "" {
			e.CPE = []string{cpe}
		}
		if t, err := time.Parse("2006-01-02", strings.TrimSpace(v.DateAdded)); err == nil {
			e.PublishedAt = t
		}
		entries = append(entries, e)
	}
	return s.pg.UpsertVulnIntel(ctx, entries)
}

// SyncNVD 拉 [since, until] 窗口内的 CVE。窗口超过 100 天会自动切段。
func (s *Service) SyncNVD(ctx context.Context, since, until time.Time) (int, error) {
	if err := s.begin("nvd"); err != nil {
		return 0, err
	}
	n, err := s.syncNVD(ctx, since, until)
	s.finish("nvd", err)
	if err == nil {
		_ = s.pg.SetSetting(settingLastNVD, time.Now().Format(time.RFC3339))
	}
	return n, err
}

// Backfill 是「全量同步」入口：按天切窗回填最近 days 天。
func (s *Service) Backfill(ctx context.Context, days int) (int, error) {
	if days <= 0 {
		days = 120
	}
	if days > 365 {
		days = 365
	}
	if err := s.begin("full"); err != nil {
		return 0, err
	}
	total := 0
	var err error
	until := time.Now()
	since := until.AddDate(0, 0, -days)
	for since.Before(until) {
		step := since.AddDate(0, 0, nvdMaxWindowDays)
		if step.After(until) {
			step = until
		}
		var n int
		n, err = s.syncNVD(ctx, since, step)
		if err != nil {
			break
		}
		total += n
		log.Printf("[vulnintel] NVD 回填 %s → %s：%d 条", since.Format("2006-01-02"), step.Format("2006-01-02"), n)
		since = step
	}
	if err == nil {
		_ = s.pg.SetSetting(settingLastNVD, time.Now().Format(time.RFC3339))
	}
	s.finish("full", err)
	return total, err
}

func (s *Service) syncNVD(ctx context.Context, since, until time.Time) (int, error) {
	total := 0
	start := 0
	for {
		url := fmt.Sprintf("%s?pubStartDate=%s&pubEndDate=%s&resultsPerPage=%d&startIndex=%d&noRejected",
			nvdEndpoint,
			since.UTC().Format("2006-01-02T15:04:05.000Z"),
			until.UTC().Format("2006-01-02T15:04:05.000Z"),
			nvdPageSize, start)
		var payload nvdResponse
		if err := s.getJSONWithKey(ctx, url, &payload); err != nil {
			return total, err
		}
		entries := payload.toEntries()
		if len(entries) > 0 {
			if _, err := s.pg.UpsertVulnIntel(ctx, entries); err != nil {
				return total, err
			}
			total += len(entries)
		}
		start += len(payload.Vulnerabilities)
		if start >= payload.TotalResults || len(payload.Vulnerabilities) == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(s.nvdInterval()):
		}
	}
	return total, nil
}

// ---- NVD 响应结构（只取用得到的字段） ----

type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			VulnStatus   string `json:"vulnStatus"`
			// NVD 2.0 会为 CISA KEV 条目回填这几个字段：即使 CISA 全量源拉不动，
			// NVD 同步也能把「在野利用」标出来。
			CisaExploitAdd   string `json:"cisaExploitAdd"`
			CisaActionDue    string `json:"cisaActionDue"`
			CisaRequiredAct  string `json:"cisaRequiredAction"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				V31 []nvdMetric `json:"cvssMetricV31"`
				V40 []nvdMetric `json:"cvssMetricV40"`
				V2  []nvdMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
			Configurations []struct {
				Nodes []nvdNode `json:"nodes"`
			} `json:"configurations"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdMetric struct {
	Type     string `json:"type"`
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"` // v2 把 severity 放在 metric 层
}

type nvdNode struct {
	CPEMatch []struct {
		Criteria   string `json:"criteria"`
		Vulnerable bool   `json:"vulnerable"`
	} `json:"cpeMatch"`
	Children []nvdNode `json:"children"`
}

func (r nvdResponse) toEntries() []db.VulnIntelEntry {
	out := make([]db.VulnIntelEntry, 0, len(r.Vulnerabilities))
	for _, v := range r.Vulnerabilities {
		c := v.CVE
		if c.ID == "" || strings.EqualFold(c.VulnStatus, "Rejected") {
			continue
		}
		desc := ""
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				desc = strings.TrimSpace(d.Value)
				break
			}
		}
		score, sev := pickMetric(c.Metrics.V31)
		if score == 0 {
			if s2, sev2 := pickMetric(c.Metrics.V40); s2 > 0 {
				score, sev = s2, sev2
			}
		}
		if score == 0 {
			if s2, sev2 := pickMetric(c.Metrics.V2); s2 > 0 {
				score, sev = s2, sev2
			}
		}
		e := db.VulnIntelEntry{
			CVEID:       c.ID,
			Source:      "nvd",
			Title:       titleFromDesc(desc),
			Description: desc,
			Severity:    strings.ToUpper(sev),
			CVSS:        score,
		}
		// CISA KEV 标记来自 NVD 回填字段（CISA 全量 JSON 拿不到时的兜底）。
		if strings.TrimSpace(c.CisaExploitAdd) != "" {
			e.KEV = true
			e.KEVDue = strings.TrimSpace(c.CisaExploitAdd)
		}
		if t, err := time.Parse("2006-01-02T15:04:05.000", c.Published); err == nil {
			e.PublishedAt = t
		}
		if t, err := time.Parse("2006-01-02T15:04:05.000", c.LastModified); err == nil {
			e.ModifiedAt = t
		}
		seen := map[string]bool{}
		for _, cfg := range c.Configurations {
			for _, node := range cfg.Nodes {
				collectCPE(node, seen, &e.CPE)
			}
		}
		for i, ref := range c.References {
			if i >= 10 {
				break
			}
			if ref.URL != "" {
				e.Refs = append(e.Refs, ref.URL)
			}
		}
		out = append(out, e)
	}
	return out
}

func pickMetric(list []nvdMetric) (float64, string) {
	for _, m := range list {
		if m.CVSSData.BaseScore > 0 {
			sev := m.CVSSData.BaseSeverity
			if sev == "" {
				sev = m.BaseSeverity
			}
			return m.CVSSData.BaseScore, sev
		}
	}
	return 0, ""
}

func collectCPE(node nvdNode, seen map[string]bool, out *[]string) {
	for _, m := range node.CPEMatch {
		if !m.Vulnerable {
			continue
		}
		if cpe := cpeKey(m.Criteria); cpe != "" && !seen[cpe] {
			seen[cpe] = true
			*out = append(*out, cpe)
		}
	}
	for _, child := range node.Children {
		collectCPE(child, seen, out)
	}
}

// cpeKey 从 cpe:2.3:a:vendor:product:... 里取 "vendor:product"，两部分都归一成
// 纯小写字母数字（"next.js" → "nextjs"），与 assets.technologies 的归一规则一致。
func cpeKey(criteria string) string {
	parts := strings.Split(criteria, ":")
	if len(parts) < 5 || parts[0] != "cpe" {
		return ""
	}
	v, p := normalizeCPE(parts[3]), normalizeCPE(parts[4])
	if v == "" || p == "" || v == "*" || p == "*" {
		return ""
	}
	return v + ":" + p
}

func normalizeCPE(s string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// titleFromDesc 用描述首句当标题（NVD 没有独立标题字段）。
func titleFromDesc(desc string) string {
	desc = strings.TrimSpace(desc)
	if desc == "" {
		return ""
	}
	cut := len(desc)
	if i := strings.IndexAny(desc, ".!?"); i > 20 && i < 200 {
		cut = i
	}
	if cut > 160 {
		cut = 160
	}
	return strings.TrimSpace(desc[:cut])
}

func (s *Service) getJSON(ctx context.Context, url string, dst any) error {
	return s.getJSONWithKey(ctx, url, dst)
}

func (s *Service) getJSONWithKey(ctx context.Context, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "artex-vulnintel/1.0")
	if key := s.nvdKey(); key != "" && strings.Contains(url, "nvd.nist.gov") {
		req.Header.Set("apiKey", key)
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: HTTP %d %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	dec := json.NewDecoder(resp.Body)
	return dec.Decode(dst)
}
