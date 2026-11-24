package vulnintel

// GitHub PoC 聚合（V10-POC）。
//
// 做法和 Pojun 一致但更保守：拿 CVE 编号当关键词打 GitHub 公开搜索
// （q=CVE-xxxx in:name,description），只落仓库元数据（repo/URL/star/描述），
// 不下载、不执行、不缓存任何代码。它的价值是「这个洞有没有现成 EXP」这个信号，
// 不是给 agent 一个能直接跑的武器——真要验，仍走授权目标上的实测。
//
// 配额是硬约束：GitHub 搜索 API 认证后 30 次/分钟、匿名 10 次/分钟。所以：
//   - 只查「高价值」CVE（KEV 或 CVSS≥9），按 KEV>CVSS>发布时间排序
//   - 查过的打 poc_checked_at，永不复查（除非人工清标记）
//   - 每轮预算：认证 25、匿名 8，间隔 2.1s / 6.5s
//
// 没有 token 也能跑，就是慢：一小时大概补 70 条。

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

	"github.com/Autumn-27/artex/db"
)

const (
	settingGHToken   = "vulnintel.github_token"
	settingGHEnable  = "vulnintel.github_enabled"
	settingLastPoc   = "vulnintel.last_poc_sync"
	githubSearchAPI  = "https://api.github.com/search/repositories"
	githubPocPerCVE  = 5                       // 每个 CVE 最多留 5 个仓库
	githubPocAuthGap = 2100 * time.Millisecond // 30 次/分钟，留一点余量
	githubPocAnonGap = 6500 * time.Millisecond // 10 次/分钟
	githubPocAuthCap = 25
	githubPocAnonCap = 8
)

// GitHubConfig 是页面「GitHub 配置」卡片的可回显部分：token 只回是否已设置 + 末四位。
type GitHubConfig struct {
	Enabled  bool   `json:"enabled"`
	TokenSet bool   `json:"token_set"`
	TokenTip string `json:"token_tip"`
	LastSync string `json:"last_sync"`
}

func (s *Service) githubEnabled() bool {
	v, ok, err := s.pg.GetSetting(settingGHEnable)
	if err != nil || !ok {
		return true // 默认开：没有 token 也能低速跑，不产生副作用
	}
	return v != "false"
}

func (s *Service) githubToken() string {
	v, _, _ := s.pg.GetSetting(settingGHToken)
	return strings.TrimSpace(v)
}

// GitHubConfig 读当前配置（不回显 token 明文）。
func (s *Service) GitHubConfig() GitHubConfig {
	tok := s.githubToken()
	cfg := GitHubConfig{Enabled: s.githubEnabled(), TokenSet: tok != ""}
	if tok != "" {
		if len(tok) <= 4 {
			cfg.TokenTip = "****"
		} else {
			cfg.TokenTip = "****" + tok[len(tok)-4:]
		}
	}
	cfg.LastSync, _, _ = s.pg.GetSetting(settingLastPoc)
	return cfg
}

// SetGitHubConfig 保存开关与 token。token 传 nil 表示不改（前端只发改动字段），
// 传 "" 表示清空。
func (s *Service) SetGitHubConfig(enabled *bool, token *string) error {
	if enabled != nil {
		v := "true"
		if !*enabled {
			v = "false"
		}
		if err := s.pg.SetSetting(settingGHEnable, v); err != nil {
			return err
		}
	}
	if token != nil {
		if err := s.pg.SetSetting(settingGHToken, strings.TrimSpace(*token)); err != nil {
			return err
		}
	}
	return nil
}

// SyncPoc 补一轮 PoC 线索。返回 (查了几个 CVE, 新增几条线索)。
// 与 NVD/KEV 共用 running 闸门：同一时刻只跑一个同步，避免抢配额。
func (s *Service) SyncPoc(ctx context.Context, max int) (checked, added int, err error) {
	if !s.githubEnabled() {
		return 0, 0, nil
	}
	tok := s.githubToken()
	if max <= 0 {
		if tok != "" {
			max = githubPocAuthCap
		} else {
			max = githubPocAnonCap
		}
	}
	queue, qerr := s.pg.VulnPocQueue(ctx, max)
	if qerr != nil || len(queue) == 0 {
		return 0, 0, qerr
	}
	if err := s.begin("poc"); err != nil {
		return 0, 0, err
	}
	// finish 必须拿到真实错误：否则页面只看到「跑完了」，看不到配额打满。
	var firstErr error
	defer func() { s.finish("poc", firstErr) }()

	gap := githubPocAnonGap
	if tok != "" {
		gap = githubPocAuthGap
	}
	for _, cve := range queue {
		pocs, err := s.searchGitHubPoc(ctx, cve, tok)
		if err != nil {
			// 配额打满就别硬撑：剩下的留给下一轮。
			firstErr = err
			break
		}
		if err := s.pg.UpsertVulnPocs(ctx, cve, pocs); err != nil {
			firstErr = err
			break
		}
		checked++
		added += len(pocs)
		select {
		case <-ctx.Done():
			return checked, added, ctx.Err()
		case <-time.After(gap):
		}
	}
	if checked > 0 {
		_ = s.pg.SetSetting(settingLastPoc, time.Now().Format(time.RFC3339))
	}
	if firstErr != nil && checked == 0 {
		return checked, added, firstErr
	}
	if firstErr != nil {
		log.Printf("[vulnintel] PoC 聚合提前结束（已查 %d）：%v", checked, firstErr)
	}
	return checked, added, nil
}

// searchGitHubPoc 查一个 CVE 的公开仓库，star 高的在前。
func (s *Service) searchGitHubPoc(ctx context.Context, cveID, token string) ([]db.VulnPoc, error) {
	q := url.Values{}
	q.Set("q", cveID+" in:name,description")
	q.Set("sort", "stars")
	q.Set("order", "desc")
	q.Set("per_page", fmt.Sprint(githubPocPerCVE))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubSearchAPI+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "artex-vulnintel/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		switch resp.StatusCode {
		case http.StatusForbidden, http.StatusTooManyRequests:
			reset := resp.Header.Get("X-RateLimit-Reset")
			return nil, fmt.Errorf("GitHub 配额用尽（HTTP %d，重置于 %s）：%s", resp.StatusCode, reset, strings.TrimSpace(string(body)))
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("GitHub token 无效（401），请在漏洞情情报页重新配置")
		}
		return nil, fmt.Errorf("GitHub 搜索 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Items []struct {
			FullName    string `json:"full_name"`
			HTMLURL     string `json:"html_url"`
			Description string `json:"description"`
			Stars       int    `json:"stargazers_count"`
			Language    string `json:"language"`
			PushedAt    string `json:"pushed_at"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	out := make([]db.VulnPoc, 0, len(payload.Items))
	for _, it := range payload.Items {
		if strings.TrimSpace(it.FullName) == "" {
			continue
		}
		p := db.VulnPoc{
			CVEID:       cveID,
			Repo:        it.FullName,
			URL:         it.HTMLURL,
			Description: truncateRunes(strings.TrimSpace(it.Description), 200),
			Stars:       it.Stars,
			Lang:        it.Language,
		}
		if t, err := time.Parse(time.RFC3339, it.PushedAt); err == nil {
			p.PushedAt = t
		}
		out = append(out, p)
	}
	return out, nil
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
