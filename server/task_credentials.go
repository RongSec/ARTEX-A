package server

// 建任务时录入的凭据（V12-TARGET）。
//
// 落点选择说明：凭据最终写进目标资产的 auth 数组（assets.auth JSONB），
// 而不是塞进任务描述或另建一张表。理由：
//   - auth 是现有唯一「凭据挂资产」的模型，agent 已有 list_assets / node_detail
//     能读到，不需要新增工具与提示词；
//   - 任务描述会进 prompt、进报告、进归档包，明文口令躺在那里会被无差别扩散；
//   - 资产是全局的，同一目标在不同任务里复用同一份凭据，符合实际。
//
// 凭据行可带 Target：留空=适用范围为整批（或本条任务），填了=只写给匹配的
// 那个目标。匹配规则是「规范化字符串相等」或「主机相等」——用户填
// `10.0.0.5` 能匹配 `http://10.0.0.5:8080`，不必逐字一致。

import (
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// TaskCredentialInput 是前端一行凭据。
type TaskCredentialInput struct {
	Target      string `json:"target,omitempty"` // 空=全部目标
	Type        string `json:"type"`             // password|hash|token|cookie|key
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	Token       string `json:"token,omitempty"`
	Description string `json:"description,omitempty"`
}

// maxTaskCredentials 是单次录入的凭据行上限。凭据是人工输入，几十行足够；
// 给上限是为了拦住误把整份字典粘进来。
const maxTaskCredentials = 100

// normalizeTaskCredentials 校验并归一化凭据行。空行（三项全空）直接丢弃，
// 其余非法项返回错误——凭据是人工录入的少量数据，错了应该当场告知，
// 不像批量目标那样静默剔除。
func normalizeTaskCredentials(in []TaskCredentialInput) ([]TaskCredentialInput, error) {
	if len(in) > maxTaskCredentials {
		return nil, fmt.Errorf("凭据最多 %d 行（当前 %d 行）", maxTaskCredentials, len(in))
	}
	out := make([]TaskCredentialInput, 0, len(in))
	for i, c := range in {
		c.Type = strings.ToLower(strings.TrimSpace(c.Type))
		c.Target = strings.TrimSpace(c.Target)
		c.Username = strings.TrimSpace(c.Username)
		c.Password = strings.TrimSpace(c.Password)
		c.Token = strings.TrimSpace(c.Token)
		c.Description = strings.TrimSpace(c.Description)
		if c.Type == "" && c.Username == "" && c.Password == "" && c.Token == "" {
			continue // 整行空白：前端「新增一行」后没填，跳过
		}
		if c.Type == "" {
			c.Type = "password"
		}
		if !db.ValidIntelCredentialKind(c.Type) {
			return nil, fmt.Errorf("第 %d 行凭据类型 %q 无效（password/hash/token/cookie/key）", i+1, c.Type)
		}
		if c.Password == "" && c.Token == "" && c.Username == "" {
			return nil, fmt.Errorf("第 %d 行凭据缺少内容（用户名 / 密码 / 令牌至少填一项）", i+1)
		}
		if c.Target != "" {
			if _, ok := normalizeTarget(c.Target); !ok {
				return nil, fmt.Errorf("第 %d 行凭据的适用目标 %q 不是合法主机或 URL", i+1, c.Target)
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// credentialAppliesTo 判断一条凭据是否适用于某个目标。
// 空 Target 表示通用；否则允许「整串相等」或「主机相等」两种匹配。
func credentialAppliesTo(c TaskCredentialInput, target string) bool {
	if c.Target == "" {
		return true
	}
	if c.Target == target {
		return true
	}
	wantHost := credentialHost(c.Target)
	if wantHost == "" {
		return false
	}
	_, gotHost, _, ok := parseTarget(target)
	return ok && strings.EqualFold(gotHost, wantHost)
}

// credentialHost 取出目标里的主机部分（IP 或域名），取不到返回空。
func credentialHost(s string) string {
	if _, host, _, ok := parseTarget(s); ok {
		return host
	}
	if norm, ok := normalizeTarget(s); ok {
		if _, host, _, ok := parseTarget(norm); ok {
			return host
		}
	}
	return ""
}

// authItemsFor 把适用于该目标的凭据转成 assets.auth 的条目。
func authItemsFor(creds []TaskCredentialInput, target string) []map[string]any {
	if len(creds) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(creds))
	for _, c := range creds {
		if !credentialAppliesTo(c, target) {
			continue
		}
		item := map[string]any{"type": c.Type}
		if c.Username != "" {
			item["username"] = c.Username
		}
		if c.Password != "" {
			item["password"] = c.Password
		}
		if c.Token != "" {
			item["token"] = c.Token
		}
		if c.Description != "" {
			item["description"] = c.Description
		}
		out = append(out, item)
	}
	return out
}
