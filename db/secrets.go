package db

import (
	"log"
	"os"
	"strings"
)

// 这一组键名与 server/manager.go 里的 setting* 常量一一对应。
// 故意在 db 包里写字面量而不是反过来 import server：db 是被 server 依赖的，
// 反向依赖会成环。改键名时必须两处一起改（这里有测试兜底，见 secrets_test.go）。
const (
	secretKeyBrave    = "brave_search_api_key"
	secretKeyTavily   = "tavily_search_api_key"
	secretKeyNVD      = "nvd_api_key"
	secretKeyGitHub   = "vulnintel_github_token"
	secretKeyOutbound = "outbound_proxy"
	secretKeyGlobal   = "global_proxy"
)

// SeedSecretsFromEnv 把部署文件（docker/.env）里的机密导入数据库。
//
// 为什么要有这一步：.env 是用户唯一需要备份的机密文件，但应用真正读的是
// 数据库里的 llm_profiles / settings。没有导入的话，「key 都写在一个文件里」
// 就只是句口号——用户填了 .env 却不生效，还得去页面再填一遍。
//
// 只填空缺，绝不覆盖：页面里改过的值优先。想用文件里的新值覆盖，先在页面
// 把该字段清空，再重启（或直接改库）。这样既不会「重启把线上配置改回去」，
// 也不会出现两套配置互相打架。
func (d *DB) SeedSecretsFromEnv() {
	d.seedLLMFromEnv()

	var n int
	for _, s := range []struct{ key, env string }{
		{secretKeyBrave, "ARTEX_BRAVE_API_KEY"},
		{secretKeyTavily, "ARTEX_TAVILY_API_KEY"},
		{secretKeyNVD, "ARTEX_NVD_API_KEY"},
		{secretKeyGitHub, "ARTEX_GITHUB_TOKEN"},
		{secretKeyOutbound, "ARTEX_OUTBOUND_PROXY"},
		{secretKeyGlobal, "ARTEX_GLOBAL_PROXY"},
	} {
		if d.seedSetting(s.key, os.Getenv(s.env)) {
			n++
		}
	}
	if n > 0 {
		log.Printf("[secrets] 已从 .env 导入 %d 项设置（只填空缺）", n)
	}
}

// seedSetting 写入一个设置项，已有非空值则跳过。返回是否真的写入。
func (d *DB) seedSetting(key, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if cur, ok, err := d.GetSetting(key); err == nil && ok && strings.TrimSpace(cur) != "" {
		return false
	}
	if err := d.SetSetting(key, value); err != nil {
		log.Printf("[secrets] 写入设置 %s 失败: %v", key, err)
		return false
	}
	return true
}

// seedLLMFromEnv 在库里一个 LLM profile 都没有时，用环境变量建一个默认的。
//
// 只在「一条都没有」时动手：新建部署的用户填完 .env 就能直接对话，不用先进
// 设置页；已有配置的用户升级上来，不会被 .env 里的残留值改掉模型。
func (d *DB) seedLLMFromEnv() {
	key := firstNonEmpty(os.Getenv("ARTEX_LLM_API_KEY"), os.Getenv("ANTHROPIC_API_KEY"), os.Getenv("OPENAI_API_KEY"))
	if key == "" {
		return
	}
	profiles, err := d.ListProfiles()
	if err != nil {
		log.Printf("[secrets] 读取 LLM 配置失败: %v", err)
		return
	}
	if len(profiles) > 0 {
		return
	}

	format := strings.TrimSpace(os.Getenv("ARTEX_LLM_FORMAT"))
	if format == "" {
		// 只有给了官方 Anthropic key 才默认 anthropic；其余按 openai 兼容处理
		// （中转网关绝大多数是 OpenAI 兼容协议）。
		if os.Getenv("ARTEX_LLM_API_KEY") == "" && os.Getenv("OPENAI_API_KEY") == "" {
			format = "anthropic"
		} else {
			format = "openai"
		}
	}
	model := strings.TrimSpace(os.Getenv("ARTEX_LLM_MODEL"))
	if model == "" {
		switch format {
		case "anthropic":
			model = "claude-opus-4-8"
		case "openai-responses":
			model = "gpt-5"
		default:
			model = "gpt-4o"
		}
	}

	p := &LLMProfile{
		Name:      "env",
		Format:    format,
		Model:     model,
		BaseURL:   strings.TrimSpace(os.Getenv("ARTEX_LLM_BASE_URL")),
		Proxy:     strings.TrimSpace(os.Getenv("ARTEX_LLM_PROXY")),
		APIKey:    key,
		Streaming: true,
	}
	id, err := d.SaveProfile(p)
	if err != nil {
		log.Printf("[secrets] 从 .env 创建 LLM 配置失败: %v", err)
		return
	}
	if err := d.SetActiveProfile(id); err != nil {
		log.Printf("[secrets] 激活 LLM 配置失败: %v", err)
		return
	}
	log.Printf("[secrets] 已从 .env 创建默认 LLM 配置（%s / %s）", format, model)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}
