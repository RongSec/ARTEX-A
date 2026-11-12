package db

import (
	"strings"
	"testing"
)

// V4 安全面层2：sanitizeActivityText 纯函数测——三类凭据形态全打码、普通文本
// 不误伤、多形态引号全覆盖。无库可跑。
func TestSanitizeActivityText(t *testing.T) {
	cases := []struct {
		name, in, want      string
		mustNotContain      []string // 输出里绝不允许出现的明文残留
	}{
		{
			name:           "PGPASSWORD 无引号",
			in:             `psql -h 10.0.0.8 -U artex 打不开 PGPASSWORD=S3cret!pass psql -c 'select 1'`,
			want:           `PGPASSWORD=***`,
			mustNotContain: []string{"S3cret!pass"},
		},
		{
			name:           "PGPASSWORD 单引号",
			in:             `env PGPASSWORD='S3cret!pass' psql -c "select version()"`,
			mustNotContain: []string{"S3cret!pass"},
		},
		{
			name:           "PGPASSWORD 双引号",
			in:             `export PGPASSWORD="S3cret!pass" && psql -h db`,
			mustNotContain: []string{"S3cret!pass"},
		},
		{
			name:           "PGPASSWORD 大小写混写",
			in:             `pgpassword=S3cret!pass`,
			mustNotContain: []string{"S3cret!pass"},
		},
		{
			name:           "postgres URL",
			in:             `连接 postgres://artex:S3cret!pass@10.0.0.8:5432/artex 成功`,
			want:           `postgres://***:***@10.0.0.8:5432/artex`,
			mustNotContain: []string{"artex:S3cret", "S3cret!pass@"},
		},
		{
			name:           "postgresql URL 大写",
			in:             `POSTGRESQL://admin:TopS3cret@db.internal/prod`,
			mustNotContain: []string{"TopS3cret"},
		},
		{
			name:           "Bearer token",
			in:             "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI' http://api",
			want:           "Authorization: Bearer ***",
			mustNotContain: []string{"eyJhbGciOiJIUzI1NiI"},
		},
		{
			name:           "Bearer 大小写+冒号变体",
			in:             "authorization:bearer ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
			mustNotContain: []string{"ABCDEFGHIJKLMNOPQRSTUVWX"},
		},
		{
			name: "多凭据混排一行",
			in: `PGPASSWORD=pw1 psql postgres://u:pw2@h/db && curl -H "Authorization: Bearer tok3abcdefghijk1234567890"`,
			mustNotContain: []string{"pw1", "pw2", "tok3abcdefghijk"},
		},
		// —— 不误伤组 ——
		{
			name: "普通侦查输出原样",
			in:   `nmap -sV 10.0.0.8 开放端口 22/80/443，Server: nginx/1.18.0；密码字段为空`,
			want: `nmap -sV 10.0.0.8 开放端口 22/80/443，Server: nginx/1.18.0；密码字段为空`,
		},
		{
			name: "短 bearer 说明文本不打码",
			in:   "接口返回 401，Authorization: Bearer 无效",
			want: "接口返回 401，Authorization: Bearer 无效",
		},
		{
			name: "无 userinfo 的 postgres URL 原样",
			in:   "psql postgres://10.0.0.8:5432/artex 需要密码",
			want: "psql postgres://10.0.0.8:5432/artex 需要密码",
		},
		{
			name: "PGPASSWORD 空值不误扩到后续文本",
			in:   "PGPASSWORD= 后接其他输出",
			want: "PGPASSWORD= 后接其他输出",
		},
		{
			name: "空串快路径",
			in:   "",
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sanitizeActivityText(c.in)
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Errorf("输出缺少期望片段 %q：%q", c.want, got)
			}
			if c.want == c.in && got != c.in {
				t.Errorf("不应误伤：%q → %q", c.in, got)
			}
			for _, bad := range c.mustNotContain {
				if strings.Contains(got, bad) {
					t.Errorf("凭据 %q 未打码：%q", bad, got)
				}
			}
		})
	}
}

// 幂等性：打码结果再进一次不落坏（*** 不会被二次替换变形）。
func TestSanitizeActivityTextIdempotent(t *testing.T) {
	in := `PGPASSWORD=S3cret psql postgres://u:pw@h/db -H "Authorization: Bearer tokabcdefghij1234567890"`
	once := sanitizeActivityText(in)
	if twice := sanitizeActivityText(once); twice != once {
		t.Errorf("非幂等：%q → %q", once, twice)
	}
}
