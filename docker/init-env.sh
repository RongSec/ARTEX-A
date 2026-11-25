#!/usr/bin/env bash
# 首次部署初始化：在 docker/.env 里生成数据库口令与管理员初始密码。
#
# 设计原则：
#   - **幂等**：.env 已存在就一个字节都不改，避免重启把口令换掉导致连不上库；
#   - **本地生成**：口令只落在本机 docker/.env（0600），不经过仓库、不进镜像；
#   - **不打印口令**：只在新建时提示文件位置，要看自己 `--show`。
#
# 用法：
#   bash docker/init-env.sh          # 生成（已存在则跳过）
#   bash docker/init-env.sh --show   # 查看当前 .env（含口令）
#   bash docker/init-env.sh --force  # 重新生成（会换掉数据库口令，旧卷需同步改）
set -euo pipefail
cd "$(dirname "$0")"

rand_hex() { # $1=字节数
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$1"
  else
    head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

rand_pass() { # 字母数字混合，避开 shell/URL 需要转义的字符
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 20
  else
    LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 20
  fi
}

case "${1:-}" in
  --show) sed -n '1,40p' .env 2>/dev/null || echo "(docker/.env 不存在，先运行 bash docker/init-env.sh)"; exit 0 ;;
  --force) FORCE=1 ;;
  *) FORCE=0 ;;
esac

if [ -f .env ] && [ "$FORCE" = "0" ]; then
  echo "== docker/.env 已存在，未修改（--force 可重新生成，但会换掉数据库口令）"
else
  PG_PASS="$(rand_hex 16)"
  ADMIN_PASS="$(rand_pass)"
  umask 077
  cat > .env <<EOF
# 由 docker/init-env.sh 生成于 $(date '+%Y-%m-%d %H:%M:%S')
# 含口令，禁止提交（已在 .gitignore）。备份到密码管理器后妥善保管。
POSTGRES_USER=artex
POSTGRES_PASSWORD=${PG_PASS}
POSTGRES_DB=artex
ARTEX_PG_DSN=postgres://artex:${PG_PASS}@postgres:5432/artex?sslmode=disable
ARTEX_INIT_PASSWORD=${ADMIN_PASS}
ARTEX_IMAGE=rongsec/artex-a:latest
ARTEX_HTTP_PORT=8801
# hs 单机部署用 host 网络，监听端口就是对外端口（Health 检查也打这个端口）。
ARTEX_LISTEN_ADDR=:8801
ARTEX_PROXY_ADDR=127.0.0.1:8802
EOF
  chmod 600 .env
  echo "== 已生成 docker/.env（0600）"
fi

mkdir -p data && chmod 700 data 2>/dev/null || true

cat <<'EOF'

下一步：
  ./run.sh
  浏览器打开 http://<本机IP>:8801 ，用户名 ARTEX，密码见 docker/.env 的 ARTEX_INIT_PASSWORD

说明：
  - 用外部 PostgreSQL 时，把 docker/.env 里 ARTEX_PG_DSN 的 host 改成实际地址；
  - run.sh 每次启动会做两步工具自愈（单文件二进制进 data/hostbin、apt 工具补进容器）；
  - 升级/回滚用 ./update.sh，不要用页面（页面只保留版本查询）；
  - 应用还会在首次启动时自动生成 jwt.key，无需手工创建；
  - 裸机（非 Docker）部署时，程序首次启动会在可执行文件旁生成 config.json 模板。
EOF
