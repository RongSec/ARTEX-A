#!/usr/bin/env bash
# 首次部署初始化：在 docker/.env 里生成数据库口令与管理员初始密码。
#
# 这个文件是**唯一的机密文件**：数据库口令、管理员密码、LLM key、搜索 key、
# NVD/GitHub token、代理账号，全部写在这里（0600，已 gitignore）。应用启动时
# 会把这些值导入数据库；页面里也能改，但以文件为准的地方是这里。
#
# 设计原则：
#   - **幂等**：.env 已存在就一个字节都不改，避免重启把口令换掉导致连不上库；
#   - **本地生成**：口令只落本机，不经过仓库、不进镜像；
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
  --show) sed -n '1,80p' .env 2>/dev/null || echo "(docker/.env 不存在，先运行 bash docker/init-env.sh)"; exit 0 ;;
  --force) FORCE=1 ;;
  *) FORCE=0 ;;
esac

if [ -f .env ] && [ "$FORCE" = "0" ]; then
  echo "== docker/.env 已存在，未修改（--force 可重新生成，但会换掉数据库口令）"
else
  PG_PASS="$(rand_hex 16)"
  ADMIN_PASS="$(rand_pass)"
  # 数据库地址随系统走：
  #   Linux  → 应用用 host 网络，走宿主机回环的映射端口 55432；
  #   macOS/Windows（Docker Desktop）→ 应用在 bridge 网络里，走 compose DNS。
  # 写错的话表现是「容器起来了但一直连不上库」，非常难查，所以在这里定死。
  case "$(uname -s)" in
    Linux) DB_HOST=127.0.0.1; DB_PORT="${ARTEX_DB_PORT:-55432}" ;;
    *)     DB_HOST=artex-db;  DB_PORT=5432 ;;
  esac
  umask 077
  cat > .env <<EOF
# 由 docker/init-env.sh 生成于 $(date '+%Y-%m-%d %H:%M:%S')
# 含全部口令与密钥，禁止提交（已在 .gitignore）。备份到密码管理器后妥善保管。

# ── 部署形态 ────────────────────────────────────────────────
ARTEX_IMAGE=rongsec/artex-a:latest
# 应用监听端口（host 网络下就是对外端口；Docker Desktop 下用 -p 映射）
ARTEX_LISTEN_ADDR=:8801
# 下面两个必须和上一行的端口一致（compose 的端口映射不会解析地址串）
ARTEX_LISTEN_PORT=8801
ARTEX_HTTP_PORT=8801
ARTEX_PROXY_ADDR=127.0.0.1:8802
ARTEX_PROXY_PORT=8802
# 数据目录：模板、报告、hostbin、apt 缓存都在这里
ARTEX_DATA_DIR=./data

# ── 数据库（compose 自带的 artex-db）────────────────────────
POSTGRES_USER=artex
POSTGRES_PASSWORD=${PG_PASS}
POSTGRES_DB=artex
# 数据库只绑 127.0.0.1；55432 避开宿主机默认的 5432。
ARTEX_DB_PORT=55432
ARTEX_PG_DSN=postgres://artex:${PG_PASS}@${DB_HOST}:${DB_PORT}/artex?sslmode=disable

# 首次启动的管理员初始密码（用户名固定 ARTEX；已建过账号后这里无效）
ARTEX_INIT_PASSWORD=${ADMIN_PASS}

# ── 机密：以下全部留空也能跑，填了启动时自动导入 ────────────
# LLM：填 ARTEX_LLM_API_KEY 即可；格式 openai / anthropic / openai-responses
#      base_url 留空走官方；接中转网关时填到 /v1 这一层
ARTEX_LLM_FORMAT=
ARTEX_LLM_API_KEY=
ARTEX_LLM_BASE_URL=
ARTEX_LLM_MODEL=
ARTEX_LLM_PROXY=
# 兼容官方变量名（与上面二选一，优先级低于 ARTEX_LLM_API_KEY）
ANTHROPIC_API_KEY=
OPENAI_API_KEY=

# 联网搜索（不填则用免密的 ddgs）
ARTEX_BRAVE_API_KEY=
ARTEX_TAVILY_API_KEY=

# 漏洞情报：NVD 匿名 5 次/30 秒，填 key 后 50 次/30 秒
ARTEX_NVD_API_KEY=
# GitHub token：PoC 聚合/GHSA 限速、宿主工具下载都用它
ARTEX_GITHUB_TOKEN=

# 代理（渗透目标流量走 global，检索/情报走 outbound）
ARTEX_OUTBOUND_PROXY=
ARTEX_GLOBAL_PROXY=
EOF
  chmod 600 .env
  echo "== 已生成 docker/.env（0600，含全部口令与密钥）"
fi

mkdir -p data && chmod 700 data 2>/dev/null || true

cat <<'EOF'

下一步：
  ./run.sh
  浏览器打开 http://<本机IP>:8801 ，用户名 ARTEX，密码：
    bash docker/init-env.sh --show | grep ARTEX_INIT_PASSWORD

说明：
  - docker/.env 是唯一的机密文件，备份它就够了；
  - 应用启动时把其中的 LLM/搜索/情报 key 导入数据库（只填空缺，不覆盖页面改过的值）；
  - run.sh 每次启动会做两步工具自愈（单文件二进制进 data/hostbin、apt 工具补进容器）；
  - 升级/回滚用 ./update.sh，页面只保留版本查询。
EOF
