#!/usr/bin/env bash
# ARTEX-A 启动脚本（宿主机侧）——唯一推荐的服务入口。
#
# 新机器上只需要三步：git clone → cd → ./run.sh。
# 首次运行会自动生成 docker/.env（随机数据库口令、管理员密码、空密钥位），
# 拉镜像（直连失败自动换加速源），起应用 + 数据库，再把工具补齐。
#
# 与另外两个脚本的分工：
#   run.sh      每次启动：拉起服务 + 把「不持久的东西」补回来   ← 本文件
#   update.sh   升级/回滚：换镜像、备份与恢复数据库、离线导入
#   install.sh  已废弃，只剩转发到 run.sh（老文档里的入口）
#
# 为什么需要它：容器里有三类东西的寿命不一样。
#   - 镜像层（nuclei/nmap/LibreOffice/Playwright）：跟着镜像走，重建容器不受影响；
#   - 挂载卷 /app/data（hostbin、pyenv、模板）：重建容器不丢，但要有人确保在位；
#   - 容器可写层（apt/yum 装出来的 hashcat/hydra/gdb…）：`docker compose up -d`
#     一重建容器就没了——这不是 bug，是容器的定义。
# 所以每次启动固定做两步（幂等，全在位时几乎不耗时）：
#   ① 单文件二进制 → $DATA/hostbin（卷里，PATH 第一位），缺则从 GitHub 取；
#   ② 系统级 apt 包 → 容器内补装（卷里缓存了 .deb，重装不重新下载）。
#
# 用法：
#   ./run.sh              启动（等价 ./run.sh up）
#   ./run.sh up           启动：生成 .env → 拉镜像 → 起服务 → 播种技能 → 补工具
#   ./run.sh ensure       只补齐工具（更新镜像之后、或怀疑工具丢了时跑）
#   ./run.sh seed-skills  只把镜像自带技能播种到 data/skills（update.sh 会调）
#   ./run.sh restart      重启容器（不重建，容器可写层的东西还在）
#   ./run.sh down         停止（应用 + 数据库）
#   ./run.sh status       状态
#   ./run.sh logs [-f]    日志
#   ./run.sh doctor       完整体检：容器、版本、PDF 预览引擎、工具缺口
#
# 环境变量（都可选）：
#   ARTEX_COMPOSE    compose 文件，默认 docker/docker-compose.hs.yml
#   ARTEX_MIRRORS    镜像加速源，空格分隔，默认 "docker.1ms.run"
#   ARTEX_DATA_DIR   覆盖 .env 里的数据目录
#   ARTEX_SKIP_TOOLS=1  只起服务，不做工具补齐（离线且不关心工具时用）
#   NO_COLOR=1       关闭彩色输出（重定向到文件时也会自动关闭）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
# 唯一差异是网络：Linux 用 host（反弹 shell、内网扫描、抓包都靠它），
# Docker Desktop（macOS/Windows）没有真 host 网络，只能 bridge + 端口映射，
# 否则容器起来了、宿主机浏览器却是空的。两种形态在同一个 compose 里用
# profile 区分（host / desktop），其余配置用 YAML 锚点共用。
case "$(uname -s)" in
  Darwin|MINGW*|MSYS*|CYGWIN*) PROFILE=desktop ;;
  *)                           PROFILE=host ;;
esac
COMPOSE="${ARTEX_COMPOSE:-$ROOT/docker/docker-compose.hs.yml}"
[ -f "$COMPOSE" ] || COMPOSE="$ROOT/docker-compose.yml"
ENV_FILE="$(dirname "$COMPOSE")/.env"
TOOLS_FILE="$ROOT/docker/apt-tools.txt"

# ── 输出 ─────────────────────────────────────────────────
# 只在真终端里上色/转圈：重定向到文件或 CI 时退化纯文本，
# 否则日志里全是 \033 转义符，贴到工单里没法看。
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'
  C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'
else
  C_RESET=''; C_DIM=''; C_BOLD=''; C_CYAN=''; C_GREEN=''; C_YELLOW=''; C_RED=''
fi

STEP=0
TOTAL=0
SPIN_LOG=""

step() { # $1=标题
  STEP=$((STEP + 1))
  printf '\n%s[%d/%d]%s %s%s%s\n' "$C_BOLD$C_CYAN" "$STEP" "$TOTAL" "$C_RESET" "$C_BOLD" "$*" "$C_RESET"
}
info() { printf '     %s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }
ok()   { printf '     \033[32m✅\033[0m %s\n' "$*"; }
warn() { printf '     %s⚠️  %s%s\n' "$C_YELLOW" "$*" "$C_RESET"; }
fail() { printf '     %s❌ %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; }
die()  { fail "$*"; exit 1; }

# spinner_run 在真终端里显示「⏳ 标签 3s」的转圈，同时把命令输出收进临时文件；
# 非终端下直接跑。失败时调用方用 spin_tail 打印最后几行，成功时不刷屏。
spinner_run() { # $1=标签，其余=命令
  local label="$1"; shift
  local rc=0 start=$SECONDS log i=0 spin='|/-'
  log="$(mktemp "${TMPDIR:-/tmp}/artex-run.XXXXXX")"
  SPIN_LOG="$log"
  if [ -t 1 ]; then
    "$@" >"$log" 2>&1 &
    local pid=$!
    while kill -0 "$pid" 2>/dev/null; do
      printf '\r     \033[36m⏳\033[0m %s  %ss ' "$label" "$((SECONDS - start))"
      i=$((i + 1)); sleep 0.3
    done
    wait "$pid" || rc=$?
    printf '\r\033[K'
  else
    "$@" >"$log" 2>&1 || rc=$?
  fi
  return "$rc"
}
spin_tail() { [ -n "$SPIN_LOG" ] && [ -f "$SPIN_LOG" ] && tail -n 15 "$SPIN_LOG" | sed 's/^/        /' >&2; }
spin_clean() { [ -n "$SPIN_LOG" ] && rm -f "$SPIN_LOG"; SPIN_LOG=""; }

banner() {
  printf '\n%s============================================================%s\n' "$C_CYAN" "$C_RESET"
  printf '  %sARTEX-A%s  ·  自主渗透测试平台\n' "$C_BOLD" "$C_RESET"
  printf '  %s镜像%s %s\n' "$C_DIM" "$C_RESET" "$IMAGE"
  printf '  %s网络%s %s    %s端口%s %s    %s数据%s %s\n' \
    "$C_DIM" "$C_RESET" "$([ "$PROFILE" = host ] && echo 'host（直连宿主网卡）' || echo 'bridge（端口映射）')" \
    "$C_DIM" "$C_RESET" "$PORT" \
    "$C_DIM" "$C_RESET" "$DATA_DIR"
  printf '%s============================================================%s\n' "$C_CYAN" "$C_RESET"
}

summary() {
  printf '\n%s============================================================%s\n' "$C_GREEN" "$C_RESET"
  printf '  \033[32m✅ 部署完成\033[0m\n'
  printf '     访问   http://127.0.0.1:%s   （局域网用 http://<本机IP>:%s）\n' "$PORT" "$PORT"
  printf '     账号   ARTEX\n'
  printf '     密码   %s → ARTEX_INIT_PASSWORD\n' "$ENV_FILE"
  printf '     机密   %s（唯一文件，0600；LLM/搜索/情报 key 都在里面）\n' "$ENV_FILE"
  printf '     体检   ./run.sh doctor          日志   ./run.sh logs -f\n'
  printf '%s============================================================%s\n\n' "$C_GREEN" "$C_RESET"
}

# ── 环境 ─────────────────────────────────────────────────
ensure_env() {
  [ -f "$ENV_FILE" ] && return 0
  if [ "$ENV_FILE" != "$ROOT/docker/.env" ]; then
    die "未找到 $ENV_FILE（自定义 ARTEX_COMPOSE 时必须自备 .env）"
  fi
  bash "$ROOT/docker/init-env.sh" >/dev/null || die "生成 docker/.env 失败"
  ENV_FRESH=1
}

load_env() {
  ensure_env
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a

  # 机密统一在 .env：GitHub token 只有一个来源，工具下载与版本查询共用。
  GITHUB_TOKEN="${GITHUB_TOKEN:-${ARTEX_GITHUB_TOKEN:-}}"

  COMPOSE_DIR="$(cd "$(dirname "$COMPOSE")" && pwd)"
  case "$COMPOSE" in
    */docker-compose.yml)
      DATA_DIR="$ROOT/data" ;;
    *)
      local d="${ARTEX_DATA_DIR:-./data}"
      case "$d" in
        /*) DATA_DIR="$d" ;;
        *)  DATA_DIR="$COMPOSE_DIR/${d#./}" ;;
      esac ;;
  esac
  IMAGE="${ARTEX_IMAGE:-rongsec/artex-a:latest}"
  # 服务名随网络形态走（artex-host / artex-desktop），容器名始终是 artex-hs。
  SERVICE="artex-$PROFILE"
  CONTAINER="${ARTEX_CONTAINER_NAME:-artex-hs}"
  if [ -n "${ARTEX_LISTEN_ADDR:-}" ]; then
    PORT="${ARTEX_LISTEN_ADDR##*:}"
  else
    PORT=8801
  fi
  if [ "$PROFILE" = "desktop" ] && [ -n "${ARTEX_HTTP_PORT:-}" ]; then
    PORT="$ARTEX_HTTP_PORT"
  fi
  HOSTBIN="$DATA_DIR/hostbin"
  STATE_DIR="$COMPOSE_DIR/state"
  EMBEDDED_DB="${ARTEX_EMBEDDED_DB:-1}"
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) warn "未知架构 $ARCH，二进制按 amd64 尝试"; ARCH=amd64 ;;
  esac
}

compose() {
  local args=(-f "$COMPOSE" --profile "$PROFILE")
  [ "${EMBEDDED_DB:-1}" != "0" ] && args+=(--profile db)
  docker compose "${args[@]}" "$@"
}

CID=""
refresh_cid() { CID="$(compose ps -q "$SERVICE" 2>/dev/null | head -1 || true)"; }

require_docker() {
  command -v docker >/dev/null 2>&1 || die "未检测到 docker，请先安装 Docker（含 compose 插件）"
  docker compose version >/dev/null 2>&1 || die "未检测到 docker compose 插件"
  docker info >/dev/null 2>&1 || die "docker 守护进程不可用（权限不足？sudo usermod -aG docker \$USER 后重新登录）"
}

# Docker Hub 在部分网络里不是「返回错误」而是「连接挂住」——docker pull 会
# 安静地重试好几分钟，用户只看到屏幕不动。先花 5 秒探一下 /v2/：401 是正常
# 响应（要求 token），000/空才是不可达，这时直接跳过直连去加速源。
hub_reachable() {
  command -v curl >/dev/null 2>&1 || return 0
  local code
  code="$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' https://registry-1.docker.io/v2/ 2>/dev/null || true)"
  [ -n "$code" ] && [ "$code" != "000" ]
}

# 拉镜像：Docker Hub 直连在国内常年超时，失败后按 ARTEX_MIRRORS 依次换加速源，
# 拉到后打回原 tag，compose 仍然按 ARTEX_IMAGE 找它。
pull_image() {
  local ref="$1" m
  docker image inspect "$ref" >/dev/null 2>&1 && return 0

  if hub_reachable; then
    if spinner_run "拉取 $ref（首次约 5.4GB）" docker pull -q "$ref"; then
      spin_clean; return 0
    fi
    spin_clean
    warn "直连拉取失败，尝试加速源…"
  else
    warn "Docker Hub 直连不可达，走加速源…"
  fi

  for m in ${ARTEX_MIRRORS:-docker.1ms.run}; do
    if spinner_run "从 $m 拉取（首次约 5.4GB）" docker pull -q "$m/$ref"; then
      spin_clean
      docker tag "$m/$ref" "$ref" >/dev/null 2>&1
      ok "已从 $m 拉取并重命名为 $ref"
      return 0
    fi
    spin_clean
  done
  return 1
}

# ── 健康检查 ─────────────────────────────────────────────
health() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 3 "http://127.0.0.1:${PORT}/api/health" 2>/dev/null
  else
    docker exec "$CID" curl -fsS --max-time 3 "http://127.0.0.1:${PORT}/api/health" 2>/dev/null
  fi
}

wait_health() {
  local timeout="${1:-90}" i=0 start=$SECONDS v
  while [ "$i" -lt "$timeout" ]; do
    if v="$(health 2>/dev/null)"; then
      printf '\r\033[K'
      v="$(printf '%s' "$v" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
      ok "服务就绪  ${v:-unknown}  （$((SECONDS - start))s）"
      return 0
    fi
    [ -t 1 ] && printf '\r     \033[36m⏳\033[0m 等待健康检查  %ss' "$((SECONDS - start))"
    sleep 2
    i=$((i + 2))
  done
  printf '\r\033[K'
  warn "等待超时（${timeout}s）。查看日志：./run.sh logs"
  return 1
}

# ── 工具：单文件二进制 → 卷 ─────────────────────────────
ensure_bins() {
  mkdir -p "$HOSTBIN"
  local f
  for f in "$HOSTBIN"/*; do
    [ -f "$f" ] || continue
    [ -x "$f" ] || chmod +x "$f" 2>/dev/null || true
  done

  local missing need="" key
  missing="$(bash "$ROOT/docker/hostbin/fetch.sh" --arch "$ARCH" --out "$HOSTBIN" --missing 2>/dev/null || true)"
  # 镜像里已经带了的（nuclei/httpx/…）不必再往卷里放一份
  for key in $missing; do
    docker exec "$CID" sh -c "command -v $key >/dev/null 2>&1" 2>/dev/null && continue
    need="$need,$key"
  done
  need="${need#,}"

  if [ -z "$need" ]; then
    ok "单文件二进制  已齐（卷 + 镜像）"
    return 0
  fi
  info "缺失：$need（从 GitHub 取，配 ARTEX_GITHUB_TOKEN 可避免限流）"
  if spinner_run "下载 $need" env GITHUB_TOKEN="${GITHUB_TOKEN:-}" \
      bash "$ROOT/docker/hostbin/fetch.sh" --arch "$ARCH" --out "$HOSTBIN" --only "$need"; then
    spin_clean
    ok "单文件二进制  已落卷 $HOSTBIN"
  else
    fail "部分二进制未取到（网络受限？）"
    spin_tail; spin_clean
    info "稍后重跑 ./run.sh ensure，或在「宿主环境」页手工安装"
  fi
}

# ── 工具：系统级 apt 包 → 容器内 ────────────────────────
ensure_pkgs() {
  [ -f "$TOOLS_FILE" ] || { warn "缺 $TOOLS_FILE，跳过"; return 0; }

  local missing="" cmd pkg note total=0
  while IFS='|' read -r cmd pkg note; do
    case "$cmd" in ''|\#*) continue ;; esac
    total=$((total + 1))
    docker exec "$CID" sh -c "command -v $cmd >/dev/null 2>&1" 2>/dev/null && continue
    missing="$missing $pkg"
  done < "$TOOLS_FILE"

  if [ -z "$missing" ]; then
    ok "系统级工具  已齐（$total 项）"
    return 0
  fi

  info "缺失：$missing"
  if spinner_run "容器内 apt 安装" docker exec -u 0 "$CID" sh -c \
      "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $missing"; then
    spin_clean
    ok "系统级工具  已补齐（$total 项）"
  else
    fail "补装未全部成功（源不可达或包名不存在）"
    spin_tail; spin_clean
    info "容器重建后需要重跑 ./run.sh ensure"
  fi
}

ensure_all() {
  [ -n "$CID" ] || { warn "容器未运行，跳过工具补齐"; return 0; }
  ensure_bins
  ensure_pkgs
}

# ── 技能播种 ─────────────────────────────────────────────
# 技能目录是挂载卷（/app/data/skills），镜像自带的技能不会自动出现，第一次
# 启动必须从镜像复制一份进去。用临时容器取，不依赖容器已启动——应用启动时
# 就扫描这个目录，晚一步补会把首屏技能列表留空。
seed_skills() {
  mkdir -p "$DATA_DIR/skills" 2>/dev/null || true
  [ -n "$(ls -A "$DATA_DIR/skills" 2>/dev/null)" ] && return 0

  local tmp="artex-seed-$$"
  docker rm -f "$tmp" >/dev/null 2>&1 || true
  if docker create --name "$tmp" "$IMAGE" >/dev/null 2>&1; then
    if docker cp "$tmp:/app/skills/." "$DATA_DIR/skills/" >/dev/null 2>&1; then
      ok "技能  已从镜像播种（$(ls -1 "$DATA_DIR/skills" | wc -l | tr -d ' ') 个）"
      [ -n "$(compose ps -q "$SERVICE" 2>/dev/null || true)" ] && \
        info "容器已在运行，重启后才会加载：./run.sh restart"
    fi
    docker rm -f "$tmp" >/dev/null 2>&1 || true
  fi
}

# ── 子命令 ───────────────────────────────────────────────
cmd_up() {
  TOTAL=6
  require_docker
  load_env
  banner

  step "运行环境"
  ok "docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?')  /  compose $(docker compose version --short 2>/dev/null || echo '?')"
  ok "形态 $PROFILE  ·  架构 $ARCH  ·  数据库 $([ "$EMBEDDED_DB" = 0 ] && echo '外部 PostgreSQL' || echo '内置 PostgreSQL')"

  step "配置文件"
  if [ "${ENV_FRESH:-0}" = "1" ]; then
    ok "已生成 $ENV_FILE（0600，含随机数据库口令与管理员密码）"
  else
    ok "沿用 $ENV_FILE"
  fi

  mkdir -p "$DATA_DIR"/{hostbin,pyenv,aptcache,aptlists,wordlists,skills} "$STATE_DIR" 2>/dev/null || true

  # 端口上已经有一个不归本 compose 管的 ARTEX：停手，别起第二个。
  # 这正是「同一台机器上两个容器、两份数据」的来源——旧部署没停，新部署又起来。
  refresh_cid
  if [ -z "$CID" ] && health >/dev/null 2>&1; then
    die "端口 ${PORT} 上已有一个 ARTEX 在运行，但不是这份 compose 管理的。
     先停掉旧实例（docker ps → docker stop <名字>），再执行 ./run.sh。
     同一台机器只保留一个实例：两个实例会各写各的库和 data，行为不一致。"
  fi

  step "镜像"
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    ok "本地已有 $IMAGE"
  else
    pull_image "$IMAGE" || { spin_tail; spin_clean; die "拉取 $IMAGE 失败。离线部署可用 ./update.sh import <镜像tar>"; }
  fi
  if [ "$EMBEDDED_DB" != "0" ]; then
    docker image inspect postgres:16-alpine >/dev/null 2>&1 || pull_image "postgres:16-alpine" >/dev/null 2>&1 || true
  fi

  step "启动容器"
  seed_skills
  if spinner_run "docker compose up" compose up -d --remove-orphans; then
    spin_clean
    refresh_cid
    ok "容器已启动  $CONTAINER"
  else
    fail "容器启动失败"
    spin_tail; spin_clean
    die "查看日志：./run.sh logs"
  fi

  step "健康检查"
  if ! wait_health 90; then
    warn "服务未按时就绪，工具补齐仍然继续（有些工具恰好是排障要用的）"
  fi

  step "工具补齐"
  if [ "${ARTEX_SKIP_TOOLS:-0}" = "1" ]; then
    warn "ARTEX_SKIP_TOOLS=1：跳过工具补齐"
  else
    ensure_all
  fi

  if [ "${ENV_FRESH:-0}" = "1" ]; then
    local admin_pass
    admin_pass="$(grep -m1 '^ARTEX_INIT_PASSWORD=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true)"
    [ -n "$admin_pass" ] && info "首次登录密码：${admin_pass}（登录后请改）"
  fi
  summary
}

cmd_ensure() {
  TOTAL=3
  require_docker
  load_env
  refresh_cid
  [ -n "$CID" ] || die "容器未运行，先 ./run.sh up"
  step "运行环境"
  ok "容器 $CONTAINER 运行中"
  step "单文件二进制"
  ensure_bins
  step "系统级工具"
  ensure_pkgs
}

cmd_seed_skills() {
  require_docker
  load_env
  mkdir -p "$DATA_DIR/skills" 2>/dev/null || true
  seed_skills
}

cmd_down()    { load_env; compose down; ok "已停止（应用 + 数据库）"; }
cmd_restart() { load_env; compose restart; wait_health 60 || true; }

cmd_status() {
  load_env
  refresh_cid
  printf 'compose : %s\n镜像    : %s\n容器    : %s\n端口    : %s\n数据    : %s\n\n' \
    "$COMPOSE" "$IMAGE" "$CONTAINER" "$PORT" "$DATA_DIR"
  docker ps -a --filter "id=$CID" --format 'table {{.Status}}\t{{.Image}}\t{{.Ports}}' || true
  health >/dev/null 2>&1 && ok "健康检查通过" || warn "健康检查未通过"
}

cmd_logs() {
  load_env
  compose logs --tail 200 "$@"
}

cmd_doctor() {
  require_docker
  load_env
  refresh_cid
  printf '%sARTEX 体检%s\n\n' "$C_BOLD" "$C_RESET"

  printf '%-12s %s\n' "镜像"     "$IMAGE"
  printf '%-12s %s\n' "容器"     "$CONTAINER"
  printf '%-12s %s\n' "数据卷"   "$DATA_DIR"
  local st h
  st="$(docker inspect -f '{{.State.Status}}' "$CID" 2>/dev/null || true)"
  h="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$CID" 2>/dev/null || true)"
  printf '%-12s %s\n' "运行状态" "${st:-未创建}${h:+ / $h}"
  printf '%-12s %s\n' "健康接口" "$(health 2>/dev/null || echo '不可达')"

  printf '\n%sPDF 预览引擎%s\n' "$C_BOLD" "$C_RESET"
  if docker exec "$CID" sh -c 'command -v soffice >/dev/null 2>&1' 2>/dev/null; then
    printf '  %s\n' "$(docker exec "$CID" sh -c 'HOME=/tmp soffice --version 2>/dev/null | head -1' 2>/dev/null)"
    if docker exec "$CID" sh -c 'fc-list 2>/dev/null | grep -qi simfang' 2>/dev/null; then
      ok "仿宋字体在位：docx → PDF 保真预览可用"
    else
      warn "缺仿宋字体：PDF 能出，但仿宋会被替换成别的字形"
    fi
  else
    warn "未安装 LibreOffice：PDF 预览降级为 HTML（升级镜像即可，见 ./update.sh）"
  fi

  printf '\n%s工具层（apt）%s\n' "$C_BOLD" "$C_RESET"
  local miss=0 cmd pkg note
  while IFS='|' read -r cmd pkg note; do
    case "$cmd" in ''|\#*) continue ;; esac
    if docker exec "$CID" sh -c "command -v $cmd >/dev/null 2>&1" 2>/dev/null; then
      printf '  \033[32m✓\033[0m %-10s %s\n' "$cmd" "$pkg"
    else
      printf '  \033[33m✗\033[0m %-10s %s（./run.sh ensure 可补）\n' "$cmd" "$pkg"
      miss=$((miss + 1))
    fi
  done < "$TOOLS_FILE"

  printf '\n%s单文件二进制（卷）%s\n' "$C_BOLD" "$C_RESET"
  local n=0 f
  for f in "$HOSTBIN"/*; do
    [ -f "$f" ] || continue
    printf '  %-14s %s\n' "$(basename "$f")" "$(du -h "$f" | cut -f1)"
    n=$((n + 1))
  done
  [ "$n" = "0" ] && printf '  （空：全部由镜像提供，或尚未安装）\n'

  [ "$miss" = "0" ] && ok "全部工具就绪" || warn "$miss 项缺失，执行 ./run.sh ensure 补齐"
}

case "${1:-up}" in
  up|"")      shift || true; cmd_up "$@" ;;
  ensure)     shift || true; cmd_ensure "$@" ;;
  seed-skills) shift || true; cmd_seed_skills "$@" ;;
  down)       shift || true; cmd_down "$@" ;;
  restart)    shift || true; cmd_restart "$@" ;;
  status|ps)  shift || true; cmd_status "$@" ;;
  logs)       shift || true; cmd_logs "$@" ;;
  doctor)     shift || true; cmd_doctor "$@" ;;
  -h|--help|help)
    sed -n '2,/^set -euo/{/^set -euo/d;p}' "$0" ;;
  *) die "未知子命令：$1（可用：up / ensure / seed-skills / down / restart / status / logs / doctor）" ;;
esac
