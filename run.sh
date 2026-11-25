#!/usr/bin/env bash
# ARTEX 启动脚本（宿主机侧）——唯一推荐的服务入口。
#
# 与三个脚本的分工：
#   install.sh  首次落地（装 docker、问端口、生成 .env、起服务）
#   run.sh      **每次启动**：拉起服务 + 把「不持久的东西」补回来   ← 本文件
#   update.sh   升级/回滚：换镜像、备份与恢复数据库、离线导入
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
#   ./run.sh up           启动：环境自检 → 起服务 → ① 补二进制 → ② 补 apt 包
#   ./run.sh ensure       只做 ① ② 两步（更新镜像之后、或怀疑工具丢了时跑）
#   ./run.sh restart      重启容器（不重建，容器可写层的东西还在）
#   ./run.sh down         停止
#   ./run.sh status       状态
#   ./run.sh logs [-f]    日志
#   ./run.sh doctor       完整体检：容器、版本、PDF 预览引擎、工具缺口
#
# 环境变量（都可选）：
#   ARTEX_COMPOSE    compose 文件，默认 docker/docker-compose.hs.yml
#   ARTEX_DATA_DIR   覆盖 .env 里的数据目录
#   ARTEX_SKIP_TOOLS=1  只起服务，不做 ①②（离线且不关心工具时用）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
# 默认用 hs 单机部署（host 网络、外部 PG、8801）；没有 docker/.env 时退回仓库根
# 那份自带 PG 的 compose（8787）。两种都支持，也可以 ARTEX_COMPOSE=... 指定。
if [ -z "${ARTEX_COMPOSE:-}" ]; then
  if [ -f "$ROOT/docker/docker-compose.hs.yml" ] && [ -f "$ROOT/docker/.env" ]; then
    COMPOSE="$ROOT/docker/docker-compose.hs.yml"
  else
    COMPOSE="$ROOT/docker-compose.yml"
  fi
else
  COMPOSE="$ARTEX_COMPOSE"
fi
ENV_FILE="$(dirname "$COMPOSE")/.env"
TOOLS_FILE="$ROOT/docker/apt-tools.txt"

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# ── 读 docker/.env（与 compose 读的是同一份）──────────────
load_env() {
  [ -f "$ENV_FILE" ] || die "未找到 $ENV_FILE —— 首次部署请先运行 bash docker/init-env.sh"
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a

  COMPOSE_DIR="$(cd "$(dirname "$COMPOSE")" && pwd)"
  case "$COMPOSE" in
    */docker-compose.yml)
      # 仓库根那份 compose 固定挂 ./data:/app/data，ARTEX_DATA_DIR 在这里是
      # **容器内**路径（/app/data），不能拿去当宿主机目录用。
      DATA_DIR="$ROOT/data" ;;
    *)
      local d="${ARTEX_DATA_DIR:-./data}"
      case "$d" in
        /*) DATA_DIR="$d" ;;
        *)  DATA_DIR="$COMPOSE_DIR/${d#./}" ;;
      esac ;;
  esac
  IMAGE="${ARTEX_IMAGE:-rongsec/artex-a:latest}"
  # 服务名与容器名：hs 版服务叫 artex-hs（容器名同名）；仓库根那份 compose
  # 服务叫 artex，容器由 compose 自动命名（<项目>-artex-1），所以统一用
  # `compose ps -q <service>` 取容器 ID，不靠猜名字。
  case "$COMPOSE" in
    */docker-compose.yml) SERVICE=artex ;;
    *) SERVICE=artex-hs ;;
  esac
  CONTAINER="${ARTEX_CONTAINER_NAME:-$SERVICE}"
  # 健康检查打哪个端口：hs 版是 host 网络 + ARTEX_LISTEN_ADDR（默认 :8801）；
  # 根 compose 是端口映射 8787:8787，容器内外的 8787 都通。
  if [ -n "${ARTEX_LISTEN_ADDR:-}" ]; then
    PORT="${ARTEX_LISTEN_ADDR##*:}"
  else
    case "$COMPOSE" in
      */docker-compose.yml) PORT=8787 ;;
      *) PORT=8801 ;;
    esac
  fi
  HOSTBIN="$DATA_DIR/hostbin"
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) warn "未知架构 $ARCH，二进制自愈将只按 amd64 尝试" ; ARCH=amd64 ;;
  esac
}

compose() { docker compose -f "$COMPOSE" "$@"; }

# 容器 ID。不用容器名：hs 版有固定 container_name，仓库根那份是 compose 自动
# 命名的（<项目>-artex-1），靠猜必然有一边错。`compose ps -q <service>` 两边都对。
CID=""
refresh_cid() { CID="$(compose ps -q "$SERVICE" 2>/dev/null | head -1 || true)"; }

require_docker() {
  command -v docker >/dev/null 2>&1 || die "未检测到 docker，请先运行 ./install.sh"
  docker compose version >/dev/null 2>&1 || die "未检测到 docker compose 插件"
  docker info >/dev/null 2>&1 || die "docker 守护进程不可用（权限不足？试试 sudo usermod -aG docker \$USER 后重新登录）"
}

# ── 健康检查 ─────────────────────────────────────────────
# 容器内 /api/health 免鉴权，返回 {"ok":true,"version":"..."}。
health() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 3 "http://127.0.0.1:${PORT}/api/health" 2>/dev/null
  else
    docker exec "$CID" curl -fsS --max-time 3 "http://127.0.0.1:${PORT}/api/health" 2>/dev/null
  fi
}

wait_health() {
  local timeout="${1:-90}" i=0
  info "等待服务就绪（最长 ${timeout}s）…"
  while [ "$i" -lt "$timeout" ]; do
    if health >/dev/null 2>&1; then
      ok "服务就绪：$(health 2>/dev/null | tr -d '\n' | head -c 200)"
      return 0
    fi
    sleep 2
    i=$((i + 2))
  done
  warn "等待超时。查看日志：./run.sh logs"
  return 1
}

# ── ① 单文件二进制 → 卷 ─────────────────────────────────
# 「一次下载、永久在位」的那一类：静态链接的单个可执行文件。
# 落在 $DATA/hostbin（compose 里 ARTEX_HOSTBIN=/app/data/hostbin，PATH 第一位），
# 重建容器不受影响——所以这里通常什么都不用做，`--missing` 一查就退出。
ensure_bins() {
  printf '\n\033[1m① 工具自愈：单文件二进制 → %s\033[0m\n' "$HOSTBIN"
  mkdir -p "$HOSTBIN"

  # 卷里已有的补一次可执行位（从 Windows 拷进来、或解压时丢了 x 位）
  local f
  for f in "$HOSTBIN"/*; do
    [ -f "$f" ] || continue
    [ -x "$f" ] || chmod +x "$f" 2>/dev/null || true
  done

  local missing
  missing="$(bash "$ROOT/docker/hostbin/fetch.sh" --arch "$ARCH" --out "$HOSTBIN" --missing 2>/dev/null || true)"

  # 镜像里已经带了的（nuclei/httpx/…）不必再往卷里放一份
  local need="" key
  for key in $missing; do
    if docker exec "$CID" sh -c "command -v $key >/dev/null 2>&1" 2>/dev/null; then
      continue
    fi
    need="$need,$key"
  done
  need="${need#,}"

  if [ -z "$need" ]; then
    ok "无需补齐（$HOSTBIN 与镜像已覆盖全部清单）"
    return 0
  fi
  info "缺失：$need —— 从 GitHub 取（有 GITHUB_TOKEN 可避免限流）"
  if GITHUB_TOKEN="${GITHUB_TOKEN:-}" bash "$ROOT/docker/hostbin/fetch.sh" --arch "$ARCH" --out "$HOSTBIN" --only "$need"; then
    ok "二进制已落卷：$HOSTBIN"
  else
    warn "部分二进制未取到（网络受限？）。可稍后重跑 ./run.sh ensure，或在「宿主环境」页手工安装"
  fi
}

# ── ② 系统级 apt 包 → 容器内 ─────────────────────────────
# 这一层注定不持久：dpkg 装进的是容器可写层。所以每次启动都查一遍，
# 缺了就补——.deb 缓存在 $DATA/aptcache（compose 挂到 /var/cache/apt/archives），
# 补装时不必重新下载，通常十几秒。
ensure_pkgs() {
  printf '\n\033[1m② 工具自愈：系统级 apt 包 → 容器内\033[0m\n'
  [ -f "$TOOLS_FILE" ] || { warn "缺 $TOOLS_FILE，跳过"; return 0; }

  local missing="" cmd pkg note
  while IFS='|' read -r cmd pkg note; do
    case "$cmd" in ''|\#*) continue ;; esac
    if docker exec "$CID" sh -c "command -v $cmd >/dev/null 2>&1" 2>/dev/null; then
      continue
    fi
    missing="$missing $pkg"
  done < "$TOOLS_FILE"

  if [ -z "$missing" ]; then
    ok "无需补齐（$(grep -cvE '^#|^$' "$TOOLS_FILE" || true) 项全部在位）"
    return 0
  fi

  info "缺失：$missing"
  info "在容器内 apt-get install（deb 缓存在卷里，重装不重新下载）…"
  if docker exec -u 0 "$CID" sh -c \
      "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $missing"; then
    ok "系统级工具已补齐"
  else
    warn "补装未全部成功（源不可达或包名不存在）。容器重建后需要重跑本脚本"
  fi
}

ensure_all() {
  [ -n "$CID" ] || { warn "容器未运行，跳过工具自愈"; return 0; }
  ensure_bins
  ensure_pkgs
}

# ── 子命令 ───────────────────────────────────────────────
cmd_up() {
  require_docker
  load_env
  info "compose: $COMPOSE"
  info "镜像:    $IMAGE"
  info "数据:    $DATA_DIR"

  mkdir -p "$DATA_DIR"/{hostbin,pyenv,aptcache,aptlists} 2>/dev/null || true

  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    info "本地无该镜像，先拉取…"
    compose pull || die "拉取镜像失败。离线部署可用 ./update.sh import <镜像tar>"
  fi

  info "启动容器…"
  compose up -d
  refresh_cid

  if ! wait_health 90; then
    warn "服务未按时就绪，工具自愈仍然继续（有些工具恰好是排障要用的）"
  fi

  if [ "${ARTEX_SKIP_TOOLS:-0}" = "1" ]; then
    warn "ARTEX_SKIP_TOOLS=1：跳过 ①② 工具自愈"
  else
    ensure_all
  fi

  printf '\n'
  ok "完成 → http://127.0.0.1:${PORT}"
  info "日志：./run.sh logs -f    体检：./run.sh doctor"
}

cmd_ensure() {
  require_docker
  load_env
  refresh_cid
  [ -n "$CID" ] || die "容器未运行，先 ./run.sh up"
  ensure_all
}

cmd_down()    { load_env; compose down; ok "已停止"; }
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
  printf '\033[1mARTEX 体检\033[0m\n\n'

  printf '%-14s %s\n' "镜像"     "$IMAGE"
  printf '%-14s %s\n' "容器"     "$CONTAINER"
  printf '%-14s %s\n' "数据卷"   "$DATA_DIR"
  local st; st="$(docker inspect -f '{{.State.Status}} / {{.State.Health.Status}}' "$CID" 2>/dev/null || true)"
  printf '%-14s %s\n' "运行状态" "${st:-未创建}"
  local hv; hv="$(health 2>/dev/null || true)"
  printf '%-14s %s\n' "健康接口" "${hv:-不可达}"

  # PDF 预览：取决于镜像里有没有 soffice + 中文字体。没有就说明这份镜像老了
  # （v0.3.16-hs.6 及以前），报告预览会降级成 HTML。
  printf '\n\033[1mPDF 预览引擎\033[0m\n'
  if docker exec "$CID" sh -c 'command -v soffice >/dev/null 2>&1' 2>/dev/null; then
    printf '  %s\n' "$(docker exec "$CID" sh -c 'HOME=/tmp soffice --version 2>/dev/null | head -1' 2>/dev/null)"
    if docker exec "$CID" sh -c 'fc-list 2>/dev/null | grep -qi simfang' 2>/dev/null; then
      ok "仿宋字体在位：docx → PDF 保真预览可用"
    else
      warn "缺仿宋字体：PDF 能出，但模板里的仿宋会被替换成别的字形"
    fi
  else
    warn "未安装 LibreOffice：PDF 预览会降级为 HTML（升级镜像即可，见 ./update.sh）"
  fi

  printf '\n\033[1m工具层（apt）\033[0m\n'
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

  printf '\n\033[1m单文件二进制（卷）\033[0m\n'
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
  down)       shift || true; cmd_down "$@" ;;
  restart)    shift || true; cmd_restart "$@" ;;
  status|ps)  shift || true; cmd_status "$@" ;;
  logs)       shift || true; cmd_logs "$@" ;;
  doctor)     shift || true; cmd_doctor "$@" ;;
  -h|--help|help) sed -n '2,40p' "$0" ;;
  *) die "未知子命令：$1（可用：up / ensure / down / restart / status / logs / doctor）" ;;
esac
