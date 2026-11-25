#!/usr/bin/env bash
# ARTEX 更新脚本（宿主机侧）——升级、回滚、离线导入的唯一入口。
#
# 为什么从程序里搬到脚本：页面一键更新只能替换容器里的 /app/artex 一个文件。
# ① `docker compose up -d` 重建容器就退回镜像自带的版本（假成功）；
# ② 换不掉基础镜像里的 LibreOffice / apt 工具层 / Playwright（版本号上去了、
#    能力没上去，比不升级更难查）；③ 回滚要旧镜像 tag + 数据库快照，进程内做不到。
# 脚本能做的正是这三件：拉完整镜像、更新前 pg_dump、失败自动退回上一个 tag。
#
# 用法：
#   ./update.sh                 查看当前版本与可用命令
#   ./update.sh check           查询 GitHub 最新正式版，与当前镜像比较
#   ./update.sh to [tag]        升级到指定 tag（省略则用最新正式版）
#   ./update.sh rollback [tag]  回滚到上一版本（或指定 tag）
#        --with-db              回滚时连同数据库一起恢复（会覆盖现有数据）
#        --no-backup            跳过更新前备份（数据库很大、已有独立备份时用）
#   ./update.sh backup          只做一次备份（更新前会做的同一套）
#   ./update.sh list            本地镜像 + 备份列表
#   ./update.sh import <file>   离线导入镜像（tar / tar.gz）并切换
#   ./update.sh local           源码部署：拉代码 + 重新编译，替换 ./artex
#
# 备份内容（backups/<时间戳>/）：
#   image.txt   更新前的镜像引用与 digest（回滚靠它）
#   env.bak     docker/.env（含数据库口令，权限 0600）
#   config.json 裸机部署的配置文件（存在才备）
#   db.dump     pg_dump -Fc 全库快照（宿主机或容器里任一有 pg_dump 即可）
#
# 环境变量：
#   ARTEX_COMPOSE    compose 文件，默认 docker/docker-compose.hs.yml
#   ARTEX_MIRRORS    镜像加速前缀，空格分隔，默认 "docker.1ms.run"
#                    （生产机实测 Docker Hub 直连会超时，1ms.run 可用）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
# 与 run.sh 同一套自动识别：有 docker/.env 就用 hs 单机部署，否则用仓库根那份。
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
STATE_FILE="$(dirname "$COMPOSE")/.update-state"
BACKUP_ROOT="$ROOT/backups"
REPO_API="https://api.github.com/repos/RongSec/ARTEX-A/releases/latest"

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
ask()  { local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }

compose() { docker compose -f "$COMPOSE" "$@"; }

# ── 环境 ─────────────────────────────────────────────────
load_env() {
  [ -f "$ENV_FILE" ] || die "未找到 $ENV_FILE —— 首次部署请先运行 ./run.sh（会自动初始化）"
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
  case "$COMPOSE" in
    */docker-compose.yml) SERVICE=artex; DATA_DIR="$ROOT/data" ;;
    *) SERVICE=artex-hs
       local d="${ARTEX_DATA_DIR:-./data}"
       case "$d" in /*) DATA_DIR="$d" ;; *) DATA_DIR="$(cd "$(dirname "$COMPOSE")" && pwd)/${d#./}" ;; esac ;;
  esac
  CONTAINER="${ARTEX_CONTAINER_NAME:-$SERVICE}"
  PORT="${ARTEX_LISTEN_ADDR:-}"
  if [ -n "$PORT" ]; then PORT="${PORT##*:}"; else
    case "$COMPOSE" in */docker-compose.yml) PORT=8787 ;; *) PORT=8801 ;; esac
  fi
  REF="${ARTEX_IMAGE:-rongsec/artex-a:latest}"
  # 拆 repo 与 tag：最后一个路径段里含 ':' 才说明带了 tag
  local last="${REF##*/}"
  if [ "$last" != "${last%%:*}" ]; then
    IMAGE_REPO="${REF%:*}"; IMAGE_TAG="${REF##*:}"
  else
    IMAGE_REPO="$REF"; IMAGE_TAG="latest"
  fi
}

version_of() { # 读运行中容器的版本（/api/health）
  local r
  if command -v curl >/dev/null 2>&1; then
    r="$(curl -fsS --max-time 3 "http://127.0.0.1:${PORT}/api/health" 2>/dev/null || true)"
  else
    r="$(docker exec "$CONTAINER" curl -fsS --max-time 3 "http://127.0.0.1:${PORT}/api/health" 2>/dev/null || true)"
  fi
  [ -n "$r" ] || return 1
  printf '%s' "$r" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p'
}

# ── 版本查询 ─────────────────────────────────────────────
latest_tag() {
  command -v curl >/dev/null 2>&1 || { warn "缺少 curl，无法查询 GitHub"; return 1; }
  local auth=()
  [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  curl -fsSL --max-time 30 "${auth[@]}" "$REPO_API" \
    | grep -m1 '"tag_name"' | sed 's/.*"[[:space:]]*:[[:space:]]*"//;s/".*//'
}

# ── 镜像操作 ─────────────────────────────────────────────
pull_image() { # $1=tag
  local tag="$1" m
  local ref="${IMAGE_REPO}:${tag}"
  if docker image inspect "$ref" >/dev/null 2>&1; then
    ok "本地已有 $ref（跳过拉取）"; return 0
  fi
  info "拉取 $ref …"
  if docker pull "$ref"; then return 0; fi
  for m in ${ARTEX_MIRRORS:-docker.1ms.run}; do
    warn "直连失败，改走加速源 $m …"
    if docker pull "$m/$ref"; then
      docker tag "$m/$ref" "$ref"
      ok "已从 $m 拉取并重命名为 $ref"
      return 0
    fi
  done
  return 1
}

write_ref() { # $1=tag  → 写回 .env 的 ARTEX_IMAGE
  local ref="${IMAGE_REPO}:$1"
  if grep -q '^ARTEX_IMAGE=' "$ENV_FILE"; then
    sed -i.bak "s|^ARTEX_IMAGE=.*|ARTEX_IMAGE=${ref}|" "$ENV_FILE" && rm -f "$ENV_FILE.bak"
  else
    printf '\nARTEX_IMAGE=%s\n' "$ref" >> "$ENV_FILE"
  fi
  REF="$ref"; IMAGE_TAG="$1"
}

wait_health() { # $1=期望 tag（可空），$2=超时秒
  local expect="${1:-}" timeout="${2:-120}" i=0 v
  while [ "$i" -lt "$timeout" ]; do
    if v="$(version_of)"; then
      ok "健康检查通过，运行版本：$v"
      if [ -n "$expect" ] && [ "${v#v}" != "${expect#v}" ]; then
        warn "版本与目标 ${expect} 不一致——可能容器没重建，或拉到的是同名旧镜像"
        return 1
      fi
      return 0
    fi
    sleep 2; i=$((i + 2))
  done
  warn "等待健康检查超时（${timeout}s）"
  return 1
}

compose_up() { compose up -d --remove-orphans; }

# ── 备份 ─────────────────────────────────────────────────
backup() { # $1=目录
  local dir="$1"
  mkdir -p "$dir"; chmod 700 "$dir"

  {
    echo "ref=$REF"
    echo "digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$REF" 2>/dev/null || echo unknown)"
    echo "time=$(date '+%F %T')"
  } > "$dir/image.txt"

  cp -f "$ENV_FILE" "$dir/env.bak" 2>/dev/null && chmod 600 "$dir/env.bak" || true
  for c in "$ROOT/config.json" "$DATA_DIR/config.json"; do
    [ -f "$c" ] && cp -f "$c" "$dir/config.json" 2>/dev/null || true
  done

  # 数据库快照。pg_dump 优先用宿主机的（生产机装了原生 PostgreSQL 18），
  # 其次用容器里的（镜像内置 postgresql-client）。都没有就明确说没备——
  # 别让用户以为「备份过了」。
  if [ -n "${ARTEX_PG_DSN:-}" ]; then
    if command -v pg_dump >/dev/null 2>&1; then
      info "pg_dump（宿主机）→ $dir/db.dump"
      if pg_dump "$ARTEX_PG_DSN" -Fc -f "$dir/db.dump" 2>/dev/null; then
        ok "数据库已备份（$(du -h "$dir/db.dump" | cut -f1)）"
      else
        warn "pg_dump 失败（数据库不可达？）——继续升级，但本次没有数据库快照"
        rm -f "$dir/db.dump"
      fi
    elif docker exec "$CONTAINER" sh -c 'command -v pg_dump >/dev/null 2>&1' 2>/dev/null; then
      info "pg_dump（容器内）→ $dir/db.dump"
      if docker exec "$CONTAINER" pg_dump "$ARTEX_PG_DSN" -Fc > "$dir/db.dump" 2>/dev/null; then
        ok "数据库已备份（$(du -h "$dir/db.dump" | cut -f1)）"
      else
        warn "容器内 pg_dump 失败——本次没有数据库快照"
        rm -f "$dir/db.dump"
      fi
    else
      warn "找不到 pg_dump，跳过数据库备份（结构迁移是幂等前向的，通常无需回滚数据）"
    fi
  else
    warn "ARTEX_PG_DSN 为空，跳过数据库备份"
  fi
}

save_state() { # $1=prev_ref  $2=new_ref  $3=backup_dir
  umask 077
  cat > "$STATE_FILE" <<EOF
PREV_REF=$1
CUR_REF=$2
BACKUP_DIR=$3
TIME=$(date '+%F %T')
EOF
  chmod 600 "$STATE_FILE"
}

# ── 主流程 ───────────────────────────────────────────────
cmd_check() {
  load_env
  local cur="$IMAGE_TAG" latest
  printf '当前镜像 : %s\n' "$REF"
  version_of >/dev/null 2>&1 && printf '运行版本 : %s\n' "$(version_of)" || printf '运行版本 : 服务未响应\n'
  if ! latest="$(latest_tag)"; then
    die "查询 GitHub 失败（内网？可在部署机设 https_proxy 后重试）"
  fi
  printf '最新发布 : %s\n\n' "$latest"
  if [ "$cur" = "$latest" ]; then
    ok "已是最新版本"
  else
    info "有新版本。升级：./update.sh to $latest"
  fi
}

cmd_to() {
  local tag="${1:-}" no_backup=0
  shift || true
  for a in "$@"; do case "$a" in --no-backup) no_backup=1 ;; esac; done
  load_env

  [ -n "$tag" ] || { info "查询最新正式版…"; tag="$(latest_tag)" || die "查询 GitHub 失败，请显式指定 tag"; }
  [ "$tag" = "$IMAGE_TAG" ] && { ok "当前已是 $tag，无需更新"; return 0; }

  info "升级 $IMAGE_TAG → $tag"

  local dir=""
  if [ "$no_backup" = "1" ]; then
    warn "--no-backup：跳过备份"
  else
    dir="$BACKUP_ROOT/$(date '+%Y%m%d-%H%M%S')"
    info "备份当前状态 → $dir"
    backup "$dir"
  fi

  pull_image "$tag" || die "拉取 ${IMAGE_REPO}:${tag} 失败。离线环境请用 ./update.sh import <镜像tar>"

  local prev="$REF"
  write_ref "$tag"
  info "重建容器…"
  if compose_up && wait_health "$tag" 120; then
    save_state "$prev" "$REF" "$dir"
    ok "已升级到 $tag"
    if [ -x "$ROOT/run.sh" ]; then
      info "重建容器会丢掉容器可写层里的 apt 工具，跑一次工具自愈…"
      ARTEX_COMPOSE="$COMPOSE" bash "$ROOT/run.sh" ensure || warn "工具自愈未全部成功，稍后可重跑 ./run.sh ensure"
    fi
    return 0
  fi

  warn "升级失败，自动回滚到 $prev"
  write_ref "${prev##*:}"
  compose_up || true
  wait_health "" 90 || warn "回滚后健康检查仍未通过，请查看 ./run.sh logs"
  die "已回滚。原因见上方日志与 $dir"
}

cmd_rollback() {
  local target="" with_db=0
  for a in "$@"; do
    case "$a" in
      --with-db) with_db=1 ;;
      -*) die "未知参数 $a" ;;
      *) target="$a" ;;
    esac
  done
  load_env

  local prev="" backup_dir=""
  if [ -f "$STATE_FILE" ]; then
    # shellcheck disable=SC1090
    . "$STATE_FILE"
    prev="${PREV_REF:-}"; backup_dir="${BACKUP_DIR:-}"
  fi
  [ -n "$target" ] || target="${prev##*:}"
  [ -n "$target" ] || die "没有可回滚的目标。用法：./update.sh rollback <tag>（./update.sh list 看本地镜像）"

  local ref="${IMAGE_REPO}:${target}"
  docker image inspect "$ref" >/dev/null 2>&1 || die "本地没有 $ref。先 docker pull 或 ./update.sh import"

  info "回滚 $IMAGE_TAG → $target"
  write_ref "$target"
  compose_up || true
  wait_health "$target" 120 || die "回滚后健康检查未通过，查看 ./run.sh logs"
  ok "已回滚到 $target"

  if [ "$with_db" = "1" ]; then
    [ -n "$backup_dir" ] && [ -f "$backup_dir/db.dump" ] || die "找不到备份快照（$backup_dir/db.dump）"
    warn "即将用 $backup_dir/db.dump 覆盖当前数据库（--clean --if-exists）"
    [ "$(ask '确认恢复数据库? (y/N)' n)" = y ] || { info "已跳过数据库恢复"; return 0; }
    if command -v pg_restore >/dev/null 2>&1; then
      pg_restore --clean --if-exists -d "$ARTEX_PG_DSN" "$backup_dir/db.dump"
    else
      docker exec -i "$CONTAINER" pg_restore --clean --if-exists -d "$ARTEX_PG_DSN" < "$backup_dir/db.dump"
    fi
    ok "数据库已恢复"
    info "重启使缓存失效：./run.sh restart"
  else
    info "数据库未动。旧版本可能读不懂新版写入的表结构，必要时加 --with-db 重跑"
  fi
}

cmd_backup() {
  load_env
  local dir="$BACKUP_ROOT/$(date '+%Y%m%d-%H%M%S')"
  backup "$dir"
  ok "备份完成 → $dir"
}

cmd_list() {
  load_env
  printf '\033[1m本地镜像\033[0m（%s）\n' "$IMAGE_REPO"
  docker images "$IMAGE_REPO" --format '  {{.Tag}}\t{{.Size}}\t{{.CreatedSince}}' | sort -V || true
  printf '\n\033[1m备份\033[0m（%s）\n' "$BACKUP_ROOT"
  if [ -d "$BACKUP_ROOT" ]; then
    for d in "$BACKUP_ROOT"/*/; do
      [ -d "$d" ] || continue
      printf '  %s  %s%s\n' "$(basename "$d")" \
        "$(sed -n 's/^ref=//p' "$d/image.txt" 2>/dev/null)" \
        "$([ -f "$d/db.dump" ] && echo "  (含数据库快照)")"
    done
  else
    printf '  （暂无）\n'
  fi
  printf '\n当前：%s\n' "$REF"
}

cmd_import() {
  local f="${1:-}"
  [ -n "$f" ] && [ -f "$f" ] || die "用法：./update.sh import <镜像tar|tar.gz>"
  load_env
  info "导入 $f …"
  case "$f" in
    *.gz|*.tgz) gzip -dc "$f" | docker load ;;
    *) docker load -i "$f" ;;
  esac
  printf '\n导入后的镜像：\n'
  docker images --format '  {{.Repository}}:{{.Tag}}' | grep -F "${IMAGE_REPO##*/}" || true
  local tag; tag="$(ask '要切换到哪个 tag' '')"
  [ -n "$tag" ] || { info "未指定 tag，仅导入未切换"; return 0; }
  docker image inspect "${IMAGE_REPO}:${tag}" >/dev/null 2>&1 || \
    docker tag "$(ask '本地镜像引用（repo:tag）' '')" "${IMAGE_REPO}:${tag}" 2>/dev/null || \
    die "本地没有 ${IMAGE_REPO}:${tag}，请先 docker tag 成这个名字"
  write_ref "$tag"
  compose_up
  wait_health "$tag" 120 || die "切换后健康检查未通过"
  ok "已切换到 $tag"
}

cmd_local() {
  command -v go >/dev/null 2>&1 || die "未检测到 Go（>=1.26）：https://go.dev/dl/"
  cd "$ROOT"
  if [ -d .git ] && command -v git >/dev/null 2>&1; then
    info "拉取最新代码（--ff-only）…"
    git pull --ff-only || warn "git pull 未快进，沿用当前代码"
  fi
  if command -v npm >/dev/null 2>&1; then
    info "重建前端静态产物…"
    ( cd web && npm ci && npm run build:static )
    rm -rf server/webui/dist && cp -r web/out server/webui/dist
    info "编译内嵌单二进制…"
    CGO_ENABLED=0 go build -tags embedui -trimpath -o artex ./cmd/artex
  else
    warn "未检测到 npm：编译**不内嵌前端**的后端"
    CGO_ENABLED=0 go build -o artex ./cmd/artex
  fi
  ok "编译完成 → $ROOT/artex（重启服务后生效）"
}

cmd_help() {
  # 打印文件头的注释块：从第 2 行到 `set -euo pipefail` 之前。
  sed -n '2,/^set -euo/{
    /^set -euo/d
    p
  }' "$0"
  printf '\n'
  if [ -f "$ENV_FILE" ]; then load_env; printf '当前镜像：%s\n' "$REF"; fi
}

case "${1:-help}" in
  check)    shift || true; cmd_check "$@" ;;
  to|update) shift || true; cmd_to "$@" ;;
  rollback) shift || true; cmd_rollback "$@" ;;
  backup)   shift || true; cmd_backup "$@" ;;
  list|ls)  shift || true; cmd_list "$@" ;;
  import)   shift || true; cmd_import "$@" ;;
  local)    shift || true; cmd_local "$@" ;;
  help|-h|--help) cmd_help ;;
  *) die "未知命令：$1（可用：check / to / rollback / backup / list / import / local）" ;;
esac
