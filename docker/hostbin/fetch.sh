#!/usr/bin/env bash
# 拉取 Go 类宿主工具的【预编译 release 二进制】，供 Dockerfile 打进镜像。
#
# 为什么不在构建期编译（go install）：
#   构建机 4C/7G、可用内存约 1G。nuclei v3 单次编译约 36 分钟且导出镜像时 OOM；
#   即使加内存到 16G，每次重建仍要重烧这 36 分钟。这些项目都提供官方静态二进制，
#   直接取 release：构建退化成一次 COPY，秒级完成，运行时零额外开销。
#
# 用法：
#   bash docker/hostbin/fetch.sh                  # 当前架构（默认 amd64）
#   bash docker/hostbin/fetch.sh --arch arm64     # 交叉取 arm64
#   bash docker/hostbin/fetch.sh --force          # 全部重下
#   bash docker/hostbin/fetch.sh --list           # 打印已取到的版本清单
#
# 产物目录：docker/hostbin/<arch>/（.gitignore 排除，只把本脚本 + 清单入库）。
# 升级工具：改 VERSIONS 表 → 重跑 → 提交脚本改动即可，二进制由 CI/部署机现取。
#
# 有 GITHUB_TOKEN 时用它调 GitHub API：匿名 60 次/小时，CI 里多次重跑很容易打满。

set -uo pipefail
cd "$(dirname "$0")" || exit 1

ARCH="${ARCH:-amd64}"
FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --force) FORCE=1 ;;
    --list)  cat "$ARCH/VERSIONS.txt" 2>/dev/null || echo "(未拉取)"; exit 0 ;;
    --arch)  shift; ARCH="${1:-amd64}" ;;
    --arch=*) ARCH="${1#--arch=}" ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
  esac
  shift
done

case "$ARCH" in
  amd64) DALFOX_ARCH="x86_64" ;;
  arm64) DALFOX_ARCH="arm64" ;;
  *) echo "不支持的架构: $ARCH（只支持 amd64 / arm64）" >&2; exit 2 ;;
esac

OUT="./$ARCH"
mkdir -p "$OUT"

# key|repo|tag|资产正则|归档类型(bin/zip/tgz/gz)|必需(1/0)
#
# 正则里的 <arch> / <dalfoxarch> 会在运行时替换。dalfox 只发 x86_64 与 arm64
# 两种命名（v3.3.0 没有 arm64 的 glibc 包时会被判为可选件缺失，不阻断构建）。
# ffuf / dalfox 不是扫描主链路（目录爆破、XSS 辅助），缺了只告警；
# nuclei/httpx/subfinder/katana/dnsx/tlsx/chisel/ffuf 是目标任务主力，缺一即失败。
VERSIONS='
nuclei|projectdiscovery/nuclei|v3.11.1|nuclei_.*_linux_<arch>\.zip|zip|1
httpx|projectdiscovery/httpx|v1.12.0|httpx_.*_linux_<arch>\.zip|zip|1
subfinder|projectdiscovery/subfinder|v2.17.0|subfinder_.*_linux_<arch>\.zip|zip|1
katana|projectdiscovery/katana|v1.8.0|katana_.*_linux_<arch>\.zip|zip|1
dnsx|projectdiscovery/dnsx|v1.3.1|dnsx_.*_linux_<arch>\.zip|zip|1
tlsx|projectdiscovery/tlsx|v1.5.0|tlsx_.*_linux_<arch>\.zip|zip|1
chisel|jpillora/chisel|v1.12.0|chisel_.*linux_<arch>\.gz|gz|1
amass|owasp-amass/amass|v5.1.3|amass_linux_<arch>\.tar\.gz|tgz|1
ffuf|ffuf/ffuf|v2.3.0|ffuf_.*_linux_<arch>\.tar\.gz|tgz|1
dalfox|hahwul/dalfox|v3.3.0|dalfox-v.*-linux-<dalfoxarch>\.tar\.gz|tgz|0
'

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

api_auth=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
  api_auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

# 解压归档，把里面的可执行文件（名字等于 key）挪到输出目录。
unpack() { # $1=归档 $2=类型 $3=key
  local f="$1" kind="$2" key="$3" found=""
  case "$kind" in
    zip)
      python3 -c "import zipfile,sys;zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$f" "$TMP/x" || return 1
      ;;
    tgz)
      mkdir -p "$TMP/x" && tar -xzf "$f" -C "$TMP/x" || return 1
      ;;
    gz)
      mkdir -p "$TMP/x" && gzip -dc "$f" > "$TMP/x/$key" || return 1
      ;;
  esac
  found="$(find "$TMP/x" -type f -name "$key" | head -1)"
  [ -n "$found" ] || { echo "  !! 归档里找不到 $key"; return 1; }
  mv -f "$found" "$OUT/$key" && chmod +x "$OUT/$key"
}

: > "$OUT/VERSIONS.txt"
FAILED=0
MISSING_OPTIONAL=0
while IFS='|' read -r key repo tag pat kind essential; do
  [ -n "$key" ] || continue
  if [ -x "$OUT/$key" ] && [ "$FORCE" = "0" ]; then
    echo "== $key: 已存在，跳过（--force 重下）"
    printf '%-10s %-10s %s\n' "$key" "$tag" "$repo" >> "$OUT/VERSIONS.txt"
    continue
  fi
  pat="${pat//<arch>/$ARCH}"
  pat="${pat//<dalfoxarch>/$DALFOX_ARCH}"
  url="$(curl -fsSL --max-time 60 "${api_auth[@]}" "https://api.github.com/repos/$repo/releases/tags/$tag" \
        | python3 -c "
import json,re,sys
d=json.load(sys.stdin)
pat=re.compile(sys.argv[1])
for a in d.get('assets',[]):
    if pat.search(a['name']):
        print(a['browser_download_url']); break
" "$pat")"
  if [ -z "$url" ]; then
    if [ "$essential" = "1" ]; then
      echo "== $key: 找不到 $tag 的 linux-$ARCH 资产"
      FAILED=$((FAILED+1))
    else
      echo "== $key: 该版本无 linux-$ARCH 资产，跳过（可选件）"
      MISSING_OPTIONAL=$((MISSING_OPTIONAL+1))
    fi
    continue
  fi
  echo "== $key $tag ← $(basename "$url")"
  rm -rf "$TMP/x"; mkdir -p "$TMP/x"
  if ! curl -fL --retry 3 --max-time 900 -o "$TMP/arch" "$url"; then
    echo "  !! 下载失败"; FAILED=$((FAILED+1)); continue
  fi
  if ! unpack "$TMP/arch" "$kind" "$key"; then
    echo "  !! 解压失败"; FAILED=$((FAILED+1)); continue
  fi
  printf '%-10s %-10s %s\n' "$key" "$tag" "$repo" >> "$OUT/VERSIONS.txt"
done <<< "$VERSIONS"

echo
echo "=== 产物 ($(pwd)/$(basename "$OUT"))"
ls -1sh "$OUT"/* 2>/dev/null | grep -v 'VERSIONS.txt' || true
echo "=== 清单"
cat "$OUT/VERSIONS.txt"
[ "$MISSING_OPTIONAL" = "0" ] || echo "!! $MISSING_OPTIONAL 个可选件在本架构无官方产物（不影响构建）"
[ "$FAILED" = "0" ] || { echo "!! 有 $FAILED 个必需工具失败，见上" >&2; exit 1; }
