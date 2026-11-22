#!/usr/bin/env bash
# 拉取 Go 类宿主工具的【预编译 linux-amd64 release 二进制】到本目录，供 Dockerfile
# 的 `COPY docker/hostbin/ /usr/local/bin/` 打进镜像。
#
# 为什么不用 `go install`（构建期编译）：
#   构建机 4C/7G、可用内存约 1G。nuclei v3 单次编译约 36 分钟且导出镜像时 OOM；
#   即使加内存到 16G，每次重建仍要重烧这 36 分钟——可用性和开销都不划算。
#   这些项目全部提供官方 linux-amd64 静态二进制，直接取 release 即可：构建变成
#   一次 COPY，秒级完成，运行时零额外开销。
#
# 用法（有外网的机器上跑一次，产物随仓库/构建上下文分发）：
#   bash docker/hostbin/fetch.sh            # 缺什么补什么（幂等）
#   bash docker/hostbin/fetch.sh --force    # 全部重下
#   bash docker/hostbin/fetch.sh --list     # 只打印当前版本清单
#
# 升级工具：改下面的 VERSIONS 表 → 重跑 → 提交 docker/hostbin/VERSIONS.txt。
# 产物（二进制）建议 .gitignore，只把本脚本 + VERSIONS.txt 入库——
#   二进制由发布流水线/部署机按脚本现取，避免仓库塞 400MB。

set -uo pipefail
cd "$(dirname "$0")" || exit 1

FORCE=0
for a in "$@"; do
  case "$a" in
    --force) FORCE=1 ;;
    --list)  cat VERSIONS.txt 2>/dev/null || echo "(未拉取)"; exit 0 ;;
  esac
done

# key|repo|tag|asset 正则|归档类型(bin/zip/tgz/gz)
VERSIONS='
nuclei|projectdiscovery/nuclei|v3.11.1|nuclei_.*_linux_amd64\.zip|zip
httpx|projectdiscovery/httpx|v1.12.0|httpx_.*_linux_amd64\.zip|zip
subfinder|projectdiscovery/subfinder|v2.17.0|subfinder_.*_linux_amd64\.zip|zip
katana|projectdiscovery/katana|v1.8.0|katana_.*_linux_amd64\.zip|zip
dnsx|projectdiscovery/dnsx|v1.3.1|dnsx_.*_linux_amd64\.zip|zip
tlsx|projectdiscovery/tlsx|v1.5.0|tlsx_.*_linux_amd64\.zip|zip
ffuf|ffuf/ffuf|v2.3.0|ffuf_.*_linux_amd64\.tar\.gz|tgz
dalfox|hahwul/dalfox|v3.3.0|dalfox-.*linux-x86_64\.tar\.gz|tgz
chisel|jpillora/chisel|v1.12.0|chisel_.*linux_amd64\.gz|gz
'

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 解压归档，把里面的可执行文件（名字等于 key）挪到本目录。
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
  mv -f "$found" "./$key" && chmod +x "./$key"
}

: > VERSIONS.txt
FAILED=0
while IFS='|' read -r key repo tag pat kind; do
  [ -n "$key" ] || continue
  if [ -x "./$key" ] && [ "$FORCE" = "0" ]; then
    echo "== $key: 已存在，跳过（--force 重下）"
    printf '%-10s %-10s %s\n' "$key" "$tag" "$repo" >> VERSIONS.txt
    continue
  fi
  url="$(curl -fsSL --max-time 60 "https://api.github.com/repos/$repo/releases/tags/$tag" \
        | python3 -c "
import json,re,sys
d=json.load(sys.stdin)
pat=re.compile(sys.argv[1])
for a in d.get('assets',[]):
    if pat.search(a['name']):
        print(a['browser_download_url']); break
" "$pat")"
  if [ -z "$url" ]; then
    echo "== $key: 找不到 $tag 的 linux-amd64 资产（跳过）"
    FAILED=$((FAILED+1)); continue
  fi
  echo "== $key $tag ← $(basename "$url")"
  rm -rf "$TMP/x"; mkdir -p "$TMP/x"
  if ! curl -fL --retry 3 --max-time 600 -o "$TMP/arch" "$url"; then
    echo "  !! 下载失败"; FAILED=$((FAILED+1)); continue
  fi
  if ! unpack "$TMP/arch" "$kind" "$key"; then
    echo "  !! 解压失败"; FAILED=$((FAILED+1)); continue
  fi
  printf '%-10s %-10s %s\n' "$key" "$tag" "$repo" >> VERSIONS.txt
done <<< "$VERSIONS"

echo
echo "=== 产物 ($(pwd))"
ls -1sh ./* 2>/dev/null | grep -v 'fetch.sh\|VERSIONS.txt' || true
echo "=== 清单"
cat VERSIONS.txt
[ "$FAILED" = "0" ] || { echo "!! 有 $FAILED 个工具失败，见上"; exit 1; }
