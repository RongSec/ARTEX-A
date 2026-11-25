#!/usr/bin/env bash
# 兼容入口：安装已合并进 ./run.sh。
#
# 以前这里是「① 全部 Docker ② 本地编译」两条互不相干的路径，各自生成不同的
# .env / compose（8787 vs 8801、自带库 vs 外部库），装完就有两套系统并存。
# 现在只保留一条：run.sh。首次运行会自动生成 docker/.env、拉镜像、起库、补工具。
#
# 老文档里的 `./install.sh` 仍然可用，直接转发。
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"
echo "[!] install.sh 已合并到 run.sh —— 直接执行 ./run.sh 即可（首次会自动初始化）"
exec ./run.sh "$@"
