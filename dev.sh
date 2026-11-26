#!/usr/bin/env bash
# 开发模式：后端(:8787) + 流量代理(:8788) 与 前端 next dev(:5173) 一起跑。
# 前端 /api 反代到后端；Ctrl-C 一并退出。
#
# 单二进制（前端内嵌）方式见 README「单二进制」一节，不走这个脚本。
set -euo pipefail
cd "$(dirname "$0")"

# 提交前敏感内容闸门（路径/凭据/机构标识/网段，含 docx 与二进制）。
# 每个 clone 装一次即可；装不上不阻断开发，CI 仍会拦。
git config core.hooksPath .githooks 2>/dev/null || true

# 开发模式下 SkillDir 默认是 BaseDir()/skills，而 go run 的 BaseDir 就是源码根，
# 于是界面上新建的技能会写进仓库目录。指到 data/ 下（已 ignore），保持源码干净。
export ARTEX_SKILL_DIR="$PWD/data/skills"

# 退出时结束本进程组内的所有子进程（后端 + 前端）。
cleanup() { kill 0 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# 后端（普通 go run，不内嵌前端）；并发 work agent 数在「系统设置」里配置。
go run ./cmd/artex -addr :8787 -proxy 127.0.0.1:8788 &

# 前端热更新（Vite/Next dev server，/api 反代到 :8787）。
( cd web && npm run dev ) &

echo "[dev] 后端 :8787 / 代理 :8788 / 前端 http://localhost:5173  (Ctrl-C 退出)"
wait
