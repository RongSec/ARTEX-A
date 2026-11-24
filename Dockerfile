# syntax=docker/dockerfile:1
#
# 运行镜像（不在镜像里编译）：只装常用工具，放入**预编译好的 Linux 单二进制**。
# 二进制由 CI 的 binaries job 交叉编译（纯 Go、无 QEMU），按目标架构放在
# 构建上下文的 dist/<TARGETARCH>/artex。这样多架构构建时 arm64 只需模拟 apt 层，
# 不再模拟 Next/Go 编译，速度快得多。
#
# 本地手动构建镜像时，先自行准备二进制：
#   cd web && npm run build:static && cd ..
#   cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/artex ./cmd/artex
#   docker build -t artex:local .
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# 常用工具：ripgrep / curl / vim，加一批 recon 常备件。
# 包清单在 docker/apt-core.txt：与 hosttools/catalog.go 的 preinstalled 基线对齐，
# 改这里必须同步改那边，否则页面会把「镜像没装」说成「断网可用」。
# Node 从 NodeSource 装 20.x：bookworm 自带的 apt nodejs 是 18，Playwright 要求 >=20。
COPY docker/apt-core.txt /tmp/apt-core.txt
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates ripgrep vim git jq unzip iputils-ping inetutils-telnet \
      $(grep -v '^#' /tmp/apt-core.txt | grep -v '^$' | tr '\n' ' ') \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# 预装 Playwright MCP 与 CLI（全局），运行时不再 npx 联网下载。
# @playwright/mcp：browser MCP 直接 `npx @playwright/mcp`（已全局装好，无需 -y/@latest）。
# @playwright/cli：提供 playwright-cli，装完顺带 --help 验证可执行。
# 再装 playwright（提供浏览器管理），装完用 --with-deps 预置 chromium 及其系统依赖，
# 这样容器内 MCP/CLI 首次启动即可用，不再联网下载浏览器。
RUN npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
# ---- 预置探测工具层（nuclei / httpx / subfinder / katana / dnsx / tlsx / chisel / ffuf …
#      共 9 件，约 380MB）----
# 二进制由 docker/hostbin/fetch.sh 在构建前现取，不入库；CI 会为 amd64 与 arm64
# 各取一份放进 docker/hostbin/<arch>/。这里按 TARGETARCH 选择对应目录。
# 位置刻意放在业务二进制之前：工具层极少变，改代码只重建后面的小层。
COPY docker/hostbin/ /tmp/hostbin/
RUN set -eux; \
    dir="/tmp/hostbin/${TARGETARCH}"; \
    if [ -d "$dir" ]; then \
      for f in "$dir"/*; do \
        case "$f" in *VERSIONS.txt) continue ;; esac; \
        install -m 0755 "$f" "/usr/local/bin/$(basename "$f")"; \
      done; \
      echo "工具层(${TARGETARCH}): $(ls -1 "$dir" | grep -v VERSIONS.txt | tr '\n' ' ')"; \
    else \
      echo "WARN: docker/hostbin/${TARGETARCH} 不存在；本镜像不含 nuclei 等工具，需在「宿主环境」页安装" >&2; \
    fi; \
    rm -rf /tmp/hostbin; \
    for b in nuclei httpx subfinder katana dnsx tlsx chisel; do \
      if command -v "$b" >/dev/null 2>&1; then "$b" -version 2>&1 | head -1 || true; fi; \
    done

WORKDIR /app
# 预编译好的对应架构二进制（dist/amd64/artex 或 dist/arm64/artex）
COPY dist/${TARGETARCH}/artex /app/artex
# 守护启动脚本：进程退出后按退出码决定是否重新拉起，页面一键更新靠它完成换装。
# 它同时负责把 SIGTERM 转发给 artex —— docker stop 只把信号发给 PID 1，
# 不转发的话 artex 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY start.sh /app/start.sh
RUN chmod +x /app/artex /app/start.sh
COPY skills/ /app/skills/
# data/（SQLite + jwt.key）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
