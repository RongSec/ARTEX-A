# V9-DOCKER：自带排版引擎与中文字体的单镜像。
#   web   → Next 静态导出（web/out）
#   build → 把 out 嵌进 Go 单二进制（-tags embedui）
#   final → debian + LibreOffice(Writer) + Noto CJK + Windows 常用中文字体
#
# 不声明 `# syntax=` 外部 frontend：部署机 Docker Hub 直连受限，只走
# daemon.json 的 registry mirror 拉基础镜像，避免额外拉 dockerfile:1。
#
# 构建上下文必须是仓库根（本文件在 docker/ 下）：
#   docker build -f docker/Dockerfile -t artex:local .
# compose 已在 docker/docker-compose.yml 里配好 context: ..

# ---------- 1. 前端静态导出 ----------
FROM node:22-slim AS web
# 国内网络默认走 npmmirror（--build-arg NPM_REGISTRY= 可切回官方源）。
ARG NPM_REGISTRY=https://registry.npmmirror.com
RUN if [ -n "$NPM_REGISTRY" ]; then \
      npm config set registry "$NPM_REGISTRY" && \
      npm config set replace-registry-host always; \
    fi
WORKDIR /src/web
# 先只拷 manifest，命中依赖层缓存（改源码不重装 node_modules）。
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
# SKIP_TSC=1：类型检查在 CI/发布前用 `tsc --noEmit` 单独跑；镜像构建不重复
# 跑一遍（部署机 4C/8G 且负载高时，Next 内联 tsc 会多花 15 分钟）。
ENV NEXT_EXPORT=1 \
    NEXT_TELEMETRY_DISABLED=1 \
    SKIP_TSC=1
RUN npm run build

# ---------- 2. Go 单二进制（内嵌 out/）----------
FROM golang:1.26 AS build
# 国内网络默认走 goproxy.cn（--build-arg GOPROXY= 可切回官方源）。
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# embedui 读 server/webui/dist；.dockerignore 排除了本地产物，这里用真实构建覆盖。
COPY --from=web /src/web/out ./server/webui/dist
ENV CGO_ENABLED=0 \
    GOOS=linux
RUN go build -trimpath -tags embedui -ldflags "-s -w" -o /out/artex ./cmd/artex

# ---------- 3. 运行阶段：LibreOffice + 中文字体 ----------
FROM debian:bookworm-slim
# 国内网络默认走阿里云 Debian 镜像（--build-arg APT_MIRROR= 可切回官方源）。
ARG APT_MIRROR=mirrors.aliyun.com
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    HOME=/app \
    ARTEX_LISTEN_ADDR=:8787

# libreoffice-writer：docx→pdf 的排版引擎（不装整套 LibreOffice，省 ~400MB）。
# fonts-noto-cjk：兜底 CJK（模板里写了「等线/微软雅黑」等系统字体时至少有字可显）。
# fonts-dejavu-core：拉丁字符基础字体。
# python3 + python3-docx：report/pybuilder 生成 docx 的运行时（render-draft 依赖）。
# fontconfig + fc-cache：让 soffice 真正认到 /usr/share/fonts/truetype/win 下的字体。
#
# 与根目录 Dockerfile 保持同一套能力：apt-core（基础层）+ apt-tools（工具层，
# 循环安装、单件失败只告警）+ 排版层。两个镜像除了「前端在镜像里编译还是预编译」
# 之外，运行时能力必须完全一致，否则同一个版本会出现「本地能预览、Hub 版不能」。
COPY docker/apt-core.txt docker/apt-tools.txt /tmp/
RUN set -eux; \
    if [ -n "${APT_MIRROR}" ]; then \
      for f in /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources; do \
        if [ -f "$f" ]; then sed -i "s|deb.debian.org|${APT_MIRROR}|g" "$f"; fi; \
      done; \
    fi; \
    apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl tzdata fontconfig \
      $(grep -v '^#' /tmp/apt-core.txt | grep -v '^$' | tr '\n' ' ') \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    while IFS='|' read -r cmd pkg note; do \
      case "$cmd" in ''|\#*) continue ;; esac; \
      if command -v "$cmd" >/dev/null 2>&1; then echo "工具层: $cmd 已随基础层就位"; continue; fi; \
      if apt-get install -y --no-install-recommends "$pkg"; then \
        echo "工具层: $cmd ← $pkg"; \
      else \
        echo "WARN 工具层: $pkg 安装失败，已跳过" >&2; \
      fi; \
    done < /tmp/apt-tools.txt
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends \
      libreoffice-writer \
      fonts-noto-cjk fonts-dejavu-core \
      python3 python3-docx \
    && rm -rf /var/lib/apt/lists/*

# 随镜像自带仿宋/黑体/宋体/Times（用户不再需要自己装字体）。
COPY docker/fonts/ /usr/share/fonts/truetype/win/
RUN fc-cache -f \
    && fc-list | grep -Ei "simfang|simhei|simsun|times new roman" >/dev/null

WORKDIR /app

# 预置探测工具（可选）：docker/hostbin/<arch>/ 存在才装。本地没跑 fetch.sh
# 也能构建（只告警），正式发布镜像由根目录 Dockerfile 负责带全套工具。
ARG TARGETARCH=amd64
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
      echo "WARN: 未预置 ${TARGETARCH} 工具二进制（只影响 nuclei 等，不影响主程序）" >&2; \
    fi; \
    rm -rf /tmp/hostbin

COPY --from=build /out/artex /app/artex
COPY skills/ /app/skills/
RUN mkdir -p /app/data && chmod +x /app/artex

# 数据目录（SQLite 残留 / 报告 docx / run.log / jwt.key）
VOLUME ["/app/data"]
EXPOSE 8787

# 容器内健康检查：/api/health 免鉴权，返回 {"ok":true}。
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
  CMD curl -fsS "http://127.0.0.1${ARTEX_LISTEN_ADDR}/api/health" || exit 1

ENTRYPOINT ["/app/artex"]
CMD ["-addr", ":8787", "-data", "/app/data", "-proxy", ""]
