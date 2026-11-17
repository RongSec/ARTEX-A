# syntax=docker/dockerfile:1
#
# V9-DOCKER：自带排版引擎与中文字体的单镜像。
#   web   → Next 静态导出（web/out）
#   build → 把 out 嵌进 Go 单二进制（-tags embedui）
#   final → debian + LibreOffice(Writer) + Noto CJK + Windows 常用中文字体
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
ENV NEXT_EXPORT=1 \
    NEXT_TELEMETRY_DISABLED=1
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
RUN set -eux; \
    if [ -n "${APT_MIRROR}" ]; then \
      for f in /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources; do \
        if [ -f "$f" ]; then sed -i "s|deb.debian.org|${APT_MIRROR}|g" "$f"; fi; \
      done; \
    fi; \
    apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl tzdata fontconfig \
      libreoffice-writer \
      fonts-noto-cjk fonts-dejavu-core \
      python3 python3-docx \
    && rm -rf /var/lib/apt/lists/*

# 随镜像自带仿宋/黑体/宋体/Times（用户不再需要自己装字体）。
COPY docker/fonts/ /usr/share/fonts/truetype/win/
RUN fc-cache -f \
    && fc-list | grep -Ei "simfang|simhei|simsun|times new roman" >/dev/null

WORKDIR /app
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
