# syntax=docker/dockerfile:1
#
# 应用镜像（不在镜像里编译）：只放**预编译好的 Linux 单二进制**与内置技能。
#
# 底座（工具 / 字体 / Chromium / LibreOffice）在 artex-base 里，见
# docker/base/Dockerfile。这样改业务代码只重建最后三层（约 40MB），
# 不再把 6GB 的 apt 层重烧一遍。
#
# 本地手动构建：
#   cd web && npm run build:static && cd ..
#   cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/artex ./cmd/artex
#   docker build -t artex:local .
#
# 底座换了要同步改 ARG 的默认值（或构建时传 --build-arg BASE_IMAGE=...）。
# 钉 tag 而不是 latest：老版本镜像必须永远对应它发布时那套工具，
# 否则回滚回去会出现「版本旧了、工具却是新的」这种不可复现状态。
ARG BASE_IMAGE=rongsec/artex-base:20261125
FROM ${BASE_IMAGE}

ARG TARGETARCH

# 预编译好的对应架构二进制（dist/amd64/artex 或 dist/arm64/artex）
COPY --chmod=0755 dist/${TARGETARCH}/artex /app/artex
# 守护启动脚本：进程退出后按退出码决定是否重新拉起。
# 它同时负责把 SIGTERM 转发给 artex —— docker stop 只把信号发给 PID 1，
# 不转发的话 artex 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY --chmod=0755 start.sh /app/start.sh
COPY skills/ /app/skills/
# data/ 持久化点（任务工作区、模板、报告、hostbin、pyenv）
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
