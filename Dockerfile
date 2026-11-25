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
#
# 分层（按「变更频率」从低到高排，改代码不会重烧前几层）：
#   ① 基础 apt（apt-core.txt）
#   ② 工具层（apt-tools.txt，循环安装、单件失败只告警）
#   ③ 排版层（LibreOffice Writer + 中文字体）—— docx→PDF 预览的引擎
#   ④ python-docx —— docx 报告生成
#   ⑤ Playwright / Chromium
#   ⑥ 预置探测工具二进制（hostbin 层）
#   ⑦ artex 本体
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# 国内构建默认走阿里云 Debian 镜像（--build-arg APT_MIRROR= 可切回官方源）。
ARG APT_MIRROR=mirrors.aliyun.com
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# 常用工具：ripgrep / curl / vim，加一批 recon 常备件。
# 包清单在 docker/apt-core.txt：与 hosttools/catalog.go 的 preinstalled 基线对齐，
# 改这里必须同步改那边，否则页面会把「镜像没装」说成「断网可用」。
# 工具层清单在 docker/apt-tools.txt：那批包体积大、装失败也不该拖垮构建，
# 所以单独循环安装（见下）。
COPY docker/apt-core.txt docker/apt-tools.txt /tmp/
RUN set -eux; \
    if [ -n "${APT_MIRROR}" ]; then \
      for f in /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources; do \
        if [ -f "$f" ]; then sed -i "s|deb.debian.org|${APT_MIRROR}|g" "$f"; fi; \
      done; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates curl ripgrep vim git jq unzip iputils-ping inetutils-telnet \
      tzdata fontconfig \
      $(grep -v '^#' /tmp/apt-core.txt | grep -v '^$' | tr '\n' ' '); \
    rm -rf /var/lib/apt/lists/*

# ---- 工具层：hashcat / hydra / john / medusa / gdb / binwalk / exiftool / awscli /
#      xfreerdp / file / strings / psql（约 350MB）----
# 逐件装而不是一次装完：某个包名在 bookworm 里不存在时只跳过这一件。
# 过去把整批包塞进一条 apt-get，nikto 一个不存在的名字就把整个镜像构建搞挂了。
# 每个 apt RUN 自带 update + 清 lists：把 update 留到下一个 RUN 的话，
# 上一层里的包索引会永久留在镜像里（约 40MB 白占）。
RUN set -eux; \
    apt-get update; \
    while IFS='|' read -r cmd pkg note; do \
      case "$cmd" in ''|\#*) continue ;; esac; \
      if command -v "$cmd" >/dev/null 2>&1; then echo "工具层: $cmd 已随基础层就位"; continue; fi; \
      if apt-get install -y --no-install-recommends "$pkg"; then \
        echo "工具层: $cmd ← $pkg"; \
      else \
        echo "WARN 工具层: $pkg 安装失败，已跳过（run.sh 启动时会再试一次）" >&2; \
      fi; \
    done < /tmp/apt-tools.txt; \
    rm -rf /var/lib/apt/lists/*

# ---- 排版层：docx → PDF 的引擎（约 450MB）----
# 为什么必须在镜像里：PDF 预览是「报告」功能的一部分，不是可选工具。
# 缺 soffice 时 server/preview_pdf.go 会降级成 HTML 预览（接口带
# X-Preview-Fidelity: approximate），排版细节全丢——标题字号、表格边框、
# 仿宋字形在 HTML 里都还原不出来。之前的 Hub 镜像就缺这一层，
# 只有 docker/Dockerfile 本地构建版才有，导致同一个版本两种能力。
# 只装 Writer（不装整套 LibreOffice，省约 400MB）。
# fonts-noto-cjk 兜底 CJK；docker/fonts 里的仿宋/黑体/宋体/Times 让模板字体
# 真正能被认到（fc-cache 必须重跑，否则 soffice 看不到）。
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      libreoffice-writer fonts-noto-cjk fonts-dejavu-core; \
    rm -rf /var/lib/apt/lists/*
COPY docker/fonts/ /usr/share/fonts/truetype/win/
RUN set -eux; \
    fc-cache -f; \
    HOME=/tmp soffice --version; \
    for f in simfang simhei simsun "times new roman"; do fc-list | grep -qi "$f"; done; \
    echo "排版层就绪：soffice + 仿宋/黑体/宋体/Times"

# Node 从 NodeSource 装 20.x：bookworm 自带的 apt nodejs 是 18，Playwright 要求 >=20。
RUN set -eux; \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -; \
    apt-get install -y --no-install-recommends nodejs; \
    rm -rf /var/lib/apt/lists/*
# docx 报告渲染依赖：report/docxgen.go 用子进程 python 调 python-docx。
# 缺这个包时整条 docx 管线会静默回退成 Markdown 桩——生产容器实测就是缺的，
# 页面看着「生成了报告」，产物却不是 docx。版本钉住，避免上游破坏兼容。
RUN pip install --no-cache-dir "python-docx==1.1.2" \
    && python3 -c "import docx; print('python-docx', docx.__version__)"

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
# 守护启动脚本：进程退出后按退出码决定是否重新拉起。
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
