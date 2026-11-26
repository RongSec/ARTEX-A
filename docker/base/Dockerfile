# syntax=docker/dockerfile:1
#
# artex-base —— 运行底座：工具、字体、浏览器、排版引擎。
#
# 为什么单独一个镜像（而不是塞在应用镜像里）：
#   应用镜像每次发版都要重建。这些层（apt 包、LibreOffice、Chromium、nuclei 等）
#   跟业务代码毫无关系，却要在 CI 里重烧一遍；GitHub 的 gha 缓存上限 10GB，
#   多架构镜像层一超就被淘汰，于是每次发版都冷构建（实测 hs.8 用了 190 分钟，
#   其中 189 分钟在装这些和代码无关的东西）。
#   拆出来后：这一层只在「工具清单/字体/取工具脚本」变动时重建，日常发版
#   只需拉它 + 拷 40MB 二进制。层按 digest 复用，用户端不会多占磁盘。
#
# 什么时候必须改 docker/base/TAG 并重建：
#   docker/apt-core.txt、docker/apt-tools.txt、docker/fonts/、docker/hostbin/fetch.sh
#   任何一处变动。TAG 是应用镜像钉住 base 的依据，不 bump 的话老应用镜像
#   会悄悄用上新底座，回滚就不可复现了。
#
# 构建（CI 用 .github/workflows/base.yml，本地验证）：
#   docker build -f docker/base/Dockerfile -t artex-base:test .
#   docker build -f docker/base/Dockerfile --build-arg TARGETARCH=arm64 ...
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
# NetExec（nxc）：AD / 横向移动的核心工具。
# 为什么烘进底座而不是让页面装：它不在 PyPI（项目 404），依赖里 certipy / impacket /
# oscrypto 三个都写死成 git+https://github.com/...。受限网络下实测三步全挂：
# PyPI 找不到包 → 换 GitHub 源码包 → poetry-dynamic-versioning 要 .git → 再换
# git clone → TLS 被中断。装一次要碰运气，不如构建时装好（约 60MB）。
# 版本钉死 v1.4.0：v1.5.x 把 certipy 换成 Pennyw0rth 的 fork，但那个包的
# metadata 名是 certipy-nxc，PyPI 上的项目名仍是 certipy-ad，pip 25 直接判
# 「certipy-ad (unavailable)」——构建必挂（实测两次）。v1.4.0 只有 impacket /
# oscrypto / pynfsclient 三个 git 依赖，能正常装。升级前先在 CI 试装。
RUN set -eux; \
    pip install --no-cache-dir --break-system-packages \
      "git+https://github.com/Pennyw0rth/NetExec@v1.4.0"; \
    nxc --version

# ---- 预置探测工具层（nuclei / httpx / subfinder / katana / dnsx / tlsx / chisel / ffuf …
#      共 9 件，约 380MB）----
# 二进制由 docker/hostbin/fetch.sh 在构建前现取，不入库；CI 会为 amd64 与 arm64
# 各取一份放进 docker/hostbin/<arch>/。这里按 TARGETARCH 选择对应目录。
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
