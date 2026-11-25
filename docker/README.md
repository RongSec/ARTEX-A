# artex 镜像与部署（Docker）

## 两个镜像：底座与应用分开

| 镜像 | 构建文件 | 什么时候变 |
|---|---|---|
| `rongsec/artex-base` | `docker/base/Dockerfile` | 工具清单、字体、Chromium、LibreOffice 变动时 |
| `rongsec/artex-a`（应用） | 根 `Dockerfile` | 每次发版（只拷二进制 + 前端 + skills，约 40MB） |

应用镜像 `FROM rongsec/artex-base:<TAG>`，**钉死 tag 而不是 latest**：老版本
镜像必须永远对应它发布时那套工具，否则回滚回去会出现「版本旧了、工具却是新的」
这种不可复现状态。

为什么要拆：这些层和业务代码无关，却要在每次发版时重烧；GitHub 的 gha 缓存上限
10GB 装不下多架构镜像层，缓存一失效就冷构建（hs.8 实测 190 分钟，其中 189 分钟
在装工具）。拆开后 base 只在改工具时重建，日常发版几分钟。

改完 `docker/apt-*.txt`、`docker/fonts/`、`docker/hostbin/fetch.sh` 任一处：

1. 把 `docker/base/TAG` 改成一个新值（如 `20261201`）；
2. 推送 `main`，`base-image` 工作流自动重建（amd64 走 `ubuntu-latest`，
   arm64 走 `ubuntu-24.04-arm` 原生 runner，不再用 QEMU 模拟）；
3. 之后再发版，应用镜像自动用新底座。

`artex:local`（`docker/Dockerfile`）是本机源码构建用，仍自带全部层，不依赖 base。

从 `v0.3.16-hs.7` 起两份镜像**都**带 LibreOffice Writer + 仿宋/黑体/宋体/Times +
`python-docx`，docx → PDF 保真预览在 Hub 镜像上同样可用。

## 首次部署

```bash
./run.sh
```

一条命令做完：生成 `docker/.env`（随机口令，0600）→ 拉镜像（直连失败自动换
`docker.1ms.run`）→ 起应用 + PostgreSQL → 补工具。浏览器打开
`http://<本机IP>:8801`，用户名 `ARTEX`，初始密码见 `docker/.env` 的
`ARTEX_INIT_PASSWORD`（首次启动会打印一次）。

Linux 用 host 网络；macOS/Windows 的 Docker Desktop 自动切 bridge + 端口映射
（桌面版没有真正的 host 网络，容器在跑但宿主访问不到是常见坑）。

## 三个脚本的分工

| 脚本 | 什么时候用 | 做什么 |
|---|---|---|
| `run.sh` | **唯一入口**，每次启动 | 首次生成 `.env`、拉镜像、起服务；之后补「容器重建就丢的东西」 |
| `update.sh` | 升级 / 回滚 | 换镜像、更新前备份数据库、失败自动回滚、离线导入 |
| `install.sh` | 老文档里的入口 | 已废弃，只剩转发到 `run.sh` |

### 为什么每次启动要补东西

容器里三类东西寿命不同：

| 类别 | 例子 | 重建容器后 |
|---|---|---|
| 镜像层 | nuclei、nmap、LibreOffice、Playwright | 还在（跟着镜像走） |
| 挂载卷 `/app/data` | hostbin、pyenv、nuclei-templates、报告产物 | 还在（重建不丢） |
| **容器可写层** | apt 装出来的 hashcat/hydra/gdb… | **没了** |

`docker compose up -d` 一重建容器，第三类就消失——这是容器的定义，不是 bug。
`run.sh` 每次启动固定做两步（幂等，全都在位时 1 秒内返回）：

1. **单文件二进制 → `data/hostbin`**（卷里，PATH 第一位）：缺哪个从 GitHub 取哪个；
2. **系统级 apt 包 → 容器内补装**：缺哪个装哪个。`.deb` 缓存在 `data/aptcache`，
   重建后补装通常十几秒，不重新下载几百兆。

```bash
./run.sh            # 启动（默认）
./run.sh ensure     # 只做上面两步（升级镜像之后跑一次）
./run.sh doctor     # 体检：容器、版本、PDF 预览引擎、工具缺口
./run.sh status / logs -f / restart / down
```

不想让它动工具（离线、或只用镜像自带的那批）：`ARTEX_SKIP_TOOLS=1 ./run.sh`。

## 升级与回滚

页面里只剩「检查更新」提示，不再执行任何更新动作——容器里换掉的只是程序文件，
`docker compose up -d` 就退回镜像版本，而且换不掉镜像里的 LibreOffice / 工具层。
升级统一走脚本：

```bash
./update.sh check                 # 查最新正式版
./update.sh to                    # 升到最新
./update.sh to v0.3.16-hs.7       # 升到指定版本
./update.sh rollback              # 回到上一个版本
./update.sh rollback --with-db    # 连数据库一起恢复（会覆盖现有数据）
./update.sh list                  # 本地镜像 + 备份列表
./update.sh import artex.tar.gz   # 离线导入镜像
```

`to` 的流程：备份 → 拉镜像（直连失败自动换加速源）→ 改 `.env` → 重建 →
健康检查校验版本号 → 失败自动退回上一个 tag → 成功后跑一次 `run.sh ensure`。

备份落在 `backups/<时间戳>/`：

| 文件 | 内容 |
|---|---|
| `image.txt` | 更新前的镜像引用与 digest（回滚靠它） |
| `env.bak` | `docker/.env`（0600） |
| `db.dump` | `pg_dump -Fc` 全库快照（宿主或容器里任一有 pg_dump 即可） |

## 敏感配置在哪里

**所有机密只有一个文件：`docker/.env`**（0600，已 gitignore）。

| 内容 | 位置 | 是否入库 |
|---|---|---|
| 数据库口令 / 管理员初始密码 / 镜像引用 | `docker/.env`（`init-env.sh` 随机生成） | 否 |
| LLM Key（`ARTEX_LLM_API_KEY`）| `docker/.env`，启动时导入数据库 | 否 |
| Brave / Tavily / NVD / GitHub Token | `docker/.env`，启动时导入 `settings` | 否 |
| 出口代理（可能带账号密码） | `docker/.env`，启动时导入 `settings` | 否 |
| JWT 签名密钥 | `docker/state/jwt.key`（首启自动生成，挂载卷） | 否 |
| 升级备份（含 `.env` 副本与库快照） | `backups/` | 否 |

导入是「只填空缺」：数据库里已有非空值就不覆盖，页面里改过的配置不会被
重启改回去。想让文件里的新值生效，先在页面把该字段清空，再重启。

`docker/.env.example` 只是字段说明，**不要**直接拿去用 —— 它没有随机口令。

## 镜像里的工具

- **apt 基础层**（`docker/apt-core.txt`）：nmap / masscan / sqlmap / gobuster / tshark / smbclient …
- **apt 工具层**（`docker/apt-tools.txt`）：hashcat / hydra / john / medusa / gdb / binwalk /
  exiftool / awscli / xfreerdp / file / strings / psql —— 逐件安装，单件失败只告警
- **Go 二进制层**（`docker/hostbin/fetch.sh`）：nuclei / httpx / subfinder / katana / dnsx /
  tlsx / chisel / amass / ffuf / dalfox
- **排版层**：libreoffice-writer + fonts-noto-cjk + 仿宋/黑体/宋体/Times

Debian 源里没有的（nikto、searchsploit、msfconsole、seclists、evil-winrm、radare2），
在「系统 → 宿主环境」页有各自的手工安装提示。
