# artex 镜像与部署（Docker）

## 两个镜像，运行时能力一致

| 镜像 | 构建文件 | 说明 |
|---|---|---|
| `rongsec/artex-a`（Docker Hub） | 根 `Dockerfile` | 发布/新部署用。CI 交叉编译好二进制后只装工具与依赖，构建快 |
| `artex:local`（本地构建） | `docker/Dockerfile` | 前端在镜像里编译，其余层与上面完全相同 |

从 `v0.3.16-hs.7` 起两份镜像**都**带 LibreOffice Writer + 仿宋/黑体/宋体/Times +
`python-docx`，也就是说 docx → PDF 保真预览在 Hub 镜像上同样可用。
之前的版本只有本地构建版带排版层，同一个版本两种能力，属于缺陷。

## 首次部署

```bash
bash docker/init-env.sh     # ① 生成随机口令到 docker/.env（0600）
./run.sh                    # ② 起服务 + 工具自愈（见下）
```

浏览器打开 `http://<本机IP>:8801`，用户名 `ARTEX`，初始密码见 `docker/.env` 的 `ARTEX_INIT_PASSWORD`。

## 三个脚本的分工

| 脚本 | 什么时候用 | 做什么 |
|---|---|---|
| `install.sh` | 一台裸机第一次装 | 装 docker、问端口、生成 `.env` |
| `run.sh` | **每次启动** | 起服务 + 把「容器重建就丢的东西」补回来 |
| `update.sh` | 升级 / 回滚 | 换镜像、更新前备份数据库、失败自动回滚、离线导入 |

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

| 内容 | 位置 | 是否入库 |
|---|---|---|
| 数据库口令 / 管理员初始密码 / 镜像引用 | `docker/.env`（0600，`init-env.sh` 随机生成） | 否，已 gitignore |
| JWT 签名密钥 | 挂载卷 `data/jwt.key`（程序首启自动生成） | 否 |
| LLM Key / GitHub Token / NVD Key | 数据库 `settings` 表（页面「同步配置」里填） | 否 |
| 配置文件 | 程序首启在可执行文件旁生成 `config.json`（0600） | 否 |
| 升级备份 | `backups/`（含数据库快照与 `.env` 副本） | 否，已 gitignore |

`.env.example` 只是字段说明，**不要**直接拿去用。

## 镜像里的工具

- **apt 基础层**（`docker/apt-core.txt`）：nmap / masscan / sqlmap / gobuster / tshark / smbclient …
- **apt 工具层**（`docker/apt-tools.txt`）：hashcat / hydra / john / medusa / gdb / binwalk /
  exiftool / awscli / xfreerdp / file / strings / psql —— 逐件安装，单件失败只告警
- **Go 二进制层**（`docker/hostbin/fetch.sh`）：nuclei / httpx / subfinder / katana / dnsx /
  tlsx / chisel / amass / ffuf / dalfox
- **排版层**：libreoffice-writer + fonts-noto-cjk + 仿宋/黑体/宋体/Times

Debian 源里没有的（nikto、searchsploit、msfconsole、seclists、evil-winrm、radare2），
在「系统 → 宿主环境」页有各自的手工安装提示。
