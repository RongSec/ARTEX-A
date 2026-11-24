# artex 镜像（自带 LibreOffice + 仿宋/黑体/宋体/Times + nuclei/httpx 等 9 个探测工具）

## 首次部署（三步）

```bash
bash docker/init-env.sh                                  # ① 生成随机口令到 docker/.env（0600）
docker compose -f docker/docker-compose.yml up -d        # ② 起库 + 起服务
docker compose -f docker/docker-compose.yml logs -f artex
```

浏览器打开 `http://<本机IP>:8801`，用户名 `ARTEX`，初始密码见 `docker/.env` 的 `ARTEX_INIT_PASSWORD`。

## 敏感配置在哪里

| 内容 | 位置 | 是否入库 |
|---|---|---|
| 数据库口令 / 管理员初始密码 | `docker/.env`（0600，`init-env.sh` 随机生成） | 否，已 gitignore |
| JWT 签名密钥 | 挂载卷 `data/jwt.key`（程序首启自动生成） | 否 |
| LLM Key / GitHub Token / NVD Key | 数据库 `settings` 表（页面「同步配置」里填） | 否 |
| 配置文件 | 程序首启在可执行文件旁生成 `config.json`（0600） | 否 |

`.env.example` 只是字段说明，**不要**直接拿去用。

## 常用操作

```bash
docker compose -f docker/docker-compose.yml up -d --build   # 本地改代码后重建
docker compose -f docker/docker-compose.yml up -d           # 改完 docker/.env 后重启生效
docker compose -f docker/docker-compose.yml down            # 停止（数据在 docker/data 与 pgdata 卷里）
```

用外部数据库时，把 `docker/.env` 里 `ARTEX_PG_DSN` 的 host 改成实际地址即可，无需重建镜像。

## 镜像里的工具

镜像已预置 `nuclei / httpx / subfinder / katana / dnsx / tlsx / chisel / ffuf / dalfox / amass`（按架构各取一份）。
其余 apt 类工具见 `docker/apt-core.txt`；go/pip 类工具在「系统 → 宿主环境」页可持久化安装到 `data/hostbin`、`data/pyenv`。
