# ARTEX-A 二开工程说明

本工程（ARTEX-A）基于 **ARTEX v0.3.15**（原版快照，上游 `github.com/Autumn-27/artex`）复制基线后进行二次开发。
主说明见 [README.md](./README.md)，变更记录见 [CHANGELOG.md](./CHANGELOG.md)。

> ⚠️ Go 模块名保持 `github.com/Autumn-27/artex` 不变（不改 go.mod），以降低依赖解析与后续合并上游的成本；二开差异全部以代码提交追溯。

---

## 二开规划（四条线）

| 线 | 名称 | 摘要 |
| --- | --- | --- |
| L1 | 项目-任务批量下发 | 在项目维度批量创建/下发渗透任务，支持模板化参数与批量调度 |
| L2 | 项目大图 + 观察者模式 | 项目级全局资产/链路拓扑大图，只读观察者视图（投屏/汇报场景） |
| L3 | 报告增强 | 参考 AntiFox 报告机制：发现富化、证据链、报告模板与排版增强 |
| L4 | Word 报告中心 | 生成标准交付用 Word（.docx）渗透测试报告，报告中心统一管理与下载 |

各条线的实现随版本发布，逐条变更可在 [CHANGELOG.md](./CHANGELOG.md) 与 git 历史中追溯。

## 环境与工具链

- Go：**1.26.9**（go.mod 要求 `go 1.26.3`，1.26.9 兼容）
- Node：**v22.22.2** / npm：**10.9.7**
- 网络受限环境建议设置模块代理：`export GOPROXY=https://goproxy.cn,direct`
  （本机验证：proxy.golang.org 不可达，goproxy.cn 全量下载成功）

## 本地开发命令

```bash
# 后端编译验证（全仓）
go build ./...

# 前后端分离开发模式：后端 :8787 + 流量代理 :8788 + 前端 next dev :5173
./dev.sh

# 单二进制构建（前端静态导出后内嵌）
cd web && npm ci && npm run build:static && cd ..
CGO_ENABLED=0 go build -tags embedui -o artex ./cmd/artex
```

- 前端 `build:static` 产出 `web/out/`，由 `-tags embedui` 内嵌进单一 Go 二进制；
- 数据库为 PostgreSQL（连接配置复制 `config.example.json` 为 `config.json`，或用环境变量 `ARTEX_PG_DSN`）。

## 目标部署（示例）

| 项 | 值 |
| --- | --- |
| 服务器 | `<TARGET_HOST>`（替换为你的部署主机地址） |
| 应用端口 | `8801`（前端 + API/SSE，对应 `-addr :8801`） |
| 流量代理端口 | `8802`（对应 `-proxy :8802`） |
| 数据库 | PostgreSQL 库名 `artex_a` |

启动示例：

```bash
./artex -addr :8801 -proxy 127.0.0.1:8802
# ARTEX_PG_DSN=postgres://user:pass@127.0.0.1:5432/artex_a?sslmode=disable
```

## 基线管理

- 首个 git commit 为 `baseline: ARTEX v0.3.15 原版快照`，之后所有二开改动均以 diff 追溯；
- 源文件 `skills/`、`db/`（Go 数据库包源码）、`config.example.json` 等全部保留；
- `.gitignore` 沿用上游：`data/`、`dist/`、`config.json`、`web/node_modules/`、`web/out/` 等运行态产物不入库。
