# 内置短路规则清单（V9-RULE）

本清单对应代码内置默认值（`guard.Defaults()`），在「系统 → 拦截规则 → 短路规则」
统一表中以 `内置` 徽标展示。内置行只读，只允许切换启用状态；保存后需重启服务端
才生效。优先级数值小的先命中（运行时顺序：工具 deny → 自定义 → 工具 ask →
工具 allow → 平台路径档）。

## 1. 工具策略（按工具名精确匹配）

| 规则名 | 动作 | 匹配内容 | 会命中 | 不会拦 |
| --- | --- | --- | --- | --- |
| `create_mcp` | deny | 工具名 `create_mcp` | 新建 MCP 服务器（新增注册、写入命令/env） | 读取已有 MCP 配置、列出 MCP 服务、调用已注册 MCP 工具 |
| `update_mcp` | deny | 工具名 `update_mcp` | 修改已有 MCP 注册（改命令/URL/header） | 查询 MCP 状态、读取 MCP 配置 |
| `delete_assets_by_host` | deny | 工具名 `delete_assets_by_host` | 按 host 批量删除业务资产 | 删除单条 finding、普通资产查询 |
| `create_skill` | allow | 工具名 `create_skill` | 新建 skill（不覆盖既有行为） | 修改/覆盖已有 skill 文件（走 `update_skill_file`） |
| `create_custom_tool` | allow | 工具名 `create_custom_tool` | 新建自定义脚本工具 | 执行工具、修改已有工具 |
| `update_custom_tool` | allow | 工具名 `update_custom_tool` | 修改自定义工具定义 | 执行工具本身 |
| `update_skill_file` | allow | 工具名 `update_skill_file` | 修改 skill 文件（改后仍要过动作层护栏） | 绕过规则/判官（后续动作仍被审查） |

> 默认 `tools.ask` 为空：V6-AUTO 起自主优先，不再内置人工确认档。管理员可在
> 自定义规则里显式配置 `ask`。

## 2. 平台凭据路径（`platform_paths`，deny）

| 规则名 | 匹配内容（正则） | 会命中 | 不会拦 |
| --- | --- | --- | --- |
| 平台凭据路径 #1 | `/app/(?:data/)?jwt\.key` | `cat /app/jwt.key`、`cat /app/data/jwt.key` | `cat /app/README.md`、普通业务文件读取 |
| 平台凭据路径 #2 | `/app/\.env\b` | `cat /app/.env`、`grep KEY /app/.env` | `/app/data/.env.example`（词边界不匹配 `.env.`） |
| 平台凭据路径 #3 | `/app/data/traffic/_ca/*.{pem,key,crt}` | 读取 MITM CA 私钥/证书 | 读取抓包记录 JSON、普通 pcap |
| 平台凭据路径 #4 | `(?:\.\./){2,}jwt\.key` | 从 `data/sessions/<key>` 用 `../../jwt.key` 回溯 | 正常的相对路径 `../report.md` |
| 平台凭据路径 #5 | `/proc/*envi*` | 读取 `/proc/1/environ`、`/proc/self/environ` | `/proc/cpuinfo`、普通进程列表 |
| 平台凭据路径 #6 | `/proc/\d+/cmdline` | 读取进程命令行（可能含密钥参数） | `/proc/self/status` |
| 平台凭据路径 #7 | `/proc/\d+/mem` | 读取进程内存 | `/proc/meminfo` |

## 3. 平台凭据宽松变形（`platform_loose_patterns`，deny）

| 规则名 | 匹配内容 | 会命中 | 不会拦 |
| --- | --- | --- | --- |
| 平台凭据宽松变形 #1 | `j[\s._-]*w[\s._-]*t...k...y` | `/app/j w t . k e y`、`jwt-key` 等插入分隔符的变形 | 正文里仅讨论 "jwt" 概念（需命中完整路径形态） |

## 4. 裸读文件名（`bare_read_names`，deny）

| 规则名 | 匹配内容 | 会命中 | 不会拦 |
| --- | --- | --- | --- |
| 裸读文件名 #1 | 读命令（cat/head/tail/less/more/cp/mv/sed/awk/strings）第一参数为裸相对名 `config.json` | `cat config.json`（cwd 恰为平台数据目录时最危险） | `cat /tmp/config.json`、`cat ./config.json`（非裸名）、`cat business.json` |
| 裸读文件名 #2 | 裸读 `.jwt` | `cat .jwt` | `cat /home/user/.jwt`（绝对路径交给其它档） |
| 裸读文件名 #3 | 裸读 `jwt.key` | `cat jwt.key` | `cat /app/jwt.key`（由平台凭据路径档处理） |

> 纯记录类工具（`record_fact`/`report_finding` 等）整体豁免本档：正文如实引用
> 被拦命令原文是审计刚需，不算执行。

## 5. 本机系统凭据（`host_paths`，deny，带远程指代豁免）

| 规则名 | 匹配内容 | 会命中 | 不会拦 |
| --- | --- | --- | --- |
| 本机系统凭据 #1 | `/etc/shadow`（含空白/分隔符变形） | `cat /etc/shadow` | `ssh target cat /etc/shadow`（远程指代豁免）、`cat /etc/hosts` |
| 本机系统凭据 #2 | `/etc/gshadow` | `cat /etc/gshadow` | 普通 `/etc` 配置文件 |
| 本机系统凭据 #3 | `/etc/sudoers`、`/etc/sudoers.d` | `cat /etc/sudoers` | `sudo -l`（命令名不含路径） |
| 本机系统凭据 #4 | `/root/.ssh/<具体文件>` | `cat /root/.ssh/id_rsa` | `ls /root/.ssh`（目录本体不拦） |

## 6. 本机 SSH 主机私钥（`ssh_host_key_patterns`，deny）

| 规则名 | 匹配内容 | 会命中 | 不会拦 |
| --- | --- | --- | --- |
| 本机 SSH 主机私钥 #1 | `/etc/ssh/ssh_host_*key` | `cat /etc/ssh/ssh_host_rsa_key` | `.pub` 公钥（代码放行）、`/etc/ssh/sshd_config` |

## 7. 平台控制面 API（`control_plane_patterns`，deny）

| 规则名 | 匹配内容 | 会命中 | 不会拦 |
| --- | --- | --- | --- |
| 平台控制面 API #1 | `127.0.0.1/localhost/[::1]/0.0.0.0:<8801|8787>/api/(intercept|settings|system|agents|mcp|tools)` | `curl http://127.0.0.1:8801/api/settings`、改拦截规则 | `GET /api/health`、`/api/facts`（只读业务面） |
| 平台控制面 API #2 | `/api/tasks/<id>/control` | 通过 API 暂停/终止任务 | 普通任务查询 `/api/tasks/<id>` |
| 平台控制面 API #3 | `/api/tasks/control(/batch)?` | 批量控制任务 | 任务列表 |

## 8. 自定义规则（非内置）

管理员新增的条目在统一表中标记为 `自定义`，可编辑优先级/名称/策略/匹配内容/
说明与启用状态。自定义规则按优先级插入执行序列（默认起点 100，位于工具 deny
之后、工具 ask/allow 之前），支持 `deny`/`ask`/`allow` 三种动作；`ask` 命中后
15 秒超时按 deny 处理。

## 维护说明

- 统一表 GET `/api/system/shortcircuit` 的 `rules` 字段是展示事实源；旧的
  `config`/`defaults` 字段保留一版兼容。
- 保存走 `PUT /api/system/shortcircuit/rules`，落盘仍是原
  `shortcircuit_rules.json` 格式（按 kind 拆回 `tools`/`platform_paths`/
  `custom_rules` 等原结构）。
- 禁用内置项不会从代码默认里删除，GET 会以 `enabled=false` 回显，便于随时恢复。
