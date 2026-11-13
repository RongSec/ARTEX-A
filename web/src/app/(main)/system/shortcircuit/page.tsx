"use client";

import * as React from "react";
import { AlertTriangleIcon, PowerIcon, RotateCcwIcon, SaveIcon, ShieldCheckIcon, XIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { ShortCircuitConfig, ShortCircuitState, ShortCircuitTools } from "@/lib/types";

// V6-CFG：短路规则页。
//
// 交互模型刻意是「编辑草稿 → 保存文件 → 重启生效」：
// 保存不会改变正在运行的判定（GET 的 config 始终是生效配置），dirty=true
// 明确告诉用户"文件已改，重启才生效"。页面不提供任何热加载按钮。

type TextField =
  | "platform_paths"
  | "platform_loose_patterns"
  | "bare_read_names"
  | "host_paths"
  | "ssh_host_key_patterns"
  | "remote_exempt_patterns"
  | "record_only_tools"
  | "control_plane_patterns";

const TEXT_FIELDS: Array<{ key: TextField; title: string; hint: string; mono?: boolean }> = [
  {
    key: "platform_paths",
    title: "平台凭据正则",
    hint: "命中即 deny，不吃远程指代豁免。一行一条，RE2 语法。",
    mono: true,
  },
  {
    key: "platform_loose_patterns",
    title: "平台凭据宽松正则",
    hint: "覆盖 jwt.key 被插入空白/分隔符的变形（如 /app/j w t . k e y）。",
    mono: true,
  },
  {
    key: "bare_read_names",
    title: "裸读文件名",
    hint: "读命令（cat/head/…）第一参数恰为这些裸相对名时 deny。按字面量处理，不需要转义点号。",
    mono: true,
  },
  {
    key: "host_paths",
    title: "本机系统凭据正则",
    hint: "命中且命令中无远程指代（ssh/scp/http 等）时 deny。一行一条。",
    mono: true,
  },
  {
    key: "ssh_host_key_patterns",
    title: "本机 SSH 主机私钥正则",
    hint: "默认匹配 /etc/ssh/ssh_host_*key；.pub 公钥由代码放行。",
    mono: true,
  },
  {
    key: "remote_exempt_patterns",
    title: "远程指代豁免正则",
    hint: "命令串出现任一形态即视为远程打靶，本机凭据档整体豁免。",
    mono: true,
  },
  {
    key: "record_only_tools",
    title: "纯记录类工具豁免名单",
    hint: "这些工具只写 DB，不落盘/不执行；其文本里引用凭据路径不算读取。一行一个工具名。",
  },
  {
    key: "control_plane_patterns",
    title: "平台控制面 API 正则",
    hint: "对平台自身监听地址（127.0.0.1/localhost:<端口>）的管理接口请求（/api/intercept|settings|system|agents|mcp|tools、/api/tasks/<id>/control）命中即 deny；实际 -addr 的 host/端口由启动时自动追加，/api/health 等只读面不拦。",
    mono: true,
  },
];

function linesToArray(v: string): string[] {
  return v
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}

function arrayToLines(v: string[]): string {
  return v.join("\n");
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ChipInput 用于三类工具名单：回车/逗号添加，点 × 删除。
function ChipInput({
  items,
  onChange,
  placeholder,
}: {
  items: string[];
  onChange: (next: string[]) => void;
  placeholder: string;
}) {
  const [draft, setDraft] = React.useState("");
  const add = () => {
    const v = draft.trim();
    if (!v) return;
    if (!items.includes(v)) onChange([...items, v]);
    setDraft("");
  };
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-1.5">
        {items.length === 0 ? (
          <span className="text-muted-foreground text-xs">（空）</span>
        ) : (
          items.map((it) => (
            <Badge key={it} variant="secondary" className="gap-1 font-mono text-[11px]">
              {it}
              <button
                type="button"
                className="text-muted-foreground hover:text-foreground"
                onClick={() => onChange(items.filter((x) => x !== it))}
                title={`移除 ${it}`}
              >
                <XIcon className="size-3" />
              </button>
            </Badge>
          ))
        )}
      </div>
      <div className="flex gap-2">
        <Input
          value={draft}
          placeholder={placeholder}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === ",") {
              e.preventDefault();
              add();
            }
          }}
          className="h-8 font-mono text-xs"
        />
        <Button type="button" size="sm" variant="outline" onClick={add}>
          添加
        </Button>
      </div>
    </div>
  );
}

export default function ShortCircuitPage() {
  const [active, setActive] = React.useState<ShortCircuitState | null>(null);
  const [tools, setTools] = React.useState<ShortCircuitTools>({ deny: [], ask: [], allow: [] });
  const [texts, setTexts] = React.useState<Record<TextField, string>>({
    platform_paths: "",
    platform_loose_patterns: "",
    bare_read_names: "",
    host_paths: "",
    ssh_host_key_patterns: "",
    remote_exempt_patterns: "",
    record_only_tools: "",
    control_plane_patterns: "",
  });
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [resetting, setResetting] = React.useState(false);
  const [restarting, setRestarting] = React.useState(false);
  const [error, setError] = React.useState("");

  const hydrate = React.useCallback((cfg: ShortCircuitConfig) => {
    setTools({
      deny: [...cfg.tools.deny],
      ask: [...cfg.tools.ask],
      allow: [...cfg.tools.allow],
    });
    setTexts({
      platform_paths: arrayToLines(cfg.platform_paths),
      platform_loose_patterns: arrayToLines(cfg.platform_loose_patterns),
      bare_read_names: arrayToLines(cfg.bare_read_names),
      host_paths: arrayToLines(cfg.host_paths),
      ssh_host_key_patterns: arrayToLines(cfg.ssh_host_key_patterns),
      remote_exempt_patterns: arrayToLines(cfg.remote_exempt_patterns),
      record_only_tools: arrayToLines(cfg.record_only_tools),
      control_plane_patterns: arrayToLines(cfg.control_plane_patterns),
    });
  }, []);

  const reload = React.useCallback(async () => {
    const next = await api.shortCircuit();
    setActive(next);
    return next;
  }, []);

  React.useEffect(() => {
    reload()
      .then((next) => hydrate(next.config))
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, [hydrate, reload]);

  const buildConfig = (): ShortCircuitConfig => ({
    version: active?.config.version ?? 1,
    tools,
    platform_paths: linesToArray(texts.platform_paths),
    platform_loose_patterns: linesToArray(texts.platform_loose_patterns),
    bare_read_names: linesToArray(texts.bare_read_names),
    host_paths: linesToArray(texts.host_paths),
    ssh_host_key_patterns: linesToArray(texts.ssh_host_key_patterns),
    remote_exempt_patterns: linesToArray(texts.remote_exempt_patterns),
    record_only_tools: linesToArray(texts.record_only_tools),
    control_plane_patterns: linesToArray(texts.control_plane_patterns),
    // 运行时派生值：服务端会忽略（按启动时的 dataDir 重新生成），仅为类型完整回传。
    platform_abs_dir: active?.config.platform_abs_dir ?? "",
  });

  const save = () => {
    setSaving(true);
    setError("");
    api
      .saveShortCircuit(buildConfig())
      .then(() => {
        toast.success("已保存到文件，需重启服务端才生效");
        return reload();
      })
      .catch((e) => {
        const msg = (e as Error).message;
        setError(msg);
        toast.error("保存失败：" + msg);
      })
      .finally(() => setSaving(false));
  };

  const reset = () => {
    if (!window.confirm("确定把短路规则文件恢复为代码内置默认值？仍需重启服务端才生效。")) return;
    setResetting(true);
    setError("");
    api
      .resetShortCircuit()
      .then(async () => {
        const next = await reload();
        hydrate(next.defaults);
        toast.success("已写入默认值，需重启服务端才生效");
      })
      .catch((e) => {
        const msg = (e as Error).message;
        setError(msg);
        toast.error("恢复默认失败：" + msg);
      })
      .finally(() => setResetting(false));
  };

  const waitForHealth = async () => {
    // 先等 2s 延迟 + 进程拉起，避免轮询打到尚未退出的旧进程。
    await sleep(3000);
    const deadline = Date.now() + 60_000;
    while (Date.now() < deadline) {
      try {
        const h = await api.health();
        if (h?.ok) return;
      } catch {
        // 重启窗口内连接失败是预期，继续轮询。
      }
      await sleep(1000);
    }
    throw new Error("等待 60s 后 /api/health 仍未恢复");
  };

  const restart = () => {
    if (
      !window.confirm(
        "重启服务端会中断正在运行的任务、对话与流量捕获，并短暂不可访问。\n\n确定立即重启？",
      )
    ) {
      return;
    }
    setRestarting(true);
    setError("");
    api
      .restartServer()
      .then(async (r) => {
        toast.info(`已排程重启，约 ${r.delay_seconds}s 后开始…`);
        await waitForHealth();
        toast.success("服务端已重启，短路规则已生效");
        await reload();
      })
      .catch((e) => {
        const msg = (e as Error).message;
        setError("重启失败：" + msg);
        toast.error("重启失败：" + msg);
      })
      .finally(() => setRestarting(false));
  };

  const setField = (key: TextField, value: string) => setTexts((prev) => ({ ...prev, [key]: value }));

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div>
        <h1 className="flex items-center gap-2 text-xl font-semibold tracking-tight">
          <ShieldCheckIcon className="size-5" />
          短路规则
        </h1>
        <p className="text-muted-foreground text-sm">
          代码级红线（不进 DB、不受 /api/settings 热改影响），只能改文件 + 重启服务端生效
        </p>
      </div>

      {/* 黄色警示条：这是整页最重要的约束，放在所有可编辑控件之前。 */}
      <div className="flex gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-amber-900 dark:text-amber-200">
        <AlertTriangleIcon className="mt-0.5 size-5 shrink-0" />
        <div className="space-y-1 text-sm">
          <div className="font-medium">短路规则为代码级红线，修改后需重启服务端才生效</div>
          <div className="text-xs opacity-90">
            保存只写文件，不会热改正在运行的判定。请确认修改后再点「重启服务端」。
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 pt-1 text-xs">
            <span>
              状态：
              {active?.dirty ? (
                <Badge className="ml-1 bg-amber-600 text-white hover:bg-amber-600">文件已改，待重启生效</Badge>
              ) : (
                <Badge variant="secondary" className="ml-1">
                  与运行配置一致
                </Badge>
              )}
            </span>
            <span className="font-mono break-all">文件：{active?.file_path ?? "—"}</span>
            <span className="font-mono break-all">
              平台 dataDir：{active?.config.platform_abs_dir || "—"}
              <span className="ml-1 opacity-70">（运行时生成，绝对值写入平台凭据档，不可编辑）</span>
            </span>
            <span>生效配置装入于：{active?.loaded_at ? new Date(active.loaded_at).toLocaleString() : "—"}</span>
          </div>
        </div>
      </div>

      {error ? (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      ) : null}

      {loading ? (
        <div className="text-muted-foreground text-sm">加载中…</div>
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">工具名单</CardTitle>
              <CardDescription>
                判定顺序：deny（硬拦，无人工放行）→ ask（转人工，60s 超时拒绝）→ allow（显式放行）。
                不命中任何名单且不触发凭据正则时，才进入 DB 规则与判官。
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-5 md:grid-cols-3">
              <div className="space-y-2">
                <Label className="text-destructive">deny · 硬拦</Label>
                <ChipInput
                  items={tools.deny}
                  onChange={(deny) => setTools((t) => ({ ...t, deny }))}
                  placeholder="如 create_mcp"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-amber-600">ask · 人工确认</Label>
                <ChipInput
                  items={tools.ask}
                  onChange={(ask) => setTools((t) => ({ ...t, ask }))}
                  placeholder="如 update_skill_file"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-emerald-600">allow · 显式放行</Label>
                <ChipInput
                  items={tools.allow}
                  onChange={(allow) => setTools((t) => ({ ...t, allow }))}
                  placeholder="如 create_skill"
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">凭据与路径正则</CardTitle>
              <CardDescription>
                一行一条。保存前后端会逐条编译校验；出现非法正则或关键列表为空会直接拒绝保存。
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-6 lg:grid-cols-2">
              {TEXT_FIELDS.map((f) => (
                <div key={f.key} className="space-y-2">
                  <Label htmlFor={`sc-${f.key}`}>{f.title}</Label>
                  <p className="text-muted-foreground text-xs">{f.hint}</p>
                  <Textarea
                    id={`sc-${f.key}`}
                    value={texts[f.key]}
                    onChange={(e) => setField(f.key, e.target.value)}
                    spellCheck={false}
                    className={`min-h-28 text-xs ${f.mono ? "font-mono" : ""}`}
                  />
                </div>
              ))}
            </CardContent>
          </Card>

          <div className="flex flex-wrap items-center gap-2">
            <Button onClick={save} disabled={saving || resetting || restarting}>
              <SaveIcon className="size-4" />
              {saving ? "保存中…" : "保存（需重启）"}
            </Button>
            <Button variant="outline" onClick={reset} disabled={saving || resetting || restarting}>
              <RotateCcwIcon className="size-4" />
              {resetting ? "恢复中…" : "恢复默认"}
            </Button>
            <Button variant="destructive" onClick={restart} disabled={saving || resetting || restarting}>
              <PowerIcon className="size-4" />
              {restarting ? "重启中…" : "重启服务端"}
            </Button>
            <span className="text-muted-foreground text-xs">
              重启会短暂中断服务；新进程起来后本页会自动确认 /api/health。
            </span>
          </div>
        </>
      )}
    </div>
  );
}
