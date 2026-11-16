"use client";

import * as React from "react";
import {
  AlertTriangleIcon,
  LockIcon,
  PencilIcon,
  PlusIcon,
  PowerIcon,
  RotateCcwIcon,
  SaveIcon,
  ShieldCheckIcon,
  Trash2Icon,
  XIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type {
  ShortCircuitConfig,
  ShortCircuitCustomRule,
  ShortCircuitState,
  ShortCircuitTools,
} from "@/lib/types";

// V6-CFG / V9-UI / V9-SC：短路规则页。
//
// 交互模型刻意是「编辑草稿 → 保存文件 → 重启生效」：
// 保存不会改变正在运行的判定（GET 的 config 始终是生效配置），页面用改动
// 计数器（pending）标记「有改动待重启生效」，重启成功后归零。页面不提供
// 任何热加载按钮。
//
// 布局跟拦截规则页对齐：内置档一条规则一行卡片、等宽等高（文本框固定高度、内部滚动，
// 不随内容撑高），默认只读；自定义条目单独分卡，可增删改。
// 内置区只读、自定义区可写 —— 内置档是代码级红线，不能被页面改写。

type TextField =
  | "platform_paths"
  | "platform_loose_patterns"
  | "bare_read_names"
  | "host_paths"
  | "ssh_host_key_patterns"
  | "remote_exempt_patterns"
  | "record_only_tools"
  | "control_plane_patterns";

const TEXT_FIELDS: Array<{ key: TextField; title: string; hint: string }> = [
  {
    key: "platform_paths",
    title: "平台凭据正则",
    hint: "命中即 deny，不吃远程指代豁免。一行一条，RE2 语法。",
  },
  {
    key: "platform_loose_patterns",
    title: "平台凭据宽松正则",
    hint: "覆盖 jwt.key 被插入空白/分隔符的变形（如 /app/j w t . k e y）。",
  },
  {
    key: "bare_read_names",
    title: "裸读文件名",
    hint: "读命令（cat/head/…）第一参数恰为这些裸相对名时 deny。按字面量处理，不需要转义点号。",
  },
  {
    key: "host_paths",
    title: "本机系统凭据正则",
    hint: "命中且命令中无远程指代（ssh/scp/http 等）时 deny。一行一条。",
  },
  {
    key: "ssh_host_key_patterns",
    title: "本机 SSH 主机私钥正则",
    hint: "默认匹配 /etc/ssh/ssh_host_*key；.pub 公钥由代码放行。",
  },
  {
    key: "remote_exempt_patterns",
    title: "远程指代豁免正则",
    hint: "命令串出现任一形态即视为远程打靶，本机凭据档整体豁免。",
  },
  {
    key: "record_only_tools",
    title: "纯记录类工具豁免名单",
    hint: "这些工具只写 DB，不落盘/不执行；其文本里引用凭据路径不算读取。一行一个工具名。",
  },
  {
    key: "control_plane_patterns",
    title: "平台控制面 API 正则",
    hint: "对平台自身监听地址（127.0.0.1/localhost:<端口>）的管理接口请求命中即 deny；实际 -addr 的 host/端口由启动时自动追加。",
  },
];

// TOOLS_FIELD 只是「工具名单」这一行卡片的编辑态标识。
const TOOLS_FIELD = "tools";

type EditingKey = TextField | typeof TOOLS_FIELD | null;

// 自定义条目（V9-SC）：key 只允许字母/数字/下划线；上限与后端一致。
const CUSTOM_KEY_RE = /^[A-Za-z0-9_]+$/;
const CUSTOM_MAX = 50;

type CustomForm = {
  key: string;
  name: string;
  pattern: string;
  note: string;
  enabled: boolean;
};

const blankCustomForm = (): CustomForm => ({
  key: "",
  name: "",
  pattern: "",
  note: "",
  enabled: true,
});

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

// ChipList 是只读态的工具名单：只展示，不提供删除按钮。
function ChipList({ items }: { items: string[] }) {
  if (items.length === 0) return <span className="text-muted-foreground text-xs">（空）</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((it) => (
        <Badge key={it} variant="secondary" className="font-mono text-[11px]">
          {it}
        </Badge>
      ))}
    </div>
  );
}

// RuleRow 是一条规则卡片的外壳：等宽等高靠固定高度的内容区 + 单行提示文字。
function RuleRow({
  title,
  hint,
  count,
  editing,
  onEdit,
  onSave,
  onCancel,
  editDisabled,
  children,
}: {
  title: string;
  hint: string;
  count: string;
  editing: boolean;
  onEdit: () => void;
  onSave: () => void;
  onCancel: () => void;
  editDisabled: boolean;
  children: React.ReactNode;
}) {
  return (
    <Card className="overflow-hidden">
      <CardContent className="flex flex-col gap-2 p-3">
        <div className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-2">
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="truncate text-sm font-medium">{title}</span>
              <Badge variant="secondary" className="shrink-0 px-1 py-0 text-[10px] tabular-nums">
                {count}
              </Badge>
              {editing && (
                <Badge variant="outline" className="shrink-0 px-1 py-0 text-[10px]">
                  编辑中
                </Badge>
              )}
            </div>
            <p className="text-muted-foreground mt-0.5 line-clamp-1 h-4 text-xs" title={hint}>
              {hint}
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-1">
            {editing ? (
              <>
                <Button size="sm" className="h-7 px-2 text-xs" onClick={onSave}>
                  保存
                </Button>
                <Button size="sm" variant="outline" className="h-7 px-2 text-xs" onClick={onCancel}>
                  取消
                </Button>
              </>
            ) : (
              <Button
                size="sm"
                variant="outline"
                className="h-7 px-2 text-xs"
                onClick={onEdit}
                disabled={editDisabled}
              >
                <PencilIcon className="size-3.5" />
                编辑
              </Button>
            )}
          </div>
        </div>
        {children}
      </CardContent>
    </Card>
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
  // 单行编辑：editing 指向唯一处于编辑态的规则，draft 是它的草稿。
  const [editing, setEditing] = React.useState<EditingKey>(null);
  const [draft, setDraft] = React.useState("");
  const [draftTools, setDraftTools] = React.useState<ShortCircuitTools>({ deny: [], ask: [], allow: [] });
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [resetting, setResetting] = React.useState(false);
  const [restarting, setRestarting] = React.useState(false);
  const [error, setError] = React.useState("");
  // 自定义条目（V9-SC）与改动计数器：pending>0 即「有改动待重启生效」。
  // 刻意不用后端 dirty（文件比对）：保存/新增/删除/恢复默认都算一次改动，
  // 重启成功后归零。
  const [customRules, setCustomRules] = React.useState<ShortCircuitCustomRule[]>([]);
  const [pending, setPending] = React.useState(0);
  const [customOpen, setCustomOpen] = React.useState(false);
  const [editingCustom, setEditingCustom] = React.useState<ShortCircuitCustomRule | null>(null);
  const [customForm, setCustomForm] = React.useState<CustomForm>(blankCustomForm());
  const [customErr, setCustomErr] = React.useState("");
  const [customSaving, setCustomSaving] = React.useState(false);

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
    setCustomRules([...(cfg.custom_rules ?? [])]);
    setEditing(null);
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

  const buildConfig = (
    nextTexts: Record<TextField, string>,
    nextTools: ShortCircuitTools,
    nextCustom: ShortCircuitCustomRule[],
  ): ShortCircuitConfig => ({
    version: active?.config.version ?? 1,
    tools: nextTools,
    platform_paths: linesToArray(nextTexts.platform_paths),
    platform_loose_patterns: linesToArray(nextTexts.platform_loose_patterns),
    bare_read_names: linesToArray(nextTexts.bare_read_names),
    host_paths: linesToArray(nextTexts.host_paths),
    ssh_host_key_patterns: linesToArray(nextTexts.ssh_host_key_patterns),
    remote_exempt_patterns: linesToArray(nextTexts.remote_exempt_patterns),
    record_only_tools: linesToArray(nextTexts.record_only_tools),
    control_plane_patterns: linesToArray(nextTexts.control_plane_patterns),
    custom_rules: nextCustom,
    // 运行时派生值：服务端会忽略（按启动时的 dataDir 重新生成），仅为类型完整回传。
    platform_abs_dir: active?.config.platform_abs_dir ?? "",
  });

  // persist 是唯一的写文件出口：整页保存、单行保存、自定义条目增删改都走它，
  // 避免两套语义。成功后 pending+1（有改动待重启生效），失败返回 false。
  const persist = (
    nextTexts: Record<TextField, string>,
    nextTools: ShortCircuitTools,
    nextCustom: ShortCircuitCustomRule[] = customRules,
  ): Promise<boolean> => {
    setSaving(true);
    setError("");
    return api
      .saveShortCircuit(buildConfig(nextTexts, nextTools, nextCustom))
      .then(() => {
        setPending((n) => n + 1);
        toast.success("已保存到文件，需重启服务端才生效");
        void reload();
        return true;
      })
      .catch((e) => {
        const msg = (e as Error).message;
        setError(msg);
        toast.error("保存失败：" + msg);
        return false;
      })
      .finally(() => setSaving(false));
  };

  const save = () => {
    if (editing) return;
    persist(texts, tools);
  };

  const startEdit = (key: EditingKey) => {
    if (editing) return;
    if (key === TOOLS_FIELD) {
      setDraftTools({
        deny: [...tools.deny],
        ask: [...tools.ask],
        allow: [...tools.allow],
      });
    } else if (key) {
      setDraft(texts[key]);
    }
    setEditing(key);
  };

  const cancelEdit = () => {
    setEditing(null);
    setDraft("");
    setDraftTools({ deny: [], ask: [], allow: [] });
  };

  // 单行保存：先把草稿落到本地状态，再按当前完整配置写文件（原子，不会丢别的行）。
  const commitRow = () => {
    if (!editing) return;
    if (editing === TOOLS_FIELD) {
      setTools(draftTools);
      persist(texts, draftTools);
    } else {
      const next = { ...texts, [editing]: draft };
      setTexts(next);
      persist(next, tools);
    }
    cancelEdit();
  };

  // ---- 自定义条目（V9-SC）：只 deny，保存后同样需重启 ----

  const openNewCustom = () => {
    setEditingCustom(null);
    setCustomForm(blankCustomForm());
    setCustomErr("");
    setCustomOpen(true);
  };

  const openEditCustom = (rule: ShortCircuitCustomRule) => {
    setEditingCustom(rule);
    setCustomForm({
      key: rule.key,
      name: rule.name,
      pattern: rule.pattern,
      note: rule.note ?? "",
      enabled: rule.enabled,
    });
    setCustomErr("");
    setCustomOpen(true);
  };

  const submitCustom = async () => {
    const key = customForm.key.trim();
    const name = customForm.name.trim();
    const pattern = customForm.pattern.trim();
    const note = customForm.note.trim();
    if (!CUSTOM_KEY_RE.test(key)) {
      setCustomErr("key 只能包含字母、数字、下划线，且不能为空");
      return;
    }
    if (!name) {
      setCustomErr("显示名不能为空");
      return;
    }
    if (!pattern) {
      setCustomErr("匹配内容不能为空");
      return;
    }
    const dup = customRules.some(
      (r) =>
        r.key.toLowerCase() === key.toLowerCase() &&
        (!editingCustom || r.key !== editingCustom.key),
    );
    if (dup) {
      setCustomErr(`key「${key}」已存在（不区分大小写）`);
      return;
    }
    if (!editingCustom && customRules.length >= CUSTOM_MAX) {
      setCustomErr(`自定义条目最多 ${CUSTOM_MAX} 条`);
      return;
    }
    const rule: ShortCircuitCustomRule = { key, name, pattern, note, enabled: customForm.enabled };
    const next = editingCustom
      ? customRules.map((r) => (r.key === editingCustom.key ? rule : r))
      : [...customRules, rule];
    setCustomErr("");
    setCustomSaving(true);
    const ok = await persist(texts, tools, next);
    setCustomSaving(false);
    if (ok) {
      setCustomRules(next);
      setCustomOpen(false);
    }
  };

  const removeCustom = async (rule: ShortCircuitCustomRule) => {
    if (!window.confirm(`确定删除自定义条目「${rule.name}」？保存后仍需重启服务端才生效。`)) return;
    const next = customRules.filter((r) => r.key !== rule.key);
    const ok = await persist(texts, tools, next);
    if (ok) setCustomRules(next);
  };

  const toggleCustom = async (rule: ShortCircuitCustomRule, enabled: boolean) => {
    const next = customRules.map((r) => (r.key === rule.key ? { ...r, enabled } : r));
    const ok = await persist(texts, tools, next);
    if (ok) setCustomRules(next);
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
        setPending((n) => n + 1);
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
        setPending(0);
        toast.success("已重启，规则已生效");
        await reload();
      })
      .catch((e) => {
        const msg = (e as Error).message;
        setError("重启失败：" + msg);
        toast.error("重启失败：" + msg);
      })
      .finally(() => setRestarting(false));
  };

  const busy = saving || resetting || restarting;

  return (
    <div className="flex flex-1 flex-col gap-5 p-6">
      <div className="flex items-center gap-2.5">
        <ShieldCheckIcon className="h-5 w-5 shrink-0" />
        <div>
          <h1 className="text-lg font-semibold leading-tight">短路规则</h1>
          <p className="text-muted-foreground mt-0.5 text-sm">
            代码级红线（不进 DB、不受 /api/settings 热改影响），只能改文件 + 重启服务端生效
          </p>
        </div>
      </div>

      {/* 黄色警示条：这是整页最重要的约束。 */}
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
              {pending > 0 ? (
                <Badge className="ml-1 bg-amber-600 text-white hover:bg-amber-600">有改动待重启生效</Badge>
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
          {/* 工具条与拦截规则页一致：说明在左，按钮右对齐、size=sm。 */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-muted-foreground text-xs">
              内置区默认只读；点某行的「编辑」只改这一行，其余行保持只读。自定义条目在下方单独维护，保存后均需重启服务端。
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" onClick={save} disabled={busy || !!editing}>
                <SaveIcon className="size-4" />
                {saving ? "保存中…" : "保存（需重启）"}
              </Button>
              <Button size="sm" variant="outline" onClick={reset} disabled={busy || !!editing}>
                <RotateCcwIcon className="size-4" />
                {resetting ? "恢复中…" : "恢复默认"}
              </Button>
              <Button
                size="sm"
                variant="destructive"
                onClick={restart}
                disabled={busy || !!editing}
              >
                <PowerIcon className="size-4" />
                {restarting ? "重启中…" : "重启服务端"}
              </Button>
            </div>
          </div>

          {/* 内置区：代码内置的 8 个固定档 + 工具名单，只读。 */}
          <div className="flex items-center gap-2 pt-1">
            <LockIcon className="text-muted-foreground size-4" />
            <h2 className="text-sm font-semibold">内置规则（代码内置，只读）</h2>
            <Badge variant="outline" className="px-1 py-0 text-[10px]">
              只读
            </Badge>
          </div>

          <div className="flex flex-col gap-2">
            {TEXT_FIELDS.map((f) => {
              const isEditing = editing === f.key;
              const count = linesToArray(isEditing ? draft : texts[f.key]).length;
              return (
                <RuleRow
                  key={f.key}
                  title={f.title}
                  hint={f.hint}
                  count={`${count} 条`}
                  editing={isEditing}
                  onEdit={() => startEdit(f.key)}
                  onSave={commitRow}
                  onCancel={cancelEdit}
                  editDisabled={!!editing || busy}
                >
                  <Textarea
                    id={`sc-${f.key}`}
                    aria-label={f.title}
                    value={isEditing ? draft : texts[f.key]}
                    onChange={(e) => setDraft(e.target.value)}
                    readOnly={!isEditing}
                    spellCheck={false}
                    placeholder="（空）"
                    className={`h-28 resize-none overflow-auto font-mono text-xs leading-relaxed ${
                      isEditing ? "" : "bg-muted/40"
                    }`}
                  />
                </RuleRow>
              );
            })}

            <RuleRow
              title="工具名单"
              hint="判定顺序：deny（硬拦，无人工放行）→ ask（转人工，60s 超时拒绝）→ allow（显式放行）。"
              count={`${tools.deny.length + tools.ask.length + tools.allow.length} 项`}
              editing={editing === TOOLS_FIELD}
              onEdit={() => startEdit(TOOLS_FIELD)}
              onSave={commitRow}
              onCancel={cancelEdit}
              editDisabled={!!editing || busy}
            >
              <div className="h-28 space-y-3 overflow-auto rounded-md border p-2">
                {editing === TOOLS_FIELD ? (
                  <div className="grid gap-3 md:grid-cols-3">
                    <div className="space-y-1.5">
                      <span className="text-destructive text-xs font-medium">deny · 硬拦</span>
                      <ChipInput
                        items={draftTools.deny}
                        onChange={(deny) => setDraftTools((t) => ({ ...t, deny }))}
                        placeholder="如 create_mcp"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <span className="text-xs font-medium text-amber-600">ask · 人工确认</span>
                      <ChipInput
                        items={draftTools.ask}
                        onChange={(ask) => setDraftTools((t) => ({ ...t, ask }))}
                        placeholder="如 update_skill_file"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <span className="text-xs font-medium text-emerald-600">allow · 显式放行</span>
                      <ChipInput
                        items={draftTools.allow}
                        onChange={(allow) => setDraftTools((t) => ({ ...t, allow }))}
                        placeholder="如 create_skill"
                      />
                    </div>
                  </div>
                ) : (
                  <div className="grid gap-3 md:grid-cols-3">
                    <div className="space-y-1.5">
                      <span className="text-destructive text-xs font-medium">deny · 硬拦</span>
                      <ChipList items={tools.deny} />
                    </div>
                    <div className="space-y-1.5">
                      <span className="text-xs font-medium text-amber-600">ask · 人工确认</span>
                      <ChipList items={tools.ask} />
                    </div>
                    <div className="space-y-1.5">
                      <span className="text-xs font-medium text-emerald-600">allow · 显式放行</span>
                      <ChipList items={tools.allow} />
                    </div>
                  </div>
                )}
              </div>
            </RuleRow>
          </div>

          {/* 自定义区：可增删改，只 deny。新增按钮与拦截规则页「新建规则」同一位置（区块右上）。 */}
          <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-semibold">自定义条目</h2>
                <Badge variant="secondary" className="px-1 py-0 text-[10px] tabular-nums">
                  {customRules.length}/{CUSTOM_MAX}
                </Badge>
              </div>
              <p className="text-muted-foreground mt-0.5 text-xs">
                命中即直接拦截（deny），只收紧不放宽；匹配执行面文本（纯记录类工具豁免）。保存后仍需重启服务端。
              </p>
            </div>
            <Button
              size="sm"
              onClick={openNewCustom}
              disabled={busy || !!editing || customRules.length >= CUSTOM_MAX}
            >
              <PlusIcon className="size-4" />
              新增条目
            </Button>
          </div>

          <Card>
            <CardContent className="p-0">
              {customRules.length === 0 ? (
                <div className="flex flex-col items-center justify-center gap-2 py-12 text-center">
                  <p className="text-muted-foreground text-sm">暂无自定义条目</p>
                  <Button size="sm" variant="outline" onClick={openNewCustom} disabled={busy || !!editing}>
                    <PlusIcon className="size-4" />
                    新增第一条
                  </Button>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="w-[180px]">标识 key</TableHead>
                      <TableHead className="w-[160px]">名称</TableHead>
                      <TableHead>匹配内容</TableHead>
                      <TableHead className="w-[180px]">说明</TableHead>
                      <TableHead className="w-[64px] text-center">启用</TableHead>
                      <TableHead className="w-[80px]" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {customRules.map((rule) => (
                      <TableRow key={rule.key} className={!rule.enabled ? "opacity-50" : ""}>
                        <TableCell className="align-top">
                          <code className="block truncate font-mono text-xs">{rule.key}</code>
                        </TableCell>
                        <TableCell className="align-top text-sm">{rule.name}</TableCell>
                        <TableCell className="align-top">
                          <code
                            className="block max-w-[280px] truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs"
                            title={rule.pattern}
                          >
                            {rule.pattern}
                          </code>
                        </TableCell>
                        <TableCell className="align-top">
                          <span
                            className="text-muted-foreground line-clamp-1 text-xs"
                            title={rule.note || ""}
                          >
                            {rule.note || "—"}
                          </span>
                        </TableCell>
                        <TableCell className="text-center align-top">
                          <Switch
                            checked={rule.enabled}
                            disabled={busy || !!editing}
                            onCheckedChange={(v) => void toggleCustom(rule, v)}
                          />
                        </TableCell>
                        <TableCell className="align-top">
                          <div className="flex items-center justify-end gap-0.5">
                            <Button
                              size="icon"
                              variant="ghost"
                              className="h-7 w-7"
                              onClick={() => openEditCustom(rule)}
                              disabled={busy || !!editing}
                              title="编辑"
                            >
                              <PencilIcon className="h-3.5 w-3.5" />
                            </Button>
                            <Button
                              size="icon"
                              variant="ghost"
                              className="text-destructive hover:text-destructive h-7 w-7"
                              onClick={() => void removeCustom(rule)}
                              disabled={busy || !!editing}
                              title="删除"
                            >
                              <Trash2Icon className="h-3.5 w-3.5" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          <p className="text-muted-foreground text-xs">
            重启会短暂中断服务；新进程起来后本页会自动确认 /api/health。
          </p>
        </>
      )}

      {/* 自定义条目编辑器：与拦截规则页同样式（右侧 Sheet）。 */}
      <Sheet
        open={customOpen}
        onOpenChange={(open) => {
          if (!customSaving) setCustomOpen(open);
        }}
      >
        <SheetContent side="right" className="flex flex-col gap-0 p-0 sm:max-w-md">
          <SheetHeader className="border-b px-6 py-4">
            <SheetTitle>{editingCustom ? "编辑自定义条目" : "新增自定义条目"}</SheetTitle>
            <SheetDescription className="text-xs">
              命中即直接拦截（deny），不能写成 allow。保存后仍需重启服务端才生效。
            </SheetDescription>
          </SheetHeader>

          <div className="min-h-0 flex-1 space-y-5 overflow-y-auto px-6 py-5">
            <div className="space-y-1.5">
              <Label className="text-muted-foreground text-xs font-medium tracking-wide uppercase">
                唯一标识 key
              </Label>
              <Input
                value={customForm.key}
                onChange={(e) => setCustomForm((f) => ({ ...f, key: e.target.value }))}
                disabled={!!editingCustom}
                placeholder="如 block_forbidden_scan"
                className="font-mono text-xs"
              />
              <p className="text-muted-foreground text-[11px]">
                只允许字母、数字、下划线；创建后不可修改。
              </p>
            </div>

            <div className="space-y-1.5">
              <Label className="text-muted-foreground text-xs font-medium tracking-wide uppercase">
                显示名
              </Label>
              <Input
                value={customForm.name}
                onChange={(e) => setCustomForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="如 拦截内部扫描脚本"
              />
            </div>

            <div className="space-y-1.5">
              <Label className="text-muted-foreground text-xs font-medium tracking-wide uppercase">
                匹配内容（一行）
              </Label>
              <Input
                value={customForm.pattern}
                onChange={(e) => setCustomForm((f) => ({ ...f, pattern: e.target.value }))}
                placeholder="如 forbidden_scan|internal_probe"
                spellCheck={false}
                className="font-mono text-xs"
              />
              <p className="text-muted-foreground text-[11px]">
                RE2 正则，大小写不敏感；命中执行面文本即拒绝。
              </p>
            </div>

            <div className="space-y-1.5">
              <Label className="text-muted-foreground text-xs font-medium tracking-wide uppercase">
                说明（可选）
              </Label>
              <Textarea
                value={customForm.note}
                onChange={(e) => setCustomForm((f) => ({ ...f, note: e.target.value }))}
                placeholder="为什么加这条，便于审计时回溯"
                rows={2}
                className="resize-none text-xs"
              />
            </div>

            <div className="flex items-center gap-3">
              <Switch
                id="sc-custom-enabled"
                checked={customForm.enabled}
                onCheckedChange={(v) => setCustomForm((f) => ({ ...f, enabled: v }))}
              />
              <Label htmlFor="sc-custom-enabled" className="cursor-pointer">
                启用此条目
              </Label>
            </div>

            {customErr ? <p className="text-destructive text-xs">{customErr}</p> : null}
          </div>

          <SheetFooter className="flex-row justify-end gap-2 border-t px-6 py-4">
            <Button variant="outline" onClick={() => setCustomOpen(false)} disabled={customSaving}>
              取消
            </Button>
            <Button onClick={() => void submitCustom()} disabled={customSaving}>
              {customSaving ? "保存中…" : "保存（需重启）"}
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </div>
  );
}
