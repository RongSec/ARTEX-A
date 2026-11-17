"use client";

// V9-RULE：短路规则区块（并入 /system/intercept）。
//
// 内置工具策略 + 平台路径 + 自定义条目已合并为一张统一规则表，交互形态与
// 拦截规则页保持一致：矮行表格（优先级/名称/策略/匹配内容/说明/启用）。
// 内置行只读（仅启用开关可切），自定义行可编辑删除。
// 任何保存都只写文件，必须重启服务端才生效。

import * as React from "react";

import { AlertTriangleIcon, LockIcon, PencilIcon, PlusIcon, PowerIcon, RotateCcwIcon, Trash2Icon } from "lucide-react";
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { ShortCircuitRule, ShortCircuitState } from "@/lib/types";

const CUSTOM_KEY_RE = /^[A-Za-z0-9_]+$/;

type CustomForm = {
  key: string;
  name: string;
  action: "allow" | "deny" | "ask";
  priority: string;
  pattern: string;
  description: string;
  enabled: boolean;
};

const blankCustomForm = (priority: number): CustomForm => ({
  key: "",
  name: "",
  action: "deny",
  priority: String(priority),
  pattern: "",
  description: "",
  enabled: true,
});

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function ActionBadge({ action }: { action: ShortCircuitRule["action"] }) {
  if (action === "deny") {
    return <Badge className="bg-destructive/90 text-white hover:bg-destructive/90">deny</Badge>;
  }
  if (action === "ask") {
    return <Badge className="bg-amber-500 text-white hover:bg-amber-500">ask</Badge>;
  }
  return <Badge className="bg-emerald-600 text-white hover:bg-emerald-600">allow</Badge>;
}

export function ShortCircuitSection() {
  const [state, setState] = React.useState<ShortCircuitState | null>(null);
  const [rules, setRules] = React.useState<ShortCircuitRule[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [resetting, setResetting] = React.useState(false);
  const [restarting, setRestarting] = React.useState(false);
  const [pending, setPending] = React.useState(0);
  const [error, setError] = React.useState("");

  const [open, setOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<ShortCircuitRule | null>(null);
  const [form, setForm] = React.useState<CustomForm>(blankCustomForm(100));
  const [formErr, setFormErr] = React.useState("");

  const hydrate = React.useCallback((next: ShortCircuitState) => {
    setState(next);
    const list = next.rules ?? [];
    setRules([...list].sort((a, b) => a.priority - b.priority));
  }, []);

  const reload = React.useCallback(async () => {
    const next = await api.shortCircuit();
    hydrate(next);
    return next;
  }, [hydrate]);

  React.useEffect(() => {
    reload()
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, [reload]);

  const persist = async (next: ShortCircuitRule[], silent = false): Promise<boolean> => {
    setSaving(true);
    setError("");
    try {
      await api.saveShortCircuitRules(next);
      setPending((n) => n + 1);
      if (!silent) toast.success("已保存到文件，需重启服务端才生效");
      void reload().catch(() => {});
      return true;
    } catch (e) {
      const msg = (e as Error).message;
      setError(msg);
      toast.error("保存失败：" + msg);
      return false;
    } finally {
      setSaving(false);
    }
  };

  const toggleRule = async (rule: ShortCircuitRule, enabled: boolean) => {
    const next = rules.map((r) => (r.id === rule.id ? { ...r, enabled } : r));
    setRules(next);
    await persist(next);
  };

  const openNew = () => {
    const maxPriority = rules.reduce((m, r) => Math.max(m, r.priority), 99);
    setEditing(null);
    setForm(blankCustomForm(maxPriority + 10));
    setFormErr("");
    setOpen(true);
  };

  const openEdit = (rule: ShortCircuitRule) => {
    setEditing(rule);
    setForm({
      key: rule.id.startsWith("custom:") ? rule.id.slice("custom:".length) : "",
      name: rule.name,
      action: rule.action,
      priority: String(rule.priority),
      pattern: rule.pattern,
      description: rule.description,
      enabled: rule.enabled,
    });
    setFormErr("");
    setOpen(true);
  };

  const submit = async () => {
    const key = form.key.trim();
    const name = form.name.trim();
    const pattern = form.pattern.trim();
    const priority = Number.parseInt(form.priority, 10);
    if (!CUSTOM_KEY_RE.test(key)) {
      setFormErr("key 只能包含字母、数字、下划线，且不能为空");
      return;
    }
    if (!name) {
      setFormErr("名称不能为空");
      return;
    }
    if (!pattern) {
      setFormErr("匹配内容不能为空");
      return;
    }
    if (!Number.isFinite(priority) || priority <= 0) {
      setFormErr("优先级必须是正整数");
      return;
    }
    const dup = rules.some(
      (r) => r.kind === "custom" && r.id.toLowerCase() === `custom:${key}`.toLowerCase() && r.id !== editing?.id,
    );
    if (dup) {
      setFormErr(`key「${key}」已存在（不区分大小写）`);
      return;
    }
    const rule: ShortCircuitRule = {
      id: `custom:${key}`,
      kind: "custom",
      priority,
      name,
      action: form.action,
      pattern,
      description: form.description.trim(),
      enabled: form.enabled,
      readonly: false,
    };
    const next = (editing ? rules.map((r) => (r.id === editing.id ? rule : r)) : [...rules, rule]).sort(
      (a, b) => a.priority - b.priority,
    );
    const ok = await persist(next);
    if (ok) setOpen(false);
  };

  const remove = async (rule: ShortCircuitRule) => {
    if (!window.confirm(`确定删除自定义规则「${rule.name}」？保存后仍需重启服务端才生效。`)) return;
    const next = rules.filter((r) => r.id !== rule.id);
    setRules(next);
    await persist(next);
  };

  const reset = () => {
    if (!window.confirm("确定把短路规则文件恢复为代码内置默认值？仍需重启服务端才生效。")) return;
    setResetting(true);
    setError("");
    api
      .resetShortCircuit()
      .then(async () => {
        await reload();
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
  const customCount = rules.filter((r) => r.kind === "custom").length;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-amber-900 dark:text-amber-200">
        <AlertTriangleIcon className="mt-0.5 size-5 shrink-0" />
        <div className="space-y-1 text-sm">
          <div className="font-medium">短路规则为代码级红线，修改后需重启服务端才生效</div>
          <div className="text-xs opacity-90">
            保存只写文件，不会热改正在运行的判定。内置行只读，只能切换启用状态。
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
          {/* 顶部工具条：待重启徽标 + 重启生效按钮（与拦截规则页同高的矮行） */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="text-muted-foreground">共 {rules.length} 条（自定义 {customCount} 条）</span>
              {pending > 0 ? (
                <Badge className="bg-amber-600 text-white hover:bg-amber-600">有改动待重启生效</Badge>
              ) : (
                <Badge variant="secondary">与运行配置一致</Badge>
              )}
              <span className="text-muted-foreground font-mono break-all">文件：{state?.file_path ?? "—"}</span>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" variant="outline" onClick={openNew} disabled={busy}>
                <PlusIcon className="size-4" />
                新增自定义规则
              </Button>
              <Button size="sm" variant="outline" onClick={reset} disabled={busy}>
                <RotateCcwIcon className="size-4" />
                {resetting ? "恢复中…" : "恢复默认"}
              </Button>
              <Button size="sm" variant="destructive" onClick={restart} disabled={busy}>
                <PowerIcon className="size-4" />
                {restarting ? "重启中…" : "重启生效"}
              </Button>
            </div>
          </div>

          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="w-[72px] text-right">优先级</TableHead>
                    <TableHead className="w-[220px]">名称</TableHead>
                    <TableHead className="w-[88px]">策略</TableHead>
                    <TableHead>匹配内容</TableHead>
                    <TableHead className="w-[220px]">说明</TableHead>
                    <TableHead className="w-[64px] text-center">启用</TableHead>
                    <TableHead className="w-[80px]" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rules.map((rule) => (
                    <TableRow key={rule.id} className={!rule.enabled ? "opacity-50" : ""}>
                      <TableCell className="text-muted-foreground text-right align-middle font-mono text-xs tabular-nums">
                        {rule.priority}
                      </TableCell>
                      <TableCell className="align-middle">
                        <div className="flex min-w-0 items-center gap-1.5">
                          <span className="truncate text-sm font-medium" title={rule.name}>
                            {rule.name}
                          </span>
                          {rule.readonly ? (
                            <Badge variant="outline" className="shrink-0 gap-0.5 px-1 py-0 text-[10px]">
                              <LockIcon className="size-2.5" />
                              内置
                            </Badge>
                          ) : (
                            <Badge variant="secondary" className="shrink-0 px-1 py-0 text-[10px]">
                              自定义
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="align-middle">
                        <ActionBadge action={rule.action} />
                      </TableCell>
                      <TableCell className="align-middle">
                        <code
                          className="bg-muted block max-w-[380px] truncate rounded px-1.5 py-0.5 font-mono text-xs"
                          title={rule.pattern}
                        >
                          {rule.pattern}
                        </code>
                      </TableCell>
                      <TableCell className="align-middle">
                        <span className="text-muted-foreground line-clamp-1 text-xs" title={rule.description}>
                          {rule.description || "—"}
                        </span>
                      </TableCell>
                      <TableCell className="text-center align-middle">
                        <Switch
                          checked={rule.enabled}
                          disabled={busy}
                          onCheckedChange={(v) => void toggleRule(rule, v)}
                        />
                      </TableCell>
                      <TableCell className="align-middle">
                        {rule.readonly ? null : (
                          <div className="flex items-center justify-end gap-0.5">
                            <Button
                              size="icon"
                              variant="ghost"
                              className="h-7 w-7"
                              onClick={() => openEdit(rule)}
                              disabled={busy}
                              title="编辑"
                            >
                              <PencilIcon className="h-3.5 w-3.5" />
                            </Button>
                            <Button
                              size="icon"
                              variant="ghost"
                              className="text-destructive hover:text-destructive h-7 w-7"
                              onClick={() => void remove(rule)}
                              disabled={busy}
                              title="删除"
                            >
                              <Trash2Icon className="h-3.5 w-3.5" />
                            </Button>
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <p className="text-muted-foreground text-xs">
            优先级数值小的先命中（deny/ask/allow 动作按此表顺序执行）。重启会短暂中断服务，新进程起来后本页会自动确认 /api/health。
          </p>
        </>
      )}

      <Sheet
        open={open}
        onOpenChange={(o) => {
          if (!saving) setOpen(o);
        }}
      >
        <SheetContent side="right" className="flex flex-col gap-0 p-0 sm:max-w-md">
          <SheetHeader className="border-b px-6 py-4">
            <SheetTitle>{editing ? "编辑自定义规则" : "新增自定义规则"}</SheetTitle>
            <SheetDescription className="text-xs">
              保存后仍需重启服务端才生效；内置规则不可被覆盖。
            </SheetDescription>
          </SheetHeader>

          <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-6 py-5">
            <div className="space-y-1.5">
              <Label className="text-muted-foreground text-xs font-medium tracking-wide uppercase">唯一标识 key</Label>
              <Input
                value={form.key}
                onChange={(e) => setForm((f) => ({ ...f, key: e.target.value }))}
                disabled={!!editing}
                placeholder="如 block_forbidden_scan"
                className="font-mono text-xs"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-muted-foreground text-xs font-medium tracking-wide uppercase">名称</Label>
                <Input
                  value={form.name}
                  onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                  placeholder="如 拦截内部扫描脚本"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-muted-foreground text-xs font-medium tracking-wide uppercase">优先级</Label>
                <Input
                  value={form.priority}
                  onChange={(e) => setForm((f) => ({ ...f, priority: e.target.value }))}
                  inputMode="numeric"
                  className="font-mono text-xs"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label className="text-muted-foreground text-xs font-medium tracking-wide uppercase">策略</Label>
              <div className="flex gap-2">
                {(["deny", "ask", "allow"] as const).map((a) => (
                  <Button
                    key={a}
                    type="button"
                    size="sm"
                    variant={form.action === a ? "default" : "outline"}
                    onClick={() => setForm((f) => ({ ...f, action: a }))}
                  >
                    {a}
                  </Button>
                ))}
              </div>
            </div>

            <div className="space-y-1.5">
              <Label className="text-muted-foreground text-xs font-medium tracking-wide uppercase">
                匹配内容（一行 RE2）
              </Label>
              <Input
                value={form.pattern}
                onChange={(e) => setForm((f) => ({ ...f, pattern: e.target.value }))}
                placeholder="如 forbidden_scan|internal_probe"
                spellCheck={false}
                className="font-mono text-xs"
              />
            </div>

            <div className="space-y-1.5">
              <Label className="text-muted-foreground text-xs font-medium tracking-wide uppercase">说明（可选）</Label>
              <Textarea
                value={form.description}
                onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                placeholder="为什么加这条，便于审计时回溯"
                rows={2}
                className="resize-none text-xs"
              />
            </div>

            <div className="flex items-center gap-3">
              <Switch
                id="sc-rule-enabled"
                checked={form.enabled}
                onCheckedChange={(v) => setForm((f) => ({ ...f, enabled: v }))}
              />
              <Label htmlFor="sc-rule-enabled" className="cursor-pointer">
                启用此规则
              </Label>
            </div>

            {formErr ? <p className="text-destructive text-xs">{formErr}</p> : null}
          </div>

          <SheetFooter className="flex-row justify-end gap-2 border-t px-6 py-4">
            <Button variant="outline" onClick={() => setOpen(false)} disabled={saving}>
              取消
            </Button>
            <Button onClick={() => void submit()} disabled={saving}>
              {saving ? "保存中…" : "保存（需重启）"}
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </div>
  );
}
