"use client";

// 项目列表页（artex-hs T08）：名称/状态/任务数/finding 分档/并发数 + 建项目对话框。
// 风格照 system/mcp + function/commands 页（shadcn、既有表格/对话框模式，不引新依赖）。

import * as React from "react";
import Link from "next/link";
import { toast } from "sonner";
import { FolderKanbanIcon, InboxIcon, PlusIcon, RefreshCwIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { ProjectWithStats } from "@/lib/types";

// FindingCells finding 分档着色（与任务列表页同一配色口径）。
function FindingCells({ f }: { f: Record<string, number> }) {
  const g = (k: string) => f[k] ?? 0;
  const total = g("critical") + g("high") + g("medium") + g("low");
  if (total === 0) return <span className="text-muted-foreground">0</span>;
  const seg = (n: number, cls: string) => (
    <span className={n > 0 ? cls : "text-muted-foreground"}>{n}</span>
  );
  return (
    <span className="font-medium whitespace-nowrap" title="严重 / 高 / 中 / 低">
      {seg(g("critical"), "text-rose-600 dark:text-rose-400")}
      <span className="text-muted-foreground">/</span>
      {seg(g("high"), "text-red-600 dark:text-red-400")}
      <span className="text-muted-foreground">/</span>
      {seg(g("medium"), "text-amber-600 dark:text-amber-400")}
      <span className="text-muted-foreground">/</span>
      {seg(g("low"), "text-slate-600 dark:text-slate-400")}
    </span>
  );
}

export default function ProjectsPage() {
  const [projects, setProjects] = React.useState<ProjectWithStats[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [statusFilter, setStatusFilter] = React.useState<"all" | "active" | "archived">("all");
  const [createOpen, setCreateOpen] = React.useState(false);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .projects(statusFilter === "all" ? undefined : statusFilter)
      .then((r) => setProjects(r.projects))
      .catch((e) => toast.error("加载项目失败：" + (e as Error).message))
      .finally(() => setLoading(false));
  }, [statusFilter]);
  React.useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="p-4 md:p-6">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <h1 className="font-semibold text-xl">项目</h1>
          <p className="text-muted-foreground text-sm">批量任务的项目分组与并发调度</p>
        </div>
        <div className="flex items-center gap-2">
          <NativeSelect
            className="w-32"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as typeof statusFilter)}
            aria-label="状态筛选"
          >
            <NativeSelectOption value="all">全部状态</NativeSelectOption>
            <NativeSelectOption value="active">进行中</NativeSelectOption>
            <NativeSelectOption value="archived">已归档</NativeSelectOption>
          </NativeSelect>
          <Button variant="outline" size="icon" onClick={load} aria-label="刷新" disabled={loading}>
            <RefreshCwIcon className={loading ? "animate-spin" : ""} />
          </Button>
          <Button onClick={() => setCreateOpen(true)}>
            <PlusIcon data-icon="inline-start" /> 新建项目
          </Button>
        </div>
      </div>

      {!loading && projects.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <InboxIcon />
            </EmptyMedia>
            <EmptyTitle>还没有项目</EmptyTitle>
            <EmptyDescription>
              项目是批量任务的分组调度单位：建项目 → 贴一行一个目标批量下发 → 按项目并发数排队放行。
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <div className="rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>名称</TableHead>
                <TableHead className="w-24">状态</TableHead>
                <TableHead className="w-20 text-center">任务数</TableHead>
                <TableHead className="w-20 text-center">排队中</TableHead>
                <TableHead className="w-28 text-center">漏洞 严/高/中/低</TableHead>
                <TableHead className="w-16 text-center">并发</TableHead>
                <TableHead className="w-24">负责人</TableHead>
                <TableHead className="w-36">创建时间</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {projects.map((p) => (
                <TableRow key={p.id}>
                  <TableCell>
                    <div className="flex min-w-0 flex-col gap-1">
                      <Link
                        href={`/function/projects/detail?id=${p.id}`}
                        className="text-foreground inline-flex items-center gap-1.5 rounded-sm font-medium hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      >
                        <FolderKanbanIcon className="text-muted-foreground size-4 shrink-0" />
                        <span className="max-w-64 truncate" title={p.description || p.name}>
                          {p.name}
                        </span>
                      </Link>
                      {/* T19 状态徽章：开关开启才显示，配色与详情页/现有一致。 */}
                      {(p.observer_enabled || p.reader_enabled || p.auto_report) && (
                        <div className="flex flex-wrap items-center gap-1">
                          {p.observer_enabled && (
                            <Badge variant="outline" className="text-emerald-600 dark:text-emerald-400">
                              观察者
                            </Badge>
                          )}
                          {p.reader_enabled && (
                            <Badge variant="outline" className="text-blue-600 dark:text-blue-400">
                              阅读者
                            </Badge>
                          )}
                          {p.auto_report && (
                            <Badge variant="outline" className="text-purple-600 dark:text-purple-400">
                              自动报告
                            </Badge>
                          )}
                        </div>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={p.status === "active" ? "default" : "secondary"}>
                      {p.status === "active" ? "进行中" : "已归档"}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-center text-xs tabular-nums">{p.stats.task_count}</TableCell>
                  <TableCell className="text-center text-xs tabular-nums">
                    {p.stats.queued_tasks > 0 ? (
                      <span className="text-amber-600 font-medium dark:text-amber-400">{p.stats.queued_tasks}</span>
                    ) : (
                      <span className="text-muted-foreground">0</span>
                    )}
                  </TableCell>
                  <TableCell className="text-center text-xs tabular-nums">
                    <FindingCells f={p.stats.findings} />
                  </TableCell>
                  <TableCell className="text-center text-xs tabular-nums">{p.concurrency}</TableCell>
                  <TableCell className="text-muted-foreground max-w-24 truncate text-xs">{p.owner || "—"}</TableCell>
                  <TableCell className="text-muted-foreground text-xs whitespace-nowrap tabular-nums">
                    {new Date(p.created_at).toLocaleString("zh-CN", {
                      month: "2-digit",
                      day: "2-digit",
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </TableCell>
                </TableRow>
              ))}
              {loading && projects.length === 0 && (
                <TableRow>
                  <TableCell colSpan={8} className="text-muted-foreground py-8 text-center text-sm">
                    加载中…
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      )}

      <CreateProjectDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={() => {
          setCreateOpen(false);
          load();
        }}
      />
    </div>
  );
}

// CreateProjectDialog 新建项目：名称必填，描述/负责人/并发数可选。
// T19 新增四设置控件：观察者 / 阅读者 / 自动写报告（三 Switch，默认关）+
// 报告模板（下拉，可留空=默认链）。后端 create 字段集已与 PATCH 对齐（方案 A），
// 四控件值直接进 POST body。
function CreateProjectDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onCreated: () => void;
}) {
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [owner, setOwner] = React.useState("");
  const [concurrency, setConcurrency] = React.useState("2");
  const [observer, setObserver] = React.useState(false);
  const [reader, setReader] = React.useState(false);
  const [autoReport, setAutoReport] = React.useState(false);
  const [templateId, setTemplateId] = React.useState<string>(""); // "" = 默认链
  const [templates, setTemplates] = React.useState<{ id: number; name: string; is_default: boolean }[]>([]);
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    if (open) {
      setName("");
      setDescription("");
      setOwner("");
      setConcurrency("2");
      setObserver(false);
      setReader(false);
      setAutoReport(false);
      setTemplateId("");
      api
        .reportTemplates()
        .then(setTemplates)
        .catch(() => setTemplates([]));
    }
  }, [open]);

  async function submit() {
    if (!name.trim()) {
      toast.error("请填写项目名");
      return;
    }
    const conc = Number(concurrency);
    if (!Number.isFinite(conc) || conc < 1 || conc > 8) {
      toast.error("并发数须为 1-8 的整数");
      return;
    }
    setSaving(true);
    try {
      const p = await api.createProject({
        name: name.trim(),
        description: description.trim(),
        owner: owner.trim(),
        concurrency: conc,
        observer_enabled: observer,
        report_template_id: templateId ? Number(templateId) : null,
        auto_report: autoReport,
        reader_enabled: reader,
      });
      toast.success(`项目已创建：${p.name}`);
      onCreated();
    } catch (e) {
      toast.error("创建失败：" + (e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !saving && onOpenChange(o)}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>新建项目</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid gap-2">
            <Label htmlFor="p-name">名称 *</Label>
            <Input id="p-name" placeholder="如：2026 春招渗透测试" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="p-desc">描述 / 测试范围</Label>
            <Textarea id="p-desc" rows={3} value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-2">
              <Label htmlFor="p-owner">负责人</Label>
              <Input id="p-owner" placeholder="可留空" value={owner} onChange={(e) => setOwner(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="p-conc">批量任务并发数</Label>
              <Input id="p-conc" type="number" min={1} max={8} value={concurrency} onChange={(e) => setConcurrency(e.target.value)} />
              <p className="text-muted-foreground text-xs">1=严格串行，2=同时两任务（默认）</p>
            </div>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="p-template">报告模板</Label>
            <NativeSelect id="p-template" value={templateId} onChange={(e) => setTemplateId(e.target.value)}>
              <NativeSelectOption value="">默认模板（跟随全局默认链）</NativeSelectOption>
              {templates.map((t) => (
                <NativeSelectOption key={t.id} value={String(t.id)}>
                  {t.name}
                  {t.is_default ? "（默认）" : ""}
                </NativeSelectOption>
              ))}
            </NativeSelect>
            <p className="text-muted-foreground text-xs">整项目收官自动写报告时用的模板；留空则用全局默认模板链。</p>
          </div>
          <div className="grid gap-3 rounded-lg border p-3">
            <label className="flex items-center justify-between gap-3 text-sm">
              <span>跨任务观察者</span>
              <Switch checked={observer} onCheckedChange={setObserver} />
            </label>
            <label className="flex items-center justify-between gap-3 text-sm">
              <span>跨项目阅读者</span>
              <Switch checked={reader} onCheckedChange={setReader} />
            </label>
            <label className="flex items-center justify-between gap-3 text-sm">
              <span>自动写报告</span>
              <Switch checked={autoReport} onCheckedChange={setAutoReport} />
            </label>
            <p className="text-muted-foreground text-xs">三项默认关闭；自动写报告在该项目全部任务收官后按所选模板生成一份项目报告。</p>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            取消
          </Button>
          <Button onClick={submit} disabled={saving}>
            {saving ? "创建中…" : "创建"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
