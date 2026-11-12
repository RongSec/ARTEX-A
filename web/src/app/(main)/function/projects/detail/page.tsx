"use client";

// 项目详情页（artex-hs T08）：三 tab = 任务列表 / 批量下发 / 全项目大图（B3 占位）。
// 任务列表复用后端 /api/projects/{id} 的 taskDTO 聚合（状态/token/finding 分档
// 与任务列表页同源），行点击进任务详情页。风格照现有页（shadcn，不引新依赖）。

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";

import {
  ArchiveIcon,
  ArrowLeftIcon,
  DatabaseIcon,
  PencilIcon,
  RefreshCwIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

import { ProjectBatchTasks } from "@/components/project-batch-tasks";
import { ProjectGraphTab } from "./project-graph-tab";
import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { ProjectDetail, ReportTemplate, Task } from "@/lib/types";

function fmtToken(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "—";
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1) + "k";
  return String(n);
}

function fmtDateTime(unix: number | undefined): string {
  if (!unix) return "—";
  return new Date(unix * 1000).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function ProjectDetailPage() {
  return (
    <React.Suspense fallback={null}>
      <ProjectDetailInner />
    </React.Suspense>
  );
}

function ProjectDetailInner() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") ?? "";
  const [detail, setDetail] = React.useState<ProjectDetail | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [editOpen, setEditOpen] = React.useState(false);
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  // 报告模板列表（编辑对话框下拉 + 概览展示模板名共用一次拉取）。
  const [templates, setTemplates] = React.useState<ReportTemplate[]>([]);

  React.useEffect(() => {
    api
      .reportTemplates()
      .then(setTemplates)
      .catch(() => setTemplates([]));
  }, []);

  const load = React.useCallback(() => {
    if (!id) return;
    setLoading(true);
    api
      .project(id)
      .then(setDetail)
      .catch((e) => toast.error("加载项目失败：" + (e as Error).message))
      .finally(() => setLoading(false));
  }, [id]);
  React.useEffect(() => {
    load();
  }, [load]);

  if (!id) {
    return (
      <div className="p-6">
        <p className="text-muted-foreground text-sm">缺少项目 id 参数。</p>
      </div>
    );
  }
  if (loading && !detail) {
    return (
      <div className="text-muted-foreground p-6 text-sm">加载中…</div>
    );
  }
  if (!detail) {
    return (
      <div className="p-6">
        <p className="text-muted-foreground text-sm">项目不存在或已删除。</p>
        <Button variant="outline" size="sm" className="mt-3" asChild>
          <Link href="/function/projects">返回项目列表</Link>
        </Button>
      </div>
    );
  }

  const p = detail.project;
  const tasks = detail.tasks;

  async function archiveToggle() {
    try {
      const next = p.status === "active" ? "archived" : "active";
      await api.updateProject(p.id, { status: next });
      toast.success(next === "archived" ? "项目已归档（其排队批量任务将停止放行）" : "项目已恢复");
      load();
    } catch (e) {
      toast.error("操作失败：" + (e as Error).message);
    }
  }

  async function doDelete() {
    try {
      await api.deleteProject(p.id);
      toast.success("项目已删除（任务保留，归属已摘除）");
      window.location.href = "/function/projects";
    } catch (e) {
      toast.error("删除失败：" + (e as Error).message);
    }
  }

  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="icon" asChild aria-label="返回列表">
              <Link href="/function/projects">
                <ArrowLeftIcon />
              </Link>
            </Button>
            <h1 className="truncate font-semibold text-xl">{p.name}</h1>
            <Badge variant={p.status === "active" ? "default" : "secondary"}>
              {p.status === "active" ? "进行中" : "已归档"}
            </Badge>
            {p.observer_enabled && (
              <Badge variant="outline" className="text-emerald-600 dark:text-emerald-400">
                观察者开
              </Badge>
            )}
            {p.reader_enabled && (
              <Badge variant="outline" className="text-blue-600 dark:text-blue-400">
                阅读者开
              </Badge>
            )}
            {p.auto_report && (
              <Badge variant="outline" className="text-purple-600 dark:text-purple-400">
                自动报告开
              </Badge>
            )}
          </div>
          {p.description && <p className="text-muted-foreground mt-1 text-sm">{p.description}</p>}
          <p className="text-muted-foreground mt-1 text-xs">
            并发 {p.concurrency} · 负责人 {p.owner || "—"} · 任务 {detail.stats.task_count}（排队 {detail.stats.queued_tasks}）
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <ProjectBatchTasks projectID={p.id} concurrency={p.concurrency} onDone={load} />
          <Button variant="outline" size="icon" onClick={load} aria-label="刷新" disabled={loading}>
            <RefreshCwIcon className={loading ? "animate-spin" : ""} />
          </Button>
          <Button variant="outline" size="icon" onClick={() => setEditOpen(true)} aria-label="编辑项目">
            <PencilIcon />
          </Button>
          <Button variant="outline" size="icon" onClick={archiveToggle} aria-label={p.status === "active" ? "归档" : "恢复"}>
            <ArchiveIcon />
          </Button>
          <Button variant="outline" size="icon" onClick={() => setDeleteOpen(true)} aria-label="删除项目">
            <Trash2Icon className="text-destructive" />
          </Button>
        </div>
      </div>

      <Tabs defaultValue="tasks">
        <TabsList>
          <TabsTrigger value="tasks">任务列表{tasks.length ? `（${tasks.length}）` : ""}</TabsTrigger>
          <TabsTrigger value="overview">项目概览</TabsTrigger>
          <TabsTrigger value="graph">全项目大图</TabsTrigger>
        </TabsList>
        <TabsContent value="tasks" className="mt-4">
          <TasksTab tasks={tasks} onChanged={load} />
        </TabsContent>
        <TabsContent value="overview" className="mt-4">
          <OverviewTab detail={detail} templates={templates} />
        </TabsContent>
        <TabsContent value="graph" className="mt-4">
          <ProjectGraphTab project={p} onChanged={load} />
        </TabsContent>
      </Tabs>

      <EditProjectDialog open={editOpen} onOpenChange={setEditOpen} project={p} templates={templates} onSaved={load} />

      <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除项目「{p.name}」？</AlertDialogTitle>
            <AlertDialogDescription>
              项目分组将被删除；其下 {tasks.length} 个任务全部保留（归属自动摘除，回到无项目状态）。
              排队中的批量任务将停止放行，需要时可手动继续。此操作不可撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                void doDelete();
              }}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              删除
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

// TasksTab 任务列表：读详情聚合 API 的 task 行，口径与任务列表页一致。
// 每行「移出」= PATCH /tasks/{id}/project 摘归属（T05 挂/摘）；操作后 toast
// 提示投影更新时机（对齐 T12(0)：摘除后大图靠下次重建清旧行、任务重启重绑）。
function TasksTab({ tasks, onChanged }: { tasks: Task[]; onChanged: () => void }) {
  const [detaching, setDetaching] = React.useState<string | null>(null);

  async function detach(taskId: string) {
    setDetaching(taskId);
    try {
      await api.attachTaskProject(taskId, null);
      toast.success("已移出项目", {
        description: "投影正在后台更新，稍后自动反映最新归属。",
        duration: 6000,
      });
      onChanged();
    } catch (e) {
      toast.error("移出失败：" + (e as Error).message);
    } finally {
      setDetaching(null);
    }
  }

  if (tasks.length === 0) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <DatabaseIcon />
          </EmptyMedia>
          <EmptyTitle>项目下还没有任务</EmptyTitle>
          <EmptyDescription>用右上角「批量下发」贴一行一个目标创建任务。</EmptyDescription>
        </EmptyHeader>
      </Empty>
    );
  }
  return (
    <div className="rounded-xl border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>任务</TableHead>
            <TableHead className="w-28">状态</TableHead>
            <TableHead className="w-24 text-center">目标 达成/总</TableHead>
            <TableHead className="w-28 text-center">漏洞 严/高/中/低</TableHead>
            <TableHead className="w-20 text-center">Token</TableHead>
            <TableHead className="w-28">创建时间</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {tasks.map((t) => {
            const f = t.findings;
            const ftotal = f ? f.critical + f.high + f.medium + f.low : 0;
            return (
              <TableRow key={t.id}>
                <TableCell className="max-w-80">
                  <Link
                    href={`/function/tasks/detail?id=${encodeURIComponent(t.id)}`}
                    className="block truncate rounded-sm hover:text-foreground hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    title={t.description}
                  >
                    #{t.id} {t.description}
                  </Link>
                </TableCell>
                <TableCell>
                  <StatusBadge domain="task" value={t.status} dot />
                </TableCell>
                <TableCell className="text-muted-foreground text-center text-xs tabular-nums">
                  {typeof t.goals_total === "number" && t.goals_total > 0 ? `${t.goals_met}/${t.goals_total}` : "—"}
                </TableCell>
                <TableCell className="text-center text-xs tabular-nums">
                  {f && ftotal > 0 ? (
                    <span title="严重 / 高 / 中 / 低">
                      <span className="text-rose-600 dark:text-rose-400">{f.critical}</span>
                      <span className="text-muted-foreground">/</span>
                      <span className="text-red-600 dark:text-red-400">{f.high}</span>
                      <span className="text-muted-foreground">/</span>
                      <span className="text-amber-600 dark:text-amber-400">{f.medium}</span>
                      <span className="text-muted-foreground">/</span>
                      <span className="text-slate-600 dark:text-slate-400">{f.low}</span>
                    </span>
                  ) : (
                    <span className="text-muted-foreground">0</span>
                  )}
                </TableCell>
                <TableCell className="text-muted-foreground text-center text-xs tabular-nums">
                  {fmtToken((t.tokens?.input_tokens ?? 0) + (t.tokens?.output_tokens ?? 0))}
                </TableCell>
                <TableCell className="text-muted-foreground text-xs tabular-nums">{fmtDateTime(t.created_unix)}</TableCell>
                <TableCell className="w-16 text-right">
                  <Button
                    variant="ghost"
                    size="xs"
                    className="text-muted-foreground hover:text-destructive"
                    onClick={() => detach(t.id)}
                    disabled={detaching === t.id}
                    title="移出本项目（任务保留）"
                  >
                    {detaching === t.id ? "移出中…" : "移出"}
                  </Button>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

// OverviewTab 项目 finding 汇总 + 基础信息 + 报告设置（T19）。
function OverviewTab({ detail, templates }: { detail: ProjectDetail; templates: ReportTemplate[] }) {
  const f = detail.stats.findings;
  const g = (k: string) => f[k] ?? 0;
  const cards: { key: string; label: string; cls: string }[] = [
    { key: "critical", label: "严重", cls: "text-rose-600 dark:text-rose-400" },
    { key: "high", label: "高危", cls: "text-red-600 dark:text-red-400" },
    { key: "medium", label: "中危", cls: "text-amber-600 dark:text-amber-400" },
    { key: "low", label: "低危", cls: "text-slate-600 dark:text-slate-400" },
  ];
  const p = detail.project;
  const bound = p.report_template_id ? templates.find((t) => t.id === p.report_template_id) : null;
  return (
    <div className="grid gap-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {cards.map((c) => (
          <div key={c.key} className="rounded-xl border p-4">
            <p className="text-muted-foreground text-xs">{c.label}</p>
            <p className={`mt-1 font-semibold text-2xl tabular-nums ${c.cls}`}>{g(c.key)}</p>
          </div>
        ))}
      </div>
      <div className="rounded-xl border p-4 text-sm">
        <p className="text-muted-foreground">
          创建时间：{new Date(detail.project.created_at).toLocaleString("zh-CN")} · 更新时间：
          {new Date(detail.project.updated_at).toLocaleString("zh-CN")} · 并发额度：{detail.project.concurrency} ·
          观察者：{detail.project.observer_enabled ? "开" : "关（将在观察者版本启用）"}
        </p>
        <p className="text-muted-foreground mt-2">
          阅读者：{p.reader_enabled ? "开（跨项目 reader 可聚合本项目洞察）" : "关"} · 自动写报告：
          {p.auto_report ? "开（全部任务收官后按下方模板生成）" : "关"}
        </p>
      </div>
      <div className="flex items-center justify-between gap-4 rounded-xl border p-4 text-sm">
        <div className="min-w-0">
          <p className="text-muted-foreground text-xs">项目报告模板</p>
          <p className="mt-1 truncate">
            {bound ? (
              <span title={bound.name}>{bound.name}</span>
            ) : p.report_template_id ? (
              <span className="text-muted-foreground">模板 #{p.report_template_id}（未在模板列表，可能已删除→按默认链）</span>
            ) : (
              <span className="text-muted-foreground">默认模板链（未绑定专属模板）</span>
            )}
          </p>
        </div>
        {p.report_template_id && (
          <Button
            variant="outline"
            size="sm"
            className="shrink-0"
            onClick={() => {
              // 报告中心 T21 会读取 query 预填；本棒只负责带上跳转参数。
              window.location.href = `/system/report?project_id=${p.id}&template_id=${p.report_template_id}`;
            }}
          >
            用此模板生成报告
          </Button>
        )}
      </div>
    </div>
  );
}

// EditProjectDialog PATCH 项目名/描述/负责人/并发 + 四设置开关
//（观察者/阅读者/自动报告 + 报告模板绑定，T19 与建项目对话框同构）。
// report_template_id 三态：保持原值不动时不传键；选「默认模板」传 null=清绑定；
// 选具体模板传数字=绑定（后端 *int64+Set 语义）。
function EditProjectDialog({
  open,
  onOpenChange,
  project,
  templates,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  project: ProjectDetail["project"];
  templates: ReportTemplate[];
  onSaved: () => void;
}) {
  const [name, setName] = React.useState(project.name);
  const [description, setDescription] = React.useState(project.description);
  const [owner, setOwner] = React.useState(project.owner);
  const [concurrency, setConcurrency] = React.useState(String(project.concurrency));
  const [observer, setObserver] = React.useState(project.observer_enabled);
  const [reader, setReader] = React.useState(project.reader_enabled);
  const [autoReport, setAutoReport] = React.useState(project.auto_report);
  const [templateId, setTemplateId] = React.useState<string>(project.report_template_id ? String(project.report_template_id) : "");
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    if (open) {
      setName(project.name);
      setDescription(project.description);
      setOwner(project.owner);
      setConcurrency(String(project.concurrency));
      setObserver(project.observer_enabled);
      setReader(project.reader_enabled);
      setAutoReport(project.auto_report);
      setTemplateId(project.report_template_id ? String(project.report_template_id) : "");
    }
  }, [open, project]);

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
      await api.updateProject(project.id, {
        name: name.trim(),
        description: description.trim(),
        owner: owner.trim(),
        concurrency: conc,
        observer_enabled: observer,
        reader_enabled: reader,
        auto_report: autoReport,
        // "" = 默认链（显式 null 清除绑定）；数字 = 绑定该模板。
        report_template_id: templateId ? Number(templateId) : null,
      });
      toast.success("已保存");
      onOpenChange(false);
      onSaved();
    } catch (e) {
      toast.error("保存失败：" + (e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !saving && onOpenChange(o)}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>编辑项目</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid gap-2">
            <Label htmlFor="ep-name">名称 *</Label>
            <Input id="ep-name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-2">
              <Label htmlFor="ep-owner">负责人</Label>
              <Input id="ep-owner" value={owner} onChange={(e) => setOwner(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="ep-conc">并发数</Label>
              <Input id="ep-conc" type="number" min={1} max={8} value={concurrency} onChange={(e) => setConcurrency(e.target.value)} />
            </div>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="ep-desc">描述</Label>
            <Input id="ep-desc" value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="ep-template">报告模板</Label>
            <NativeSelect id="ep-template" value={templateId} onChange={(e) => setTemplateId(e.target.value)}>
              <NativeSelectOption value="">默认模板（跟随全局默认链）</NativeSelectOption>
              {templates.map((t) => (
                <NativeSelectOption key={t.id} value={String(t.id)}>
                  {t.name}
                  {t.is_default ? "（默认）" : ""}
                </NativeSelectOption>
              ))}
            </NativeSelect>
            <p className="text-muted-foreground text-xs">整项目收官自动写报告时用的模板；选「默认模板」= 清除专属绑定。</p>
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
            <p className="text-muted-foreground text-xs">观察者=项目级索引+观察 agent 触发+洞察注入；阅读者=允许跨项目 reader 聚合本项目；自动报告=全部任务收官后按上方模板生成项目报告。均默认关。</p>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            取消
          </Button>
          <Button onClick={submit} disabled={saving}>
            {saving ? "保存中…" : "保存"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
