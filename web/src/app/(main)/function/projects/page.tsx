"use client";

// 项目列表页（artex-hs T08）：名称/状态/任务数/finding 分档/并发数 + 建项目对话框。
// 风格照 system/mcp + function/commands 页（shadcn、既有表格/对话框模式，不引新依赖）。

import * as React from "react";
import Link from "next/link";
import { toast } from "sonner";
import { ArchiveIcon, ArchiveRestoreIcon, FolderKanbanIcon, InboxIcon, MoreHorizontalIcon, PlusIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
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
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { DeleteOptionFields, emptyDeleteOptions } from "@/components/delete-option-fields";
import { api } from "@/lib/api";
import type { DeleteTaskOptions, ProjectWithStats } from "@/lib/types";

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
  const [deleteTarget, setDeleteTarget] = React.useState<ProjectWithStats | null>(null);
  const [archivingId, setArchivingId] = React.useState<number | null>(null);

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

  // toggleArchive 归档/恢复：与任务侧一致，只切 status，不动任务与产线。
  const toggleArchive = React.useCallback(
    async (p: ProjectWithStats) => {
      const next = p.status === "active" ? "archived" : "active";
      setArchivingId(p.id);
      try {
        await api.updateProject(p.id, { status: next });
        toast.success(next === "archived" ? `已归档「${p.name}」` : `已恢复「${p.name}」`);
        load();
      } catch (e) {
        toast.error("操作失败：" + (e as Error).message);
      } finally {
        setArchivingId(null);
      }
    },
    [load],
  );

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
                <TableHead className="w-12 text-right">操作</TableHead>
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
                      {/* V6-DUAL 徽章：两个尺度各自一个开关，开哪个显示哪个。 */}
                      {(p.observer_enabled || p.reader_enabled || p.auto_report) && (
                        <div className="flex flex-wrap items-center gap-1">
                          {p.observer_enabled && (
                            <Badge variant="outline" className="text-emerald-600 dark:text-emerald-400">
                              跨任务阅读者
                            </Badge>
                          )}
                          {p.reader_enabled && (
                            <Badge variant="outline" className="text-blue-600 dark:text-blue-400">
                              跨项目阅读者
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
                  <TableCell className="text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button size="icon" variant="ghost" aria-label="项目操作" disabled={archivingId === p.id}>
                          <MoreHorizontalIcon />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onSelect={() => void toggleArchive(p)}>
                          {p.status === "active" ? (
                            <>
                              <ArchiveIcon /> 归档
                            </>
                          ) : (
                            <>
                              <ArchiveRestoreIcon /> 取消归档
                            </>
                          )}
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem variant="destructive" onSelect={() => setDeleteTarget(p)}>
                          <Trash2Icon /> 删除项目
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
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

      <DeleteProjectDialog
        project={deleteTarget}
        onOpenChange={(o) => {
          if (!o) setDeleteTarget(null);
        }}
        onDeleted={() => {
          setDeleteTarget(null);
          load();
        }}
      />
    </div>
  );
}

// CreateProjectDialog 新建项目：名称必填，描述/负责人/并发数可选。
// T19 新增四设置控件：跨任务阅读（项目内）/ 跨项目阅读 / 自动写报告
// （三 Switch，默认关）+ 报告模板（下拉，可留空=默认链）。后端 create 字段集
// 已与 PATCH 对齐（方案 A），四控件值直接进 POST body。
// V6-DUAL：observer_enabled 与 reader_enabled 是两个独立尺度，各传各的值、
// 各自生效——绝不合并成一个开关，也绝不传同值镜像。
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
  const [autoReportTasks, setAutoReportTasks] = React.useState(false);
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
      setAutoReportTasks(false);
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
        auto_report_tasks: autoReportTasks,
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
              <span>跨任务阅读者（项目内）</span>
              <Switch checked={observer} onCheckedChange={setObserver} />
            </label>
            <p className="text-muted-foreground text-xs">
              本项目内任务之间共享经验：任务图变更触发跨任务阅读者，判定勾连后 adopt 并给规划者下发 hint。与跨项目无关。
            </p>
            <label className="flex items-center justify-between gap-3 text-sm">
              <span>跨项目阅读者</span>
              <Switch checked={reader} onCheckedChange={setReader} />
            </label>
            <p className="text-muted-foreground text-xs">
              本项目参与跨项目串联：允许跨项目阅读者读到本项目的资产重叠与任务图、并把打法 adopt 到本项目正在运行的任务。与项目无关的项目可以关掉，省配额。
            </p>
            <label className="flex items-center justify-between gap-3 text-sm">
              <span>只出一个项目报告（汇总）</span>
              <Switch checked={autoReport} onCheckedChange={setAutoReport} />
            </label>
            <p className="text-muted-foreground text-xs">全部任务收官后生成一份项目汇总报告。</p>
            <label className="flex items-center justify-between gap-3 text-sm">
              <span>子任务都出报告</span>
              <Switch checked={autoReportTasks} onCheckedChange={setAutoReportTasks} />
            </label>
            <p className="text-muted-foreground text-xs">
              每个子任务终态各生成一份任务报告。两个勾选可同时开启（汇总 + 每个子任务各一份）；任务级勾选始终叠加生效。
            </p>
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

// DeleteProjectDialog 永久删除项目：清理项与任务删除完全一致（同一个
// DeleteOptionFields），另外多一个「同时删除旗下任务」开关——关掉时任务保留，
// 只是失去项目归属（后端 FK SET NULL），与任务侧的处置动作保持同一套语义。
function DeleteProjectDialog({
  project,
  onOpenChange,
  onDeleted,
}: {
  project: ProjectWithStats | null;
  onOpenChange: (open: boolean) => void;
  onDeleted: () => void;
}) {
  const [options, setOptions] = React.useState<DeleteTaskOptions>(emptyDeleteOptions);
  const [deleteTasks, setDeleteTasks] = React.useState(false);
  const [deleting, setDeleting] = React.useState(false);

  const open = project !== null;
  const taskCount = project?.stats.task_count ?? 0;

  React.useEffect(() => {
    if (open) {
      setOptions(emptyDeleteOptions());
      setDeleteTasks(false);
    }
  }, [open]);

  const submit = async () => {
    if (!project) return;
    setDeleting(true);
    try {
      const r = await api.deleteProject(project.id, { ...options, delete_tasks: deleteTasks });
      const parts = [`已删除项目「${project.name}」`];
      if (r.tasks_deleted > 0) parts.push(`删除 ${r.tasks_deleted} 个任务`);
      if (r.tasks_kept > 0) parts.push(`${r.tasks_kept} 个任务保留为未分组`);
      toast.success(parts.join("，"));
      if (r.task_errors?.length) {
        toast.warning(`${r.task_errors.length} 个任务未能删除，已保留：${r.task_errors[0]}`);
      }
      onDeleted();
    } catch (e) {
      toast.error("删除失败：" + (e as Error).message);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <AlertDialog open={open} onOpenChange={(o) => !deleting && onOpenChange(o)}>
      <AlertDialogContent className="sm:max-w-xl">
        <AlertDialogHeader>
          <AlertDialogTitle>永久删除项目「{project?.name}」？</AlertDialogTitle>
          <AlertDialogDescription className="break-words">
            该项目下有 {taskCount} 个任务。项目本身删除后不可恢复。
          </AlertDialogDescription>
        </AlertDialogHeader>

        <div className="max-h-[62vh] space-y-4 overflow-y-auto pr-1">
          <div className="flex items-start justify-between gap-3 rounded-lg border p-3">
            <div className="min-w-0">
              <p className="text-sm font-medium">同时删除旗下 {taskCount} 个任务</p>
              <p className="text-muted-foreground mt-1 text-xs">
                关闭时任务会保留，但会失去项目归属（变为未分组），可稍后重新挂到其他项目。
              </p>
            </div>
            <Switch
              checked={deleteTasks}
              onCheckedChange={setDeleteTasks}
              aria-label="同时删除旗下任务"
              disabled={deleting || taskCount === 0}
            />
          </div>

          <DeleteOptionFields
            idPrefix={`project-${project?.id ?? "x"}`}
            options={options}
            onOptionsChange={setOptions}
            disabled={deleting || (taskCount > 0 && !deleteTasks)}
          />
          {taskCount > 0 && !deleteTasks && (
            <p className="text-muted-foreground text-xs">
              上面这些清理项只对「同时删除旗下任务」生效；当前任务会全部保留。
            </p>
          )}
        </div>

        <AlertDialogFooter>
          <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
          <AlertDialogAction
            variant="destructive"
            disabled={deleting}
            onClick={(event) => {
              event.preventDefault();
              void submit();
            }}
          >
            {deleting ? "删除中…" : "永久删除"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
