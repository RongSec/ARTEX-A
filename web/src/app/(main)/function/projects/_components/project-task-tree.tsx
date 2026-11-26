"use client";

// 项目 + 任务树（V12-MERGE）：一个页面按「项目 → 任务」两级展示，替代原来的
// 项目列表 + 任务列表两个入口。
//
// 设计口径：
//   - 项目行 = 原来的项目列表元素（名称/状态/任务数/排队/漏洞分档/并发/负责人/操作）；
//   - 任务行 = 原任务列表的核心元素（名称或目的/状态/目标进度/漏洞/队列/最近活动/操作）；
//   - 顶部同时给「新建项目」「新建任务」，两边共用创建表单的四段口径；
//   - 未归属任务（project_id 为空）单独一组「未分组」兜底，不丢任务。

import * as React from "react";
import Link from "next/link";
import { toast } from "sonner";
import {
  ChevronDownIcon,
  ChevronRightIcon,
  ChevronsDownIcon,
  ChevronsUpIcon,
  FolderKanbanIcon,
  InboxIcon,
  MoreHorizontalIcon,
  PlusIcon,
  RefreshCwIcon,
  Trash2Icon,
  ArchiveIcon,
  ArchiveRestoreIcon,
  PauseIcon,
  PlayIcon,
  ExternalLinkIcon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { DeleteTaskDialog } from "@/app/(main)/function/tasks/page";
import { api } from "@/lib/api";
import type { ProjectWithStats, Task, TaskStatus } from "@/lib/types";

const STATUS_LABEL: Record<string, string> = {
  pending: "待启动",
  running: "运行中",
  paused: "已暂停",
  done: "已完成",
  failed: "失败",
  timeout: "超时",
  queued: "排队",
};

function statusText(t: Task): string {
  if (t.queued) return "排队";
  if (t.paused) return "已暂停";
  return STATUS_LABEL[t.status] ?? t.status;
}

function statusClass(t: Task): string {
  if (t.queued) return "border-amber-300 text-amber-600 dark:text-amber-400";
  switch (t.status) {
    case "running":
      return "border-emerald-300 text-emerald-600 dark:text-emerald-400";
    case "done":
      return "border-slate-300 text-slate-600 dark:text-slate-300";
    case "failed":
    case "timeout":
      return "border-red-300 text-red-600 dark:text-red-400";
    default:
      return "";
  }
}

// FindingCells 与项目/任务列表同一配色口径（严重/高/中/低）。
function FindingCells({ f }: { f?: Record<string, number> }) {
  const g = (k: string) => f?.[k] ?? 0;
  const total = g("critical") + g("high") + g("medium") + g("low");
  if (total === 0) return <span className="text-muted-foreground">0</span>;
  const seg = (n: number, cls: string) => <span className={n > 0 ? cls : "text-muted-foreground"}>{n}</span>;
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

function fmtWhen(unix?: number | string): string {
  if (!unix) return "—";
  const d = typeof unix === "number" ? new Date(unix * 1000) : new Date(unix);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

interface Props {
  projects: ProjectWithStats[];
  tasks: Task[];
  loading: boolean;
  onCreateProject: () => void;
  onCreateTask: () => void;
  onRefresh: () => void;
  onDeleteProject: (p: ProjectWithStats) => void;
}

export function ProjectTaskTree({
  projects,
  tasks,
  loading,
  onCreateProject,
  onCreateTask,
  onRefresh,
  onDeleteProject,
}: Props) {
  const [query, setQuery] = React.useState("");
  // 折叠集合按「行 key」记：项目用 `p<id>`，未分组用 `orphans`。
  // 早先用 Set<number> 只装项目 id，导致未分组那一组没有可点的三角、永远展开。
  const [collapsed, setCollapsed] = React.useState<Set<string>>(() => new Set());
  const [archiving, setArchiving] = React.useState<number | null>(null);
  const [busyTask, setBusyTask] = React.useState<string | null>(null);

  const toggleCollapsed = React.useCallback((key: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const q = query.trim().toLowerCase();
  const byProject = React.useMemo(() => {
    const m = new Map<number, Task[]>();
    for (const t of tasks) {
      const pid = t.project_id ?? 0; // 0 = 未分组兜底
      const list = m.get(pid) ?? [];
      list.push(t);
      m.set(pid, list);
    }
    return m;
  }, [tasks]);

  const rows = React.useMemo(() => {
    const out: { project: ProjectWithStats | null; tasks: Task[]; key: string }[] = [];
    for (const p of projects) {
      const list = byProject.get(p.id) ?? [];
      const matchProject = !q || p.name.toLowerCase().includes(q) || p.owner?.toLowerCase().includes(q);
      const matched = q ? list.filter((t) => (t.name || t.description || "").toLowerCase().includes(q)) : list;
      if (q && !matchProject && matched.length === 0) continue;
      out.push({ project: p, tasks: q && !matchProject ? matched : list, key: `p${p.id}` });
    }
    const orphans = byProject.get(0) ?? [];
    if (orphans.length > 0) {
      const matched = q ? orphans.filter((t) => (t.name || t.description || "").toLowerCase().includes(q)) : orphans;
      if (!q || matched.length > 0) out.push({ project: null, tasks: matched, key: "orphans" });
    }
    return out;
  }, [byProject, projects, q]);

  // 全展开/全收起：一次改完所有可见分组（含「未分组」）。
  const allCollapsed = rows.length > 0 && rows.every((r) => collapsed.has(r.key));

  async function toggleArchive(p: ProjectWithStats) {
    setArchiving(p.id);
    try {
      await api.updateProject(p.id, { status: p.status === "active" ? "archived" : "active" });
      toast.success(p.status === "active" ? `已归档「${p.name}」` : `已恢复「${p.name}」`);
      onRefresh();
    } catch (e) {
      toast.error("操作失败：" + (e as Error).message);
    } finally {
      setArchiving(null);
    }
  }

  async function controlTask(t: Task, action: "pause" | "resume") {
    setBusyTask(t.id);
    try {
      const r = await api.controlTask(t.id, action);
      toast.success(action === "pause" ? `任务已暂停` : `任务已继续${r.queued ? "，已进入队列" : ""}`);
      onRefresh();
    } catch (e) {
      toast.error("操作失败：" + (e as Error).message);
    } finally {
      setBusyTask(null);
    }
  }

  async function deleteTask(id: string, options: Parameters<typeof api.deleteTask>[1]) {
    try {
      const r = await api.deleteTask(id, options);
      const bits = ["任务已删除"];
      if (r.findings_deleted) bits.push(`漏洞 ${r.findings_deleted}`);
      if (r.intel_deleted) bits.push(`情报 ${r.intel_deleted}`);
      toast.success(bits.join("，"));
      onRefresh();
    } catch (e) {
      toast.error("删除失败：" + (e as Error).message);
      throw e;
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">项目与任务</h1>
          <p className="text-muted-foreground text-sm">按项目分组的任务树；展开项目看任务，操作与列表页一致。</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="搜索项目 / 任务"
            className="h-8 w-56"
            aria-label="搜索项目或任务"
          />
          <Button
            size="sm"
            variant="ghost"
            disabled={rows.length === 0}
            onClick={() => setCollapsed(allCollapsed ? new Set() : new Set(rows.map((r) => r.key)))}
            title={allCollapsed ? "展开全部分组" : "收起全部分组"}
          >
            {allCollapsed ? <ChevronsDownIcon /> : <ChevronsUpIcon />}
            {allCollapsed ? "全部展开" : "全部收起"}
          </Button>
          <Button size="sm" variant="outline" onClick={onRefresh} disabled={loading}>
            <RefreshCwIcon className={loading ? "animate-spin" : ""} /> 刷新
          </Button>
          <Button size="sm" variant="outline" onClick={onCreateProject}>
            <FolderKanbanIcon /> 新建项目
          </Button>
          <Button size="sm" onClick={onCreateTask}>
            <PlusIcon /> 新建任务
          </Button>
        </div>
      </div>

      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-8" />
              <TableHead className="min-w-64">名称</TableHead>
              <TableHead className="w-24">状态</TableHead>
              <TableHead className="w-28 text-center">资产 / 任务</TableHead>
              <TableHead className="w-28 text-center">漏洞（严/高/中/低）</TableHead>
              <TableHead className="w-24 text-center">队列</TableHead>
              <TableHead className="w-32">更新</TableHead>
              <TableHead className="w-28 text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 && (
              <TableRow>
                <TableCell colSpan={8} className="text-muted-foreground py-10 text-center text-sm">
                  {loading ? "加载中…" : q ? "没有匹配的项目或任务" : "还没有项目。点「新建项目」贴资产批量下发，或先建一个任务。"}
                </TableCell>
              </TableRow>
            )}
            {rows.map(({ project, tasks: list, key }) => {
              const isCollapsed = collapsed.has(key);
              const active = project?.status !== "archived";
              return (
                <React.Fragment key={key}>
                  <TableRow className={project ? "bg-muted/30" : ""}>
                    <TableCell className="pr-0">
                      <button
                        type="button"
                        aria-label={isCollapsed ? "展开分组" : "收起分组"}
                        aria-expanded={!isCollapsed}
                        className="text-muted-foreground hover:text-foreground p-1"
                        onClick={() => toggleCollapsed(key)}
                      >
                        {isCollapsed ? <ChevronRightIcon className="size-4" /> : <ChevronDownIcon className="size-4" />}
                      </button>
                    </TableCell>
                    <TableCell>
                      {project ? (
                        <div className="flex min-w-0 items-center gap-2">
                          <FolderKanbanIcon className="text-muted-foreground size-4 shrink-0" />
                          <Link
                            href={`/function/projects/detail?id=${project.id}`}
                            className="truncate font-medium hover:underline"
                          >
                            {project.name}
                          </Link>
                          {project.status === "archived" && <Badge variant="outline">已归档</Badge>}
                          {project.owner && (
                            <span className="text-muted-foreground shrink-0 text-xs">{project.owner}</span>
                          )}
                        </div>
                      ) : (
                        <span className="flex items-center gap-2 font-medium">
                          <InboxIcon className="text-muted-foreground size-4" /> 未分组任务
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      {project ? (
                        <Badge variant="outline" className={active ? "text-emerald-600" : "text-muted-foreground"}>
                          {active ? "进行中" : "已归档"}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground text-xs">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-center text-xs tabular-nums">
                      {project ? `${list.length} 个任务` : `${list.length} 个`}
                    </TableCell>
                    <TableCell className="text-center text-xs">
                      <FindingCells f={project?.stats.findings} />
                    </TableCell>
                    <TableCell className="text-center text-xs tabular-nums">
                      {project && project.stats.queued_tasks > 0 ? (
                        <span className="font-medium text-amber-600">{project.stats.queued_tasks} 排队</span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-xs tabular-nums">
                      {project ? fmtWhen(project.created_at) : "—"}
                    </TableCell>
                    <TableCell className="text-right">
                      {project ? (
                        <div className="flex items-center justify-end gap-1">
                          <Button size="sm" variant="outline" asChild>
                            <Link href={`/function/projects/detail?id=${project.id}`}>详情</Link>
                          </Button>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button size="icon" variant="ghost" aria-label="项目操作" disabled={archiving === project.id}>
                                <MoreHorizontalIcon />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onSelect={() => void toggleArchive(project)}>
                                {project.status === "active" ? (
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
                              <DropdownMenuItem variant="destructive" onSelect={() => onDeleteProject(project)}>
                                <Trash2Icon /> 删除项目
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      ) : (
                        <span />
                      )}
                    </TableCell>
                  </TableRow>
                  {!isCollapsed &&
                    list.map((t) => (
                      <TableRow key={`t${t.id}`} className="hover:bg-muted/20">
                        <TableCell />
                        <TableCell>
                          <div className="flex min-w-0 items-center gap-2 pl-5">
                            <span className="bg-border h-4 w-px shrink-0" />
                            <Link
                              href={`/function/tasks/detail?id=${t.id}`}
                              className="min-w-0 truncate hover:underline"
                              title={t.description}
                            >
                              {t.name || t.description || `任务 #${t.id}`}
                            </Link>
                            <span className="text-muted-foreground shrink-0 font-mono text-[10px]">#{t.id}</span>
                            {t.in_flight ? (
                              <span className="text-muted-foreground shrink-0 text-xs">{t.in_flight} worker</span>
                            ) : null}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={statusClass(t)}>
                            {statusText(t)}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground text-center text-xs tabular-nums">
                          {t.goals_total ? `${t.goals_met ?? 0}/${t.goals_total}` : "—"}
                        </TableCell>
                        <TableCell className="text-center text-xs">
                          <FindingCells f={t.findings} />
                        </TableCell>
                        <TableCell className="text-muted-foreground text-center text-xs tabular-nums">
                          {t.queued ? "排队" : (t.in_flight ?? 0) > 0 ? `${t.in_flight} 运行` : "—"}
                        </TableCell>
                        <TableCell className="text-muted-foreground text-xs tabular-nums">
                          {fmtWhen(t.last_activity || t.created_at)}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1">
                            <Button size="icon" variant="ghost" aria-label="打开任务" asChild>
                              <Link href={`/function/tasks/detail?id=${t.id}`}>
                                <ExternalLinkIcon className="size-4" />
                              </Link>
                            </Button>
                            {t.status === "running" || t.paused || t.queued ? (
                              <Button
                                size="icon"
                                variant="ghost"
                                aria-label={t.paused ? "继续任务" : "暂停任务"}
                                disabled={busyTask === t.id}
                                onClick={() => void controlTask(t, t.paused ? "resume" : "pause")}
                              >
                                {t.paused ? <PlayIcon className="size-4" /> : <PauseIcon className="size-4" />}
                              </Button>
                            ) : null}
                            <DeleteTaskDialog task={t} onDelete={deleteTask} />
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                </React.Fragment>
              );
            })}
          </TableBody>
        </Table>
      </div>
      {tasks.length > 0 && (
        <p className="text-muted-foreground text-xs">
          共 {projects.length} 个项目、{tasks.length} 个任务。任务的创建/删除口径与任务详情页一致；项目删除可勾选是否连带任务。
        </p>
      )}
    </div>
  );
}
