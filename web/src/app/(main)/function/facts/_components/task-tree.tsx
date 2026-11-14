"use client";

// 左栏文档树：项目 → 任务。
// 默认全部折叠；选中任务后只保证其所属项目展开；搜索命中任务名/目标/项目名时
// 过滤并自动展开父节点。键盘 ↑/↓ 在可见任务间切换，Enter 选中。

import * as React from "react";

import {
  ChevronDownIcon,
  ChevronRightIcon,
  FolderIcon,
  FolderOpenIcon,
  RefreshCwIcon,
  SearchIcon,
  XIcon,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { statusMeta, toneDot } from "@/lib/status";
import { cn } from "@/lib/utils";

export interface TreeTask {
  id: string;
  name: string;
  goal: string;
  status: string;
}

export interface TreeProject {
  id: string;
  name: string;
  tasks: TreeTask[];
}

export function TaskTree({
  projects,
  selectedId,
  loading,
  error,
  onRetry,
  onSelect,
}: {
  projects: TreeProject[];
  selectedId: string;
  loading: boolean;
  error: string;
  onRetry: () => void;
  onSelect: (taskId: string) => void;
}) {
  const [search, setSearch] = React.useState("");
  const [expanded, setExpanded] = React.useState<Set<string>>(new Set());
  const [activeIndex, setActiveIndex] = React.useState(-1);
  const itemRefs = React.useRef(new Map<string, HTMLButtonElement>());

  const q = search.trim().toLowerCase();

  // 选中任务所在项目始终保持展开（深链/外部切换都能定位）。
  React.useEffect(() => {
    if (!selectedId) return;
    const owner = projects.find((p) => p.tasks.some((t) => t.id === selectedId));
    if (!owner) return;
    setExpanded((cur) => (cur.has(owner.id) ? cur : new Set(cur).add(owner.id)));
  }, [selectedId, projects]);

  const filtered = React.useMemo(() => {
    return projects
      .map((p) => {
        const projectHit = q !== "" && p.name.toLowerCase().includes(q);
        const tasks =
          q === ""
            ? p.tasks
            : projectHit
              ? p.tasks
              : p.tasks.filter(
                  (t) => t.name.toLowerCase().includes(q) || t.goal.toLowerCase().includes(q),
                );
        return { project: p, tasks, projectHit };
      })
      .filter((x) => (q === "" ? true : x.projectHit || x.tasks.length > 0));
  }, [projects, q]);

  // 当前可见（父节点已展开）的任务，键盘导航与滚动定位都基于它。
  const flatTasks = React.useMemo(() => {
    const out: TreeTask[] = [];
    for (const { project, tasks } of filtered) {
      const open = q !== "" || expanded.has(project.id);
      if (!open) continue;
      out.push(...tasks);
    }
    return out;
  }, [filtered, expanded, q]);

  React.useEffect(() => {
    if (activeIndex < 0) return;
    const id = flatTasks[activeIndex]?.id;
    if (id) itemRefs.current.get(id)?.scrollIntoView({ block: "nearest" });
  }, [activeIndex, flatTasks]);

  // 深链/外部切换选中后，把该任务滚进视野（项目展开后的下一次渲染生效）。
  React.useEffect(() => {
    if (!selectedId) return;
    itemRefs.current.get(selectedId)?.scrollIntoView({ block: "nearest" });
  }, [selectedId, expanded, loading]);

  React.useEffect(() => {
    // 列表变化后修正越界的高亮下标。
    setActiveIndex((i) => (i >= flatTasks.length ? flatTasks.length - 1 : i));
  }, [flatTasks.length]);

  const toggleProject = (id: string) =>
    setExpanded((cur) => {
      const next = new Set(cur);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      // 全部折叠时键盘无处可去：下键先展开第一个项目（只展开一个，不铺满）。
      if (flatTasks.length === 0 && e.key === "ArrowDown" && q === "") {
        const first = filtered.find((x) => x.tasks.length > 0)?.project;
        if (first) toggleProject(first.id);
        return;
      }
      if (flatTasks.length === 0) return;
      const step = e.key === "ArrowDown" ? 1 : -1;
      setActiveIndex((i) => Math.min(flatTasks.length - 1, Math.max(0, i < 0 ? 0 : i + step)));
      return;
    }
    if (e.key === "Enter" && activeIndex >= 0) {
      const t = flatTasks[activeIndex];
      if (!t) return;
      e.preventDefault();
      onSelect(t.id);
    }
  };

  const totalTasks = React.useMemo(
    () => projects.reduce((n, p) => n + p.tasks.length, 0),
    [projects],
  );

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 items-center gap-2 border-b px-3 py-2.5">
        <span className="text-sm font-semibold">任务小结</span>
        <span className="text-muted-foreground text-xs tabular-nums">{totalTasks} 个任务</span>
      </div>

      <div className="shrink-0 p-2">
        <div className="focus-within:border-ring flex h-8 items-center gap-1.5 rounded-lg border px-2">
          <SearchIcon className="text-muted-foreground size-3.5 shrink-0" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="搜索任务 / 目标 / 项目"
            className="placeholder:text-muted-foreground min-w-0 flex-1 bg-transparent text-xs outline-none"
            aria-label="搜索任务"
          />
          {search && (
            <button
              type="button"
              className="text-muted-foreground hover:text-foreground shrink-0"
              onClick={() => setSearch("")}
              aria-label="清除搜索"
            >
              <XIcon className="size-3.5" />
            </button>
          )}
        </div>
      </div>

      <div
        className="focus-visible:ring-ring/40 min-h-0 flex-1 overflow-y-auto rounded-md px-2 pb-3 outline-none focus-visible:ring-2"
        role="tree"
        aria-label="项目与任务"
        tabIndex={0}
        onKeyDown={onKeyDown}
      >
        {loading ? (
          <div className="space-y-2 px-1 py-2">
            {Array.from({ length: 7 }).map((_, i) => (
              <Skeleton key={i} className="h-7 w-full" />
            ))}
          </div>
        ) : error ? (
          <div className="space-y-2 px-1 py-6 text-center">
            <p className="text-destructive text-xs">加载失败：{error}</p>
            <Button size="sm" variant="outline" onClick={onRetry}>
              <RefreshCwIcon className="size-3.5" /> 重试
            </Button>
          </div>
        ) : filtered.length === 0 ? (
          <p className="text-muted-foreground px-2 py-8 text-center text-xs">
            {q ? "没有匹配的任务" : "暂无项目或任务"}
          </p>
        ) : (
          <div className="space-y-0.5">
            {filtered.map(({ project, tasks }) => {
              const open = q !== "" || expanded.has(project.id);
              return (
                <div key={project.id} role="treeitem" aria-expanded={open} aria-label={project.name}>
                  <button
                    type="button"
                    onClick={() => toggleProject(project.id)}
                    className="hover:bg-muted/60 flex w-full items-center gap-1.5 rounded-md px-1.5 py-1.5 text-left"
                  >
                    {open ? (
                      <ChevronDownIcon className="text-muted-foreground size-3.5 shrink-0" />
                    ) : (
                      <ChevronRightIcon className="text-muted-foreground size-3.5 shrink-0" />
                    )}
                    {open ? (
                      <FolderOpenIcon className="text-muted-foreground size-3.5 shrink-0" />
                    ) : (
                      <FolderIcon className="text-muted-foreground size-3.5 shrink-0" />
                    )}
                    <span className="min-w-0 flex-1 truncate text-xs font-medium" title={project.name}>
                      {project.name}
                    </span>
                    <span className="text-muted-foreground shrink-0 text-[11px] tabular-nums">
                      {project.tasks.length}
                    </span>
                  </button>

                  {open && (
                    <div className="mt-0.5 space-y-0.5 pb-1 pl-4">
                      {tasks.length === 0 ? (
                        <p className="text-muted-foreground px-2 py-1 text-[11px]">暂无任务</p>
                      ) : (
                        tasks.map((t) => {
                          const selected = t.id === selectedId;
                          const active = flatTasks[activeIndex]?.id === t.id;
                          const meta = statusMeta("task", t.status);
                          return (
                            <button
                              key={t.id}
                              ref={(el) => {
                                if (el) itemRefs.current.set(t.id, el);
                                else itemRefs.current.delete(t.id);
                              }}
                              type="button"
                              role="treeitem"
                              aria-selected={selected}
                              onClick={() => {
                                setActiveIndex(flatTasks.findIndex((x) => x.id === t.id));
                                onSelect(t.id);
                              }}
                              className={cn(
                                "flex w-full items-center gap-1.5 rounded-md px-2 py-1.5 text-left transition-colors",
                                selected
                                  ? "bg-primary/10 text-primary"
                                  : active
                                    ? "bg-muted/70"
                                    : "hover:bg-muted/50",
                              )}
                            >
                              <span
                                className={cn("size-1.5 shrink-0 rounded-full", toneDot[meta.tone])}
                                title={meta.label}
                              />
                              <span className="min-w-0 flex-1 truncate text-xs" title={t.name}>
                                {t.name}
                              </span>
                            </button>
                          );
                        })
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
