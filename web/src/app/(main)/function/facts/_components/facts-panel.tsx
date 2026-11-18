"use client";

// 任务小结面板（V9-UI5）：从独立页 `/function/facts` 抽出来，任务页的「任务小结」
// tab 与旧路由共用同一份实现。布局沿用「左树 + 右三段式详情」，高度由外层容器
// 决定（h-full），方便嵌进 Tabs。
//
// 数据：GET /api/projects + GET /api/tasks 组树；GET /api/tasks/{id}/intel 取详情。
// 深链 ?task_id= 仍生效；写入 URL 时保留其它 query（例如 tab=summary）。

import * as React from "react";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

import { AlertCircleIcon, FileTextIcon, RefreshCwIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import type { ProjectWithStats, Task, TaskIntelGroups, TaskIntelResp } from "@/lib/types";

import { CredentialTable } from "./credential-table";
import { EndpointTable } from "./endpoint-table";
import { IntelExtraSections } from "./intel-extra";
import { TaskTree, type TreeProject, type TreeTask } from "./task-tree";
import { TaskSummaryBar, TaskSummarySection } from "./task-summary";

// 后端 groups 固定键、空组为 []，但前端仍按缺失兜底：不显示 undefined。
function normalizeIntel(raw: TaskIntelResp): TaskIntelResp {
  const g = (raw.groups ?? {}) as Partial<TaskIntelGroups>;
  return {
    ...raw,
    summary: raw.summary ?? null,
    groups: {
      endpoint: g.endpoint ?? [],
      credential: g.credential ?? [],
      component: g.component ?? [],
      asset: g.asset ?? [],
      vuln: g.vuln ?? [],
    },
  };
}

// buildTree 把项目列表与任务列表拼成「项目 → 任务」，未挂项目的任务单列一组。
function buildTree(projects: ProjectWithStats[], tasks: Task[]): TreeProject[] {
  const byProject = new Map<number, TreeTask[]>();
  const orphans: TreeTask[] = [];
  for (const t of tasks) {
    const item: TreeTask = {
      id: String(t.id),
      name: t.name?.trim() || t.description?.trim() || `任务#${t.id}`,
      goal: t.goal ?? "",
      status: t.status,
    };
    if (t.project_id == null) {
      orphans.push(item);
      continue;
    }
    const list = byProject.get(t.project_id);
    if (list) list.push(item);
    else byProject.set(t.project_id, [item]);
  }
  const out: TreeProject[] = projects.map((p) => ({
    id: String(p.id),
    name: p.name,
    tasks: byProject.get(p.id) ?? [],
  }));
  if (orphans.length > 0) out.push({ id: "none", name: "未挂项目", tasks: orphans });
  return out;
}

function DetailSkeleton() {
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Skeleton className="h-4 w-40" />
        <Skeleton className="h-24 w-full" />
      </div>
      <div className="space-y-2">
        <Skeleton className="h-4 w-32" />
        <Skeleton className="h-40 w-full" />
      </div>
      <div className="space-y-2">
        <Skeleton className="h-4 w-32" />
        <Skeleton className="h-28 w-full" />
      </div>
    </div>
  );
}

function ErrorBar({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="border-destructive/40 bg-destructive/5 flex flex-wrap items-center gap-2 rounded-lg border px-3 py-2">
      <AlertCircleIcon className="text-destructive size-4 shrink-0" />
      <span className="text-destructive min-w-0 flex-1 text-xs">加载失败：{message}</span>
      <Button size="sm" variant="outline" onClick={onRetry}>
        <RefreshCwIcon className="size-3.5" /> 重试
      </Button>
    </div>
  );
}

function FactsPanelInner() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const urlTaskId = searchParams.get("task_id") ?? "";

  // ---- 树数据 ----
  const [projects, setProjects] = React.useState<TreeProject[]>([]);
  const [listLoading, setListLoading] = React.useState(true);
  const [listError, setListError] = React.useState("");
  const [listAttempt, setListAttempt] = React.useState(0);

  React.useEffect(() => {
    let alive = true;
    setListLoading(true);
    Promise.all([api.projects(), api.tasks()])
      .then(([projectResp, taskResp]) => {
        if (!alive) return;
        setProjects(buildTree(projectResp.projects, taskResp.tasks));
        setListError("");
      })
      .catch((e) => {
        if (alive) setListError((e as Error).message || "加载失败");
      })
      .finally(() => {
        if (alive) setListLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [listAttempt]);

  // ---- 选中任务 ----
  const [selectedId, setSelectedId] = React.useState(urlTaskId);
  const [treeOpen, setTreeOpen] = React.useState(false);

  // 外部改 URL（深链/浏览器前进后退）时跟随；选任务本身由 selectTask 驱动。
  React.useEffect(() => {
    if (urlTaskId && urlTaskId !== selectedId) setSelectedId(urlTaskId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [urlTaskId]);

  // 选中变化用 replace 同步 URL（不新增历史记录）。
  React.useEffect(() => {
    if (!selectedId || urlTaskId === selectedId) return;
    const params = new URLSearchParams(searchParams.toString());
    params.set("task_id", selectedId);
    router.replace(`${pathname}?${params.toString()}`, { scroll: false });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId, urlTaskId, pathname, router]);

  const selectTask = (id: string) => {
    setSelectedId(id);
    setTreeOpen(false);
  };

  const selectedTask = React.useMemo(() => {
    for (const p of projects) {
      const t = p.tasks.find((x) => x.id === selectedId);
      if (t) return t;
    }
    return null;
  }, [projects, selectedId]);

  // ---- 详情数据 ----
  const [intel, setIntel] = React.useState<TaskIntelResp | null>(null);
  const [intelLoading, setIntelLoading] = React.useState(false);
  const [intelError, setIntelError] = React.useState("");
  const [detailAttempt, setDetailAttempt] = React.useState(0);

  React.useEffect(() => {
    if (!selectedId) {
      setIntel(null);
      setIntelError("");
      setIntelLoading(false);
      return;
    }
    let alive = true;
    setIntelLoading(true);
    setIntelError("");
    setIntel(null);
    api
      .taskIntel(selectedId)
      .then((r) => {
        if (alive) setIntel(normalizeIntel(r));
      })
      .catch((e) => {
        if (alive) setIntelError((e as Error).message || "加载失败");
      })
      .finally(() => {
        if (alive) setIntelLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [selectedId, detailAttempt]);

  // 摘要条在 intel 未到时用树里的任务信息兜底（名称/状态/目标），不闪空。
  const barSummary = intel?.summary ?? (selectedTask
    ? { name: selectedTask.name, goal: selectedTask.goal, status: selectedTask.status }
    : null);

  const tree = (
    <TaskTree
      projects={projects}
      selectedId={selectedId}
      loading={listLoading}
      error={listError}
      onRetry={() => setListAttempt((n) => n + 1)}
      onSelect={selectTask}
    />
  );

  return (
    <div className="flex h-full min-h-0 flex-col gap-3 lg:flex-row lg:gap-4">
      <aside className="hidden w-[300px] shrink-0 overflow-hidden rounded-xl border bg-card lg:block">
        {tree}
      </aside>

      <Sheet open={treeOpen} onOpenChange={setTreeOpen}>
        <SheetContent side="left" className="w-[88vw] max-w-[320px] gap-0 p-0">
          <SheetTitle className="sr-only">任务列表</SheetTitle>
          {tree}
        </SheetContent>
      </Sheet>

      <section className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-xl border bg-card">
        <TaskSummaryBar
          taskId={selectedId}
          summary={barSummary}
          fallbackName={selectedTask?.name ?? ""}
          onOpenTree={() => setTreeOpen(true)}
        />

        <div className="min-h-0 flex-1 overflow-y-auto">
          <div className="space-y-4 p-4">
            {!selectedId ? (
              <div className="flex flex-col items-center justify-center gap-2 py-20 text-center">
                <FileTextIcon className="text-muted-foreground/60 size-8" />
                <p className="text-sm font-medium">选择一个任务查看小结</p>
                <p className="text-muted-foreground text-xs">
                  左侧任务树按项目归档；窄屏点顶部「选择任务」打开列表。
                </p>
              </div>
            ) : intelLoading ? (
              <DetailSkeleton />
            ) : intelError ? (
              <ErrorBar message={intelError} onRetry={() => setDetailAttempt((n) => n + 1)} />
            ) : intel ? (
              <>
                <TaskSummarySection
                  key={`summary-${selectedId}`}
                  taskId={selectedId}
                  summary={intel.summary}
                  hint={intel.hint}
                />
                <EndpointTable
                  key={`endpoint-${selectedId}`}
                  taskId={selectedId}
                  rows={intel.groups.endpoint}
                />
                <CredentialTable
                  key={`credential-${selectedId}`}
                  rows={intel.groups.credential}
                />
                <IntelExtraSections
                  key={`extra-${selectedId}`}
                  taskId={selectedId}
                  components={intel.groups.component}
                  assets={intel.groups.asset}
                  vulns={intel.groups.vuln}
                />
              </>
            ) : null}
          </div>
        </div>
      </section>
    </div>
  );
}

// useSearchParams 在静态导出下必须位于 Suspense 边界内。
export function FactsPanel() {
  return (
    <React.Suspense fallback={null}>
      <FactsPanelInner />
    </React.Suspense>
  );
}
