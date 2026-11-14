"use client";

// 右栏顶部摘要条 + 第一段「基本摘要」。
// 摘要条固定在滚动区之外，任务名/状态/项目/起止时间始终可见。

import * as React from "react";

import Link from "next/link";

import {
  ChevronDownIcon,
  ChevronRightIcon,
  ClockIcon,
  ExternalLinkIcon,
  FileTextIcon,
  PanelLeftIcon,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { statusMeta, toneClasses } from "@/lib/status";
import type { TaskIntelSummary } from "@/lib/types";
import { cn } from "@/lib/utils";

import { fmtDuration, fmtTime, MiniBadge, SectionTitle } from "./shared";

const COUNT_ITEMS = [
  { key: "endpoint", label: "接口" },
  { key: "credential", label: "账号" },
  { key: "component", label: "组件" },
  { key: "asset", label: "资产" },
  { key: "vuln", label: "漏洞" },
  { key: "finding", label: "发现" },
] as const;

export function TaskSummaryBar({
  taskId,
  summary,
  fallbackName,
  onOpenTree,
}: {
  taskId: string;
  summary: TaskIntelSummary | null;
  fallbackName: string;
  onOpenTree: () => void;
}) {
  const meta = summary ? statusMeta("task", summary.status) : null;
  const name = summary?.name || fallbackName || (taskId ? `任务#${taskId}` : "");
  const project = summary ? summary.project_name || (summary.project_id ? `项目 #${summary.project_id}` : "") : "";

  return (
    <div className="flex shrink-0 flex-col gap-1.5 border-b px-4 py-2.5">
      <div className="flex min-w-0 items-center gap-2">
        <Button size="sm" variant="outline" className="lg:hidden" onClick={onOpenTree}>
          <PanelLeftIcon className="size-3.5" /> 选择任务
        </Button>
        {taskId ? (
          <Link
            href={`/function/tasks/detail?id=${encodeURIComponent(taskId)}`}
            className="hover:text-primary min-w-0 truncate text-sm font-semibold"
            title={name}
          >
            {name}
          </Link>
        ) : (
          <span className="truncate text-sm font-semibold">任务小结</span>
        )}
        {meta && <MiniBadge className={toneClasses[meta.tone]}>{meta.label}</MiniBadge>}
        {project && (
          <MiniBadge className="bg-muted text-muted-foreground max-w-48 truncate" title={project}>
            {project}
          </MiniBadge>
        )}
        {taskId && (
          <Link
            href={`/function/tasks/detail?id=${encodeURIComponent(taskId)}`}
            className="text-muted-foreground hover:text-foreground ml-auto flex shrink-0 items-center gap-0.5 text-[11px]"
          >
            任务详情 <ExternalLinkIcon className="size-3" />
          </Link>
        )}
      </div>
      <div className="text-muted-foreground flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] tabular-nums">
        {taskId ? (
          <>
            <span className="inline-flex items-center gap-1">
              <ClockIcon className="size-3" /> 用时 {fmtDuration(summary?.duration_seconds)}
            </span>
            <span>开始 {fmtTime(summary?.started_at)}</span>
            <span>结束 {fmtTime(summary?.ended_at)}</span>
          </>
        ) : (
          <span>从左侧任务树中选择一个任务</span>
        )}
      </div>
    </div>
  );
}

export function TaskSummarySection({
  taskId,
  summary,
  hint,
}: {
  taskId: string;
  summary: TaskIntelSummary | null;
  hint?: string;
}) {
  const [goalOpen, setGoalOpen] = React.useState(false);
  React.useEffect(() => setGoalOpen(false), [taskId]);

  const goal = summary?.goal?.trim() ?? "";
  const meta = summary ? statusMeta("task", summary.status) : null;
  const longGoal = goal.length > 90 || goal.includes("\n");

  return (
    <section className="space-y-2">
      <SectionTitle icon={<FileTextIcon className="size-4" />} title="基本摘要">
        <div className="ml-auto flex flex-wrap justify-end gap-1">
          {COUNT_ITEMS.map((c) => (
            <MiniBadge key={c.key} className="bg-muted/60 border-transparent text-muted-foreground">
              {c.label}
              <span className="text-foreground font-medium tabular-nums">
                {summary?.counts?.[c.key] ?? 0}
              </span>
            </MiniBadge>
          ))}
        </div>
      </SectionTitle>

      <div className="space-y-2.5 rounded-lg border p-3">
        <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-xs sm:grid-cols-2 lg:grid-cols-3">
          <div className="flex min-w-0 gap-2">
            <dt className="text-muted-foreground w-10 shrink-0">项目</dt>
            <dd className="min-w-0 truncate" title={summary?.project_name || "未挂项目"}>
              {summary?.project_name || (summary?.project_id ? `项目 #${summary.project_id}` : "未挂项目")}
            </dd>
          </div>
          <div className="flex gap-2">
            <dt className="text-muted-foreground w-10 shrink-0">状态</dt>
            <dd>
              {meta ? (
                <MiniBadge className={toneClasses[meta.tone]}>{meta.label}</MiniBadge>
              ) : (
                "—"
              )}
            </dd>
          </div>
          <div className="flex gap-2">
            <dt className="text-muted-foreground w-10 shrink-0">用时</dt>
            <dd className="tabular-nums">{fmtDuration(summary?.duration_seconds)}</dd>
          </div>
          <div className="flex gap-2">
            <dt className="text-muted-foreground w-10 shrink-0">开始</dt>
            <dd className="tabular-nums">{fmtTime(summary?.started_at)}</dd>
          </div>
          <div className="flex gap-2">
            <dt className="text-muted-foreground w-10 shrink-0">结束</dt>
            <dd className="tabular-nums">{fmtTime(summary?.ended_at)}</dd>
          </div>
          <div className="flex gap-2">
            <dt className="text-muted-foreground w-10 shrink-0">任务</dt>
            <dd className="truncate font-mono">#{taskId}</dd>
          </div>
        </dl>

        <div className="border-t pt-2">
          <div className="text-muted-foreground mb-1 text-[11px]">目标</div>
          <p
            className={cn(
              "text-xs break-words whitespace-pre-wrap",
              !goalOpen && longGoal && "line-clamp-4",
            )}
          >
            {goal || "—"}
          </p>
          {longGoal && (
            <button
              type="button"
              onClick={() => setGoalOpen((v) => !v)}
              className="text-muted-foreground hover:text-foreground mt-1 inline-flex items-center gap-0.5 text-[11px]"
            >
              {goalOpen ? <ChevronDownIcon className="size-3" /> : <ChevronRightIcon className="size-3" />}
              {goalOpen ? "收起目标" : "展开目标全文"}
            </button>
          )}
        </div>
      </div>

      {hint && <p className="text-muted-foreground bg-muted/40 rounded-md px-2.5 py-1.5 text-[11px]">{hint}</p>}
    </section>
  );
}
