// 任务小结页共用的小件：时间/时长格式化、迷你徽章、空行文案。
// 只做展示，不含数据请求，方便三张表与摘要区复用。

import * as React from "react";

import { cn } from "@/lib/utils";

export function fmtTime(ts?: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function fmtDuration(seconds?: number | null): string {
  const s = Math.max(0, Math.round(seconds ?? 0));
  if (!s) return "—";
  if (s < 60) return `${s} 秒`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} 分 ${s % 60} 秒`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} 小时 ${m % 60} 分`;
  const d = Math.floor(h / 24);
  return `${d} 天 ${h % 24} 小时`;
}

export function MiniBadge({
  children,
  className,
  title,
}: {
  children: React.ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] leading-none whitespace-nowrap",
        className,
      )}
    >
      {children}
    </span>
  );
}

// EmptyHint 是表格/折叠区无数据时的统一弱文案。
export function EmptyHint({ children }: { children: React.ReactNode }) {
  return <p className="text-muted-foreground px-1 py-6 text-center text-xs">{children}</p>;
}

// SectionTitle 是详情内三个主区块的标题行（图标 + 标题 + 计数 + 右侧工具）。
export function SectionTitle({
  icon,
  title,
  count,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  count?: number;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-muted-foreground">{icon}</span>
      <h3 className="text-sm font-semibold">{title}</h3>
      {typeof count === "number" && (
        <span className="bg-muted text-muted-foreground rounded px-1.5 py-0.5 text-[11px] tabular-nums">{count}</span>
      )}
      {children}
    </div>
  );
}
