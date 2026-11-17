"use client";

// 分段切换（V9-UI2）：外形与 shadcn Tabs 的 segmented 一致，但只是普通
// Button 组——切换动作完全由调用方用 URL query 驱动。静态导出 + 客户端
// router 下用受控 Radix Tabs 时，首次切换后其内部状态机不再响应点击，
// 故这里用按钮组实现同样的视觉与 ARIA tab 语义。

import * as React from "react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export interface SegmentedTabItem<T extends string> {
  value: T;
  label: string;
}

export function SegmentedTabs<T extends string>({
  value,
  items,
  onChange,
  ariaLabel,
  className,
}: {
  value: T;
  items: SegmentedTabItem<T>[];
  onChange: (v: T) => void;
  ariaLabel: string;
  className?: string;
}) {
  return (
    <div
      role="tablist"
      aria-label={ariaLabel}
      className={cn("bg-muted inline-flex w-fit items-center justify-center gap-0.5 rounded-lg p-[3px]", className)}
    >
      {items.map((it) => {
        const active = it.value === value;
        return (
          <Button
            key={it.value}
            type="button"
            role="tab"
            aria-selected={active}
            variant="ghost"
            size="sm"
            onClick={() => onChange(it.value)}
            className={cn(
              "h-8 rounded-md px-3 text-sm font-medium shadow-none",
              active
                ? "bg-background text-foreground shadow-sm hover:bg-background"
                : "text-muted-foreground hover:bg-transparent hover:text-foreground",
            )}
          >
            {it.label}
          </Button>
        );
      })}
    </div>
  );
}
