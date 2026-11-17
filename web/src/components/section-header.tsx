import type { ReactNode } from "react";

import type { LucideIcon } from "lucide-react";

// SectionHeader 是合并页内的区块标题（图标 + 大标题 + 一行灰色副标题），
// 与页面原头部同款样式；右侧 actions 放该区块自己的工具条。
export function SectionHeader({
  icon: Icon,
  title,
  description,
  actions,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 className="flex items-center gap-2 text-lg font-semibold">
          <Icon className="size-5" /> {title}
        </h2>
        <p className="text-muted-foreground text-sm">{description}</p>
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}
