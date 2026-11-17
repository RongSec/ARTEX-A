"use client";

// 报告中心（V9-UI2）：顶部一个 segmented tabs 在「报告中心 / 报告归档」之间
// 切换，只显示当前 tab 的区块（含自己的标题区），不再上下堆叠。
// 当前 tab 记在 URL query（?tab=archive），刷新/分享都能还原；旧 /system/reports
// 客户端跳到 ?tab=archive。

import * as React from "react";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

import { SegmentedTabs } from "@/components/segmented-tabs";

import { ReportArchiveSection } from "./_components/report-archive";
import { ReportTemplatesSection } from "./_components/report-templates";

type ReportTab = "templates" | "archive";

const TABS: { value: ReportTab; label: string }[] = [
  { value: "templates", label: "报告中心" },
  { value: "archive", label: "报告归档" },
];

function ReportCenterInner() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const tab: ReportTab = searchParams.get("tab") === "archive" ? "archive" : "templates";

  const onTabChange = (v: ReportTab) => {
    const q = new URLSearchParams(searchParams.toString());
    if (v === "archive") q.set("tab", "archive");
    else q.delete("tab");
    const qs = q.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  };

  return (
    <div className="flex flex-1 flex-col gap-4">
      <SegmentedTabs value={tab} items={TABS} onChange={onTabChange} ariaLabel="报告中心视图" />

      {/* 隐藏而非卸载：来回切换保留模板选中态/归档树展开态。 */}
      <div className={tab === "templates" ? "" : "hidden"}>
        <ReportTemplatesSection />
      </div>
      <div className={tab === "archive" ? "" : "hidden"}>
        <ReportArchiveSection />
      </div>
    </div>
  );
}

export default function ReportCenterPage() {
  // useSearchParams 在静态导出下要求 Suspense 边界。
  return (
    <React.Suspense fallback={null}>
      <ReportCenterInner />
    </React.Suspense>
  );
}
