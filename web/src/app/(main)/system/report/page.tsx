"use client";

// 报告中心（V9-UI）：模板管理 + 报告归档合并到同一页（路由仍为 /system/report）。
// 两个区块各自带「图标 + 大标题 + 灰色副标题」的区块标题；旧的 /system/reports
// 只做重定向到这里。

import * as React from "react";

import { ReportArchiveSection } from "./_components/report-archive";
import { ReportTemplatesSection } from "./_components/report-templates";

export default function ReportCenterPage() {
  return (
    <div className="flex flex-1 flex-col gap-8">
      <ReportTemplatesSection />
      <ReportArchiveSection />
    </div>
  );
}
