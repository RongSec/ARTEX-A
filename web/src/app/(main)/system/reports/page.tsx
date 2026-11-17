"use client";

// 报告归档已并入 /system/report（同一页两个区块）。旧链接保留可用：
// 静态导出没有服务端重定向，这里由客户端跳转过去。

import * as React from "react";

import { useRouter } from "next/navigation";

import { Spinner } from "@/components/ui/spinner";

export default function LegacyReportsRedirectPage() {
  const router = useRouter();
  React.useEffect(() => {
    router.replace("/system/report");
  }, [router]);
  return (
    <div className="text-muted-foreground flex flex-1 items-center justify-center gap-2 p-6 text-sm">
      <Spinner className="size-4" /> 正在跳转到报告中心…
    </div>
  );
}
