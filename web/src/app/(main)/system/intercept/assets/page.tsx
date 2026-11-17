"use client";

// 资产拦截已并入 /system/intercept 的第三个 tab（V9-UI2）。旧链接保留可用：
// 静态导出没有服务端重定向，这里由客户端跳转到 ?tab=assets。

import * as React from "react";

import { useRouter } from "next/navigation";

import { Spinner } from "@/components/ui/spinner";

export default function LegacyAssetInterceptRedirectPage() {
  const router = useRouter();
  React.useEffect(() => {
    router.replace("/system/intercept?tab=assets");
  }, [router]);
  return (
    <div className="text-muted-foreground flex flex-1 items-center justify-center gap-2 p-6 text-sm">
      <Spinner className="size-4" /> 正在跳转到资产拦截…
    </div>
  );
}
