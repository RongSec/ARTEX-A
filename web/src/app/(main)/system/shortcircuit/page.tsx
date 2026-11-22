"use client";

// V12-RULES：短路规则已删除（三类规则合并为 intercept_rules 一套）。
// 旧链接保留可用，跳到拦截规则页。

import * as React from "react";

import { useRouter } from "next/navigation";

import { Spinner } from "@/components/ui/spinner";

export default function LegacyShortCircuitRedirectPage() {
  const router = useRouter();
  React.useEffect(() => {
    router.replace("/system/intercept");
  }, [router]);
  return (
    <div className="text-muted-foreground flex flex-1 items-center justify-center gap-2 p-6 text-sm">
      <Spinner className="size-4" /> 正在跳转到拦截规则…
    </div>
  );
}
