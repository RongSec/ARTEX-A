"use client";

// 旧路由 /function/facts（V9-UI5）：任务小结已并入任务页的「任务小结」tab，
// 这里只做客户端重定向，保留旧书签与外部链接可用。
// 静态导出没有服务端 redirect，所以走 router.replace。

import * as React from "react";

import { useRouter } from "next/navigation";

export default function FactsPage() {
  const router = useRouter();

  React.useEffect(() => {
    const taskId = new URLSearchParams(window.location.search).get("task_id");
    router.replace(taskId ? `/function/tasks?tab=summary&task_id=${encodeURIComponent(taskId)}` : "/function/tasks?tab=summary");
  }, [router]);

  return null;
}
