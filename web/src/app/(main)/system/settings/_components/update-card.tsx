"use client";

import * as React from "react";

import { CheckCircle2Icon, CopyIcon, ExternalLinkIcon, RefreshCwIcon, TerminalIcon, TriangleAlertIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { UpdateCheck } from "@/lib/types";

/**
 * 「版本与更新」：只做版本查询，不做更新。
 *
 * 程序内一键更新已经删掉了（v0.3.16-hs.7）。原因不是界面不好看，而是那套机制
 * 在容器部署下必然「假成功」：它替换的是容器可写层里的 /app/artex 一个文件，
 * `docker compose up -d` 重建容器立刻退回镜像自带的版本；而且它换不掉基础镜像里的
 * LibreOffice、apt 工具层、Playwright 浏览器——版本号上去了、能力没上去。
 *
 * 现在升级统一走部署机上的 update.sh：拉完整镜像 → 更新前 pg_dump → 重建 →
 * 健康检查失败自动回滚。它能做进程内做不到的三件事：换镜像、备份数据库、退回去。
 * 这张卡片负责把「该跑哪条命令」说清楚，并把命令放进剪贴板。
 */
export function UpdateCard() {
  const [info, setInfo] = React.useState<UpdateCheck | null>(null);
  const [checking, setChecking] = React.useState(true);

  // quiet 同时决定要不要绕过后端缓存：进页面时的自动检查用缓存（顶栏刚查过），
  // 用户手动点「检查更新」则强制回源，否则刚发布的版本要等缓存过期才看得到。
  const check = React.useCallback((quiet = false) => {
    setChecking(true);
    api
      .checkUpdate(!quiet)
      .then((r) => {
        setInfo(r);
        if (!quiet) {
          if (r.error) toast.error("检查更新失败：" + r.error);
          else if (r.has_update) toast.success(`发现新版本 ${r.latest}`);
          else if (r.comparable) toast.success("当前已是最新版本");
        }
      })
      .catch((e) => {
        if (!quiet) toast.error("检查更新失败：" + (e as Error).message);
      })
      .finally(() => setChecking(false));
  }, []);

  React.useEffect(() => {
    check(true);
  }, [check]);

  const copy = (text: string) => {
    void navigator.clipboard
      ?.writeText(text)
      .then(() => toast.success("已复制"))
      .catch(() => toast.error("复制失败，请手动选中"));
  };

  // 镜像部署与源码部署的升级路径不同：前者拉镜像，后者要重新编译。
  const cmds =
    info?.mode === "docker"
      ? [`${info.update_cmd}              # 拉新镜像并重建（更新前自动备份数据库）`,
         `${info.update_cmd} rollback       # 回到上一版本`]
      : [`${info?.update_cmd ?? "./update.sh"} local      # 重新编译并替换二进制`,
         `${info?.update_cmd ?? "./update.sh"} rollback   # 回到上一版本`];

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <TerminalIcon className="size-4" />
          版本与更新
        </CardTitle>
        <CardDescription>
          查询 GitHub 上的最新版本。升级在部署机上执行 update.sh 完成，页面不再直接改程序。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-muted-foreground">当前版本</span>
          <Badge variant="secondary" className="font-mono">
            {info?.current ?? "…"}
          </Badge>
          {info && (
            <>
              <Badge variant="outline" className="font-mono">
                {info.os}/{info.arch}
              </Badge>
              <Badge variant="outline">{info.mode === "docker" ? "Docker" : "独立程序"}</Badge>
            </>
          )}
          {info?.latest && (
            <>
              <span className="text-muted-foreground">最新版本</span>
              <Badge variant={info.has_update ? "default" : "secondary"} className="font-mono">
                {info.latest}
              </Badge>
            </>
          )}
          {info?.html_url && (
            <a
              href={info.html_url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-xs text-muted-foreground underline-offset-4 hover:underline"
            >
              更新日志 <ExternalLinkIcon className="size-3" />
            </a>
          )}
        </div>

        {info?.error && (
          <p className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">
            <TriangleAlertIcon className="mt-0.5 size-3.5 shrink-0" />
            无法连接 GitHub：{info.error}
            {"　"}可在上方配置全局代理后重试。
          </p>
        )}

        {info && !info.comparable && info.reason && <p className="text-xs text-muted-foreground">{info.reason}</p>}

        {info && info.comparable && !info.has_update && !info.error && (
          <p className="flex items-center gap-2 text-xs text-muted-foreground">
            <CheckCircle2Icon className="size-3.5 text-emerald-600" />
            当前已是最新版本。
          </p>
        )}

        {info?.has_update && (
          <div className="space-y-2">
            <p className="text-xs text-muted-foreground">
              在部署机的 ARTEX 目录（docker/.env 所在的那一级）执行。更新会重建容器，
              正在运行的任务会被中断；数据库会在更新前自动备份到 <span className="font-mono">backups/</span>。
            </p>
            <div className="relative rounded-md border bg-muted/40 p-3 pr-10 font-mono text-xs leading-6">
              {cmds.map((c) => (
                <div key={c} className="whitespace-pre">
                  {c}
                </div>
              ))}
              <Button
                variant="ghost"
                size="icon"
                className="absolute top-1.5 right-1.5 size-7"
                onClick={() => copy(cmds.map((c) => c.split("#")[0].trim()).join("\n"))}
                title="复制命令"
              >
                <CopyIcon className="size-3.5" />
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              为什么不在页面里点：容器里换掉的只是程序文件，重建容器就退回镜像版本，
              而且换不掉镜像里的 LibreOffice / 工具层；脚本能拉完整镜像、能备份和恢复数据库、能回滚。
            </p>
          </div>
        )}

        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" onClick={() => check(false)} disabled={checking}>
            <RefreshCwIcon className={checking ? "size-4 animate-spin" : "size-4"} />
            检查更新
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
