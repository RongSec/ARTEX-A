"use client";

// 宿主环境体检（V10-HOSTENV）：把渗透常用外部工具编成一份目录逐件探测。
//
// 为什么需要：agent 最常踩的坑不是「不会用 nmap」，而是「以为有 nmap 结果没有」。
// 体检把「工具缺失」从运行期的一个报错，变成页面上可见的状态。
//
// 安装只走服务端目录里的白名单命令，前端传不了任意 shell。

import * as React from "react";

import { CheckCircle2Icon, CircleSlashIcon, DownloadIcon, RefreshCwIcon, TerminalIcon, XCircleIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { HostInstallJob, HostToolsResult } from "@/lib/types";

function fmtTime(s?: string) {
  if (!s) return "—";
  const d = new Date(s);
  if (isNaN(d.getTime())) return "—";
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export default function HostEnvPage() {
  const [data, setData] = React.useState<HostToolsResult | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [job, setJob] = React.useState<HostInstallJob | null>(null);
  const [openLog, setOpenLog] = React.useState<string | null>(null);

  const load = React.useCallback(async (refresh = false) => {
    setLoading(true);
    try {
      setData(await api.hostTools(refresh));
    } catch (e) {
      toast.error("体检失败：" + (e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load(false);
  }, [load]);

  // 安装任务轮询：2 秒一次，完成后刷新体检。
  React.useEffect(() => {
    if (!job || job.state === "done") return;
    const t = setInterval(async () => {
      try {
        const next = await api.hostToolsInstallStatus(job.id);
        setJob(next);
        if (next.state === "done") {
          toast.success("安装任务结束");
          void load(true);
        }
      } catch {
        // 任务被服务重启清掉时停止轮询
        clearInterval(t);
      }
    }, 2000);
    return () => clearInterval(t);
  }, [job, load]);

  async function install(keys: string[]) {
    if (keys.length === 0) return;
    try {
      setJob(await api.hostToolsInstall(keys));
    } catch (e) {
      toast.error("触发安装失败：" + (e as Error).message);
    }
  }

  const missingInstallable = React.useMemo(() => {
    if (!data) return [];
    const out: string[] = [];
    for (const g of data.groups) {
      for (const t of g.tools) {
        if (!t.present && t.installable) out.push(t.key);
      }
    }
    return out;
  }, [data]);

  const doneCount = job ? job.items.filter((i) => i.state === "done" || i.state === "failed" || i.state === "skipped").length : 0;
  const pct = job && job.items.length > 0 ? Math.round((doneCount / job.items.length) * 100) : 0;

  return (
    <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">宿主环境</h1>
          <p className="text-muted-foreground text-sm">
            渗透工具链体检：存在性 + 版本。缺失的工具 agent 会绕开，但提前装齐能少踩坑。
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void load(true)} disabled={loading}>
            {loading ? <Spinner data-icon="inline-start" /> : <RefreshCwIcon />} 重新体检
          </Button>
          <Button
            size="sm"
            disabled={missingInstallable.length === 0 || (job?.state === "running")}
            onClick={() => void install(missingInstallable)}
          >
            <DownloadIcon /> 一键装齐缺失 {missingInstallable.length > 0 ? `(${missingInstallable.length})` : ""}
          </Button>
        </div>
      </div>

      {data?.container && (
        <div className="border-amber-500/40 bg-amber-500/5 flex items-start gap-2 rounded-lg border p-3 text-sm">
          <TerminalIcon className="mt-0.5 size-4 shrink-0 text-amber-600" />
          <div>
            <p className="font-medium">当前运行在容器内</p>
            <p className="text-muted-foreground text-xs">
              这里装出来的工具属于容器这一层：<code className="font-mono">docker compose up --build</code> 重建镜像后会消失。
              apt 安装的包还会带上数据目录（如 nmap 的脚本库），只挂二进制活不下来——要长期可用，把安装项写进 Dockerfile，
              或用 <code className="font-mono">ARTEX_HOSTBIN</code> 把 go/pip 类工具落到挂载卷（当前落地目录：
              <code className="font-mono">{data.bin_dir || "/usr/local/bin"}</code>）。
            </p>
          </div>
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-3">
        <Card className="gap-0 py-4">
          <CardHeader className="px-4 pb-1">
            <CardDescription className="text-xs">目录工具</CardDescription>
          </CardHeader>
          <CardContent className="px-4">
            <div className="text-2xl font-semibold tabular-nums">{data?.summary.total ?? 0}</div>
            <p className="text-muted-foreground mt-1 text-[11px]">{data?.platform ?? "—"}</p>
          </CardContent>
        </Card>
        <Card className="gap-0 py-4">
          <CardHeader className="px-4 pb-1">
            <CardDescription className="text-xs">已就绪</CardDescription>
          </CardHeader>
          <CardContent className="px-4">
            <div className="text-2xl font-semibold tabular-nums text-emerald-600 dark:text-emerald-400">
              {data?.summary.present ?? 0}
            </div>
            <p className="text-muted-foreground mt-1 text-[11px]">体检时间 {fmtTime(data?.checked_at)}</p>
          </CardContent>
        </Card>
        <Card className="gap-0 py-4">
          <CardHeader className="px-4 pb-1">
            <CardDescription className="text-xs">缺失</CardDescription>
          </CardHeader>
          <CardContent className="px-4">
            <div className="text-2xl font-semibold tabular-nums text-rose-600 dark:text-rose-400">
              {data?.summary.missing ?? 0}
            </div>
            <p className="text-muted-foreground mt-1 text-[11px]">其中 {missingInstallable.length} 件可自动安装</p>
          </CardContent>
        </Card>
      </div>

      {job && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <TerminalIcon className="size-4" /> 安装进度
              <Badge variant="outline">{job.state === "done" ? "已完成" : "进行中"}</Badge>
            </CardTitle>
            <CardDescription className="text-xs">
              {doneCount}/{job.items.length} · 串行执行，点条目看输出
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Progress value={pct} />
            <div className="grid gap-1">
              {job.items.map((it) => (
                <div key={it.key} className="rounded-md border text-xs">
                  <button
                    type="button"
                    className="flex w-full items-center gap-2 px-2 py-1.5 text-left"
                    onClick={() => setOpenLog(openLog === it.key ? null : it.key)}
                  >
                    {it.state === "done" && <CheckCircle2Icon className="size-3.5 text-emerald-500" />}
                    {it.state === "failed" && <XCircleIcon className="size-3.5 text-rose-500" />}
                    {it.state === "skipped" && <CircleSlashIcon className="text-muted-foreground size-3.5" />}
                    {it.state === "running" && <Spinner className="size-3.5" />}
                    <span className="font-medium">{it.name || it.key}</span>
                    <span className="text-muted-foreground ml-auto">{it.state}</span>
                  </button>
                  {openLog === it.key && it.output && (
                    <pre className="bg-muted max-h-56 overflow-auto rounded-b-md p-2 font-mono text-[11px] whitespace-pre-wrap">
                      {it.output}
                    </pre>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {data?.groups.map((g) => (
        <div key={g.name} className="overflow-hidden rounded-lg border">
          <div className="bg-muted/40 flex items-center justify-between px-3 py-2">
            <h2 className="text-sm font-medium">{g.name}</h2>
            <span className="text-muted-foreground text-xs tabular-nums">
              {g.tools.filter((t) => t.present).length}/{g.tools.length}
            </span>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-24">状态</TableHead>
                <TableHead className="w-56">工具</TableHead>
                <TableHead className="w-48">可执行文件</TableHead>
                <TableHead>版本 / 说明</TableHead>
                <TableHead className="w-24 text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {g.tools.map((t) => (
                <TableRow key={t.key}>
                  <TableCell>
                    {t.present ? (
                      <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                        就绪
                      </Badge>
                    ) : t.offline ? (
                      <Badge variant="outline" className="border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400">
                        应内置未装
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400">
                        缺失
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-sm">{t.name}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {t.kind === "dir" ? <span className="text-muted-foreground">{t.bin}</span> : t.bin}
                  </TableCell>
                  <TableCell className="text-xs">
                    {t.present ? (
                      <span className="text-muted-foreground break-all">{t.version || t.path || "已安装"}</span>
                    ) : t.offline ? (
                      <span className="text-amber-600 dark:text-amber-400">
                        镜像基线应内置这件工具，实际未探到：检查镜像 tag，或构建时是否漏了 apt-core.txt / hostbin 层
                      </span>
                    ) : (
                      <span className="text-muted-foreground">
                        {t.hint || t.note || "需联网安装（go/pip/apt 都要出网）"}
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    {!t.present && t.installable && (
                      <Button variant="outline" size="sm" disabled={job?.state === "running"} onClick={() => void install([t.key])}>
                        安装
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      ))}
    </div>
  );
}
