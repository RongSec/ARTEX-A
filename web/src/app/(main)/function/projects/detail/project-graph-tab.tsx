"use client";

// 全项目大图 tab（artex-hs T13，架构 §2.1 投影常开定稿）。数据源 = GET /api/projects/{id}/graph
// （project_index 投影，[已核实 T12 定稿] 投影常开——observer_enabled 关了也看得到，
// 该开关只管触发与 insight 注入）。不强求力导向布局（拍板1：无跨任务边投影）：
// 按任务分组卡片网格，卡内 kind 着色节点行；点 finding/fact 行新 tab 下钻该任务
// 探索链路（?tab=graph）。右侧洞察面板读 project_insights（observer 产出）可删。
//
// 与 T12(0) 语义对齐的 UX 已知项：任务挂/摘项目不即时改投影——批量下发/移出
// 操作后 toast「投影将在任务重启或重建后更新」，本页「重建投影」按钮即补账入口。

import * as React from "react";

import {
  DatabaseIcon,
  PauseIcon,
  PlayIcon,
  RefreshCwIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import type { GraphTaskGroup, Project, ProjectGraphNode, ProjectInsight } from "@/lib/types";

const POLL_MS = 10_000; // 自动刷新周期（任务书钉 10s）

// kind 行着色（任务书口径：fact 灰 / intent 蓝 / finding 按 severity 红黄绿 /
// goal 紫；begin/hint/digest 归中性弱化）。色板取站内 status.ts tone 家族。
const kindDot: Record<string, string> = {
  fact: "bg-slate-400",
  intent: "bg-blue-500",
  goal: "bg-purple-500",
  finding: "bg-rose-500", // 默认红；下方按 severity 覆盖
  begin: "bg-zinc-300 dark:bg-zinc-600",
  hint: "bg-teal-500",
  digest: "bg-zinc-400",
};
const severityDot: Record<string, string> = {
  critical: "bg-rose-600",
  high: "bg-red-500",
  medium: "bg-amber-500",
  low: "bg-emerald-500", // 任务书"红黄绿"梯度：低危绿（区别于 fact 灰、更醒目）
};
function nodeDot(n: ProjectGraphNode): string {
  if (n.kind === "finding") return severityDot[n.severity] ?? kindDot.finding;
  return kindDot[n.kind] ?? "bg-zinc-400";
}
// finding/fact 可下钻（有真实探索节点可看）；intent/goal 行仅展示。
const DRILLDOWN_KINDS = new Set(["finding", "fact"]);

function fmtNodeTime(unix: number): string {
  if (!unix) return "";
  return new Date(unix * 1000).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export function ProjectGraphTab({ project, onChanged }: { project: Project; onChanged: () => void }) {
  const [groups, setGroups] = React.useState<GraphTaskGroup[]>([]);
  const [hint, setHint] = React.useState("");
  const [loading, setLoading] = React.useState(true);
  const [auto, setAuto] = React.useState(true);
  const [rebuilding, setRebuilding] = React.useState(false);

  // 跨任务（项目内）开关的本地镜像：只动 observer_enabled 这一列（V6-DUAL：
  // 跨项目阅读是另一个独立开关，工具条绝不连带改它）；PATCH 成功后同步父级 detail。
  const [observer, setObserver] = React.useState(project.observer_enabled);
  React.useEffect(() => setObserver(project.observer_enabled), [project.observer_enabled]);

  const load = React.useCallback(
    (silent = false) => {
      if (!silent) setLoading(true);
      api
        .projectGraph(project.id)
        .then((r) => {
          setGroups(r.groups ?? []);
          setHint(r.hint ?? "");
        })
        .catch((e) => {
          if (!silent) toast.error("加载大图失败：" + (e as Error).message);
        })
        .finally(() => !silent && setLoading(false));
    },
    [project.id],
  );

  React.useEffect(() => {
    load();
  }, [load]);

  // 10s 轮询（暂停=清 timer；离开页面自动停）。静默刷新，不闪 loading。
  React.useEffect(() => {
    if (!auto) return;
    const t = setInterval(() => load(true), POLL_MS);
    return () => clearInterval(t);
  }, [auto, load]);

  async function rebuild() {
    setRebuilding(true);
    try {
      const r = await api.projectGraphRebuild(project.id);
      toast.success(`投影已重建（${r.rebuilt} 个节点）`);
      load(true);
    } catch (e) {
      toast.error("重建失败：" + (e as Error).message);
    } finally {
      setRebuilding(false);
    }
  }

  // V6-DUAL：这里只切「跨任务阅读（项目内）」= observer_enabled 单列；
  // 跨项目阅读（reader_enabled）在项目设置里单独开关，不随这里联动。
  async function toggleObserver(on: boolean) {
    const prev = observer;
    setObserver(on); // 乐观翻转；失败回滚
    try {
      await api.updateProject(project.id, { observer_enabled: on });
      toast.success(on ? "已开启跨任务阅读（项目内触发与洞察注入生效；投影本就常开）" : "已关闭跨任务阅读（停止项目内触发与注入；大图投影保留）");
      onChanged();
    } catch (e) {
      setObserver(prev);
      toast.error("切换失败：" + (e as Error).message);
    }
  }

  const totalNodes = groups.reduce((n, g) => n + g.nodes.length, 0);

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
      <div className="grid gap-3">
        {/* 工具条 */}
        <div className="bg-background flex flex-wrap items-center gap-x-4 gap-y-2 rounded-xl border px-3 py-2 text-sm">
          <span className="text-muted-foreground text-xs">
            {groups.length} 任务 · {totalNodes} 节点
          </span>
          <Separator orientation="vertical" className="h-4" />
          <label className="flex items-center gap-2 text-xs" htmlFor="pg-observer">
            <Switch id="pg-observer" checked={observer} onCheckedChange={toggleObserver} />
            跨任务阅读
          </label>
          <span className="text-muted-foreground text-xs">并发 {project.concurrency}</span>
          <div className="ml-auto flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={rebuild} disabled={rebuilding} title="全量清旧灌新（挂/摘项目后补投影的入口）">
              <RefreshCwIcon className={rebuilding ? "animate-spin" : ""} />
              重建投影
            </Button>
            <Button variant="outline" size="sm" onClick={() => setAuto((a) => !a)} title="10s 轮询开关">
              {auto ? <PauseIcon /> : <PlayIcon />}
              {auto ? "暂停刷新" : "自动刷新"}
            </Button>
          </div>
        </div>

        {loading ? (
          <div className="text-muted-foreground p-6 text-sm">加载中…</div>
        ) : groups.length === 0 ? (
          <Empty>
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <DatabaseIcon />
              </EmptyMedia>
              <EmptyTitle>暂无项目投影</EmptyTitle>
              <EmptyDescription>{hint || "任务运行中会实时出现；点「重建投影」可立即补齐存量图。"}</EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 2xl:grid-cols-3">
            {groups.map((g) => (
              <GraphTaskCard key={g.task_id} g={g} />
            ))}
          </div>
        )}
      </div>

      <InsightsPanel projectID={project.id} />
    </div>
  );
}

function GraphTaskCard({ g }: { g: GraphTaskGroup }) {
  // 下钻=新 tab 打开该任务详情页的探索链路 tab（graph tab 不按节点定位，
  // 摘要行给的是全貌入口；节点级定位留待真实需求，别造假锚点）。
  const taskHref = `/function/tasks/detail?id=${encodeURIComponent(String(g.task_id))}&tab=graph`;
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm">
          <span className="truncate" title={g.task_desc || g.task_name}>
            {g.task_name || `任务#${g.task_id}`}
          </span>
          {g.status && <StatusBadge domain="task" value={g.status} dot />}
          {!g.projected && <Badge variant="outline">已归档</Badge>}
        </CardTitle>
        <CardDescription className="text-xs tabular-nums">
          {Object.entries(g.counts_by_kind)
            .map(([k, n]) => `${k} ${n}`)
            .join(" · ") || "无节点"}
        </CardDescription>
        <CardAction>
          <span className="text-muted-foreground text-xs tabular-nums">{g.nodes.length}</span>
        </CardAction>
      </CardHeader>
      <CardContent className="grid max-h-72 gap-0.5 overflow-y-auto">
        {g.nodes.map((n) => {
          const drill = g.projected && DRILLDOWN_KINDS.has(n.kind);
          const row = (
            <div className="hover:bg-muted/60 flex items-center gap-2 rounded-md px-1.5 py-1 text-xs" title={`${n.kind}/${n.state}${n.severity ? "/" + n.severity : ""} ${n.summary}`}>
              <span className={`size-2 shrink-0 rounded-full ${nodeDot(n)}`} />
              <span className="min-w-0 flex-1 truncate">{n.summary || n.node_id}</span>
              {n.asset_keys.length > 0 && (
                <span className="text-muted-foreground hidden max-w-24 truncate sm:inline" title={n.asset_keys.join(", ")}>
                  {n.asset_keys[0]}
                  {n.asset_keys.length > 1 ? ` +${n.asset_keys.length - 1}` : ""}
                </span>
              )}
              <span className="text-muted-foreground shrink-0 tabular-nums">{fmtNodeTime(n.updated_at)}</span>
            </div>
          );
          return drill ? (
            <a key={n.node_id} href={taskHref} target="_blank" rel="noreferrer" className="rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
              {row}
            </a>
          ) : (
            <React.Fragment key={n.node_id}>{row}</React.Fragment>
          );
        })}
      </CardContent>
    </Card>
  );
}

// InsightsPanel 观察者经验：列表 + keywords 徽章 + 来源任务回链 + 删除。
function InsightsPanel({ projectID }: { projectID: number }) {
  const [list, setList] = React.useState<ProjectInsight[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [deleting, setDeleting] = React.useState<number | null>(null);

  const load = React.useCallback(
    (silent = false) => {
      if (!silent) setLoading(true);
      api
        .projectInsights(projectID)
        .then((r) => setList(r.insights))
        .catch((e) => !silent && toast.error("加载洞察失败：" + (e as Error).message))
        .finally(() => !silent && setLoading(false));
    },
    [projectID],
  );
  React.useEffect(() => {
    load();
  }, [load]);

  async function remove(id: number) {
    setDeleting(id);
    try {
      await api.deleteProjectInsight(projectID, id);
      setList((l) => l.filter((x) => x.id !== id));
      toast.success("洞察已删除");
    } catch (e) {
      toast.error("删除失败：" + (e as Error).message);
    } finally {
      setDeleting(null);
    }
  }

  return (
    <Card size="sm" className="max-h-[calc(100vh-12rem)] self-start">
      <CardHeader>
        <CardTitle className="text-sm">观察者洞察{list.length ? `（${list.length}）` : ""}</CardTitle>
        <CardDescription className="text-xs">跨任务可借鉴经验（planner 按资产命中限量注入）</CardDescription>
        <CardAction>
          <Button variant="ghost" size="icon" onClick={() => load()} aria-label="刷新洞察">
            <RefreshCwIcon className={loading ? "animate-spin" : ""} />
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-2 overflow-y-auto">
        {!loading && list.length === 0 && (
          <p className="text-muted-foreground py-6 text-center text-xs">
            还没有洞察。开启项目「观察者」后，观察 agent 会在图变更时自动沉淀可借鉴经验。
          </p>
        )}
        {list.map((it) => (
          <div key={it.id} className="rounded-lg border p-2.5 text-xs">
            <p className="leading-relaxed break-words">{it.content}</p>
            <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
              {it.source_task_id ? (
                <a
                  className="text-primary hover:underline"
                  href={`/function/tasks/detail?id=${encodeURIComponent(String(it.source_task_id))}&tab=graph`}
                  target="_blank"
                  rel="noreferrer"
                >
                  来源任务#{it.source_task_id}
                </a>
              ) : (
                <span className="text-muted-foreground">来源未知</span>
              )}
              {it.keywords.map((k) => (
                <Badge key={k} variant="secondary" className="px-1.5 py-0 text-[10px]">
                  {k}
                </Badge>
              ))}
              <span className="text-muted-foreground ml-auto">{new Date(it.created_at).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}</span>
              <Button variant="ghost" size="icon-xs" className="text-destructive" onClick={() => remove(it.id)} disabled={deleting === it.id} aria-label="删除洞察">
                <Trash2Icon />
              </Button>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
