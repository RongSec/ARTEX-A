"use client";

// 事实台账页（V4-A）：三层结构浏览/编辑全部事实（exploration_nodes kind='fact'）。
// 项目（含"未挂项目"组）→ 任务（状态徽+详情链接）→ 事实行。
// 行=summary 加粗一行 + description 折叠展开 + 徽章（来源/类别/锚定资产）
// + 时间 + 行内编辑（乐观更新，失败回滚 toast，照 findings 页 updateStatus 范式）。
// 人工编辑过的行带"人工编辑"徽 + 可展开机器原文（machine_original）。
// 顶部工具条：项目/任务两级筛选 + 300ms 防抖搜索 + 统计。数据量可控不分页。

import * as React from "react";

import Link from "next/link";

import {
  BookOpenTextIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  PencilIcon,
  SearchIcon,
  XIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import { statusMeta, toneClasses } from "@/lib/status";
import {
  FACT_CATEGORY_OPTIONS,
  type Fact,
  type FactProjectGroup,
  type FactSource,
  type FactTaskGroup,
} from "@/lib/types";
import { cn } from "@/lib/utils";

const ALL = "all";

function fmtTime(ts: string) {
  return new Date(ts).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

const sourceMeta: Record<FactSource, { label: string; cls: string }> = {
  worker: { label: "worker", cls: "bg-muted text-muted-foreground border-transparent" },
  observer: { label: "observer", cls: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/20" },
  human: { label: "人工", cls: "bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/20" },
};

function MiniBadge({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 text-[11px] leading-none whitespace-nowrap",
        className,
      )}
    >
      {children}
    </span>
  );
}

// 行内编辑表单的草稿态。
interface EditDraft {
  summary: string;
  description: string;
  category: string; // ""=未选（保存时按"其他"落空串删键）
}

export default function FactsPage() {
  const [groups, setGroups] = React.useState<FactProjectGroup[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");

  // 筛选 + 搜索（300ms 防抖）
  const [projectFilter, setProjectFilter] = React.useState<string>(ALL);
  const [taskFilter, setTaskFilter] = React.useState<string>(ALL);
  const [search, setSearch] = React.useState("");
  const [debouncedSearch, setDebouncedSearch] = React.useState("");
  React.useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search.trim()), 300);
    return () => clearTimeout(t);
  }, [search]);

  // 项目/任务下拉选项（任务选项随项目筛选级联）
  const [projectOptions, setProjectOptions] = React.useState<{ id: string; name: string }[]>([]);
  const [taskOptions, setTaskOptions] = React.useState<{ id: string; name: string; project_id?: number | null }[]>([]);
  React.useEffect(() => {
    api
      .projects()
      .then((r) => setProjectOptions(r.projects.map((p) => ({ id: String(p.id), name: p.name }))))
      .catch(() => setProjectOptions([]));
    api
      .tasks()
      .then((r) =>
        setTaskOptions(
          r.tasks.map((t) => ({ id: String(t.id), name: t.name || t.description, project_id: t.project_id })),
        ),
      )
      .catch(() => setTaskOptions([]));
  }, []);
  const visibleTaskOptions =
    projectFilter === ALL
      ? taskOptions
      : projectFilter === "none"
        ? taskOptions.filter((t) => t.project_id == null)
        : taskOptions.filter((t) => t.project_id != null && String(t.project_id) === projectFilter);
  React.useEffect(() => {
    // 项目切换后已选任务可能不在新范围内，回退"全部"。
    if (taskFilter !== ALL && !visibleTaskOptions.some((t) => t.id === taskFilter)) setTaskFilter(ALL);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectFilter]);

  // 折叠态（默认展开；Set 里存"已收起"的 key）
  const [collapsedProjects, setCollapsedProjects] = React.useState<Set<string>>(new Set());
  const [collapsedTasks, setCollapsedTasks] = React.useState<Set<string>>(new Set());
  const [expandedDesc, setExpandedDesc] = React.useState<Set<string>>(new Set());
  const [expandedOriginal, setExpandedOriginal] = React.useState<Set<string>>(new Set());

  const toggleSet = (setter: React.Dispatch<React.SetStateAction<Set<string>>>, key: string) =>
    setter((cur) => {
      const next = new Set(cur);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  // 数据拉取：筛选/防抖搜索变化时。
  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .listFacts({
        project_id: projectFilter === ALL ? undefined : projectFilter,
        task_id: taskFilter === ALL ? undefined : taskFilter,
        q: debouncedSearch || undefined,
      })
      .then((g) => {
        if (!alive) return;
        setGroups(g);
        setError("");
      })
      .catch((e) => {
        if (!alive) return;
        setError((e as Error).message);
      })
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [projectFilter, taskFilter, debouncedSearch]);

  // 编辑态
  const [editingId, setEditingId] = React.useState<string | null>(null);
  const [draft, setDraft] = React.useState<EditDraft>({ summary: "", description: "", category: "" });
  const [saving, setSaving] = React.useState(false);

  // 三层扁平化：定位 fact + 计数（统计条）。
  const factIndex = React.useMemo(() => {
    const map = new Map<string, { fact: Fact; task: FactTaskGroup }>();
    let taskCount = 0;
    let factCount = 0;
    for (const g of groups) {
      for (const t of g.tasks) {
        taskCount += 1;
        for (const f of t.facts) {
          map.set(f.id, { fact: f, task: t });
          factCount += 1;
        }
      }
    }
    return { map, projectCount: groups.length, taskCount, factCount };
  }, [groups]);

  const startEdit = (f: Fact) => {
    setEditingId(f.id);
    setDraft({ summary: f.summary, description: f.description, category: f.category ?? "" });
  };

  const replaceFact = (id: string, next: Fact) =>
    setGroups((cur) =>
      cur.map((g) => ({
        ...g,
        tasks: g.tasks.map((t) => ({
          ...t,
          facts: t.facts.map((f) => (f.id === id ? next : f)),
        })),
      })),
    );

  const saveEdit = async (f: Fact) => {
    if (!draft.summary.trim()) {
      toast.error("摘要不能为空");
      return;
    }
    const prev = f;
    const optimistic: Fact = {
      ...prev,
      summary: draft.summary,
      description: draft.description,
      category: draft.category || prev.category,
      edited: true,
      source: "human",
    };
    // 乐观更新（含类别清空语义：空串=其他，后端删键；本地先按"其他"呈现）。
    replaceFact(f.id, { ...optimistic, category: draft.category });
    setSaving(true);
    try {
      const updated = await api.patchFact(f.id, {
        summary: draft.summary,
        description: draft.description,
        category: draft.category,
      });
      // 用后端回读（machine_original 首次出现等）覆盖本地行；task_id/created_at
      // 保持本地值（PATCH 响应不带归属，后端回 0 占位）。
      replaceFact(f.id, {
        ...updated,
        task_id: prev.task_id,
        origin_fact: updated.origin_fact ?? prev.origin_fact,
        created_at: updated.created_at || prev.created_at,
        anchors: updated.anchors?.length ? updated.anchors : prev.anchors,
        machine_original: updated.machine_original ?? prev.machine_original,
      });
      toast.success("已保存");
      setEditingId(null);
    } catch (e) {
      replaceFact(f.id, prev); // 回滚
      toast.error(`更新失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col gap-4 p-4">
      {/* 工具条 */}
      <Card className="shrink-0">
        <CardContent className="flex flex-wrap items-center gap-3 p-3">
          <div className="flex items-center gap-1.5 text-sm font-medium">
            <BookOpenTextIcon className="size-4" /> 任务小结
          </div>
          <Select value={projectFilter} onValueChange={setProjectFilter}>
            <SelectTrigger size="sm" className="w-40">
              <SelectValue placeholder="项目" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>全部项目</SelectItem>
              {projectOptions.map((p) => (
                <SelectItem key={p.id} value={p.id}>
                  {p.name}
                </SelectItem>
              ))}
              <SelectItem value="none">未挂项目</SelectItem>
            </SelectContent>
          </Select>
          <Select value={taskFilter} onValueChange={setTaskFilter}>
            <SelectTrigger size="sm" className="w-44">
              <SelectValue placeholder="任务" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>全部任务</SelectItem>
              {visibleTaskOptions.map((t) => (
                <SelectItem key={t.id} value={t.id}>
                  {t.name || `任务#${t.id}`}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <InputGroup className="w-64">
            <InputGroupAddon>
              <SearchIcon className="size-4" />
            </InputGroupAddon>
            <InputGroupInput
              placeholder="搜索摘要/描述…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            {search && (
              <InputGroupAddon align="inline-end">
                <button className="text-muted-foreground hover:text-foreground" onClick={() => setSearch("")} aria-label="清除搜索">
                  <XIcon className="size-3.5" />
                </button>
              </InputGroupAddon>
            )}
          </InputGroup>
          <div className="text-muted-foreground ml-auto text-xs tabular-nums">
            {factIndex.projectCount} 个项目 / {factIndex.taskCount} 个任务 / {factIndex.factCount} 条事实
          </div>
        </CardContent>
      </Card>

      {/* 三层主体（滚动容器） */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {loading ? (
          <div className="flex items-center justify-center py-16">
            <Spinner className="size-5" />
          </div>
        ) : error ? (
          <p className="text-destructive py-16 text-center text-sm">加载失败：{error}</p>
        ) : groups.length === 0 ? (
          <p className="text-muted-foreground py-16 text-center text-sm">暂无事实。任务探索中由 agent record_fact 写入后会自动出现在这里。</p>
        ) : (
          <div className="space-y-4">
            {groups.map((g) => {
              const pKey = g.project ? `p${g.project.id}` : "p-none";
              const collapsed = collapsedProjects.has(pKey);
              return (
                <Card key={pKey}>
                  <button
                    className="hover:bg-muted/50 flex w-full items-center gap-2 px-4 py-3 text-left"
                    onClick={() => toggleSet(setCollapsedProjects, pKey)}
                  >
                    {collapsed ? <ChevronRightIcon className="size-4" /> : <ChevronDownIcon className="size-4" />}
                    <span className="text-sm font-semibold">{g.project ? g.project.name : "未挂项目"}</span>
                    <span className="text-muted-foreground text-xs tabular-nums">
                      {g.tasks.length} 个任务 / {g.tasks.reduce((n, t) => n + t.facts.length, 0)} 条事实
                    </span>
                  </button>
                  {!collapsed && (
                    <CardContent className="space-y-4 border-t pt-3">
                      {g.tasks.map((t) => {
                        const tKey = `t${t.id}`;
                        const tCollapsed = collapsedTasks.has(tKey);
                        return (
                          <div key={tKey} className="space-y-1.5">
                            <div className="flex items-center gap-2">
                              <button
                                className="text-muted-foreground hover:text-foreground"
                                onClick={() => toggleSet(setCollapsedTasks, tKey)}
                                aria-label={tCollapsed ? "展开任务" : "收起任务"}
                              >
                                {tCollapsed ? <ChevronRightIcon className="size-3.5" /> : <ChevronDownIcon className="size-3.5" />}
                              </button>
                              <Link
                                href={`/function/tasks/detail?id=${encodeURIComponent(t.id)}`}
                                className="hover:text-primary truncate text-sm font-medium"
                              >
                                {t.name || `任务#${t.id}`}
                              </Link>
                              <MiniBadge className={toneClasses[statusMeta("task", t.status).tone]}>
                                {statusMeta("task", t.status).label}
                              </MiniBadge>
                              <span className="text-muted-foreground text-xs tabular-nums">{t.facts.length} 条</span>
                            </div>
                            {!tCollapsed && (
                              <div className="ml-5 space-y-1.5">
                                {t.facts.map((f) => (
                                  <FactRow
                                    key={f.id}
                                    fact={f}
                                    editing={editingId === f.id}
                                    saving={saving}
                                    draft={draft}
                                    setDraft={setDraft}
                                    descExpanded={expandedDesc.has(f.id)}
                                    onToggleDesc={() => toggleSet(setExpandedDesc, f.id)}
                                    origExpanded={expandedOriginal.has(f.id)}
                                    onToggleOrig={() => toggleSet(setExpandedOriginal, f.id)}
                                    onEdit={() => startEdit(f)}
                                    onCancel={() => setEditingId(null)}
                                    onSave={() => void saveEdit(f)}
                                  />
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </CardContent>
                  )}
                </Card>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function FactRow(props: {
  fact: Fact;
  editing: boolean;
  saving: boolean;
  draft: EditDraft;
  setDraft: React.Dispatch<React.SetStateAction<EditDraft>>;
  descExpanded: boolean;
  onToggleDesc: () => void;
  origExpanded: boolean;
  onToggleOrig: () => void;
  onEdit: () => void;
  onCancel: () => void;
  onSave: () => void;
}) {
  const { fact: f } = props;
  const src = sourceMeta[f.source] ?? sourceMeta.worker;
  const hasDesc = Boolean(f.description || f.evidence);

  if (props.editing) {
    return (
      <div className="bg-muted/40 rounded-lg border p-2.5">
        <div className="space-y-2">
          <Input
            value={props.draft.summary}
            onChange={(e) => props.setDraft((d) => ({ ...d, summary: e.target.value }))}
            placeholder="摘要（一行结论）"
            autoFocus
          />
          <Textarea
            rows={3}
            value={props.draft.description}
            onChange={(e) => props.setDraft((d) => ({ ...d, description: e.target.value }))}
            placeholder="描述/细节（可留空）"
          />
          <Select value={props.draft.category || "none"} onValueChange={(v) => props.setDraft((d) => ({ ...d, category: v === "none" ? "" : String(v) }))}>
            <SelectTrigger size="sm" className="w-40">
              <SelectValue placeholder="类别" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="none">未分类（其他）</SelectItem>
              {FACT_CATEGORY_OPTIONS.map((c) => (
                <SelectItem key={c} value={c}>
                  {c}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="mt-2 flex gap-2">
          <Button size="sm" onClick={props.onSave} disabled={props.saving}>
            {props.saving ? <Spinner className="size-3.5" /> : null} 保存
          </Button>
          <Button size="sm" variant="outline" onClick={props.onCancel} disabled={props.saving}>
            取消
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="hover:bg-muted/30 rounded-lg border px-3 py-2">
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="truncate text-sm font-semibold">{f.summary || "（无摘要）"}</span>
            <MiniBadge className={src.cls}>{src.label}</MiniBadge>
            {f.origin_fact && (
              <MiniBadge className="border-transparent bg-muted text-muted-foreground">任务起点</MiniBadge>
            )}
            <MiniBadge className="border-transparent bg-muted text-muted-foreground">
              {f.category || "其他"}
            </MiniBadge>
            {f.edited && (
              <MiniBadge className="border-blue-500/20 bg-blue-500/15 text-blue-600 dark:text-blue-400">人工编辑</MiniBadge>
            )}
            {f.anchors?.map((a) => (
              <MiniBadge key={a.id} className="border-transparent bg-slate-500/15 font-mono text-slate-600 dark:text-slate-400">
                {a.label}
              </MiniBadge>
            ))}
          </div>
          {hasDesc && (
            <button
              className="text-muted-foreground hover:text-foreground mt-0.5 flex items-center gap-1 text-xs"
              onClick={props.onToggleDesc}
            >
              {props.descExpanded ? <ChevronDownIcon className="size-3" /> : <ChevronRightIcon className="size-3" />}
              {props.descExpanded ? "收起细节" : "展开细节"}
            </button>
          )}
          {props.descExpanded && (
            <div className="mt-1 space-y-1">
              {f.description && (
                <p className="text-muted-foreground text-xs break-words whitespace-pre-wrap">{f.description}</p>
              )}
              {f.evidence && (
                <p className="text-muted-foreground bg-muted/60 rounded border px-2 py-1 font-mono text-xs break-words whitespace-pre-wrap">
                  {f.evidence}
                </p>
              )}
            </div>
          )}
          {f.edited && (
            <button
              className="text-muted-foreground hover:text-foreground mt-0.5 flex items-center gap-1 text-xs"
              onClick={props.onToggleOrig}
            >
              {props.origExpanded ? <ChevronDownIcon className="size-3" /> : <ChevronRightIcon className="size-3" />}
              机器原文
            </button>
          )}
          {props.origExpanded && f.machine_original && (
            <div className="mt-1 space-y-0.5 rounded border border-dashed px-2 py-1.5">
              <p className="text-xs break-words whitespace-pre-wrap">{f.machine_original.summary || "（无）"}</p>
              {f.machine_original.description && (
                <p className="text-muted-foreground text-xs break-words whitespace-pre-wrap">{f.machine_original.description}</p>
              )}
            </div>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          <span className="text-muted-foreground text-xs tabular-nums" title={`创建 ${fmtTime(f.created_at)} / 更新 ${fmtTime(f.updated_at)}`}>
            {fmtTime(f.updated_at)}
          </span>
          <Button size="sm" variant="ghost" className="text-muted-foreground h-6 w-6 p-0" onClick={props.onEdit} aria-label="编辑">
            <PencilIcon className="size-3.5" />
          </Button>
        </div>
      </div>
    </div>
  );
}
