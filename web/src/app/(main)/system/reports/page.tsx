"use client";

// R6 报告归档中心：左侧「项目 → 任务 → 报告」树，右侧内嵌预览，多选
// 导出 / 重新生成 / 删除。
//
// 后端：GET /api/reports/tree（status/q 过滤）、GET /api/reports/{id}/preview.pdf
// （docx→PDF 保真预览；无 LibreOffice 时回退 HTML 近似预览）、
// POST /api/reports/download-batch（zip，含同目录 PDF）、
// POST /api/reports/delete-batch、POST /api/reports/regenerate-batch。
// 预览走 fetch+blob（iframe 带不了 JWT 头）。

import * as React from "react";

import {
  ChevronRightIcon,
  DownloadIcon,
  FileTextIcon,
  FolderIcon,
  RefreshCwIcon,
  RotateCcwIcon,
  SearchIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Spinner } from "@/components/ui/spinner";
import { api } from "@/lib/api";
import type { PreviewCapability, ReportJob, ReportTree, ReportTreeProject, ReportTreeTask } from "@/lib/types";

const STATUS_OPTIONS = [
  { v: "", label: "全部状态" },
  { v: "done", label: "成功" },
  { v: "failed", label: "失败" },
  { v: "running", label: "生成中" },
  { v: "pending", label: "排队中" },
];

export default function ReportsArchivePage() {
  const [tree, setTree] = React.useState<ReportTree | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [status, setStatus] = React.useState("");
  const [query, setQuery] = React.useState("");
  const [debounced, setDebounced] = React.useState("");
  const [checked, setChecked] = React.useState<Set<number>>(new Set());
  const [expanded, setExpanded] = React.useState<Set<number>>(new Set());

  const [previewId, setPreviewId] = React.useState<number | null>(null);
  const [preview, setPreview] = React.useState<{
    id: number;
    url: string;
    report: ReportJob;
    fidelity: "exact" | "approximate";
    pdf: boolean;
  } | null>(null);
  const [previewBusy, setPreviewBusy] = React.useState(false);
  const [previewErr, setPreviewErr] = React.useState("");
  const [capability, setCapability] = React.useState<PreviewCapability | null>(null);
  const [downloading, setDownloading] = React.useState(false);
  const [deleting, setDeleting] = React.useState(false);
  const [regenerating, setRegenerating] = React.useState(false);
  const [confirmDeleteOpen, setConfirmDeleteOpen] = React.useState(false);
  const previewUrlRef = React.useRef<string | null>(null);
  const previewAbortRef = React.useRef<AbortController | null>(null);
  const mountedRef = React.useRef(true);

  React.useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // PDF 保真预览能力（LibreOffice 是否安装），决定徽标文案。
  React.useEffect(() => {
    api
      .previewCapability()
      .then(setCapability)
      .catch(() => setCapability({ pdf: false, engine: "none", version: "" }));
  }, []);

  // 搜索防抖 300ms。
  React.useEffect(() => {
    const t = setTimeout(() => setDebounced(query.trim()), 300);
    return () => clearTimeout(t);
  }, [query]);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.reportsTree({ status, q: debounced || undefined });
      setTree(data);
      // 首次加载默认展开全部项目。
      setExpanded((cur) => {
        const next = new Set(cur);
        for (const p of data.projects) next.add(p.id);
        return next;
      });
    } catch (e) {
      toast.error(`加载报告树失败：${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, [status, debounced]);

  React.useEffect(() => {
    void load();
  }, [load]);

  // 预览：优先 PDF（docx 经 LibreOffice 转换）；失败（如转换 502）回退 HTML
  // 近似预览。fetch blob（带 JWT），URL.createObjectURL 给 iframe。
  React.useEffect(() => {
    if (previewId == null) {
      setPreview(null);
      return;
    }
    previewAbortRef.current?.abort();
    const ac = new AbortController();
    previewAbortRef.current = ac;
    setPreviewBusy(true);
    setPreviewErr("");
    const report = findReport(tree, previewId) ?? fallbackReport(previewId);
    const apply = (blob: Blob, fidelity: "exact" | "approximate", pdf: boolean) => {
      if (ac.signal.aborted || !mountedRef.current) return;
      const url = URL.createObjectURL(blob);
      if (previewUrlRef.current) URL.revokeObjectURL(previewUrlRef.current);
      previewUrlRef.current = url;
      setPreview({ id: previewId, url, report, fidelity, pdf });
    };
    api
      .reportPreviewPDFBlob(previewId, ac.signal)
      .then(({ blob, fidelity }) => apply(blob, fidelity, blob.type === "application/pdf"))
      .catch(async (e) => {
        if ((e as Error)?.name === "AbortError") return;
        // PDF 通道失败 → 回退现有 HTML 预览（版式近似），保证仍能看内容。
        try {
          const blob = await api.reportPreviewBlob(previewId, ac.signal);
          apply(blob, "approximate", false);
          toast.warning(`PDF 预览不可用，已回退近似预览：${(e as Error).message}`, { duration: 6000 });
        } catch (e2) {
          if ((e2 as Error)?.name === "AbortError") return;
          setPreviewErr((e2 as Error).message);
        }
      })
      .finally(() => {
        if (!ac.signal.aborted && mountedRef.current) setPreviewBusy(false);
      });
    return () => ac.abort();
    // tree 变化（刷新）时重取同一份报告，保持预览最新。
  }, [previewId, tree]);

  React.useEffect(
    () => () => {
      if (previewUrlRef.current) URL.revokeObjectURL(previewUrlRef.current);
    },
    [],
  );

  const allIDs = React.useMemo(() => {
    const ids: number[] = [];
    if (!tree) return ids;
    for (const p of tree.projects) ids.push(...projectReportIDs(p));
    for (const o of tree.orphans) ids.push(...taskReportIDs(o));
    return ids;
  }, [tree]);

  const toggleMany = (ids: number[]) => {
    setChecked((cur) => {
      const next = new Set(cur);
      const all = ids.length > 0 && ids.every((id) => next.has(id));
      for (const id of ids) {
        if (all) next.delete(id);
        else next.add(id);
      }
      return next;
    });
  };

  const checkState = (ids: number[]): boolean | "indeterminate" => {
    if (ids.length === 0) return false;
    const n = ids.filter((id) => checked.has(id)).length;
    if (n === 0) return false;
    return n === ids.length ? true : "indeterminate";
  };

  const openLatest = (reports: ReportJob[]) => {
    if (reports.length > 0) setPreviewId(reports[0].id);
  };

  const downloadSelected = async () => {
    const ids = [...checked];
    if (ids.length === 0) {
      toast.error("请先勾选要导出的报告");
      return;
    }
    setDownloading(true);
    try {
      const { filename } = await api.downloadReportsBatch(ids);
      toast.success(`已打包 ${ids.length} 份报告：${filename}`);
    } catch (e) {
      toast.error(`批量导出失败：${(e as Error).message}`);
    } finally {
      setDownloading(false);
    }
  };

  // 批量删除：二次确认后执行；失败项逐条提示原因；随后刷新树与列表。
  const deleteSelected = async () => {
    const ids = [...checked];
    if (ids.length === 0) return;
    setDeleting(true);
    try {
      const res = await api.deleteReportsBatch(ids);
      if (res.deleted > 0) toast.success(`已删除 ${res.deleted} 份报告`);
      for (const f of res.failed) toast.error(`#${f.id} 删除失败：${f.error}`);
      if (previewId != null && ids.includes(previewId)) setPreviewId(null);
      setChecked(new Set());
      setConfirmDeleteOpen(false);
      await load();
    } catch (e) {
      toast.error(`批量删除失败：${(e as Error).message}`);
    } finally {
      setDeleting(false);
    }
  };

  // 批量重新生成：新 job 入队后刷新（新行显示「生成中」），每 3s 轮询 job
  // 状态，全部终态或满 2 分钟后再刷新一次。
  const regenerateSelected = async () => {
    const ids = [...checked];
    if (ids.length === 0) {
      toast.error("请先勾选要重新生成的报告");
      return;
    }
    setRegenerating(true);
    try {
      const res = await api.regenerateReportsBatch(ids);
      for (const f of res.failed) toast.error(`#${f.id} 重新生成失败：${f.error}`);
      if (res.queued.length === 0) {
        toast.error("没有可重新生成的报告");
        return;
      }
      toast.success(`已重新排入 ${res.queued.length} 个报告任务`);
      await load();
      const deadline = Date.now() + 120_000;
      while (mountedRef.current && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 3000));
        if (!mountedRef.current) return;
        const jobs = await Promise.all(res.queued.map((id) => api.reportJob(id).catch(() => null)));
        if (jobs.every((j) => !j || j.status === "done" || j.status === "failed")) break;
      }
      if (mountedRef.current) await load();
    } catch (e) {
      toast.error(`批量重新生成失败：${(e as Error).message}`);
    } finally {
      if (mountedRef.current) setRegenerating(false);
    }
  };

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold">
            <FileTextIcon className="size-5" /> 报告归档
          </h1>
          <p className="text-muted-foreground text-sm">按项目/任务浏览已生成的报告，内嵌预览并多选打包下载。</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <SearchIcon className="text-muted-foreground pointer-events-none absolute top-1/2 left-2 size-4 -translate-y-1/2" />
            <Input
              className="h-8 w-56 pl-8"
              placeholder="搜索任务名…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <NativeSelect className="h-8 w-32" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="状态过滤">
            {STATUS_OPTIONS.map((o) => (
              <NativeSelectOption key={o.v} value={o.v}>
                {o.label}
              </NativeSelectOption>
            ))}
          </NativeSelect>
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            <RefreshCwIcon className={loading ? "animate-spin" : ""} /> 刷新
          </Button>
        </div>
      </div>

      <div className="grid min-h-[70vh] gap-4 lg:grid-cols-[320px_minmax(0,1fr)] lg:gap-6">
        {/* 左：项目→任务→报告树 */}
        <Card className="flex min-h-0 flex-col">
          <CardHeader className="flex-row items-center justify-between py-3">
            <CardTitle className="text-sm">项目 / 任务</CardTitle>
            <label className="text-muted-foreground flex items-center gap-1.5 text-xs">
              <Checkbox
                checked={checkState(allIDs)}
                onCheckedChange={() => toggleMany(allIDs)}
                aria-label="全选所有报告"
              />
              全选
            </label>
          </CardHeader>
          <CardContent className="min-h-0 flex-1 p-2">
            {loading && !tree ? (
              <div className="flex justify-center py-10">
                <Spinner />
              </div>
            ) : !tree || (tree.projects.length === 0 && tree.orphans.length === 0) ? (
              <p className="text-muted-foreground p-6 text-center text-sm">暂无报告。</p>
            ) : (
              <ScrollArea className="h-[calc(70vh-3.5rem)]">
                <div className="flex flex-col gap-1 pr-2">
                  {tree.projects.map((p) => (
                    <ProjectNode
                      key={p.id}
                      project={p}
                      expanded={expanded.has(p.id)}
                      onToggleExpand={() =>
                        setExpanded((cur) => {
                          const next = new Set(cur);
                          if (next.has(p.id)) next.delete(p.id);
                          else next.add(p.id);
                          return next;
                        })
                      }
                      checked={checked}
                      checkState={checkState}
                      onToggle={() => toggleMany(projectReportIDs(p))}
                      onPreview={(id) => setPreviewId(id)}
                      onPreviewProject={() => openLatest([...p.reports, ...p.tasks.flatMap((t) => t.reports)])}
                      onToggleTask={toggleMany}
                    />
                  ))}
                  {tree.orphans.length > 0 && (
                    <div className="mt-2 border-t pt-2">
                      <p className="text-muted-foreground px-2 py-1 text-xs">未归档</p>
                      {tree.orphans.map((t) => (
                        <TaskNode
                          key={`orphan-${t.id}`}
                          task={t}
                          checked={checked}
                          checkState={checkState}
                          onToggle={() => toggleMany(taskReportIDs(t))}
                          onPreview={(id) => setPreviewId(id)}
                          onToggleReport={(id) =>
                            setChecked((cur) => {
                              const next = new Set(cur);
                              if (next.has(id)) next.delete(id);
                              else next.add(id);
                              return next;
                            })
                          }
                        />
                      ))}
                    </div>
                  )}
                </div>
              </ScrollArea>
            )}
          </CardContent>
          <div className="flex flex-wrap items-center justify-between gap-2 border-t p-2">
            <div className="text-muted-foreground text-xs">
              <span>已选 {checked.size} 份</span>
              {regenerating && (
                <span className="ml-2 inline-flex items-center gap-1 text-sky-600">
                  <Spinner className="size-3" /> 重新生成中，完成后自动刷新…
                </span>
              )}
              {capability && !capability.pdf && (
                <span className="ml-2 text-amber-600">未检测到 LibreOffice，预览为近似渲染</span>
              )}
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => void downloadSelected()} disabled={downloading || checked.size === 0}>
                {downloading ? <Spinner /> : <DownloadIcon />} 导出
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => void regenerateSelected()}
                disabled={regenerating || checked.size === 0}
              >
                {regenerating ? <Spinner /> : <RotateCcwIcon />} 重新生成
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="text-rose-600 hover:text-rose-700"
                onClick={() => setConfirmDeleteOpen(true)}
                disabled={deleting || checked.size === 0}
              >
                {deleting ? <Spinner /> : <Trash2Icon />} 删除
              </Button>
            </div>
          </div>
        </Card>

        {/* 右：内嵌预览 */}
        <Card className="flex min-h-0 flex-col">
          <CardHeader className="flex-row flex-wrap items-center justify-between gap-2 py-3">
            <div className="flex items-center gap-2">
              <CardTitle className="text-sm">报告预览</CardTitle>
              {preview && <Badge variant="secondary">#{preview.id}</Badge>}
              {preview && <StatusPill status={preview.report.status} />}
              {preview?.report.warning && (
                <Badge variant="outline" className="border-amber-400 text-amber-600">
                  警告
                </Badge>
              )}
              {preview && (
                <Badge
                  variant="outline"
                  className={
                    preview.fidelity === "exact"
                      ? "border-emerald-500 text-emerald-600"
                      : "border-amber-400 text-amber-600"
                  }
                >
                  {preview.fidelity === "exact" ? "与最终 docx 一致（PDF 渲染）" : "近似预览（未安装 LibreOffice）"}
                </Badge>
              )}
            </div>
            {preview && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => void downloadOne(preview.id).catch((e) => toast.error(String(e)))}
              >
                <DownloadIcon /> 下载本份
              </Button>
            )}
          </CardHeader>
          <CardContent className="flex min-h-0 flex-1 flex-col p-3">
            <div className="relative min-h-[60vh] flex-1 overflow-hidden rounded-lg border bg-white">
              {previewId == null ? (
                <div className="text-muted-foreground flex h-full items-center justify-center p-6 text-center text-sm">
                  点击左侧任务或报告查看预览。
                </div>
              ) : previewErr ? (
                <div className="text-muted-foreground flex h-full items-center justify-center p-6 text-center text-sm">
                  预览失败：{previewErr}
                </div>
              ) : previewBusy && !preview ? (
                <div className="flex h-full items-center justify-center">
                  <Spinner />
                </div>
              ) : preview ? (
                preview.pdf ? (
                  // PDF 由服务端生成（自有产物），直接交浏览器内置阅读器；
                  // 加 sandbox 会挡住 PDF viewer，故此处不沙箱。
                  <iframe title={`报告预览 #${preview.id}`} src={preview.url} className="size-full" />
                ) : (
                  <iframe title={`报告预览 #${preview.id}`} src={preview.url} className="size-full" sandbox="allow-same-origin" />
                )
              ) : null}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* 删除二次确认：显示条数，确认后删行+文件并刷新。 */}
      <AlertDialog open={confirmDeleteOpen} onOpenChange={(o) => !deleting && setConfirmDeleteOpen(o)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除 {checked.size} 份报告？</AlertDialogTitle>
            <AlertDialogDescription>
              将同时删除报告记录与磁盘文件（docx/pdf），此操作不可撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              className="bg-rose-600 text-white hover:bg-rose-700"
              disabled={deleting}
              onClick={(e) => {
                e.preventDefault();
                void deleteSelected();
              }}
            >
              {deleting ? "删除中…" : `确认删除 ${checked.size} 份`}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function ProjectNode(props: {
  project: ReportTreeProject;
  expanded: boolean;
  onToggleExpand: () => void;
  checked: Set<number>;
  checkState: (ids: number[]) => boolean | "indeterminate";
  onToggle: () => void;
  onPreview: (id: number) => void;
  onPreviewProject: () => void;
  onToggleTask: (ids: number[]) => void;
}) {
  const { project, expanded, onToggleExpand, checkState, onToggle, onPreview, onPreviewProject, onToggleTask } = props;
  const ids = projectReportIDs(project);
  return (
    <div>
      <div className="hover:bg-muted/60 flex items-center gap-1.5 rounded-md px-2 py-1.5">
        <button type="button" onClick={onToggleExpand} className="text-muted-foreground" aria-label="展开/收起">
          <ChevronRightIcon className={`size-4 transition-transform ${expanded ? "rotate-90" : ""}`} />
        </button>
        <Checkbox checked={checkState(ids)} onCheckedChange={onToggle} aria-label={`选择项目 ${project.name}`} />
        <button
          type="button"
          className="flex min-w-0 flex-1 items-center gap-1.5 text-left text-sm font-medium"
          onClick={onPreviewProject}
        >
          <FolderIcon className="text-muted-foreground size-4 shrink-0" />
          <span className="truncate">{project.name}</span>
        </button>
        <CountsBadges counts={project.counts} />
      </div>
      {expanded && (
        <div className="ml-4 border-l pl-1">
          {project.reports.length > 0 && (
            <div className="flex flex-col">
              {project.reports.map((r) => (
                <ReportLeaf
                  key={r.id}
                  report={r}
                  onPreview={onPreview}
                  selected={props.checked.has(r.id)}
                  onToggle={(id) => onToggleTask([id])}
                />
              ))}
            </div>
          )}
          {project.tasks.map((t) => (
            <TaskNode
              key={t.id}
              task={t}
              checked={props.checked}
              checkState={checkState}
              onToggle={() => onToggleTask(taskReportIDs(t))}
              onPreview={onPreview}
              onToggleReport={(id) => props.onToggleTask([id])}
            />
          ))}
          {ids.length === 0 && <p className="text-muted-foreground px-3 py-2 text-xs">该项目暂无报告</p>}
        </div>
      )}
    </div>
  );
}

function TaskNode(props: {
  task: ReportTreeTask;
  checked: Set<number>;
  checkState: (ids: number[]) => boolean | "indeterminate";
  onToggle: () => void;
  onPreview: (id: number) => void;
  onToggleReport: (id: number) => void;
}) {
  const { task, checked, checkState, onToggle, onPreview, onToggleReport } = props;
  const ids = taskReportIDs(task);
  return (
    <div>
      <div className="hover:bg-muted/60 flex items-center gap-1.5 rounded-md px-2 py-1.5">
        <span className="size-4" />
        <Checkbox checked={checkState(ids)} onCheckedChange={onToggle} aria-label={`选择任务 ${task.name}`} />
        <button
          type="button"
          className="min-w-0 flex-1 truncate text-left text-sm"
          onClick={() => ids.length > 0 && onPreview(ids[0])}
        >
          {task.name}
        </button>
        <CountsBadges counts={task.counts} />
      </div>
      <div className="ml-6 flex flex-col">
        {task.reports.map((r) => (
          <div
            key={r.id}
            role="button"
            tabIndex={0}
            onClick={() => onPreview(r.id)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") onPreview(r.id);
            }}
            className="hover:bg-muted flex cursor-pointer items-center gap-1.5 rounded px-2 py-1 text-left text-xs"
          >
            <Checkbox
              checked={checked.has(r.id)}
              onCheckedChange={() => onToggleReport(r.id)}
              onClick={(e) => e.stopPropagation()}
              aria-label={`选择报告 ${r.id}`}
            />
            <span className="text-muted-foreground">#{r.id}</span>
            <StatusPill status={r.status} />
            <span className="text-muted-foreground ml-auto">{fmtTime(r.created_at)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function CountsBadges({ counts }: { counts: ReportTreeProject["counts"] }) {
  return (
    <span className="flex shrink-0 items-center gap-1 text-[11px]">
      <Badge variant="secondary">{counts.total}</Badge>
      {counts.done > 0 && <span className="text-emerald-600">{counts.done}✓</span>}
      {counts.failed > 0 && <span className="text-rose-600">{counts.failed}✕</span>}
      {counts.running + counts.pending > 0 && <span className="text-sky-600">{counts.running + counts.pending}…</span>}
    </span>
  );
}

// ReportLeaf 仅用于项目级报告行（项目节点直属）。
function ReportLeaf({
  report,
  onPreview,
  selected,
  onToggle,
}: {
  report: ReportJob;
  onPreview: (id: number) => void;
  selected: boolean;
  onToggle?: (id: number) => void;
}) {
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onPreview(report.id)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") onPreview(report.id);
      }}
      className="hover:bg-muted flex cursor-pointer items-center gap-1.5 rounded px-2 py-1 text-left text-xs"
    >
      <Checkbox checked={selected} onCheckedChange={() => onToggle?.(report.id)} onClick={(e) => e.stopPropagation()} />
      <span className="text-muted-foreground">#{report.id}</span>
      <span>项目汇总</span>
      <StatusPill status={report.status} />
      <span className="text-muted-foreground ml-auto">{fmtTime(report.created_at)}</span>
    </div>
  );
}

function StatusPill({ status }: { status: ReportJob["status"] }) {
  const map: Record<ReportJob["status"], { label: string; cls: string }> = {
    pending: { label: "排队", cls: "bg-muted text-muted-foreground" },
    running: { label: "生成中", cls: "bg-sky-500/15 text-sky-600" },
    done: { label: "成功", cls: "bg-emerald-500/15 text-emerald-600" },
    failed: { label: "失败", cls: "bg-rose-500/15 text-rose-600" },
  };
  const m = map[status] ?? map.pending;
  return <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium ${m.cls}`}>{m.label}</span>;
}

function projectReportIDs(p: ReportTreeProject): number[] {
  const ids = p.reports.map((r) => r.id);
  for (const t of p.tasks) ids.push(...taskReportIDs(t));
  return ids;
}

function taskReportIDs(t: ReportTreeTask): number[] {
  return t.reports.map((r) => r.id);
}

function findReport(tree: ReportTree | null, id: number): ReportJob | null {
  if (!tree) return null;
  for (const p of tree.projects) {
    for (const r of p.reports) if (r.id === id) return r;
    for (const t of p.tasks) for (const r of t.reports) if (r.id === id) return r;
  }
  for (const t of tree.orphans) for (const r of t.reports) if (r.id === id) return r;
  return null;
}

function fallbackReport(id: number): ReportJob {
  return {
    id,
    scope: "task",
    locale: "zh-CN",
    format: "docx",
    status: "done",
    file_path: "",
    error: "",
    warning: "",
    finding_ids: [],
    created_at: "",
    started_at: "",
    finished_at: "",
  };
}

async function downloadOne(id: number) {
  return api.downloadReportJob(id);
}

function fmtTime(iso: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
