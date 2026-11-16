"use client";

// 报告中心·实时预览列（artex-hs T21；V3-R5 默认完整显示）。iframe 展示
// render-draft(format=html) 的产物。防抖 800ms + AbortController 取消
// in-flight（连改只发最后一次）。
//
// V3-R5：预览列默认即全列高（父 Card 提供 lg 视口高，见 report/page.tsx
// 中列 `lg:h-[calc(100dvh-10rem)]`；本组件根节点 h-full + iframe flex-1
// min-h-0，iframe 内部自然滚动到全文，不再被压成小块），另在工具条右上角
// 提供「全屏查看」=近全屏 Dialog iframe（Esc/遮罩关）。无需用户先开开关。
//
// 数据源三选一（设计 §1.2A/D）：
//   demo   = 内置样例（后端 fixture 旁路，跳任务取数与伪资产红线）
//   task   = 选真实任务（buildReportInput 现链路）
//   project= 选真实项目
// 模板一律走 **inline draft**（未保存的编辑态直接渲染=对话所见即预览），
// 保存与否不影响预览内容。
//
// 「docx 交付预览」= 显式重路径：同步渲染下载（iframe 装不了 docx，下载即
// 交付所见）。HTML 预览顶部固定标注「结构预览，交付以 docx 为准」（§1.2C）。

import * as React from "react";

import { DownloadIcon, EyeIcon, MaximizeIcon, RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Spinner } from "@/components/ui/spinner";
import { api } from "@/lib/api";
import type { ReportDraftInput, ReportTemplateInput, Task } from "@/lib/types";

export type PreviewSource = "demo" | "task" | "project";

export interface PreviewDebugForm {
  task_id: string;
  project_id: string;
  locale: string;
}

export function TemplatePreview(props: {
  draft: ReportTemplateInput | null;
  source: PreviewSource;
  setSource: (s: PreviewSource) => void;
  form: PreviewDebugForm;
  setForm: React.Dispatch<React.SetStateAction<PreviewDebugForm>>;
  tasks: Task[];
  projects: { id: number; name: string }[];
  // 对话回合计数：chat 应用补丁后 +1 → 跳过防抖立即重渲。
  chatTick: number;
}) {
  const { draft, source, setSource, form, setForm, tasks, projects, chatTick } = props;

  const [url, setUrl] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState("");
  const [warning, setWarning] = React.useState("");
  // V3-R5：右上角「全屏查看」=近全屏 Dialog iframe（默认预览列已全列高，
  // 这里再给一个更大视口；Esc/遮罩关）。
  const [fullscreen, setFullscreen] = React.useState(false);
  const abortRef = React.useRef<AbortController | null>(null);
  const urlRef = React.useRef<string | null>(null);
  const timerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = React.useRef(true);

  // 卸载清理：取消在途请求 + 回收 blob URL。
  React.useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      abortRef.current?.abort();
      if (urlRef.current) URL.revokeObjectURL(urlRef.current);
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  const targetReady = source === "demo" || (source === "task" ? !!form.task_id : !!form.project_id);

  const buildInput = React.useCallback((): ReportDraftInput | null => {
    if (!draft) return null;
    if (source === "demo") {
      return { scope: "task", task_id: 0, demo: true, template: draft, locale: form.locale || undefined, format: "html" };
    }
    if (!targetReady) return null;
    return {
      scope: source === "project" ? "project" : "task",
      task_id: source === "task" ? Number(form.task_id) : undefined,
      project_id: source === "project" ? Number(form.project_id) : undefined,
      template: draft,
      locale: form.locale || undefined,
      format: "html",
    };
  }, [draft, source, form.task_id, form.project_id, form.locale, targetReady]);

  const doRender = React.useCallback(async () => {
    const input = buildInput();
    if (!input) return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setBusy(true);
    try {
      const { blob, warning: warn } = await api.renderReportPreview(input, ac.signal);
      if (!mountedRef.current || ac.signal.aborted) return;
      const next = URL.createObjectURL(blob);
      if (urlRef.current) URL.revokeObjectURL(urlRef.current);
      urlRef.current = next;
      setUrl(next);
      setWarning(warn);
      setErr("");
    } catch (e) {
      if ((e as Error)?.name === "AbortError") return;
      if (mountedRef.current) setErr((e as Error).message);
    } finally {
      if (mountedRef.current && abortRef.current === ac) setBusy(false);
    }
  }, [buildInput]);

  // 编辑/切源/对话回合 → 800ms 防抖重渲；目标没选就不发（保留上一份内容）。
  React.useEffect(() => {
    if (!targetReady || !draft) return;
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => void doRender(), 800);
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [doRender, targetReady, chatTick, draft]);

  // docx 交付预览=同步渲染下载（inline 草稿与 html 预览同源内容；子进程
  // 失败 502 如实 toast）。
  const renderDocx = async () => {
    const input = buildInput();
    if (!input) return;
    try {
      const { filename, warning: warn } = await api.renderReportDraft({ ...input, format: "docx" });
      toast.success(`交付小样已下载：${filename}`);
      if (warn) toast.warning(warn, { duration: 8000 });
    } catch (e) {
      toast.error(`docx 渲染失败：${(e as Error).message}`);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5">
          <EyeIcon className="text-muted-foreground size-4" />
          <span className="text-sm font-medium">实时预览</span>
        </div>
        <NativeSelect
          className="w-28"
          value={source}
          onChange={(e) => setSource(e.target.value as PreviewSource)}
          aria-label="预览数据源"
        >
          <NativeSelectOption value="demo">样例数据</NativeSelectOption>
          <NativeSelectOption value="task">选任务</NativeSelectOption>
          <NativeSelectOption value="project">选项目</NativeSelectOption>
        </NativeSelect>
        {source === "task" && (
          <NativeSelect className="w-40" value={form.task_id} onChange={(e) => setForm((f) => ({ ...f, task_id: e.target.value }))} aria-label="任务">
            <NativeSelectOption value="">— 选择任务 —</NativeSelectOption>
            {tasks.map((t) => (
              <NativeSelectOption key={t.id} value={t.id}>
                {t.name || t.description.slice(0, 30)}
              </NativeSelectOption>
            ))}
          </NativeSelect>
        )}
        {source === "project" && (
          <NativeSelect className="w-40" value={form.project_id} onChange={(e) => setForm((f) => ({ ...f, project_id: e.target.value }))} aria-label="项目">
            <NativeSelectOption value="">— 选择项目 —</NativeSelectOption>
            {projects.map((p) => (
              <NativeSelectOption key={p.id} value={String(p.id)}>
                {p.name}
              </NativeSelectOption>
            ))}
          </NativeSelect>
        )}
        <div className="ml-auto flex items-center gap-1.5">
          {busy && <Spinner className="size-4" />}
          <Button variant="outline" size="sm" onClick={() => void doRender()} disabled={busy || !targetReady}>
            <RefreshCwIcon /> 预览渲染
          </Button>
          <Button variant="outline" size="sm" onClick={() => void renderDocx()} disabled={!targetReady}>
            <DownloadIcon /> docx 交付预览
          </Button>
          {/* V3-R5：全屏看渲染产物（blob URL 同一份，无需重渲）。 */}
          <Button variant="outline" size="sm" onClick={() => setFullscreen(true)} disabled={!url}>
            <MaximizeIcon /> 全屏查看
          </Button>
        </div>
      </div>

      <div className="flex items-center gap-2 text-xs">
        {/* R2：数据来源必须显式标注，避免「示例数据」与真实任务混淆。 */}
        <Badge variant="secondary">
          {source === "demo" ? "示例数据" : source === "task" ? `任务#${form.task_id || "?"}` : `项目#${form.project_id || "?"}`}
        </Badge>
        <Badge variant="outline" className="border-amber-400 text-amber-600">
          结构预览，交付以 docx 为准
        </Badge>
        {warning && (
          <span className="text-amber-600 truncate" title={warning}>
            {warning}
          </span>
        )}
      </div>

      {/* V3-R5：预览区吃满父列剩余高度（父 Card 在 lg 下给视口高，见
          report/page.tsx 中列），iframe 内部自然滚动到全文=默认完整显示。 */}
      <div className="relative min-h-0 flex-1 overflow-hidden rounded-lg border bg-white">
        {err ? (
          <div className="text-muted-foreground flex h-full items-center justify-center p-6 text-center text-sm">
            预览失败：{err}
          </div>
        ) : !targetReady ? (
          // 进到这里必是 task/project 源（demo 恒 ready），无需再分。
          <div className="text-muted-foreground flex h-full items-center justify-center p-6 text-center text-sm">
            选择任务或项目后自动预览。
          </div>
        ) : url ? (
          // sandbox=allow-same-origin：渲染产物是我们自己 Go 端转义过的静态
          // HTML（无脚本）；禁 script 双保险防 XSS 直通 iframe。
          <iframe title="报告预览" src={url} className="size-full" sandbox="allow-same-origin" />
        ) : (
          <div className="flex h-full items-center justify-center">
            <Spinner />
          </div>
        )}
      </div>

      {/* 全屏查看：近全屏 Dialog + 同一 blob URL iframe，Esc/遮罩关。 */}
      <Dialog open={fullscreen} onOpenChange={setFullscreen}>
        <DialogContent
          className="flex h-[94dvh] w-[96vw] max-w-none flex-col gap-2 overflow-hidden sm:max-w-none"
          aria-label="报告预览·全屏"
        >
          <DialogTitle className="text-sm text-muted-foreground">报告预览（全屏）</DialogTitle>
          {url && (
            <iframe title="报告预览（全屏）" src={url} className="min-h-0 w-full flex-1 rounded-md border bg-white" sandbox="allow-same-origin" />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
