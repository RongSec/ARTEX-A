"use client";

// 报告中心·实时预览列（artex-hs T21；V3-R5 默认完整显示）。防抖 800ms +
// AbortController 取消 in-flight（连改只发最后一次）。
//
// V3-R5：预览列默认即全列高（父 Card 提供 lg 视口高，见 report/page.tsx
// 中列 `lg:h-[calc(100dvh-10rem)]`；本组件根节点 h-full + iframe flex-1
// min-h-0，iframe 内部自然滚动到全文，不再被压成小块），另在工具条右上角
// 提供「全屏查看」=近全屏 Dialog iframe（Esc/遮罩关）。无需用户先开开关。
//
// V9-RPT2：预览改为 **PDF 优先**——服务端把同一次 docx 渲染产物交给
// LibreOffice 转 PDF，iframe 内嵌即「与最终 docx 一致」。
//
// V9-DOCXJS：新增「浏览器内 docx 渲染」轻量通道（docx-preview 纯前端解析）。
// 三选模式：自动（默认，PDF 失败/无能力时回退浏览器）/ 精确（仅 PDF）/
// 快速（仅浏览器）。回退数据源 = render-draft(format=docx) 的同一份 docx。
//
// 数据源三选一（设计 §1.2A/D）：
//   demo   = 内置样例（后端 fixture 旁路，跳任务取数与伪资产红线）
//   task   = 选真实任务（buildReportInput 现链路）
//   project= 选真实项目
// 模板一律走 **inline draft**（未保存的编辑态直接渲染=对话所见即预览），
// 保存与否不影响预览内容。
//
// 「docx 交付预览」= 同步渲染下载（交付所见）。

import * as React from "react";

import { DownloadIcon, EyeIcon, MaximizeIcon, RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";

import { DocxCanvas } from "@/components/docx-canvas";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Spinner } from "@/components/ui/spinner";
import { api } from "@/lib/api";
import type { PreviewCapability, ReportDraftInput, ReportTemplateInput, Task } from "@/lib/types";

export type PreviewSource = "demo" | "task" | "project";

// V9-DOCXJS：预览通道三选。auto=PDF 优先、失败回退浏览器；exact=仅 PDF；
// fast=仅浏览器内 docx（不依赖服务端 Office 能力）。
export type PreviewMode = "auto" | "exact" | "fast";

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
  // V9-DOCXJS：浏览器渲染通道直接持有 docx 字节交 DocxCanvas。
  const [docxBlob, setDocxBlob] = React.useState<Blob | null>(null);
  const [kind, setKind] = React.useState<"pdf" | "docx" | null>(null);
  const [mode, setMode] = React.useState<PreviewMode>("auto");
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState("");
  const [warning, setWarning] = React.useState("");
  const [fidelity, setFidelity] = React.useState<"exact" | "approximate">("approximate");
  const [capability, setCapability] = React.useState<PreviewCapability | null>(null);
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

  // LibreOffice 能力探测：决定预览走 PDF 还是 HTML 近似通道。
  React.useEffect(() => {
    api
      .previewCapability()
      .then(setCapability)
      .catch(() => setCapability({ pdf: false, engine: "none", version: "" }));
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
    const applyPDF = (blob: Blob, warn: string, f: "exact" | "approximate") => {
      if (!mountedRef.current || ac.signal.aborted) return;
      const next = URL.createObjectURL(blob);
      if (urlRef.current) URL.revokeObjectURL(urlRef.current);
      urlRef.current = next;
      setUrl(next);
      setDocxBlob(null);
      setKind("pdf");
      setWarning(warn);
      setFidelity(f);
      setErr("");
    };
    const applyDocx = (blob: Blob, warn: string) => {
      if (!mountedRef.current || ac.signal.aborted) return;
      // 浏览器渲染不占 blob URL：直接交字节给 DocxCanvas。
      if (urlRef.current) {
        URL.revokeObjectURL(urlRef.current);
        urlRef.current = null;
      }
      setUrl(null);
      setDocxBlob(blob);
      setKind("docx");
      setWarning(warn);
      setFidelity("approximate");
      setErr("");
    };
    try {
      // fast=直接浏览器渲染；auto/exact 先走 PDF（能力明确为 false 时跳过）。
      if (mode !== "fast") {
        if (capability?.pdf === false) {
          if (mode === "exact") {
            setErr("未检测到 PDF 渲染能力（LibreOffice），请切换到「快速（浏览器）」预览。");
            return;
          }
        } else {
          try {
            const { blob, warning: warn, fidelity: f } = await api.renderReportPreviewPDF(input, ac.signal);
            applyPDF(blob, warn, f);
            return;
          } catch (e) {
            if ((e as Error)?.name === "AbortError") return;
            // 精确模式只认 PDF，失败如实报错；自动模式回退浏览器渲染。
            if (mode === "exact") {
              if (mountedRef.current) setErr((e as Error).message);
              return;
            }
            toast.warning(`PDF 预览不可用，已回退浏览器渲染：${(e as Error).message}`, { duration: 6000 });
          }
        }
      }
      // 浏览器渲染：同一份 docx（render-draft format=docx），纯前端解析。
      const { blob, warning: warn } = await api.renderReportDocxBlob(input, ac.signal);
      applyDocx(blob, warn);
    } catch (e) {
      if ((e as Error)?.name === "AbortError") return;
      if (mountedRef.current) setErr((e as Error).message);
    } finally {
      if (mountedRef.current && abortRef.current === ac) setBusy(false);
    }
  }, [buildInput, capability?.pdf, mode]);

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
        {/* V9-DOCXJS：预览通道三选（默认自动=PDF 优先，失败回退浏览器）。 */}
        <NativeSelect
          className="w-36"
          value={mode}
          onChange={(e) => setMode(e.target.value as PreviewMode)}
          aria-label="预览模式"
        >
          <NativeSelectOption value="auto">自动</NativeSelectOption>
          <NativeSelectOption value="exact">精确（PDF）</NativeSelectOption>
          <NativeSelectOption value="fast">快速（浏览器）</NativeSelectOption>
        </NativeSelect>
        <div className="ml-auto flex items-center gap-1.5">
          {busy && <Spinner className="size-4" />}
          <Button variant="outline" size="sm" onClick={() => void doRender()} disabled={busy || !targetReady}>
            <RefreshCwIcon /> 预览渲染
          </Button>
          <Button variant="outline" size="sm" onClick={() => void renderDocx()} disabled={!targetReady}>
            <DownloadIcon /> docx 交付预览
          </Button>
          {/* V3-R5：全屏看渲染产物（PDF blob URL / docx 字节同一份，无需重渲）。 */}
          <Button variant="outline" size="sm" onClick={() => setFullscreen(true)} disabled={!url && !docxBlob}>
            <MaximizeIcon /> 全屏查看
          </Button>
        </div>
      </div>

      <div className="flex items-center gap-2 text-xs">
        {/* R2：数据来源必须显式标注，避免「示例数据」与真实任务混淆。 */}
        <Badge variant="secondary">
          {source === "demo" ? "示例数据" : source === "task" ? `任务#${form.task_id || "?"}` : `项目#${form.project_id || "?"}`}
        </Badge>
        <Badge
          variant="outline"
          className={fidelity === "exact" ? "border-emerald-500 text-emerald-600" : "border-amber-400 text-amber-600"}
        >
          {fidelity === "exact"
            ? "与最终 docx 一致（PDF 渲染）"
            : kind === "docx"
              ? "浏览器渲染（同一份 docx，版式近似）"
              : "近似预览"}
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
        ) : kind === "docx" && docxBlob ? (
          // V9-DOCXJS：纯前端 docx 渲染；失败时组件内提示，不白屏。
          <DocxCanvas
            source={docxBlob}
            onError={(e) => toast.error(`浏览器渲染 docx 失败：${e.message}`)}
          />
        ) : kind === "pdf" && url ? (
          // PDF 交浏览器内置阅读器（加 sandbox 会挡住 viewer）。
          <iframe title="报告预览" src={url} className="size-full" />
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
          {kind === "docx" && docxBlob ? (
            <DocxCanvas
              source={docxBlob}
              className="min-h-0 flex-1 rounded-md border"
              onError={(e) => toast.error(`浏览器渲染 docx 失败：${e.message}`)}
            />
          ) : kind === "pdf" && url ? (
            <iframe title="报告预览（全屏）" src={url} className="min-h-0 w-full flex-1 rounded-md border bg-white" />
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
