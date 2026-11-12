"use client";

// 发现详情·分步复现呈现（artex-hs T16(3/3)；V3-R4 证据区改版）。
//
// finding.reproduction 存在（T14 agent 逐字填写）→ 渲染结构化步骤卡片：
//   入口点/前置条件框 + 步骤 1..N 卡片（expected/proves 说明 + 逐字
//   request/response <pre> + 「查看流量」按钮〔exchange_id 命中时〕+ 证据
//   粘贴框〔V3-R4：大 dropzone 直接粘贴/拖拽，图卡点击灯箱放大+悬浮删除，
//   「重新生成」按请求响应重渲报文截图〕）；step_index 约定：1..N=步骤、
//   0=漏洞级。
// 父组件（detail 页）负责无 reproduction 时回退原 Markdown——本组件只做有
// 复现的呈现，保持单一职责。

import * as React from "react";

import { CameraIcon, EyeIcon, ImagePlusIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { CapturedTrafficViewer } from "@/components/traffic-evidence-viewer";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { Spinner } from "@/components/ui/spinner";
import { api } from "@/lib/api";
import type { FindingEvidenceImage, Reproduction } from "@/lib/types";
import { cn } from "@/lib/utils";

const MAX_IMAGE_BYTES = 8 << 20;
const IMAGE_EXT = /\.(png|jpe?g|gif|webp|bmp)$/i;

export function FindingReproView({
  findingId,
  repro,
  readOnly,
}: {
  findingId: string;
  repro: Reproduction;
  readOnly?: boolean;
}) {
  const [images, setImages] = React.useState<FindingEvidenceImage[]>([]);
  const [trafficId, setTrafficId] = React.useState<string | null>(null);

  const reload = React.useCallback(() => {
    api
      .findingEvidence(findingId)
      .then(setImages)
      .catch(() => setImages([]));
  }, [findingId]);
  React.useEffect(reload, [reload]);

  const byStep = React.useMemo(() => {
    const m = new Map<number, FindingEvidenceImage[]>();
    for (const img of images) {
      const list = m.get(img.step_index) ?? [];
      list.push(img);
      m.set(img.step_index, list);
    }
    return m;
  }, [images]);

  const upload = async (stepIndex: number, input: File | null | undefined) => {
    let file = input ?? null;
    if (!file) return;
    // 粘贴来源的文件名常为空/通用，补 .png 扩展过类型卡（类型以 MIME 为准）。
    const named = file.name && IMAGE_EXT.test(file.name)
      ? file
      : file.type.startsWith("image/")
        ? new File([file], (file.name || "paste") + ".png", { type: file.type })
        : null;
    if (!named || !IMAGE_EXT.test(named.name)) {
      toast.error("仅支持 png/jpg/gif/webp/bmp 图片");
      return;
    }
    file = named;
    if (file.size > MAX_IMAGE_BYTES) {
      toast.error("图片超过 8MB");
      return;
    }
    try {
      const created = await api.uploadFindingEvidence(findingId, file, stepIndex);
      setImages((cur) => [...cur, created].sort((a, b) => a.step_index - b.step_index || a.sort_order - b.sort_order || a.id - b.id));
      toast.success("证据图已上传");
    } catch (e) {
      toast.error(`上传失败：${(e as Error).message}`);
    }
  };

  const remove = async (img: FindingEvidenceImage) => {
    try {
      await api.deleteFindingEvidence(findingId, img.id);
      setImages((cur) => cur.filter((x) => x.id !== img.id));
    } catch (e) {
      toast.error(`删除失败：${(e as Error).message}`);
    }
  };

  // T22/V3-R4 报文一键补渲（幂等只覆盖 auto 行，手工截图不动）。V3 起按钮
  // 常驻「重新生成」：已有图也可点，后端替换旧 auto 行、重渲成功必须刷新。
  const [generatingStep, setGeneratingStep] = React.useState<number | null>(null);
  const generateShot = async (stepIndex: number) => {
    if (generatingStep != null) return;
    setGeneratingStep(stepIndex);
    try {
      const r = await api.autoGenerateEvidence(findingId, stepIndex);
      if (r.rendered > 0) toast.success(`步骤 ${stepIndex} 报文截图已重新生成`);
      else toast.warning("该步没有可渲染的请求/响应报文");
      reload();
    } catch (e) {
      toast.error(`生成截图失败：${(e as Error).message}`);
    } finally {
      setGeneratingStep(null);
    }
  };

  const steps = repro.steps ?? [];

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">复现过程</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {(repro.entry_point || (repro.prerequisites?.length ?? 0) > 0) && (
          <div className="rounded-md border bg-muted/30 p-3 text-sm">
            {repro.entry_point && (
              <p className="mb-1">
                <span className="text-muted-foreground">入口点：</span>
                <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs break-all">{repro.entry_point}</code>
              </p>
            )}
            {(repro.prerequisites?.length ?? 0) > 0 && (
              <p className="mb-1">
                <span className="text-muted-foreground">前置条件：</span>
                {repro.prerequisites!.join("；")}
              </p>
            )}
            {repro.provenance && (
              <p className="text-xs text-muted-foreground">来源：{repro.provenance}</p>
            )}
          </div>
        )}

        {steps.length === 0 && <p className="text-muted-foreground text-sm">（无复现步骤）</p>}

        {steps.map((st, i) => {
          const stepNo = i + 1;
          return (
            <div key={stepNo} className="rounded-md border">
              <div className="bg-muted/40 flex items-center gap-2 border-b px-3 py-1.5 text-xs font-medium">
                步骤 {stepNo}
                {st.exchange_id && (
                  <Button variant="outline" size="xs" className="ml-auto" onClick={() => setTrafficId(st.exchange_id!)}>
                    <EyeIcon /> 查看流量
                  </Button>
                )}
              </div>
              <div className="flex flex-col gap-2 p-3">
                {st.expected && <p className="text-muted-foreground text-sm">预期：{st.expected}</p>}
                {st.proves && <p className="text-sm">证明：{st.proves}</p>}
                {st.request && <Packet title="请求" text={st.request} />}
                {st.response && <Packet title="响应" text={st.response} />}
                {/* V3-R4：证据区=大粘贴框（粘贴/拖拽上传+悬浮删除+点击灯箱
                    放大）；「重新生成」按该步请求/响应报文重渲截图（幂等只
                    覆盖 auto 行）。readOnly（继承漏洞）隐藏全部编辑
                    affordances（含重新生成），保持纯只读。 */}
                <EvidenceStrip
                  images={byStep.get(stepNo) ?? []}
                  editable={!readOnly}
                  onUpload={(f) => void upload(stepNo, f)}
                  onRemove={(img) => void remove(img)}
                  onGenerate={st.request || st.response ? () => void generateShot(stepNo) : undefined}
                  generating={generatingStep === stepNo}
                />
              </div>
            </div>
          );
        })}

        {/* 漏洞级证据（step_index=0）：不属于任何单步的截图（无报文可渲，
            不提供重新生成）。 */}
        <div className="rounded-md border border-dashed p-3">
          <div className="mb-1 text-xs font-medium text-muted-foreground">漏洞级截图</div>
          <EvidenceStrip
            images={byStep.get(0) ?? []}
            editable={!readOnly}
            onUpload={(f) => void upload(0, f)}
            onRemove={(img) => void remove(img)}
          />
        </div>
      </CardContent>

      <CapturedTrafficViewer id={trafficId} onClose={() => setTrafficId(null)} />
    </Card>
  );
}

// Packet 逐字呈现 request/response：等宽 pre，不截断不重排（T14 红线：内容
// 本身已要求逐字真实，前端再原样展示）。
function Packet({ title, text }: { title: string; text: string }) {
  return (
    <div>
      <div className="text-muted-foreground mb-0.5 text-xs">{title}</div>
      <pre className="bg-muted/40 max-h-72 overflow-auto rounded-md border p-2 font-mono text-xs whitespace-pre-wrap break-all">{text}</pre>
    </div>
  );
}

function EvidenceStrip({
  images,
  editable,
  onUpload,
  onRemove,
  onGenerate,
  generating,
}: {
  images: FindingEvidenceImage[];
  // V3-R4：readOnly（inherited）时 editable=false——粘贴框退化为「无截图」
  // 徽标/只读图卡，删除、重新生成等编辑 affordances 全部隐藏。
  editable?: boolean;
  onUpload?: (file: File | null | undefined) => void;
  onRemove?: (img: FindingEvidenceImage) => void;
  // 该步有报文时显示「重新生成」：POST auto-generate?step_index=N，后端幂等
  // 只覆盖 auto 行、手工行不动；成功后父组件 reload 刷新本步图。
  onGenerate?: () => void;
  generating?: boolean;
}) {
  // 灯箱：点击图卡全屏放大预览（Dialog 大尺寸 iframe 位用 <img> 代替）。
  const [zoom, setZoom] = React.useState<FindingEvidenceImage | null>(null);
  // 拖拽悬停高亮（dragenter/leave 冒泡计数，避免子元素抖动）。
  const dragDepth = React.useRef(0);
  const [dragOver, setDragOver] = React.useState(false);

  // 粘贴截图：dropzone 聚焦（tabIndex=0）后 Ctrl+V 取剪贴板图片直传。
  const handlePaste = (e: React.ClipboardEvent) => {
    if (!editable || !onUpload) return;
    const item = Array.from(e.clipboardData?.items ?? []).find((i) => i.type.startsWith("image/"));
    const file = item?.getAsFile();
    if (file) {
      e.preventDefault();
      onUpload(file);
    }
  };
  // 拖拽文件上传（与粘贴同通道：走 onUpload，source=upload/paste 语义不变）。
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    dragDepth.current = 0;
    setDragOver(false);
    if (!editable || !onUpload) return;
    const file = Array.from(e.dataTransfer.files ?? []).find((f) => f.type.startsWith("image/") || /\.(png|jpe?g|gif|webp|bmp)$/i.test(f.name));
    if (file) onUpload(file);
  };

  // 隐藏 file input 仅作拖拽外的兜底不需要——点击框体本身=聚焦供 Ctrl+V，
  // 本地选文件入口按用户要求已移除（拖拽/粘贴即上传通道）。
  const showDropzone = editable && images.length === 0;

  return (
    <div className="flex flex-col gap-2">
      {images.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          {images.map((img) => (
            <div key={img.id} className="group relative">
              {/* 同源 artex_token cookie 自动随行过 requireAuth（auth.go 支持
                  cookie 取值），无需拼 ?token=。点击=灯箱放大预览。 */}
              <button
                type="button"
                onClick={() => setZoom(img)}
                className="block cursor-zoom-in"
                title="点击放大"
                aria-label={`放大查看截图：${img.caption || "证据截图"}`}
              >
                <img src={img.url} alt={img.caption || "证据截图"} className="border-primary/30 hover:border-primary h-24 w-36 rounded-md border object-cover" />
              </button>
              {img.source === "auto" && (
                <span className="bg-sky-500/90 text-white absolute bottom-0.5 left-0.5 rounded px-1 py-px text-[10px] leading-none">
                  自动生成
                </span>
              )}
              {editable && onRemove && (
                <button
                  type="button"
                  onClick={() => onRemove(img)}
                  className="bg-destructive text-destructive-foreground absolute -top-1.5 -right-1.5 hidden rounded-full p-0.5 group-hover:block"
                  title="删除证据图"
                >
                  <Trash2Icon className="size-3" />
                </button>
              )}
            </div>
          ))}
          {/* 有图但框体空间已用 flex-wrap 吸收；追加一张待贴的迷你占位框，
              让「直接粘贴」入口在有图时依然可见可用。 */}
          {editable && (
            <PasteDropzone compact dragOver={dragOver} onSetDragOver={setDragOver} dragDepth={dragDepth} onPaste={handlePaste} onDrop={handleDrop} />
          )}
        </div>
      )}

      {showDropzone && (
        <PasteDropzone dragOver={dragOver} onSetDragOver={setDragOver} dragDepth={dragDepth} onPaste={handlePaste} onDrop={handleDrop} />
      )}

      {(onGenerate || images.length === 0) && (
        <div className="flex items-center gap-2">
          {editable && onGenerate && (
            <Button variant="outline" size="xs" onClick={onGenerate} disabled={generating}>
              {generating ? <Spinner className="size-3" /> : <CameraIcon />} 重新生成
            </Button>
          )}
          {images.length === 0 && !editable && <Badge variant="outline">无截图</Badge>}
        </div>
      )}

      {/* 灯箱：近全屏预览，Esc/点遮罩关闭（复用 Dialog 原语）。 */}
      <Dialog open={zoom !== null} onOpenChange={(o) => !o && setZoom(null)}>
        <DialogContent
          className="max-h-[92dvh] w-[92vw] max-w-[1400px] gap-2 overflow-auto sm:max-w-[1400px]"
          aria-label="截图预览"
        >
          <DialogTitle className="text-sm text-muted-foreground truncate pr-8">
            {zoom?.caption || "证据截图"}
          </DialogTitle>
          {zoom && (
            // 放大后保持原比例：宽自适应、超高滚动（不裁剪报文全文）。
            <img src={zoom.url} alt={zoom.caption || "证据截图"} className="mx-auto w-full rounded-md border object-contain" />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

// PasteDropzone V3-R4 截图粘贴框：输入框样式的虚线大 dropzone——点击聚焦后
// Ctrl+V 粘贴、拖文件进来即上传；无任何说明行，占位只有淡色图标+「粘贴截图」。
function PasteDropzone({
  compact,
  dragOver,
  onSetDragOver,
  dragDepth,
  onPaste,
  onDrop,
}: {
  compact?: boolean;
  dragOver: boolean;
  onSetDragOver: (v: boolean) => void;
  dragDepth: React.MutableRefObject<number>;
  onPaste: (e: React.ClipboardEvent) => void;
  onDrop: (e: React.DragEvent) => void;
}) {
  return (
    <div
      role="button"
      tabIndex={0}
      aria-label="截图粘贴框：点击聚焦后 Ctrl+V 粘贴，或拖拽图片文件到此处"
      onPaste={onPaste}
      onDragEnter={(e) => {
        e.preventDefault();
        dragDepth.current += 1;
        onSetDragOver(true);
      }}
      onDragOver={(e) => e.preventDefault()}
      onDragLeave={(e) => {
        e.preventDefault();
        dragDepth.current -= 1;
        if (dragDepth.current <= 0) onSetDragOver(false);
      }}
      onDrop={onDrop}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          (e.currentTarget as HTMLElement).focus();
        }
      }}
      className={cn(
        "flex items-center justify-center gap-2 rounded-md border border-dashed text-muted-foreground/60 outline-none transition-colors",
        "hover:border-primary/50 focus-visible:border-primary focus-visible:ring-2 focus-visible:ring-ring",
        dragOver && "border-primary bg-primary/5 text-primary",
        compact ? "h-24 w-36" : "min-h-24 w-full",
      )}
    >
      <ImagePlusIcon className="size-5" />
      <span className="text-xs">粘贴截图</span>
    </div>
  );
}
