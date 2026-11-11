"use client";

// 发现详情·分步复现呈现（artex-hs T16(3/3)）。
//
// finding.reproduction 存在（T14 agent 逐字填写）→ 渲染结构化步骤卡片：
//   入口点/前置条件框 + 步骤 1..N 卡片（expected/proves 说明 + 逐字
//   request/response <pre> + 「查看流量」按钮〔exchange_id 命中时〕+ 证据条
//   〔粘贴/上传截图，按 step_index〕）；step_index 约定：1..N=步骤、0=漏洞级。
// 父组件（detail 页）负责无 reproduction 时回退原 Markdown——本组件只做有
// 复现的呈现，保持单一职责。

import * as React from "react";

import { EyeIcon, ImagePlusIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { CapturedTrafficViewer } from "@/components/traffic-evidence-viewer";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { FindingEvidenceImage, Reproduction } from "@/lib/types";

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
                <EvidenceStrip images={byStep.get(stepNo) ?? []} onUpload={!readOnly ? (f) => void upload(stepNo, f) : undefined} onRemove={!readOnly ? (img) => void remove(img) : undefined} />
              </div>
            </div>
          );
        })}

        {/* 漏洞级证据（step_index=0）：不属于任何单步的截图 */}
        <div className="rounded-md border border-dashed p-3">
          <div className="mb-1 text-xs font-medium text-muted-foreground">漏洞级截图</div>
          <EvidenceStrip images={byStep.get(0) ?? []} onUpload={!readOnly ? (f) => void upload(0, f) : undefined} onRemove={!readOnly ? (img) => void remove(img) : undefined} />
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
  onUpload,
  onRemove,
}: {
  images: FindingEvidenceImage[];
  onUpload?: (file: File | null | undefined) => void;
  onRemove?: (img: FindingEvidenceImage) => void;
}) {
  // 粘贴截图：证据条聚焦（或内部控件获得焦点）时 Ctrl+V 取剪贴板图片直传。
  const handlePaste = (e: React.ClipboardEvent) => {
    if (!onUpload) return;
    const item = Array.from(e.clipboardData?.items ?? []).find((i) => i.type.startsWith("image/"));
    const file = item?.getAsFile();
    if (file) {
      e.preventDefault();
      onUpload(file);
    }
  };
  // 每个步骤条一个实例，文件输入 ref 自管（点击「截图」= 打开系统选图框）。
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  return (
    <div className="flex flex-wrap items-center gap-2" onPaste={handlePaste}>
      {onUpload && <span className="text-muted-foreground/70 text-[11px]">点击「截图」选文件或聚焦后 Ctrl+V 粘贴</span>}
      {images.map((img) => (
        <div key={img.id} className="group relative">
          {/* 同源 artex_token cookie 自动随行过 requireAuth（auth.go 支持
              cookie 取值），无需拼 ?token=。 */}
          <img src={img.url} alt={img.caption || "证据截图"} className="border-primary/30 hover:border-primary h-20 w-28 rounded-md border object-cover" title={img.caption} />
          {onRemove && (
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
      {onUpload && (
        <>
          <input ref={inputRef} type="file" accept="image/png,image/jpeg,image/gif,image/webp,image/bmp" className="hidden" onChange={(e) => { onUpload(e.target.files?.[0]); e.target.value = ""; }} />
          <Button variant="outline" size="xs" onClick={() => inputRef.current?.click()}>
            <ImagePlusIcon /> 截图
          </Button>
        </>
      )}
      {images.length === 0 && !onUpload && <Badge variant="outline">无截图</Badge>}
    </div>
  );
}
