"use client";

// V9-DOCXJS：浏览器内 docx 渲染通道（docx-preview 纯前端解析 OOXML → HTML）。
// 不依赖服务端 LibreOffice/Office，作为 PDF 预览失败时的轻量兜底。
//
// 约束：
//   - docx-preview 体积大且依赖 DOM，只能客户端动态 import（静态导出安全）；
//   - >20MB 的 blob 不自动渲染（解析会卡死主线程），给出改用 PDF 的提示；
//   - 同一 blob 不重复解析（ref 缓存），卸载时清空容器并回收 docx-preview
//     为图片生成的 blob URL。

import * as React from "react";

import { FileWarningIcon } from "lucide-react";

import { Spinner } from "@/components/ui/spinner";
import { cn } from "@/lib/utils";

/** 自动渲染的 docx 体积上限：超过后建议改用服务端 PDF 预览。 */
const MAX_DOCX_BYTES = 20 * 1024 * 1024;

export interface DocxCanvasProps {
  /** docx 字节：Blob 或 ArrayBuffer；null=空闲。 */
  source: Blob | ArrayBuffer | null;
  className?: string;
  onError?: (err: Error) => void;
}

export function DocxCanvas({ source, className, onError }: DocxCanvasProps) {
  const hostRef = React.useRef<HTMLDivElement | null>(null);
  // 已解析的源引用：同一 blob 在 state 抖动时跳过重复 parse。
  const parsedRef = React.useRef<Blob | ArrayBuffer | null>(null);
  const onErrorRef = React.useRef(onError);
  onErrorRef.current = onError;

  const [busy, setBusy] = React.useState(false);
  const [tooLarge, setTooLarge] = React.useState(false);
  const [err, setErr] = React.useState("");

  React.useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    // docx-preview useBase64URL=false 时图片是 blob: URL，卸载/重渲前回收。
    const revokeImages = () => {
      for (const img of host.querySelectorAll<HTMLImageElement>('img[src^="blob:"]')) {
        try {
          URL.revokeObjectURL(img.src);
        } catch {
          /* 已释放/非本组件创建的 URL 忽略 */
        }
      }
    };

    if (!source) {
      host.innerHTML = "";
      parsedRef.current = null;
      setBusy(false);
      setTooLarge(false);
      setErr("");
      return;
    }

    const size = source instanceof Blob ? source.size : source.byteLength;
    if (size > MAX_DOCX_BYTES) {
      host.innerHTML = "";
      parsedRef.current = null;
      setBusy(false);
      setTooLarge(true);
      setErr("");
      return;
    }

    // 同一个 blob 已渲染过 → 不重复解析。
    if (parsedRef.current === source) return;
    parsedRef.current = source;

    let cancelled = false;
    let observer: ResizeObserver | null = null;
    setBusy(true);
    setTooLarge(false);
    setErr("");

    // 窄预览列里把 A4 页按容器宽度等比缩放（zoom 会参与布局，滚动高度正确）。
    // V9-UI2：先统一归零再量未缩放的页宽，避免 offsetWidth 已带 zoom 时反复
    // 相除导致缩放值越算越小。
    const fitWidth = () => {
      if (!hostRef.current) return;
      const pages = Array.from(hostRef.current.querySelectorAll<HTMLElement>("section.docx-view"));
      const first = pages[0];
      if (!first) return;
      for (const page of pages) page.style.zoom = "1";
      const pageWidth = first.offsetWidth;
      // 用页面所在容器的内容宽度（wrapper 有 px-2 内边距），否则页会多出
      // 一个内边距的横向溢出条。
      const wrap = first.parentElement;
      const wrapStyle = wrap ? window.getComputedStyle(wrap) : null;
      const avail = wrap
        ? wrap.clientWidth -
          (parseFloat(wrapStyle?.paddingLeft ?? "0") || 0) -
          (parseFloat(wrapStyle?.paddingRight ?? "0") || 0)
        : hostRef.current.clientWidth;
      if (!pageWidth || !avail) return;
      const zoom = Math.min(1, avail / pageWidth);
      for (const page of pages) page.style.zoom = String(zoom);
    };

    void (async () => {
      try {
        // 客户端动态 import：避免 docx-preview 进入 SSR/静态导出产物。
        const docx = await import("docx-preview");
        if (cancelled || !hostRef.current) return;
        host.innerHTML = "";
        await docx.renderAsync(source, host, undefined, {
          className: "docx-view",
          inWrapper: true,
          breakPages: true,
          // V9-UI2：保留页宽（A4 版面靠 zoom 等比缩放），表格固定宽度改由
          // CSS 归一为 100%——只 ignoreWidth 会把页边距留下、正文挤成窄条。
          ignoreWidth: false,
          ignoreLastRenderedPageBreak: true,
          useBase64URL: false,
        });
        if (cancelled) return;
        fitWidth();
        observer = new ResizeObserver(fitWidth);
        observer.observe(host);
        setBusy(false);
      } catch (e) {
        if (cancelled) return;
        parsedRef.current = null;
        const error = e instanceof Error ? e : new Error(String(e));
        setBusy(false);
        setErr(error.message);
        onErrorRef.current?.(error);
      }
    })();

    return () => {
      cancelled = true;
      observer?.disconnect();
      revokeImages();
      if (hostRef.current) hostRef.current.innerHTML = "";
    };
  }, [source]);

  const notice = tooLarge
    ? "文件过大，建议用 PDF 预览（超过 20 MB 不在浏览器内解析）"
    : err
      ? `浏览器渲染失败：${err}`
      : "";

  return (
    <div className={cn("relative flex h-full min-h-0 w-full flex-col overflow-hidden bg-white", className)}>
      <div
        ref={hostRef}
        className={cn(
          "docx-host min-h-0 flex-1 overflow-auto",
          "[&_.docx-view-wrapper]:bg-transparent [&_.docx-view-wrapper]:px-2 [&_.docx-view-wrapper]:py-2",
          "[&_.docx-view-wrapper>section.docx-view]:mx-auto [&_.docx-view-wrapper>section.docx-view]:my-2 [&_.docx-view-wrapper>section.docx-view]:shadow-md",
        )}
      />
      {notice ? (
        <div className="text-muted-foreground absolute inset-0 flex items-center justify-center gap-2 bg-white p-6 text-center text-sm">
          <FileWarningIcon className="size-4 shrink-0" />
          <span>{notice}</span>
        </div>
      ) : null}
      {busy && (
        <div className="bg-background/60 pointer-events-none absolute inset-0 flex items-center justify-center">
          <Spinner className="size-5" />
        </div>
      )}
    </div>
  );
}
