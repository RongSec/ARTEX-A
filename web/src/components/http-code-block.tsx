"use client";
import * as React from "react";

import { CheckIcon, CopyIcon, SearchIcon, WrapTextIcon, XIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn, copyText } from "@/lib/utils";

function statusTone(status: number) {
  if (status >= 500) return "text-red-500";
  if (status >= 400) return "text-amber-500";
  if (status >= 300) return "text-blue-500";
  if (status >= 200) return "text-emerald-500";
  return "text-muted-foreground";
}

// markText 把 segment 内所有大小写不敏感的 query 命中包进 <mark>（搜索高亮，
// T16(3/3) 报文查看器）。无 query/无命中 → 原字符串返回，零开销路径。
// 用 React key 前缀 segKey 区分同组件多次调用产生的片段，防 reconciliation 错位。
function markText(seg: string, query: string, segKey: string): React.ReactNode {
  if (!query || !seg) return seg;
  const lower = seg.toLowerCase();
  const q = query.toLowerCase();
  const first = lower.indexOf(q);
  if (first < 0) return seg;
  const parts: React.ReactNode[] = [];
  let cursor = 0;
  let i = first;
  let n = 0;
  for (;;) {
    if (i > cursor) parts.push(seg.slice(cursor, i));
    parts.push(
      <mark className="rounded-sm bg-amber-300/45 text-inherit dark:bg-amber-400/35" key={`${segKey}-m${n++}`}>
        {seg.slice(i, i + q.length)}
      </mark>,
    );
    cursor = i + q.length;
    i = lower.indexOf(q, cursor);
    if (i < 0) break;
  }
  if (cursor < seg.length) parts.push(seg.slice(cursor));
  return parts;
}

function StartLine({ line, query }: { line: string; query?: string }) {
  const q = query ?? "";
  const response = /^(HTTP\/\S+)(\s+)(\d{3})(.*)$/.exec(line);
  if (response) {
    return (
      <>
        <span className="text-muted-foreground">{markText(response[1], q, "rs1")}</span>
        {response[2]}
        <span className={statusTone(Number(response[3]))}>{markText(response[3], q, "rs3")}</span>
        {markText(response[4], q, "rs4")}
      </>
    );
  }

  const request = /^([A-Z]+)(\s+)(\S+)(\s+)(HTTP\/\S+)$/.exec(line);
  if (request) {
    return (
      <>
        <span className="font-semibold text-primary">{markText(request[1], q, "rq1")}</span>
        {request[2]}
        <span className="text-chart-2">{markText(request[3], q, "rq3")}</span>
        {request[4]}
        <span className="text-muted-foreground">{markText(request[5], q, "rq5")}</span>
      </>
    );
  }

  return markText(line, q, "rl");
}

function HeaderLine({ line, query }: { line: string; query?: string }) {
  const q = query ?? "";
  const separator = line.indexOf(":");
  if (separator <= 0) return markText(line, q, "h0");
  return (
    <>
      <span className="text-primary">{markText(line.slice(0, separator), q, "h1")}</span>
      <span className="text-muted-foreground">:</span>
      <span className="text-chart-2">{markText(line.slice(separator + 1), q, "h2")}</span>
    </>
  );
}

function JsonBody({ body, query }: { body: string; query?: string }) {
  const q = query ?? "";
  const parts: React.ReactNode[] = [];
  const tokens = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
  let cursor = 0;
  for (const match of body.matchAll(tokens)) {
    const index = match.index ?? 0;
    if (index > cursor) parts.push(markText(body.slice(cursor, index), q, `jg${index}`));
    let className = "text-chart-4";
    if (match[1]) className = match[2] ? "text-primary" : "text-chart-2";
    else if (match[3]) className = "text-chart-3";
    parts.push(
      <span className={className} key={`${index}-${match[0].length}`}>
        {markText(match[0], q, `jt${index}`)}
      </span>,
    );
    cursor = index + match[0].length;
  }
  if (cursor < body.length) parts.push(markText(body.slice(cursor), q, `je${cursor}`));
  return parts;
}

function MarkupBody({ body, query }: { body: string; query?: string }) {
  const q = query ?? "";
  const parts: React.ReactNode[] = [];
  const tags = /<\/?[A-Za-z][^>]*>|<!--[\s\S]*?-->/g;
  let cursor = 0;
  for (const match of body.matchAll(tags)) {
    const index = match.index ?? 0;
    if (index > cursor) parts.push(markText(body.slice(cursor, index), q, `mg${index}`));
    parts.push(
      <span className="text-primary" key={`${index}-${match[0].length}`}>
        {markText(match[0], q, `mt${index}`)}
      </span>,
    );
    cursor = index + match[0].length;
  }
  if (cursor < body.length) parts.push(markText(body.slice(cursor), q, `me${cursor}`));
  return parts;
}

type BodyFormat = "json" | "markup" | "plain";

function detectBodyFormat(body: string): BodyFormat {
  const trimmed = body.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) return "json";
  if (trimmed.startsWith("<")) return "markup";
  return "plain";
}

function HighlightedBody({ body, format, query }: { body: string; format: BodyFormat; query?: string }) {
  if (format === "json") return <JsonBody body={body} query={query} />;
  if (format === "markup") return <MarkupBody body={body} query={query} />;
  return markText(body, query ?? "", "pb");
}

export function HttpCodeBlock({ raw }: { raw: string }) {
  const [wrapLines, setWrapLines] = React.useState(true);
  const [copied, setCopied] = React.useState(false);
  const [searchOpen, setSearchOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const value = raw || "（空）";
  const lines = value.replaceAll("\r\n", "\n").split("\n");
  const separator = lines.indexOf("");
  const body = separator >= 0 ? lines.slice(separator + 1).join("\n") : "";
  const bodyFormat = detectBodyFormat(body);

  React.useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 1500);
    return () => window.clearTimeout(timer);
  }, [copied]);

  const copyPacket = async () => {
    const ok = await copyText(value);
    if (ok) {
      setCopied(true);
      return;
    }
    toast.error("复制失败，请使用 Ctrl/Cmd+A 后复制");
  };

  // 搜索命中统计（大小写不敏感、全报文=头+体，与逐行 mark 同口径）。
  const q = searchOpen ? query.trim() : "";
  const matchCount = React.useMemo(() => {
    if (!q) return 0;
    const lq = q.toLowerCase();
    let n = 0;
    let i = value.toLowerCase().indexOf(lq);
    while (i >= 0) {
      n++;
      i = value.toLowerCase().indexOf(lq, i + lq.length);
    }
    return n;
  }, [value, q]);

  const renderLine = (line: string, index: number) => {
    if (index === 0) return <StartLine line={line} query={q} />;
    if (separator < 0 || index < separator) return <HeaderLine line={line} query={q} />;
    if (index === separator) return null;
    return <HighlightedBody body={line} format={bodyFormat} query={q} />;
  };

  const closeSearch = () => {
    setSearchOpen(false);
    setQuery("");
  };

  return (
    <div className="relative mx-3 my-4 overflow-hidden rounded-md border bg-background shadow-xs">
      <div className="absolute top-2 right-2 flex items-center gap-0.5 rounded-md border bg-background/95 p-0.5 shadow-xs">
        {searchOpen && (
          <span className="flex items-center gap-1 pr-1">
            <Input
              autoFocus
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="搜索报文…"
              aria-label="在报文中搜索"
              className="h-6 w-36 text-xs"
              onKeyDown={(e) => {
                if (e.key === "Escape") closeSearch();
              }}
            />
            <span className={cn("shrink-0 text-xs", q && matchCount === 0 ? "text-red-500" : "text-muted-foreground")}>
              {q ? `${matchCount} 处` : ""}
            </span>
          </span>
        )}
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon-xs"
              aria-label={searchOpen ? "关闭搜索" : "在报文中搜索"}
              aria-pressed={searchOpen}
              onClick={() => (searchOpen ? closeSearch() : setSearchOpen(true))}
            >
              {searchOpen ? <XIcon /> : <SearchIcon />}
            </Button>
          </TooltipTrigger>
          <TooltipContent side="bottom">{searchOpen ? "关闭搜索" : "搜索"}</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon-xs"
              aria-label={wrapLines ? "关闭自动换行" : "开启自动换行"}
              aria-pressed={wrapLines}
              onClick={() => setWrapLines((current) => !current)}
            >
              <WrapTextIcon />
            </Button>
          </TooltipTrigger>
          <TooltipContent side="bottom">{wrapLines ? "关闭自动换行" : "开启自动换行"}</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon-xs"
              aria-label={copied ? "已复制报文" : "复制报文"}
              onClick={() => void copyPacket()}
            >
              {copied ? <CheckIcon /> : <CopyIcon />}
            </Button>
          </TooltipTrigger>
          <TooltipContent side="bottom">{copied ? "已复制" : "复制报文"}</TooltipContent>
        </Tooltip>
      </div>
      {/* biome-ignore lint/a11y/useSemanticElements: textarea cannot preserve line numbers and syntax-highlighting markup. */}
      <div
        role="textbox"
        aria-label="HTTP 报文代码"
        aria-multiline="true"
        aria-readonly="true"
        tabIndex={0}
        className="max-h-[calc(100vh-15rem)] min-w-0 overflow-auto bg-background py-3 font-mono text-xs outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
        onKeyDown={(event) => {
          if (!(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== "a") return;
          event.preventDefault();
          const selection = window.getSelection();
          if (!selection) return;
          const range = document.createRange();
          range.selectNodeContents(event.currentTarget);
          selection.removeAllRanges();
          selection.addRange(range);
        }}
      >
        {lines.map((line, index) => (
          <div
            key={`${index}-${line}`}
            data-line={index + 1}
            className="grid min-w-0 grid-cols-[1.5rem_minmax(0,1fr)] leading-relaxed before:sticky before:left-0 before:self-stretch before:border-r before:bg-muted/20 before:px-1 before:text-right before:text-muted-foreground/60 before:content-[attr(data-line)]"
          >
            <code
              className={cn(
                "min-h-[1lh] min-w-0 pr-16 pl-1.5 [tab-size:4]",
                wrapLines ? "break-words whitespace-pre-wrap" : "whitespace-pre",
              )}
            >
              {renderLine(line, index)}
            </code>
          </div>
        ))}
      </div>
    </div>
  );
}
