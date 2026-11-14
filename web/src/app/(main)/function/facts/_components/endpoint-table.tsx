"use client";

// 第二段「测过的接口」：可筛选/搜索/排序的表格，行展开显示证据链。
// 表格横向滚动由 ui/table 容器负责，窄屏不压成竖排。

import * as React from "react";

import Link from "next/link";

import { ChevronDownIcon, ChevronRightIcon, NetworkIcon, SearchIcon, XIcon } from "lucide-react";

import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SortableHead } from "@/components/ui/sortable-head";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { SortDirection } from "@/lib/sort-preference";
import { toneClasses } from "@/lib/status";
import type { TaskIntelEvidence, TaskIntelEndpoint } from "@/lib/types";
import { cn } from "@/lib/utils";

import { EmptyHint, MiniBadge, SectionTitle } from "./shared";

type SortField = "method" | "path" | "host" | "status" | "hits";

const METHOD_TONE: Record<string, string> = {
  get: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/20",
  post: "bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/20",
  put: "bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/20",
  patch: "bg-violet-500/15 text-violet-600 dark:text-violet-400 border-violet-500/20",
  delete: "bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/20",
};

function methodTone(method: string) {
  return METHOD_TONE[method.toLowerCase()] ?? "bg-muted text-muted-foreground border-transparent";
}

// evidenceHref 把证据指到任务详情对应 tab：finding→发现，fact→探索链路。
function evidenceHref(taskId: string, e: TaskIntelEvidence): string {
  if (e.finding_id) return `/function/tasks/detail?id=${encodeURIComponent(taskId)}&tab=findings`;
  if (e.fact_node_id) return `/function/tasks/detail?id=${encodeURIComponent(taskId)}&tab=graph`;
  return "";
}

function EvidenceChip({
  taskId,
  evidence,
}: {
  taskId: string;
  evidence: TaskIntelEvidence;
}) {
  const chips: { label: string; href: string }[] = [];
  if (evidence.finding_id) {
    chips.push({ label: `发现 #${evidence.finding_id}`, href: evidenceHref(taskId, evidence) });
  }
  if (evidence.fact_node_id) {
    chips.push({
      label: `事实节点 #${evidence.fact_node_id}`,
      href: evidenceHref(taskId, evidence),
    });
  }
  if (evidence.asset_id) chips.push({ label: `资产 #${evidence.asset_id}`, href: "" });

  if (chips.length === 0) return <span className="text-muted-foreground text-[11px]">无证据记录</span>;

  return (
    <>
      {chips.map((c) =>
        c.href ? (
          <Link
            key={c.label}
            href={c.href}
            className="bg-background hover:border-primary hover:text-primary inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] transition-colors"
          >
            {c.label}
          </Link>
        ) : (
          <span
            key={c.label}
            className="text-muted-foreground bg-background inline-flex items-center rounded border border-dashed px-1.5 py-0.5 font-mono text-[11px]"
          >
            {c.label}
          </span>
        ),
      )}
    </>
  );
}

export function EndpointTable({
  taskId,
  rows,
}: {
  taskId: string;
  rows: TaskIntelEndpoint[];
}) {
  const [method, setMethod] = React.useState("all");
  const [query, setQuery] = React.useState("");
  const [sortField, setSortField] = React.useState<SortField>("hits");
  const [sortDir, setSortDir] = React.useState<SortDirection>("desc");
  const [expanded, setExpanded] = React.useState<Set<string>>(new Set());

  const methods = React.useMemo(() => {
    const set = new Set<string>();
    for (const r of rows) set.add((r.method || "get").toUpperCase());
    return Array.from(set).sort();
  }, [rows]);

  const visible = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = rows.filter((r) => {
      if (method !== "all" && (r.method || "get").toUpperCase() !== method) return false;
      if (q && !(r.path || "").toLowerCase().includes(q)) return false;
      return true;
    });
    const dir = sortDir === "asc" ? 1 : -1;
    const val = (r: TaskIntelEndpoint): string | number => {
      switch (sortField) {
        case "method":
          return (r.method || "").toLowerCase();
        case "path":
          return (r.path || "").toLowerCase();
        case "host":
          return (r.hosts?.[0] || "").toLowerCase();
        case "status":
          return r.status_codes?.[0] ?? 0;
        case "hits":
          return r.hit_count ?? 0;
      }
    };
    return [...list].sort((a, b) => {
      const va = val(a);
      const vb = val(b);
      if (typeof va === "number" && typeof vb === "number") return (va - vb) * dir;
      return String(va).localeCompare(String(vb)) * dir;
    });
  }, [rows, method, query, sortField, sortDir]);

  const onSort = (field: SortField) => {
    if (field === sortField) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortField(field);
      setSortDir(field === "hits" ? "desc" : "asc");
    }
  };

  const toggleRow = (key: string) =>
    setExpanded((cur) => {
      const next = new Set(cur);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  return (
    <section className="space-y-2">
      <SectionTitle icon={<NetworkIcon className="size-4" />} title="测过的接口" count={rows.length}>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <Select value={method} onValueChange={setMethod}>
            <SelectTrigger size="sm" className="h-8 w-28" aria-label="按方法筛选">
              <SelectValue placeholder="方法" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部方法</SelectItem>
              {methods.map((m) => (
                <SelectItem key={m} value={m}>
                  {m}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <InputGroup className="h-8 w-52">
            <InputGroupAddon>
              <SearchIcon className="size-3.5" />
            </InputGroupAddon>
            <InputGroupInput
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="搜索路径…"
              className="text-xs"
            />
            {query && (
              <InputGroupAddon align="inline-end">
                <button
                  type="button"
                  className="text-muted-foreground hover:text-foreground"
                  onClick={() => setQuery("")}
                  aria-label="清除路径搜索"
                >
                  <XIcon className="size-3.5" />
                </button>
              </InputGroupAddon>
            )}
          </InputGroup>
        </div>
      </SectionTitle>

      <div className="overflow-hidden rounded-lg border">
        <Table className="min-w-[900px]">
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <SortableHead
                field="method"
                label="方法"
                activeField={sortField}
                direction={sortDir}
                onSort={onSort}
                className="w-20"
              />
              <SortableHead field="path" label="路径" activeField={sortField} direction={sortDir} onSort={onSort} />
              <SortableHead
                field="host"
                label="主机"
                activeField={sortField}
                direction={sortDir}
                onSort={onSort}
                className="w-40"
              />
              <TableHead className="w-56">用途</TableHead>
              <TableHead className="w-40">参数</TableHead>
              <SortableHead
                field="status"
                label="状态码"
                activeField={sortField}
                direction={sortDir}
                onSort={onSort}
                className="w-24"
              />
              <TableHead className="w-20">登录</TableHead>
              <SortableHead
                field="hits"
                label="命中"
                activeField={sortField}
                direction={sortDir}
                onSort={onSort}
                align="right"
                className="w-16"
              />
            </TableRow>
          </TableHeader>
          <TableBody>
            {visible.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={8}>
                  <EmptyHint>
                    {rows.length === 0 ? "本任务暂无接口记录" : "没有匹配的接口"}
                  </EmptyHint>
                </TableCell>
              </TableRow>
            ) : (
              visible.map((r) => {
                const open = expanded.has(r.key);
                const methodLabel = (r.method || "get").toUpperCase();
                return (
                  <React.Fragment key={r.key}>
                    <TableRow
                      className="cursor-pointer"
                      onClick={() => toggleRow(r.key)}
                      aria-expanded={open}
                    >
                      <TableCell>
                        <MiniBadge className={methodTone(methodLabel)}>{methodLabel}</MiniBadge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          {open ? (
                            <ChevronDownIcon className="text-muted-foreground size-3 shrink-0" />
                          ) : (
                            <ChevronRightIcon className="text-muted-foreground size-3 shrink-0" />
                          )}
                          <span className="block max-w-[320px] truncate font-mono text-xs" title={r.path}>
                            {r.path || "—"}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <span className="block max-w-[150px] truncate font-mono text-xs" title={(r.hosts || []).join(", ")}>
                          {r.hosts?.[0] || "—"}
                          {r.hosts && r.hosts.length > 1 && (
                            <span className="text-muted-foreground"> +{r.hosts.length - 1}</span>
                          )}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span
                          className={cn("block max-w-[220px] truncate text-xs", !r.purpose && "text-muted-foreground")}
                          title={r.purpose || "—"}
                        >
                          {r.purpose || "—"}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span
                          className={cn(
                            "block max-w-[180px] truncate font-mono text-[11px]",
                            !r.params?.length && "text-muted-foreground",
                          )}
                          title={(r.params || []).join(", ")}
                        >
                          {r.params?.length ? r.params.join(", ") : "—"}
                        </span>
                      </TableCell>
                      <TableCell>
                        {r.status_codes?.length ? (
                          <span className="flex flex-wrap gap-1">
                            {r.status_codes.map((c) => (
                              <MiniBadge key={c} className="bg-muted border-transparent font-mono">
                                {c}
                              </MiniBadge>
                            ))}
                          </span>
                        ) : (
                          <span className="text-muted-foreground text-xs">—</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {r.auth_required ? (
                          <MiniBadge className={toneClasses.amber}>需登录</MiniBadge>
                        ) : (
                          <span className="text-muted-foreground text-xs">否</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right text-xs tabular-nums">
                        {r.hit_count ?? 0}
                      </TableCell>
                    </TableRow>
                    {open && (
                      <TableRow className="hover:bg-transparent">
                        <TableCell colSpan={8} className="bg-muted/30 p-3">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="text-muted-foreground mr-1 text-[11px]">证据</span>
                            {(r.evidence || []).length === 0 ? (
                              <span className="text-muted-foreground text-[11px]">无证据记录</span>
                            ) : (
                              r.evidence.map((e, i) => (
                                <EvidenceChip key={i} taskId={taskId} evidence={e} />
                              ))
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
    </section>
  );
}
