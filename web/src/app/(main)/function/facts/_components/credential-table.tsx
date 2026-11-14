"use client";

// 第三段「账号与口令」：类型用色点区分，口令默认打码，逐行「显示」只在本地
// state 里切换（不请求明文、不写 localStorage）。

import * as React from "react";

import { EyeIcon, EyeOffIcon, KeyRoundIcon } from "lucide-react";

import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { TaskIntelCredential } from "@/lib/types";
import { cn } from "@/lib/utils";

import { EmptyHint, MiniBadge, SectionTitle } from "./shared";

const CRED_TYPES: Record<string, { label: string; dot: string }> = {
  password: { label: "口令", dot: "bg-amber-500" },
  hash: { label: "哈希", dot: "bg-violet-500" },
  token: { label: "令牌", dot: "bg-blue-500" },
  cookie: { label: "Cookie", dot: "bg-emerald-500" },
  key: { label: "密钥", dot: "bg-red-500" },
};

const SOURCE_LABEL: Record<string, string> = {
  finding: "发现",
  fact: "事实",
  asset: "资产",
  manual: "人工",
};

function credType(t: string) {
  return CRED_TYPES[t.toLowerCase()] ?? { label: "其他", dot: "bg-slate-400" };
}

function MaskedSecret({ row }: { row: TaskIntelCredential }) {
  const [shown, setShown] = React.useState(false);
  const hasSecret = Boolean(row.secret_masked);

  let display = "—";
  if (hasSecret) display = shown ? row.secret_masked : "••••••••";

  return (
    <div className="space-y-0.5">
      <div className="flex items-center gap-1.5">
        <span className={cn("font-mono text-xs", !hasSecret && "text-muted-foreground")}>{display}</span>
        {hasSecret && (
          <button
            type="button"
            onClick={() => setShown((v) => !v)}
            className="text-muted-foreground hover:text-foreground inline-flex items-center gap-0.5 text-[11px]"
            aria-label={shown ? "隐藏口令" : "显示口令"}
          >
            {shown ? <EyeOffIcon className="size-3" /> : <EyeIcon className="size-3" />}
            {shown ? "隐藏" : "显示"}
          </button>
        )}
      </div>
      {row.value && (
        <p className="text-muted-foreground max-w-[220px] truncate text-[11px]" title={row.value}>
          {row.value}
        </p>
      )}
    </div>
  );
}

export function CredentialTable({
  rows,
}: {
  rows: TaskIntelCredential[];
}) {
  return (
    <section className="space-y-2">
      <SectionTitle icon={<KeyRoundIcon className="size-4" />} title="账号与口令" count={rows.length}>
        <span className="text-muted-foreground ml-auto text-[11px]">口令默认打码，点「显示」仅本地展开</span>
      </SectionTitle>

      <div className="overflow-hidden rounded-lg border">
        <Table className="min-w-[860px]">
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="w-24">类型</TableHead>
              <TableHead className="w-32">用户名</TableHead>
              <TableHead className="w-36">服务</TableHead>
              <TableHead className="w-56">口令</TableHead>
              <TableHead>使用位置</TableHead>
              <TableHead className="w-20">来源</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={6}>
                  <EmptyHint>本任务暂无账号或口令</EmptyHint>
                </TableCell>
              </TableRow>
            ) : (
              rows.map((r) => {
                const t = credType(r.credential_type || "");
                const where = r.where_used || [];
                return (
                  <TableRow key={r.key}>
                    <TableCell>
                      <span className="inline-flex items-center gap-1.5 text-xs">
                        <span className={cn("size-2 shrink-0 rounded-full", t.dot)} />
                        {t.label}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="block max-w-[120px] truncate font-mono text-xs" title={r.username || "—"}>
                        {r.username || "—"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="block max-w-[140px] truncate text-xs" title={r.service || "—"}>
                        {r.service || "—"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <MaskedSecret row={r} />
                    </TableCell>
                    <TableCell>
                      {where.length === 0 ? (
                        <span className="text-muted-foreground text-xs">—</span>
                      ) : (
                        <div className="flex max-w-[380px] flex-wrap gap-1">
                          {where.slice(0, 4).map((w) => (
                            <MiniBadge
                              key={w}
                              className="bg-muted/60 max-w-[160px] border-transparent font-mono text-[11px]"
                              title={w}
                            >
                              <span className="truncate">{w}</span>
                            </MiniBadge>
                          ))}
                          {where.length > 4 && (
                            <MiniBadge className="bg-muted/60 border-transparent text-[11px]" title={where.join("\n")}>
                              +{where.length - 4}
                            </MiniBadge>
                          )}
                        </div>
                      )}
                    </TableCell>
                    <TableCell>
                      <MiniBadge className="bg-muted text-muted-foreground border-transparent">
                        {SOURCE_LABEL[r.source] ?? (r.source || "—")}
                      </MiniBadge>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
    </section>
  );
}
