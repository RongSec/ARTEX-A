"use client";

// 底部折叠区：组件 / 资产 / 漏洞。默认全部收起，避免一屏铺满。

import * as React from "react";

import Link from "next/link";

import {
  BoxesIcon,
  BugIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  ServerIcon,
} from "lucide-react";

import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { statusMeta, toneClasses } from "@/lib/status";
import type { TaskIntelAsset, TaskIntelComponent, TaskIntelVuln } from "@/lib/types";

import { EmptyHint, MiniBadge } from "./shared";

function FoldSection({
  icon,
  title,
  count,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  count: number;
  children: React.ReactNode;
}) {
  const [open, setOpen] = React.useState(false);
  return (
    <div className="rounded-lg border">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="hover:bg-muted/40 flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left"
      >
        {open ? (
          <ChevronDownIcon className="text-muted-foreground size-3.5 shrink-0" />
        ) : (
          <ChevronRightIcon className="text-muted-foreground size-3.5 shrink-0" />
        )}
        <span className="text-muted-foreground">{icon}</span>
        <span className="text-xs font-semibold">{title}</span>
        <span className="bg-muted text-muted-foreground rounded px-1.5 py-0.5 text-[11px] tabular-nums">{count}</span>
      </button>
      {open && <div className="overflow-hidden border-t">{children}</div>}
    </div>
  );
}

export function IntelExtraSections({
  taskId,
  components,
  assets,
  vulns,
}: {
  taskId: string;
  components: TaskIntelComponent[];
  assets: TaskIntelAsset[];
  vulns: TaskIntelVuln[];
}) {
  return (
    <section className="space-y-2">
      <FoldSection icon={<BoxesIcon className="size-3.5" />} title="组件" count={components.length}>
        <Table className="min-w-[560px]">
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead>产品</TableHead>
              <TableHead className="w-28">版本</TableHead>
              <TableHead>证据</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {components.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={3}>
                  <EmptyHint>暂无组件情报</EmptyHint>
                </TableCell>
              </TableRow>
            ) : (
              components.map((c) => (
                <TableRow key={c.key}>
                  <TableCell>
                    <span className="block max-w-[260px] truncate text-xs" title={c.product}>
                      {c.product || "—"}
                    </span>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{c.version || "—"}</TableCell>
                  <TableCell>
                    <span className="text-muted-foreground block max-w-[360px] truncate text-[11px]" title={c.value || ""}>
                      {c.value || "—"}
                    </span>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </FoldSection>

      <FoldSection icon={<ServerIcon className="size-3.5" />} title="资产" count={assets.length}>
        <Table className="min-w-[480px]">
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead>主机</TableHead>
              <TableHead className="w-24">端口</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {assets.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={2}>
                  <EmptyHint>暂无资产情报</EmptyHint>
                </TableCell>
              </TableRow>
            ) : (
              assets.map((a) => (
                <TableRow key={a.key}>
                  <TableCell>
                    <span className="block max-w-[360px] truncate font-mono text-xs" title={a.host || a.key}>
                      {a.host || a.key || "—"}
                    </span>
                  </TableCell>
                  <TableCell className="font-mono text-xs tabular-nums">{a.port || "—"}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </FoldSection>

      <FoldSection icon={<BugIcon className="size-3.5" />} title="漏洞" count={vulns.length}>
        <Table className="min-w-[640px]">
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead>标题</TableHead>
              <TableHead className="w-24">等级</TableHead>
              <TableHead className="w-56">资产</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {vulns.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={3}>
                  <EmptyHint>暂无漏洞情报</EmptyHint>
                </TableCell>
              </TableRow>
            ) : (
              vulns.map((v) => {
                const meta = v.severity ? statusMeta("severity", v.severity) : null;
                return (
                  <TableRow key={v.key}>
                    <TableCell>
                      {v.finding_id ? (
                        <Link
                          href={`/function/tasks/detail?id=${encodeURIComponent(taskId)}&tab=findings`}
                          className="hover:text-primary block max-w-[320px] truncate text-xs"
                          title={v.title}
                        >
                          {v.title || `发现 #${v.finding_id}`}
                        </Link>
                      ) : (
                        <span className="block max-w-[320px] truncate text-xs" title={v.title}>
                          {v.title || "—"}
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      {meta ? (
                        <MiniBadge className={toneClasses[meta.tone]}>{meta.label}</MiniBadge>
                      ) : (
                        <span className="text-muted-foreground text-xs">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <span className="block max-w-[220px] truncate font-mono text-xs" title={v.asset || ""}>
                        {v.asset || "—"}
                      </span>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </FoldSection>
    </section>
  );
}
