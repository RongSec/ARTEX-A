"use client";

// 发现详情主体（V3-R1 共用子组件）：分步复现卡片 + 详细报告 Card。
//
// 详情页（(main)/function/findings/detail）与发现列表展开行共用同一份呈现
// （用户诉求「展开的和进入详情一致」），两处的 report Markdown Card 逻辑
// （report_stale 提示 / 复制按钮 / 空态文案、有复现时标题标注「补充」）只
// 保留这一份，不复制粘贴。
//
// evidenceId = 证据截图接口的句柄（findings 表 id）。详情页传 URL 上的 id；
// 列表展开行传 f.finding_id。缺省回退 finding.finding_id ?? finding.id。

import * as React from "react";

import { CopyButton } from "@/components/copy-button";
import { FindingReproView } from "@/components/finding-repro-view";
import { Markdown } from "@/components/markdown";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { Finding } from "@/lib/types";

export function FindingDetailBody({
  finding,
  evidenceId,
}: {
  finding: Finding;
  evidenceId?: string;
}) {
  const hasRepro = !!finding.reproduction?.steps?.length;
  const reproId = evidenceId ?? finding.finding_id ?? finding.id;
  return (
    <div className="flex flex-col gap-4">
      {/* T16(3/3) 分步呈现：有 reproduction → 结构化复现卡片（步骤+流量
          +证据图）；无 → 回退下方 report Markdown（原版行为，零回归）。 */}
      {hasRepro ? <FindingReproView findingId={reproId} repro={finding.reproduction!} readOnly={finding.inherited} /> : null}

      {/* 证据下方：详细报告(Markdown 渲染)。有逐字复现时详细报告是
          补充说明（标题标注），无复现时它仍是正文（回退主路径）。 */}
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle className="text-sm">{hasRepro ? "详细报告（补充）" : "详细报告"}</CardTitle>
          {finding.report && <CopyButton text={finding.report} successMessage="已复制详细报告" />}
        </CardHeader>
        <CardContent>
          {finding.report_stale ? (
            <Alert>
              <AlertDescription>流量证据已变更，详细报告待更新。</AlertDescription>
            </Alert>
          ) : null}
          {finding.report ? (
            <Markdown text={finding.report} />
          ) : (
            <p className="text-sm text-muted-foreground">暂无详细报告。</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
