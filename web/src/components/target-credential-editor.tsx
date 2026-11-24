"use client";

// 目标 + 凭据行式编辑器（V12-CREATE-UNIFY）。
//
// 交互（按用户口径）：
//   1) 上方大文本框粘贴所有资产（可混 URL/IP/IP:port/CIDR/域名，一行或逗号分隔）；
//   2) 点「解析」按与后端同语义的 parseTargets 清洗 → 下方一行一个有效资产；
//   3) 每行默认跟「用户名 + 密码」两个输入位；同一资产有多套口令时点行尾「＋」
//      再复制一行该资产（target 相同、凭据不同）；
//   4) 行尾垃圾桶删除这一条凭据行。
//
// 提交时：资产列表 = 行内 target 去重；凭据 = 每行一条 {target,type:password,...}。
// 项目创建与任务创建共用，保证两边口径一致。

import * as React from "react";
import { PlusIcon, Trash2Icon, WandSparklesIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { parseTargets } from "@/lib/target-parse";

export interface TargetCredRow {
  target: string;
  username: string;
  password: string;
}

export const EMPTY_TARGET_ROW: TargetCredRow = { target: "", username: "", password: "" };

/** rowsToTargets 返回去重后的资产列表（保持首次出现顺序）。 */
export function rowsToTargets(rows: TargetCredRow[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const r of rows) {
    const t = r.target.trim();
    if (!t || seen.has(t)) continue;
    seen.add(t);
    out.push(t);
  }
  return out;
}

/** rowsFromTargets 把一段资产文本解析成行（模板预置资产带出用，无凭据）。 */
export function rowsFromTargets(text: string): TargetCredRow[] {
  return parseTargets(text).targets.map((t) => ({ ...EMPTY_TARGET_ROW, target: t }));
}

/** rowsToCredentials 转成后端 credentials 入参（丢掉没填任何凭据的行）。 */
export function rowsToCredentials(rows: TargetCredRow[]) {
  return rows
    .filter((r) => r.target.trim() && (r.username.trim() || r.password.trim()))
    .map((r) => ({
      target: r.target.trim(),
      type: "password" as const,
      username: r.username.trim(),
      password: r.password.trim(),
    }));
}

interface Props {
  rows: TargetCredRow[];
  onChange: (rows: TargetCredRow[]) => void;
  /** 资产文本域的内容（受控，方便提交前再解析一次）。 */
  raw: string;
  onRawChange: (raw: string) => void;
  /** 解析后被剔除的行（展示给用户看，空数组不渲染）。 */
  invalid?: string[];
  onInvalidChange?: (invalid: string[]) => void;
  /** 解析成功后的提示（可选，父组件接 toast）。 */
  onParsed?: (info: { count: number; duplicate: number; invalid: number }) => void;
  disabled?: boolean;
  /** 文本框行数，默认 6。 */
  rawRows?: number;
  /** 外层已有「资产」标题时置 true，避免标题重复（计数与解析按钮保留）。 */
  hideLabel?: boolean;
}

// TargetCredentialEditor 是受控组件：raw 文本与 rows 都归父组件，避免「解析后
// 再改文本」两边状态打架。解析动作本身也由父组件可复用的 runParse 完成——
// 这里只做 UI 与行操作，保持单一数据源。
export function TargetCredentialEditor({
  rows,
  onChange,
  raw,
  onRawChange,
  invalid = [],
  onInvalidChange,
  onParsed,
  disabled,
  rawRows = 6,
  hideLabel,
}: Props) {
  function runParse() {
    const r = parseTargets(raw);
    onInvalidChange?.(r.invalid);
    // 保留按 target 匹配到的旧凭据（多账号行也保留），其余按新资产重建。
    const byTarget = new Map<string, TargetCredRow[]>();
    for (const row of rows) {
      const t = row.target.trim();
      if (!t) continue;
      const list = byTarget.get(t) ?? [];
      list.push(row);
      byTarget.set(t, list);
    }
    const next: TargetCredRow[] = [];
    for (const t of r.targets) {
      const existing = byTarget.get(t);
      if (existing && existing.length > 0) next.push(...existing);
      else next.push({ ...EMPTY_TARGET_ROW, target: t });
    }
    onChange(next);
    onParsed?.({ count: r.targets.length, duplicate: r.duplicate.length, invalid: r.invalid.length });
  }

  function patch(i: number, next: Partial<TargetCredRow>) {
    onChange(rows.map((row, idx) => (idx === i ? { ...row, ...next } : row)));
  }

  // 同一资产多账号：复制当前行的 target，凭据留空。
  function addSameTarget(i: number) {
    const t = rows[i]?.target.trim() ?? "";
    const next = [...rows];
    next.splice(i + 1, 0, { ...EMPTY_TARGET_ROW, target: t });
    onChange(next);
  }

  function remove(i: number) {
    onChange(rows.filter((_, idx) => idx !== i));
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between gap-3">
        {hideLabel ? (
          <span />
        ) : (
          <Label htmlFor="target-cred-raw">资产</Label>
        )}
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground text-xs tabular-nums">
            {rowsToTargets(rows).length > 0 ? `${rowsToTargets(rows).length} 个资产` : "粘贴后点解析"}
          </span>
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="h-7 gap-1 px-2 text-xs"
            onClick={runParse}
            disabled={disabled || !raw.trim()}
          >
            <WandSparklesIcon className="h-3 w-3" />
            解析
          </Button>
        </div>
      </div>
      <Textarea
        id="target-cred-raw"
        rows={rawRows}
        className="font-mono text-sm"
        placeholder={"粘贴所有资产，再点「解析」：\nhttp://target-a.example.com\n10.0.0.5\n10.0.0.6:8080\n10.0.0.0/24"}
        value={raw}
        onChange={(e) => onRawChange(e.target.value)}
        disabled={disabled}
      />

      {invalid.length > 0 && (
        <div className="border-destructive/30 bg-destructive/5 rounded-md border px-2 py-1.5">
          <p className="text-destructive text-xs">已剔除（不会建任务）：</p>
          <p className="text-muted-foreground mt-0.5 line-clamp-3 font-mono text-[11px] break-all">
            {invalid.join("  ·  ")}
          </p>
        </div>
      )}

      {rows.length === 0 ? (
        <div className="text-muted-foreground rounded-md border border-dashed px-3 py-4 text-center text-xs">
          解析后这里一行一个资产，每行填账号密码；同一资产多套口令点行尾「＋」。
        </div>
      ) : (
        <div className="flex flex-col gap-1.5">
          <div className="text-muted-foreground grid grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)_minmax(0,1fr)_2rem_2rem] gap-1.5 px-0.5 text-[11px]">
            <span>资产</span>
            <span>用户名</span>
            <span>密码</span>
            <span />
            <span />
          </div>
          {rows.map((row, i) => (
            <div
              key={`${row.target}-${i}`}
              className="grid grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)_minmax(0,1fr)_2rem_2rem] items-center gap-1.5"
            >
              <Input
                aria-label="资产"
                className="h-8 font-mono text-xs"
                placeholder="10.0.0.5 / https://a.example.com"
                value={row.target}
                onChange={(e) => patch(i, { target: e.target.value })}
                disabled={disabled}
              />
              <Input
                aria-label="用户名"
                className="h-8 font-mono text-xs"
                placeholder="用户名"
                value={row.username}
                onChange={(e) => patch(i, { username: e.target.value })}
                disabled={disabled}
              />
              <Input
                aria-label="密码"
                className="h-8 font-mono text-xs"
                placeholder="密码"
                value={row.password}
                onChange={(e) => patch(i, { password: e.target.value })}
                disabled={disabled}
              />
              <Button
                type="button"
                size="sm"
                variant="ghost"
                aria-label="同一资产新增一条凭据"
                title="同一资产再加一套账号密码"
                className="h-8 w-8 p-0"
                onClick={() => addSameTarget(i)}
                disabled={disabled}
              >
                <PlusIcon className="h-3.5 w-3.5" />
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                aria-label="删除这条凭据"
                className="text-muted-foreground hover:text-destructive h-8 w-8 p-0"
                onClick={() => remove(i)}
                disabled={disabled}
              >
                <Trash2Icon className="h-3.5 w-3.5" />
              </Button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
