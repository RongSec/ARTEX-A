"use client";

// 操作约束编辑器（V12-CREATE-UNIFY）。
//
// 两段式：
//   1) 自然语言框 + 「解析」：把「不要爆破、只测 443、别碰生产数据」这类口头
//      要求经 LLM 编成 allow/deny 条目（POST /api/constraints/parse，不落库）；
//   2) 结构化列表：每条带 允许/禁止 徽标，可改可删，也可手动补一条。
//
// 项目创建、任务创建、任务总览（后续）共用同一套视觉与语义。

import * as React from "react";
import { toast } from "sonner";
import { CheckIcon, PencilIcon, PlusIcon, ShieldAlertIcon, Trash2Icon, WandSparklesIcon, XIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";

export type ConstraintKind = "allow" | "deny";

export interface ConstraintItem {
  kind: ConstraintKind;
  text: string;
}

interface Props {
  items: ConstraintItem[];
  onChange: (items: ConstraintItem[]) => void;
  disabled?: boolean;
  /** 文本框行数，默认 3。 */
  rawRows?: number;
  /** 外层已有「操作约束」标题时置 true，避免标题重复（计数仍保留）。 */
  hideLabel?: boolean;
}

// ConstraintEditor 是受控组件；解析结果按 (kind,text) 去重后追加，不覆盖用户
// 已经手改过的条目。
export function ConstraintEditor({ items, onChange, disabled, rawRows = 3, hideLabel }: Props) {
  const [raw, setRaw] = React.useState("");
  const [parsing, setParsing] = React.useState(false);
  const [conKind, setConKind] = React.useState<ConstraintKind>("deny");
  const [conText, setConText] = React.useState("");
  const [editing, setEditing] = React.useState<number | null>(null);
  const [editKind, setEditKind] = React.useState<ConstraintKind>("deny");
  const [editText, setEditText] = React.useState("");

  function merge(incoming: ConstraintItem[]) {
    const seen = new Set(items.map((c) => `${c.kind}\x00${c.text}`));
    const next = [...items];
    let added = 0;
    for (const c of incoming) {
      const key = `${c.kind}\x00${c.text}`;
      if (seen.has(key)) continue;
      seen.add(key);
      next.push(c);
      added++;
    }
    onChange(next);
    return added;
  }

  async function runParse() {
    if (!raw.trim()) {
      toast.error("请先写一段约束描述");
      return;
    }
    setParsing(true);
    try {
      const r = await api.parseConstraints({ text: raw.trim() });
      if (!r.constraints?.length) {
        toast.warning("模型没有抽到明确约束，可手动添加");
        return;
      }
      const added = merge(r.constraints.map((c) => ({ kind: c.kind as ConstraintKind, text: c.text })));
      toast.success(added > 0 ? `已解析 ${added} 条约束` : "解析结果与现有条目重复");
    } catch (e) {
      toast.error("解析失败：" + (e as Error).message);
    } finally {
      setParsing(false);
    }
  }

  function addManual() {
    const text = conText.trim();
    if (!text) return;
    merge([{ kind: conKind, text }]);
    setConText("");
  }

  function startEdit(i: number) {
    setEditing(i);
    setEditKind(items[i].kind);
    setEditText(items[i].text);
  }

  function saveEdit() {
    if (editing === null) return;
    const text = editText.trim();
    if (!text) return;
    onChange(items.map((c, i) => (i === editing ? { kind: editKind, text } : c)));
    setEditing(null);
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between gap-3">
        {hideLabel ? (
          <span />
        ) : (
          <Label className="flex items-center gap-1.5">
            <ShieldAlertIcon className="size-3.5 text-amber-500" />
            操作约束
          </Label>
        )}
        <span className="text-muted-foreground text-xs tabular-nums">
          {items.length > 0 ? `${items.length} 条` : "可留空"}
        </span>
      </div>

      <div className="flex items-start gap-2">
        <Textarea
          rows={rawRows}
          className="min-h-0 flex-1 text-sm"
          placeholder={
            "用自然语言写测试边界，例如：\n不要爆破密码，同一账号最多试 3 次；只测 443，不扫其他端口；不得删改生产数据。"
          }
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
          disabled={disabled || parsing}
        />
        <Button
          type="button"
          size="sm"
          variant="outline"
          className="h-7 shrink-0 gap-1 px-2 text-xs"
          onClick={() => void runParse()}
          disabled={disabled || parsing || !raw.trim()}
        >
          <WandSparklesIcon className="h-3 w-3" />
          {parsing ? "解析中…" : "解析"}
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <NativeSelect
          size="sm"
          value={conKind}
          onChange={(e) => setConKind(e.target.value as ConstraintKind)}
          disabled={disabled}
          aria-label="约束类型"
        >
          <NativeSelectOption value="deny">禁止</NativeSelectOption>
          <NativeSelectOption value="allow">允许</NativeSelectOption>
        </NativeSelect>
        <Input
          className="h-7 min-w-52 flex-1 text-sm"
          placeholder="手动补一条，如『仅测 443 端口』"
          value={conText}
          onChange={(e) => setConText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") addManual();
          }}
          disabled={disabled}
        />
        <Button type="button" size="sm" variant="outline" onClick={addManual} disabled={disabled || !conText.trim()}>
          <PlusIcon className="size-3.5" /> 添加
        </Button>
      </div>

      {items.length === 0 ? (
        <p className="text-muted-foreground text-xs">
          暂无约束。上面写自然语言点「解析」由模型编成条目；也可以直接手动添加。
        </p>
      ) : (
        <div className="flex flex-col gap-1.5">
          {items.map((c, i) =>
            editing === i ? (
              <div key={i} className="flex flex-wrap items-center gap-2 rounded-md border px-2.5 py-1.5">
                <NativeSelect
                  size="sm"
                  value={editKind}
                  onChange={(e) => setEditKind(e.target.value as ConstraintKind)}
                  aria-label="约束类型"
                >
                  <NativeSelectOption value="deny">禁止</NativeSelectOption>
                  <NativeSelectOption value="allow">允许</NativeSelectOption>
                </NativeSelect>
                <Input
                  className="h-7 min-w-52 flex-1 text-sm"
                  value={editText}
                  onChange={(e) => setEditText(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") saveEdit();
                    if (e.key === "Escape") setEditing(null);
                  }}
                  autoFocus
                />
                <Button size="sm" variant="ghost" className="h-6 shrink-0 px-1.5" onClick={saveEdit}>
                  <CheckIcon className="size-3.5 text-emerald-500" />
                </Button>
                <Button size="sm" variant="ghost" className="h-6 shrink-0 px-1.5" onClick={() => setEditing(null)}>
                  <XIcon className="size-3.5" />
                </Button>
              </div>
            ) : (
              <div key={i} className="flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-sm">
                <span
                  className={`shrink-0 rounded px-1.5 py-0.5 text-xs ${
                    c.kind === "allow"
                      ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
                      : "bg-red-500/15 text-red-600 dark:text-red-400"
                  }`}
                >
                  {c.kind === "allow" ? "允许" : "禁止"}
                </span>
                <span className="min-w-0 flex-1 break-words">{c.text}</span>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-6 shrink-0 px-1.5"
                  onClick={() => startEdit(i)}
                  disabled={disabled}
                  aria-label="编辑约束"
                >
                  <PencilIcon className="size-3.5" />
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-6 shrink-0 px-1.5"
                  onClick={() => onChange(items.filter((_, idx) => idx !== i))}
                  disabled={disabled}
                  aria-label="删除约束"
                >
                  <Trash2Icon className="size-3.5 text-red-500" />
                </Button>
              </div>
            ),
          )}
        </div>
      )}
    </div>
  );
}
