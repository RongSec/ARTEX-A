"use client";

// 凭据多行编辑器（V12-TARGET）。批量下发与单任务创建共用。
//
// 设计取舍：
//   - 一行一条凭据，类型 + 适用目标 + 用户名 + 密码/令牌；
//   - 「适用目标」留空=整批通用。填了=只写给匹配的那个目标：批量下发时同
//     一批目标常有多套口令（A 机 admin/admin、B 机 root/123456），不绑定就
//     会把 A 的密码也挂到 B 的资产上，agent 拿着乱试会触发锁定；
//   - type 为 token/cookie/key 时只显示「令牌」，不显示用户名+密码；
//   - 不显示备注字段：备注对 agent 有用但录入时是负担，需要时后端仍接受。

import * as React from "react";
import { PlusIcon, Trash2Icon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";

export type CredentialType = "password" | "hash" | "token" | "cookie" | "key";

export interface CredentialRow {
  target: string; // "" = 全部目标
  type: CredentialType;
  username: string;
  password: string;
  token: string;
}

export const EMPTY_CREDENTIAL: CredentialRow = {
  target: "",
  type: "password",
  username: "",
  password: "",
  token: "",
};

const TYPE_LABELS: { value: CredentialType; label: string }[] = [
  { value: "password", label: "密码" },
  { value: "hash", label: "哈希" },
  { value: "token", label: "令牌" },
  { value: "cookie", label: "Cookie" },
  { value: "key", label: "密钥" },
];

/** 令牌型凭据：只填 token，不填用户名+密码。 */
export function isTokenType(t: CredentialType): boolean {
  return t === "token" || t === "cookie" || t === "key";
}

interface CredentialEditorProps {
  value: CredentialRow[];
  onChange: (rows: CredentialRow[]) => void;
  /** 可选的目标列表（来自左侧解析结果），用于「适用目标」下拉。 */
  targets: string[];
  /** 右侧栏紧凑模式：去掉说明文字，行高更小。 */
  compact?: boolean;
}

export function CredentialEditor({ value, onChange, targets, compact }: CredentialEditorProps) {
  function patch(i: number, next: Partial<CredentialRow>) {
    onChange(value.map((row, idx) => (idx === i ? { ...row, ...next } : row)));
  }
  function remove(i: number) {
    onChange(value.filter((_, idx) => idx !== i));
  }
  function add() {
    // 新增行默认沿用上一行的适用目标：连续录同一台机器的多套凭据时少点一次。
    const last = value[value.length - 1];
    onChange([...value, { ...EMPTY_CREDENTIAL, target: last?.target ?? "" }]);
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <Label className="text-xs">凭据（{value.length} 条）</Label>
        <Button type="button" size="sm" variant="outline" onClick={add} className="h-7 gap-1 px-2 text-xs">
          <PlusIcon className="h-3 w-3" />
          新增
        </Button>
      </div>

      {value.length === 0 ? (
        <div className="text-muted-foreground rounded-md border border-dashed px-3 py-6 text-center text-xs">
          未填凭据。需要登录测试时点「新增」，一条一行。
        </div>
      ) : (
        <div className="flex max-h-[420px] flex-col gap-2 overflow-y-auto pr-1">
          {value.map((row, i) => (
            <div key={i} className="rounded-md border p-2">
              <div className="flex items-center gap-1.5">
                <NativeSelect
                  aria-label="凭据类型"
                  className="h-8 flex-1 text-xs"
                  value={row.type}
                  onChange={(e) => patch(i, { type: e.target.value as CredentialType })}
                >
                  {TYPE_LABELS.map((t) => (
                    <NativeSelectOption key={t.value} value={t.value}>
                      {t.label}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
                {targets.length > 0 ? (
                  <NativeSelect
                    aria-label="适用目标"
                    className="h-8 min-w-0 flex-[1.4] text-xs"
                    value={row.target}
                    onChange={(e) => patch(i, { target: e.target.value })}
                  >
                    <NativeSelectOption value="">全部目标</NativeSelectOption>
                    {targets.map((t) => (
                      <NativeSelectOption key={t} value={t}>
                        {t}
                      </NativeSelectOption>
                    ))}
                  </NativeSelect>
                ) : (
                  // 单任务创建没有目标列表可选项，允许手填（留空=全部目标）。
                  <Input
                    aria-label="适用目标"
                    className="h-8 min-w-0 flex-[1.4] text-xs"
                    placeholder="适用目标（留空=全部）"
                    value={row.target}
                    onChange={(e) => patch(i, { target: e.target.value })}
                  />
                )}
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  aria-label="删除这条凭据"
                  className="h-8 w-8 shrink-0 p-0 text-muted-foreground hover:text-destructive"
                  onClick={() => remove(i)}
                >
                  <Trash2Icon className="h-3.5 w-3.5" />
                </Button>
              </div>
              <div className="mt-1.5 grid grid-cols-2 gap-1.5">
                {isTokenType(row.type) ? (
                  <div className="col-span-2">
                    <Input
                      aria-label="令牌"
                      className="h-8 font-mono text-xs"
                      placeholder={
                        row.type === "cookie" ? "SESSION=...; csrftoken=..." : row.type === "key" ? "私钥 / API Key" : "Bearer token"
                      }
                      value={row.token}
                      onChange={(e) => patch(i, { token: e.target.value })}
                    />
                  </div>
                ) : (
                  <>
                    <Input
                      aria-label="用户名"
                      className="h-8 font-mono text-xs"
                      placeholder="用户名"
                      value={row.username}
                      onChange={(e) => patch(i, { username: e.target.value })}
                    />
                    <Input
                      aria-label="密码"
                      className="h-8 font-mono text-xs"
                      placeholder={row.type === "hash" ? "hash 值" : "密码"}
                      value={row.password}
                      onChange={(e) => patch(i, { password: e.target.value })}
                    />
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {!compact && (
        <p className="text-muted-foreground text-xs">
          凭据写入目标资产的 auth 字段，执行者用 list_assets 读取；不会进任务描述或报告正文。
        </p>
      )}
    </div>
  );
}

/** 把编辑器行转成后端入参（丢掉全空行）。 */
export function credentialsToPayload(rows: CredentialRow[]) {
  return rows
    .filter((r) => r.username.trim() || r.password.trim() || r.token.trim())
    .map((r) => ({
      target: r.target,
      type: r.type,
      username: r.username.trim(),
      password: r.password.trim(),
      token: r.token.trim(),
    }));
}
