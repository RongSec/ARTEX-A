"use client";

// V9-UI3：报告设置弹窗（名称占位符模板）。
//
// 只做一件事：编辑 report_settings.name_template，占用例 chips 插入光标处，
// 下方按当前输入实时渲染示例文件名。真正生成时的文件名由后端决定。

import * as React from "react";

import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";
import { api } from "@/lib/api";
import {
  DEFAULT_REPORT_NAME_TEMPLATE,
  previewReportFileName,
  type ReportNameData,
} from "@/lib/report-name";

// 占位符 chips：token + 一行解释（title 悬停）。
const PLACEHOLDERS: { token: string; hint: string }[] = [
  { token: "{system}", hint: "系统名；识别不到资产时任务用「任务13」、项目用「项目3」" },
  { token: "{title}", hint: "封面标题（系统名+渗透测试报告）" },
  { token: "{task}", hint: "任务名称" },
  { token: "{project}", hint: "项目名称" },
  { token: "{task_id}", hint: "任务 ID（没有则为空）" },
  { token: "{project_id}", hint: "项目 ID（没有则为空）" },
  { token: "{date}", hint: "生成日期 YYYY-MM-DD" },
  { token: "{date:YYYY年M月D日}", hint: "生成日期，支持 YYYY MM DD HH mm ss 与中文年月日" },
  { token: "{date:YYYYMMDD}", hint: "生成日期紧凑格式，如 20261118" },
  { token: "{YYYY}", hint: "四位年份" },
  { token: "{MM}", hint: "两位月份" },
  { token: "{DD}", hint: "两位日期" },
  { token: "{HH}", hint: "两位小时（24 小时制，UTC+8）" },
  { token: "{mm}", hint: "两位分钟" },
];

// 示例数据：用户原话里的 127.0.0.1，固定任务/项目便于理解 ID 占位符。
const SAMPLE: ReportNameData = {
  system: "127.0.0.1",
  title: "127.0.0.1渗透测试报告",
  taskId: 13,
  projectId: 3,
  taskName: "示例任务",
  projectName: "示例项目",
};

export function ReportSettingsDialog({
  open,
  onOpenChange,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSaved?: () => void;
}) {
  const [value, setValue] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);

  React.useEffect(() => {
    if (!open) return;
    let alive = true;
    setLoading(true);
    api
      .reportSettings()
      .then((s) => {
        if (alive) setValue(s.name_template ?? "");
      })
      .catch((e) => {
        if (alive) toast.error(`加载报告设置失败：${(e as Error).message}`);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [open]);

  // 示例按当前输入实时渲染；空输入即默认模板。日期取当前时间。
  const example = React.useMemo(() => previewReportFileName(value, SAMPLE, new Date()), [value]);

  // 点击 chip：插入光标处（有选区则替换选区），并保持焦点。
  const insertToken = (token: string) => {
    const el = inputRef.current;
    const start = el?.selectionStart ?? value.length;
    const end = el?.selectionEnd ?? value.length;
    const next = value.slice(0, start) + token + value.slice(end);
    setValue(next);
    requestAnimationFrame(() => {
      const target = inputRef.current;
      if (!target) return;
      target.focus();
      const caret = start + token.length;
      target.setSelectionRange(caret, caret);
    });
  };

  const save = async () => {
    setSaving(true);
    try {
      await api.patchReportSettings({ name_template: value.trim() });
      toast.success("报告设置已保存");
      onSaved?.();
      onOpenChange(false);
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !saving && onOpenChange(o)}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>报告设置</DialogTitle>
        </DialogHeader>

        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="report-name-template">报告名称模板</Label>
            <Input
              id="report-name-template"
              ref={inputRef}
              value={value}
              disabled={loading}
              placeholder={DEFAULT_REPORT_NAME_TEMPLATE}
              onChange={(e) => setValue(e.target.value)}
              autoComplete="off"
            />
            <p className="text-muted-foreground text-xs">
              留空使用默认模板；文件名后缀（.docx）由系统自动补全。
            </p>
          </div>

          <div className="flex flex-col gap-1.5">
            <span className="text-muted-foreground text-xs">可用占位符（点击插入光标处）</span>
            <div className="flex flex-wrap gap-1.5">
              {PLACEHOLDERS.map((p) => (
                <button
                  key={p.token}
                  type="button"
                  title={p.hint}
                  onClick={() => insertToken(p.token)}
                  className="bg-muted hover:bg-muted/70 rounded-md border px-2 py-1 font-mono text-xs"
                >
                  {p.token}
                </button>
              ))}
            </div>
            <p className="text-muted-foreground text-xs">
              时间分量按 UTC+8；未知占位符会原样显示，便于自检。
            </p>
          </div>

          <div className="bg-muted/40 rounded-md border px-3 py-2 text-sm">
            <span className="text-muted-foreground">示例：</span>
            <span className="font-mono break-all">{example}</span>
          </div>
        </div>

        <DialogFooter className="sm:justify-between">
          <Button
            variant="outline"
            size="sm"
            className="sm:mr-auto"
            onClick={() => setValue(DEFAULT_REPORT_NAME_TEMPLATE)}
            disabled={saving || loading}
          >
            恢复默认
          </Button>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => onOpenChange(false)} disabled={saving}>
              取消
            </Button>
            <Button size="sm" onClick={() => void save()} disabled={saving || loading}>
              {saving ? <Spinner /> : null} 保存
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
