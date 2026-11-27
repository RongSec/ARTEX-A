"use client";

import * as React from "react";
import { toast } from "sonner";
import { SendIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { TaskTemplateControls } from "@/components/task-template-controls";
import { ConstraintEditor, type ConstraintItem } from "@/components/constraint-editor";
import {
  TargetCredentialEditor,
  rowsFromTargetsAndCreds,
  rowsToCredentials,
  rowsToTargets,
  type TargetCredRow,
} from "@/components/target-credential-editor";
import { api } from "@/lib/api";
import type { TaskTemplate } from "@/lib/types";

interface ProjectBatchTasksProps {
  projectID: number;
  concurrency: number;
  /** 项目默认任务模板：打开弹窗时自动带出，用户仍可改。 */
  defaultTemplateID?: number | null;
  /** 项目默认测试资产文本：打开弹窗时预填成行（可改，不改项目）。 */
  defaultTargets?: string;
  /** 项目默认凭据行：按 target 挂到对应资产行上。 */
  defaultCredentials?: Record<string, unknown>[];
  /** 项目暂停/归档时禁用下发（后端也会拒绝，这里只是不给入口）。 */
  disabled?: boolean;
  onDone: () => void;
}

// 批量下发卡（项目详情用）：资产 + 凭据行式录入、操作约束、任务参数。
// 与「新建项目」「新建任务」共用同一套编辑器，口径一致。
export function ProjectBatchTasks({
  projectID,
  concurrency,
  defaultTemplateID,
  defaultTargets = "",
  defaultCredentials,
  disabled = false,
  onDone,
}: ProjectBatchTasksProps) {
  const [open, setOpen] = React.useState(false);
  const [targetRaw, setTargetRaw] = React.useState("");
  const [targetRows, setTargetRows] = React.useState<TargetCredRow[]>([]);
  const [targetInvalid, setTargetInvalid] = React.useState<string[]>([]);
  const [constraints, setConstraints] = React.useState<ConstraintItem[]>([]);
  const [concurrencyOverride, setConcurrencyOverride] = React.useState<string>(String(concurrency));
  const [categoryID, setCategoryID] = React.useState<number | null>(null);
  const [templateID, setTemplateID] = React.useState<number | null>(null);
  const [descTemplate, setDescTemplate] = React.useState("");
  const [seedFirstIntent, setSeedFirstIntent] = React.useState(false);
  const [timeoutSeconds, setTimeoutSeconds] = React.useState<string>("0");
  const [categories, setCategories] = React.useState<{ id: number; name: string }[]>([]);
  const [template, setTemplate] = React.useState<TaskTemplate | null>(null);
  const [submitting, setSubmitting] = React.useState(false);
  // 模态弹窗 body 上 pointer-events:none，模板下拉得 portal 回弹窗内容里才能点中。
  const dialogContentRef = React.useRef<HTMLDivElement>(null);

  const targetList = React.useMemo(() => rowsToTargets(targetRows), [targetRows]);
  const willCreate = targetList.length;

  // defaultRows 是「项目默认测试资产」解析成的行；打开弹窗与重置都用它。
  const defaultRows = React.useMemo(
    () => rowsFromTargetsAndCreds(defaultTargets, defaultCredentials),
    [defaultTargets, defaultCredentials],
  );

  React.useEffect(() => {
    if (!open) return;
    // 预填项目默认资产（用户可能已经把行改过，只在空表时填）。
    setTargetRows((current) => (current.length > 0 ? current : defaultRows));
    setTargetRaw((current) => (current.trim() ? current : defaultTargets));
    api.taskCategories().then(setCategories).catch(() => {});
    api
      .taskTemplates()
      .then((list) => {
        if (defaultTemplateID && templateID === null) {
          const t = list.find((x) => x.id === defaultTemplateID);
          if (t) {
            setTemplateID(t.id);
            applyTemplate(t);
          }
        }
      })
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  function applyTemplate(t: TaskTemplate) {
    setTemplate(t);
    if (t.category_id) setCategoryID(t.category_id);
    if (t.description && !descTemplate) setDescTemplate(t.description);
    if (t.constraints?.length) {
      setConstraints(t.constraints.map((c) => ({ kind: c.kind, text: c.text })));
    }
  }

  function reset() {
    // 重置回项目默认值，而不是空表——项目里配好的资产就是要反复下发用的。
    setTargetRaw(defaultTargets);
    setTargetRows(defaultRows);
    setTargetInvalid([]);
    setConstraints([]);
    setConcurrencyOverride(String(concurrency));
    setCategoryID(null);
    setTemplateID(defaultTemplateID ?? null);
    setTemplate(null);
    setDescTemplate("");
    setSeedFirstIntent(false);
    setTimeoutSeconds("0");
  }

  async function submit() {
    if (willCreate === 0) {
      toast.error("请至少填写一个有效资产");
      return;
    }
    const conc = Number(concurrencyOverride);
    if (!Number.isFinite(conc) || conc < 1 || conc > 8) {
      toast.error("并发数须为 1-8 的整数");
      return;
    }
    const timeout = Number(timeoutSeconds);
    if (!Number.isFinite(timeout) || timeout < 0) {
      toast.error("超时秒数须为 ≥0 的数字（0=不限时）");
      return;
    }
    setSubmitting(true);
    try {
      const r = await api.batchProjectTasks(projectID, {
        targets: targetList.join("\n"),
        concurrency: conc,
        common: {
          desc_template: descTemplate.trim() || undefined,
          category_id: categoryID,
          llm_profile_ids: [],
          timeout_seconds: timeout || 0,
          seed_first_intent: seedFirstIntent,
          credentials: rowsToCredentials(targetRows),
          constraints,
        },
      });
      const created = r.created?.length ?? 0;
      const skipped = r.skipped?.length ?? 0;
      const invalid = r.invalid?.length ?? 0;
      const failed = r.failed?.length ?? 0;
      const bits = [`已下发 ${created} 个任务（排队等项目并发额）`];
      if (skipped) bits.push(`重复跳过 ${skipped} 行`);
      if (invalid) bits.push(`非法剔除 ${invalid} 行`);
      if (failed) bits.push(`失败 ${failed} 行`);
      if (failed) {
        toast.warning(bits.join("，") + "：" + (r.failed ?? []).join("、"), { duration: 8000 });
      } else {
        toast.success(bits.join("，"));
      }
      reset();
      setOpen(false);
      onDone();
    } catch (e) {
      toast.error("批量下发失败：" + (e as Error).message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <Button onClick={() => setOpen(true)} disabled={disabled} title={disabled ? "项目已暂停/归档，不能下发新任务" : undefined}>
        <SendIcon data-icon="inline-start" /> 批量下发
      </Button>
      <Dialog open={open} onOpenChange={(o) => !submitting && setOpen(o)}>
        <DialogContent ref={dialogContentRef} className="max-h-[92vh] gap-0 overflow-y-auto sm:max-w-4xl">
          <DialogHeader>
            <DialogTitle>批量创建任务</DialogTitle>
          </DialogHeader>
          <div className="grid gap-4 py-2">
            <div className="rounded-lg border p-3">
              <TargetCredentialEditor
                rows={targetRows}
                onChange={setTargetRows}
                raw={targetRaw}
                onRawChange={setTargetRaw}
                invalid={targetInvalid}
                onInvalidChange={setTargetInvalid}
                onParsed={({ count, duplicate, invalid }) => {
                  const bits = [`有效 ${count} 条`];
                  if (duplicate) bits.push(`去重 ${duplicate} 条`);
                  if (invalid) bits.push(`剔除 ${invalid} 条非法`);
                  toast.success(bits.join("，"));
                }}
                disabled={submitting}
                rawRows={6}
              />
              <p className="text-muted-foreground mt-2 text-xs">
                将创建 <span className="text-foreground font-medium tabular-nums">{willCreate}</span> 个任务；建后排队，按项目并发自动放行。
              </p>
            </div>

            <div className="rounded-lg border p-3">
              <ConstraintEditor
                items={constraints}
                onChange={setConstraints}
                disabled={submitting}
                rawRows={3}
              />
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="batch-concurrency">项目并发数覆盖</Label>
                <Input
                  id="batch-concurrency"
                  type="number"
                  min={1}
                  max={8}
                  value={concurrencyOverride}
                  onChange={(e) => setConcurrencyOverride(e.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="batch-category">任务分类</Label>
                <NativeSelect
                  className="w-full"
                  id="batch-category"
                  value={categoryID ?? ""}
                  onChange={(e) => setCategoryID(e.target.value ? Number(e.target.value) : null)}
                >
                  <NativeSelectOption value="">未分类</NativeSelectOption>
                  {categories.map((c) => (
                    <NativeSelectOption key={c.id} value={c.id}>
                      {c.name}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              </div>
            </div>
            <p className="text-muted-foreground -mt-2 text-xs">
              当前项目并发 {concurrency}；1=严格串行。提交后写回项目设置。
            </p>

            <TaskTemplateControls
              description={descTemplate}
              goal=""
              categoryID={categoryID ?? undefined}
              interceptRules={[]}
              constraints={constraints}
              selectedTemplateID={templateID}
              onSelectedTemplateIDChange={(id) => {
                setTemplateID(id);
                if (id === null) setTemplate(null);
              }}
              onApply={(t) => applyTemplate(t)}
              portalContainer={dialogContentRef}
            />
            {template && (
              <p className="text-muted-foreground -mt-2 text-xs">
                已带出模板「{template.name}」；模板里的资产不会覆盖左侧列表（批量以每行资产为准）。
              </p>
            )}

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="batch-desc">目的模板（{"{target}"}=每行资产）</Label>
                <Input
                  id="batch-desc"
                  placeholder="资产：{target}"
                  value={descTemplate}
                  onChange={(e) => setDescTemplate(e.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="batch-timeout">任务超时（秒，0=不限）</Label>
                <Input
                  id="batch-timeout"
                  type="number"
                  min={0}
                  value={timeoutSeconds}
                  onChange={(e) => setTimeoutSeconds(e.target.value)}
                />
              </div>
            </div>

            <label className="flex items-center gap-3 text-sm">
              <Switch checked={seedFirstIntent} onCheckedChange={setSeedFirstIntent} />
              立即执行模式（建任务时直接下发种子意图，跳过首轮规划）
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)} disabled={submitting}>
              取消
            </Button>
            <Button onClick={submit} disabled={submitting || willCreate === 0}>
              {submitting ? "下发中…" : `下发 ${willCreate > 0 ? willCreate : ""} 个任务`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
