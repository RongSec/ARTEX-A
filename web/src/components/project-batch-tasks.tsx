"use client";

import * as React from "react";
import { toast } from "sonner";
import { SendIcon, WandSparklesIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
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
import { CredentialEditor, credentialsToPayload, type CredentialRow } from "@/components/credential-editor";
import { api } from "@/lib/api";
import { parseTargets } from "@/lib/target-parse";
import type { TaskTemplate } from "@/lib/types";

// 单批上限与后端 server/projects_batch.go maxBatchCreate 同步（改一边必须改另一边）。
const MAX_BATCH = 200;

interface ProjectBatchTasksProps {
  projectID: number;
  concurrency: number;
  /** 项目默认任务模板：打开弹窗时自动带出，用户仍可改。 */
  defaultTemplateID?: number | null;
  onDone: () => void;
}

// 批量下发卡：左栏贴目标（可点「解析」清洗成一行一个有效目标），右栏录凭据
// （一条一行，可指定适用目标），下方是任务参数。提交 POST
// /api/projects/{id}/batch-tasks，回显 created/skipped/invalid/failed。
export function ProjectBatchTasks({ projectID, concurrency, defaultTemplateID, onDone }: ProjectBatchTasksProps) {
  const [open, setOpen] = React.useState(false);
  const [targets, setTargets] = React.useState("");
  const [creds, setCreds] = React.useState<CredentialRow[]>([]);
  const [concurrencyOverride, setConcurrencyOverride] = React.useState<string>(String(concurrency));
  const [categoryID, setCategoryID] = React.useState<number | null>(null);
  const [templateID, setTemplateID] = React.useState<number | null>(null);
  const [descTemplate, setDescTemplate] = React.useState("");
  const [seedFirstIntent, setSeedFirstIntent] = React.useState(false);
  const [timeoutSeconds, setTimeoutSeconds] = React.useState<string>("0");
  const [categories, setCategories] = React.useState<{ id: number; name: string }[]>([]);
  const [template, setTemplate] = React.useState<TaskTemplate | null>(null);
  const [submitting, setSubmitting] = React.useState(false);
  // 最近一次「解析」剔除了什么：不回显的话用户不知道少了哪几行。
  const [lastInvalid, setLastInvalid] = React.useState<string[]>([]);

  const parsed = React.useMemo(() => parseTargets(targets), [targets]);
  const willCreate = parsed.targets.length;

  React.useEffect(() => {
    if (!open) return;
    api.taskCategories().then(setCategories).catch(() => {});
    api
      .taskTemplates()
      .then((list) => {
        // 项目默认模板：打开时带出一次；用户手动改过（templateID 非空）就不覆盖。
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
    // 模板的 description 里的目标占位语义与批量不同（批量每行=目标），
    // 这里只把模板描述当默认 desc_template 的提示底稿。
    if (t.description && !descTemplate) setDescTemplate(t.description);
  }

  // runParse 是「解析」按钮：清洗文本 → 一行一个有效目标 + 反馈剔除了什么。
  function runParse() {
    const r = parseTargets(targets);
    setLastInvalid(r.invalid);
    if (r.targets.length === 0) {
      toast.error(`没有有效目标${r.invalid.length ? `（剔除 ${r.invalid.length} 行非法内容）` : ""}`);
      return;
    }
    setTargets(r.targets.join("\n"));
    const bits = [`有效 ${r.targets.length} 条`];
    if (r.duplicate.length) bits.push(`去重 ${r.duplicate.length} 条`);
    if (r.invalid.length) bits.push(`剔除 ${r.invalid.length} 条非法`);
    toast.success(bits.join("，"));
  }

  function reset() {
    setTargets("");
    setCreds([]);
    setConcurrencyOverride(String(concurrency));
    setCategoryID(null);
    setTemplateID(defaultTemplateID ?? null);
    setTemplate(null);
    setDescTemplate("");
    setSeedFirstIntent(false);
    setTimeoutSeconds("0");
    setLastInvalid([]);
  }

  async function submit() {
    if (willCreate === 0) {
      toast.error("请至少填写一个有效目标");
      return;
    }
    if (willCreate > MAX_BATCH) {
      toast.error(`单批最多 ${MAX_BATCH} 个目标（当前 ${willCreate} 个）`);
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
    const common: {
      desc_template?: string;
      category_id?: number | null;
      llm_profile_ids?: number[];
      timeout_seconds?: number;
      seed_first_intent?: boolean;
      credentials?: ReturnType<typeof credentialsToPayload>;
    } = {
      desc_template: descTemplate.trim() || undefined,
      category_id: categoryID,
      llm_profile_ids: [], // 批量通道不指定 LLM 链=跟随全局激活配置
      timeout_seconds: timeout || 0,
      seed_first_intent: seedFirstIntent,
      credentials: credentialsToPayload(creds),
    };
    setSubmitting(true);
    try {
      // 送后端的是解析后的目标，不是原始文本：前端看到的数量必须等于实际建的任务数。
      const r = await api.batchProjectTasks(projectID, {
        targets: parsed.targets.join("\n"),
        concurrency: conc,
        common,
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
      <Button onClick={() => setOpen(true)}>
        <SendIcon data-icon="inline-start" /> 批量下发
      </Button>
      <Dialog open={open} onOpenChange={(o) => !submitting && setOpen(o)}>
        <DialogContent className="max-h-[92vh] gap-0 overflow-y-auto sm:max-w-4xl">
          <DialogHeader>
            <DialogTitle>批量创建任务</DialogTitle>
          </DialogHeader>
          <div className="grid gap-4 py-2">
            {/* 左右两栏：目标（可解析） + 凭据（一条一行） */}
            <div className="grid gap-4 lg:grid-cols-[1.35fr_1fr]">
              <div className="grid gap-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="batch-targets">目标列表</Label>
                  <Button type="button" size="sm" variant="outline" className="h-7 gap-1 px-2 text-xs" onClick={runParse}>
                    <WandSparklesIcon className="h-3 w-3" />
                    解析
                  </Button>
                </div>
                <Textarea
                  id="batch-targets"
                  rows={14}
                  className="font-mono text-sm"
                  placeholder={"http://target-a.example.com\n10.0.0.5\n10.0.0.6:8080\nexample.com, 10.0.0.7"}
                  value={targets}
                  onChange={(e) => setTargets(e.target.value)}
                />
                <div className="text-muted-foreground flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
                  <span>
                    将创建 <span className="text-foreground font-medium tabular-nums">{willCreate}</span> 个任务
                  </span>
                  {parsed.duplicate.length > 0 && (
                    <span className="text-amber-600">重复 {parsed.duplicate.length}</span>
                  )}
                  {parsed.invalid.length > 0 && (
                    <span className="text-destructive">非法 {parsed.invalid.length}</span>
                  )}
                  {willCreate > MAX_BATCH && <span className="text-destructive">超出上限 {MAX_BATCH}</span>}
                  <span>建后排队，按项目并发自动放行</span>
                </div>
                {lastInvalid.length > 0 && (
                  <div className="border-destructive/30 bg-destructive/5 rounded-md border px-2 py-1.5">
                    <p className="text-destructive text-xs">已剔除（不会建任务）：</p>
                    <p className="text-muted-foreground mt-0.5 line-clamp-3 font-mono text-[11px] break-all">
                      {lastInvalid.join("  ·  ")}
                    </p>
                  </div>
                )}
              </div>

              <CredentialEditor value={creds} onChange={setCreds} targets={parsed.targets} compact />
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
                <p className="text-muted-foreground text-xs">当前项目 {concurrency}；1=严格串行。提交后写回项目设置。</p>
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

            <TaskTemplateControls
              description={descTemplate}
              goal=""
              categoryID={categoryID ?? undefined}
              interceptRules={[]}
              selectedTemplateID={templateID}
              onSelectedTemplateIDChange={(id) => {
                setTemplateID(id);
                if (id === null) setTemplate(null);
              }}
              onApply={(t) => applyTemplate(t)}
            />
            {template && (
              <p className="text-muted-foreground -mt-2 text-xs">
                已带出模板「{template.name}」；模板里的目标不会覆盖左侧列表（批量以每行目标为准）。
              </p>
            )}

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="batch-desc">描述模板（{"{target}"}=每行目标）</Label>
                <Input
                  id="batch-desc"
                  placeholder="目标：{target}"
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
            <Button onClick={submit} disabled={submitting || willCreate === 0 || willCreate > MAX_BATCH}>
              {submitting ? "下发中…" : `下发 ${willCreate > 0 ? willCreate : ""} 个任务`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
