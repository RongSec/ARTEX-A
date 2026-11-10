"use client";

import * as React from "react";
import { toast } from "sonner";
import { SendIcon } from "lucide-react";

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
import { api } from "@/lib/api";
import type { TaskTemplate } from "@/lib/types";

// 单批上限与后端 server/projects_batch.go maxBatchCreate 同步（改一边必须改另一边）。
const MAX_BATCH = 200;

// splitTargets 与后端 splitBatchTargets 同语义（TrimSpace/丢空/去重保首条）。
// 只做展示用预估；权威拆分在后端。
function splitTargets(text: string): { targets: string[]; dup: string[] } {
  const seen = new Set<string>();
  const targets: string[] = [];
  const dup: string[] = [];
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    if (seen.has(t)) {
      dup.push(t);
      continue;
    }
    seen.add(t);
    targets.push(t);
  }
  return { targets, dup };
}

interface ProjectBatchTasksProps {
  projectID: number;
  concurrency: number;
  onDone: () => void;
}

// 批量下发卡：textarea 贴目标（一行一个）+ 参数区（分类/模板/并发覆盖/立即执行）
// + 实时行数统计。提交 POST /api/projects/{id}/batch-tasks，回显 created/skipped/failed。
// （对照 CSAI batch-import-modal 语义简化：砍掉 cron 定时调度与 HITL 审批策略下拉，
//  本平台批量任务走项目 dispatcher 的排队放行，不需要那两个维度。）
export function ProjectBatchTasks({ projectID, concurrency, onDone }: ProjectBatchTasksProps) {
  const [open, setOpen] = React.useState(false);
  const [targets, setTargets] = React.useState("");
  const [concurrencyOverride, setConcurrencyOverride] = React.useState<string>(String(concurrency));
  const [categoryID, setCategoryID] = React.useState<number | null>(null);
  const [templateID, setTemplateID] = React.useState<number | null>(null);
  const [descTemplate, setDescTemplate] = React.useState("");
  const [seedFirstIntent, setSeedFirstIntent] = React.useState(false);
  const [timeoutSeconds, setTimeoutSeconds] = React.useState<string>("0");
  const [categories, setCategories] = React.useState<{ id: number; name: string }[]>([]);
  const [templates, setTemplates] = React.useState<TaskTemplate[]>([]);
  const [template, setTemplate] = React.useState<TaskTemplate | null>(null);
  const [submitting, setSubmitting] = React.useState(false);

  const parsed = React.useMemo(() => splitTargets(targets), [targets]);
  const willCreate = parsed.targets.length;

  React.useEffect(() => {
    if (!open) return;
    api.taskCategories().then(setCategories).catch(() => {});
    api.taskTemplates().then(setTemplates).catch(() => {});
  }, [open]);

  function applyTemplate(t: TaskTemplate) {
    setTemplate(t);
    if (t.category_id) setCategoryID(t.category_id);
    // 模板的 description 里的目标占位语义与批量不同（批量每行=目标），
    // 这里只把模板描述当默认 desc_template 的提示底稿。
    if (t.description && !descTemplate) setDescTemplate(t.description);
  }

  function reset() {
    setTargets("");
    setConcurrencyOverride(String(concurrency));
    setCategoryID(null);
    setTemplateID(null);
    setTemplate(null);
    setDescTemplate("");
    setSeedFirstIntent(false);
    setTimeoutSeconds("0");
  }

  async function submit() {
    if (willCreate === 0) {
      toast.error("请至少填写一个目标（一行一个）");
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
    } = {
      desc_template: descTemplate.trim() || undefined,
      category_id: categoryID,
      llm_profile_ids: [], // 批量通道不指定 LLM 链=跟随全局激活配置
      timeout_seconds: timeout || 0,
      seed_first_intent: seedFirstIntent,
    };
    setSubmitting(true);
    try {
      const r = await api.batchProjectTasks(projectID, { targets, concurrency: conc, common });
      const created = r.created?.length ?? 0;
      const skipped = r.skipped?.length ?? 0;
      const failed = r.failed?.length ?? 0;
      const bits = [`已下发 ${created} 个任务（排队等项目并发额）`];
      if (skipped) bits.push(`重复跳过 ${skipped} 行`);
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
        <DialogContent className="max-h-[90vh] gap-0 overflow-y-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>批量创建任务</DialogTitle>
          </DialogHeader>
          <div className="grid gap-4 py-2">
            <div className="grid gap-2">
              <Label htmlFor="batch-targets">目标列表（一行一个）</Label>
              <Textarea
                id="batch-targets"
                rows={8}
                className="font-mono text-sm"
                placeholder={"http://target-a.example.com\n10.0.0.5\nhttps://shop.example.com"}
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
              />
              <div className="text-muted-foreground flex items-center justify-between text-xs">
                <span>
                  将创建 <span className="text-foreground font-medium tabular-nums">{willCreate}</span> 个任务
                  {parsed.dup.length > 0 && <span className="text-amber-600">（{parsed.dup.length} 行重复将跳过）</span>}
                  {willCreate > MAX_BATCH && <span className="text-destructive">（超出单批上限 {MAX_BATCH}）</span>}
                </span>
                <span>任务建立后进入排队，按项目并发数自动放行</span>
              </div>
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
