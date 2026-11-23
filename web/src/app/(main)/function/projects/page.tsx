"use client";

// 项目列表页（artex-hs T08）：名称/状态/任务数/finding 分档/并发数 + 建项目对话框。
// 风格照 system/mcp + function/commands 页（shadcn、既有表格/对话框模式，不引新依赖）。

import * as React from "react";
import Link from "next/link";
import { toast } from "sonner";
import { ArchiveIcon, ArchiveRestoreIcon, FolderKanbanIcon, InboxIcon, MoreHorizontalIcon, PlusIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { DeleteOptionFields, emptyDeleteOptions } from "@/components/delete-option-fields";
import { ProjectTaskTree } from "./_components/project-task-tree";
import { CreateTaskSheet } from "@/app/(main)/function/tasks/page";
import { TaskTemplateControls } from "@/components/task-template-controls";
import {
  TargetCredentialEditor,
  EMPTY_TARGET_ROW,
  rowsToCredentials,
  rowsToTargets,
  type TargetCredRow,
} from "@/components/target-credential-editor";
import { ConstraintEditor, type ConstraintItem } from "@/components/constraint-editor";
import { api } from "@/lib/api";
import type { DeleteTaskOptions, ProjectWithStats, Task, TaskCategory } from "@/lib/types";

// FindingCells finding 分档着色（与任务列表页同一配色口径）。
function FindingCells({ f }: { f: Record<string, number> }) {
  const g = (k: string) => f[k] ?? 0;
  const total = g("critical") + g("high") + g("medium") + g("low");
  if (total === 0) return <span className="text-muted-foreground">0</span>;
  const seg = (n: number, cls: string) => (
    <span className={n > 0 ? cls : "text-muted-foreground"}>{n}</span>
  );
  return (
    <span className="font-medium whitespace-nowrap" title="严重 / 高 / 中 / 低">
      {seg(g("critical"), "text-rose-600 dark:text-rose-400")}
      <span className="text-muted-foreground">/</span>
      {seg(g("high"), "text-red-600 dark:text-red-400")}
      <span className="text-muted-foreground">/</span>
      {seg(g("medium"), "text-amber-600 dark:text-amber-400")}
      <span className="text-muted-foreground">/</span>
      {seg(g("low"), "text-slate-600 dark:text-slate-400")}
    </span>
  );
}

export default function ProjectsPage() {
  const [projects, setProjects] = React.useState<ProjectWithStats[]>([]);
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [categories, setCategories] = React.useState<TaskCategory[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [createOpen, setCreateOpen] = React.useState(false);
  const [taskCreateOpen, setTaskCreateOpen] = React.useState(false);
  const [deleteTarget, setDeleteTarget] = React.useState<ProjectWithStats | null>(null);

  // 一次拉齐：项目（含统计）+ 全部活任务 + 任务分类（建任务抽屉用）。
  const load = React.useCallback(() => {
    setLoading(true);
    Promise.all([api.projects(), api.tasks(), api.taskCategories().catch(() => [] as TaskCategory[])])
      .then(([pr, tr, cats]) => {
        setProjects(pr.projects ?? []);
        setTasks(tr.tasks ?? []);
        setCategories(cats);
      })
      .catch((e) => toast.error("加载失败：" + (e as Error).message))
      .finally(() => setLoading(false));
  }, []);
  React.useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="p-4 md:p-6">
      <ProjectTaskTree
        projects={projects}
        tasks={tasks}
        loading={loading}
        onCreateProject={() => setCreateOpen(true)}
        onCreateTask={() => setTaskCreateOpen(true)}
        onRefresh={load}
        onDeleteProject={setDeleteTarget}
      />

      <CreateProjectDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={() => {
          setCreateOpen(false);
          load();
        }}
      />

      <CreateTaskSheet
        tasks={tasks}
        categories={categories}
        open={taskCreateOpen}
        onOpenChange={setTaskCreateOpen}
        hideTrigger
        onCreated={() => {
          setTaskCreateOpen(false);
          load();
        }}
        onCategoriesChanged={load}
      />

      <DeleteProjectDialog
        project={deleteTarget}
        onOpenChange={(o) => {
          if (!o) setDeleteTarget(null);
        }}
        onDeleted={() => {
          setDeleteTarget(null);
          load();
        }}
      />
    </div>
  );
}

// CreateProjectDialog 新建项目：名称必填，描述/负责人/并发数可选。
// T19 新增四设置控件：跨任务阅读（项目内）/ 跨项目阅读 / 自动写报告
// （三 Switch，默认关）+ 报告模板（下拉，可留空=默认链）。后端 create 字段集
// 已与 PATCH 对齐（方案 A），四控件值直接进 POST body。
// V6-DUAL：observer_enabled 与 reader_enabled 是两个独立尺度，各传各的值、
// 各自生效——绝不合并成一个开关，也绝不传同值镜像。
function CreateProjectDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onCreated: () => void;
}) {
  const [name, setName] = React.useState("");
  // 目的 = 描述/测试范围；目标 = 资产列表（行式，含凭据）；约束 = allow/deny。
  const [purpose, setPurpose] = React.useState("");
  const [targetRaw, setTargetRaw] = React.useState("");
  const [targetRows, setTargetRows] = React.useState<TargetCredRow[]>([]);
  const [targetInvalid, setTargetInvalid] = React.useState<string[]>([]);
  const [constraintItems, setConstraintItems] = React.useState<ConstraintItem[]>([]);
  const [owner, setOwner] = React.useState("");
  const [concurrency, setConcurrency] = React.useState("2");
  const [observer, setObserver] = React.useState(false);
  const [reader, setReader] = React.useState(false);
  const [autoReport, setAutoReport] = React.useState(false);
  const [autoReportTasks, setAutoReportTasks] = React.useState(false);
  const [templateId, setTemplateId] = React.useState<string>(""); // "" = 默认链
  // 项目默认任务模板（task_templates.id）：只存引用，批量下发时带出。
  const [taskTemplateID, setTaskTemplateID] = React.useState<number | null>(null);
  const [templates, setTemplates] = React.useState<{ id: number; name: string; is_default: boolean }[]>([]);
  const [saving, setSaving] = React.useState(false);

  const targetList = React.useMemo(() => rowsToTargets(targetRows), [targetRows]);

  React.useEffect(() => {
    if (open) {
      setName("");
      setPurpose("");
      setTargetRaw("");
      setTargetRows([]);
      setTargetInvalid([]);
      setConstraintItems([]);
      setOwner("");
      setConcurrency("2");
      setObserver(false);
      setReader(false);
      setAutoReport(false);
      setAutoReportTasks(false);
      setTemplateId("");
      setTaskTemplateID(null);
      api
        .reportTemplates()
        .then(setTemplates)
        .catch(() => setTemplates([]));
    }
  }, [open]);

  async function submit() {
    if (!name.trim()) {
      toast.error("请填写项目名");
      return;
    }
    const conc = Number(concurrency);
    if (!Number.isFinite(conc) || conc < 1 || conc > 8) {
      toast.error("并发数须为 1-8 的整数");
      return;
    }
    if (targetList.length > 200) {
      toast.error(`单批最多 200 个目标（当前 ${targetList.length} 个），请分批下发`);
      return;
    }
    setSaving(true);
    try {
      const p = await api.createProject({
        name: name.trim(),
        description: purpose.trim(),
        owner: owner.trim(),
        concurrency: conc,
        observer_enabled: observer,
        report_template_id: templateId ? Number(templateId) : null,
        auto_report: autoReport,
        auto_report_tasks: autoReportTasks,
        reader_enabled: reader,
        task_template_id: taskTemplateID,
      });
      // 约束先落项目：之后每次批量下发都会复制一份到新任务，作为项目默认边界。
      if (constraintItems.length > 0) {
        try {
          await api.setProjectConstraints(p.id, constraintItems);
        } catch (e) {
          toast.warning(`项目已创建，但约束保存失败：${(e as Error).message}`, { duration: 8000 });
        }
      }
      toast.success(`项目已创建：${p.name}`);
      // 有目标就顺手下发首轮批量：项目与任务一次成型，不用再进详情页贴一遍。
      // 批量失败不回滚项目——项目已经建好，用户可在详情页重新下发。
      const willCreate = targetList.length;
      if (willCreate > 0) {
        try {
          const r = await api.batchProjectTasks(p.id, {
            targets: targetList.join("\n"),
            concurrency: conc,
            common: {
              category_id: null,
              credentials: rowsToCredentials(targetRows),
              constraints: constraintItems,
              desc_template: purpose.trim() ? `${purpose.trim()}\n目标：{target}` : undefined,
            },
          });
          const createdN = r.created?.length ?? 0;
          const skippedN = r.skipped?.length ?? 0;
          const failedN = r.failed?.length ?? 0;
          const bits = [`已下发 ${createdN} 个任务`];
          if (skippedN) bits.push(`重复跳过 ${skippedN}`);
          if (failedN) bits.push(`失败 ${failedN}`);
          if (failedN) toast.warning(bits.join("，"), { duration: 8000 });
          else toast.success(bits.join("，"));
        } catch (e) {
          toast.warning(`项目已创建，但批量下发失败：${(e as Error).message}`, { duration: 10000 });
        }
      }
      onCreated();
    } catch (e) {
      toast.error("创建失败：" + (e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !saving && onOpenChange(o)}>
      <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>新建项目</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid gap-2">
            <Label htmlFor="p-name">名称 *</Label>
            <Input id="p-name" placeholder="如：2026 春招渗透测试" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="p-purpose">目的（描述 / 测试范围）</Label>
            <Textarea
              id="p-purpose"
              rows={3}
              placeholder="这次测试要达成什么、背景与范围说明；会作为每个子任务的描述前缀。"
              value={purpose}
              onChange={(e) => setPurpose(e.target.value)}
            />
          </div>

          {/* 目标 + 凭据：粘贴 → 解析 → 一行一个目标，每行带账号密码。 */}
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
              disabled={saving}
              rawRows={5}
            />
          </div>

          {/* 约束：自然语言 → LLM 编成 allow/deny；随项目保存并复制给每个任务。 */}
          <div className="rounded-lg border p-3">
            <ConstraintEditor
              items={constraintItems}
              onChange={setConstraintItems}
              targets={targetList}
              disabled={saving}
              rawRows={3}
            />
          </div>

          <div className="grid grid-cols-2 items-start gap-4">
            <div className="grid gap-2">
              <Label htmlFor="p-owner">负责人</Label>
              <Input id="p-owner" placeholder="可留空" value={owner} onChange={(e) => setOwner(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="p-conc">批量任务并发数</Label>
              <Input id="p-conc" type="number" min={1} max={8} value={concurrency} onChange={(e) => setConcurrency(e.target.value)} />
            </div>
          </div>
          <p className="text-muted-foreground -mt-2 text-xs">并发数：1=严格串行，2=同时两任务（默认）。</p>
          <div className="grid gap-2">
            <Label htmlFor="p-template">报告模板</Label>
            <NativeSelect id="p-template" value={templateId} onChange={(e) => setTemplateId(e.target.value)}>
              <NativeSelectOption value="">默认模板（跟随全局默认链）</NativeSelectOption>
              {templates.map((t) => (
                <NativeSelectOption key={t.id} value={String(t.id)}>
                  {t.name}
                  {t.is_default ? "（默认）" : ""}
                </NativeSelectOption>
              ))}
            </NativeSelect>
            <p className="text-muted-foreground text-xs">整项目收官自动写报告时用的模板；留空则用全局默认模板链。</p>
          </div>
          <div className="rounded-lg border p-3">
            <TaskTemplateControls
              description=""
              goal=""
              constraints={constraintItems}
              selectedTemplateID={taskTemplateID}
              onSelectedTemplateIDChange={setTaskTemplateID}
              onApply={(t) => {
                if (t.constraints?.length) {
                  setConstraintItems(t.constraints.map((c) => ({ kind: c.kind, text: c.text })));
                }
              }}
              hint="作为本项目的默认任务模板：批量下发时自动带出，可在那时再改。只存引用，不复制模板内容。"
            />
          </div>

          {/* 初始目标 + 凭据已在上面按行式录入，这里不再重复。 */}
          <div className="grid gap-3 rounded-lg border p-3">
            <label className="flex items-center justify-between gap-3 text-sm">
              <span>跨任务阅读者（项目内）</span>
              <Switch checked={observer} onCheckedChange={setObserver} />
            </label>
            <p className="text-muted-foreground text-xs">
              本项目内任务之间共享经验：任务图变更触发跨任务阅读者，判定勾连后 adopt 并给规划者下发 hint。与跨项目无关。
            </p>
            <label className="flex items-center justify-between gap-3 text-sm">
              <span>跨项目阅读者</span>
              <Switch checked={reader} onCheckedChange={setReader} />
            </label>
            <p className="text-muted-foreground text-xs">
              本项目参与跨项目串联：允许跨项目阅读者读到本项目的资产重叠与任务图、并把打法 adopt 到本项目正在运行的任务。与项目无关的项目可以关掉，省配额。
            </p>
            <label className="flex items-center justify-between gap-3 text-sm">
              <span>只出一个项目报告（汇总）</span>
              <Switch checked={autoReport} onCheckedChange={setAutoReport} />
            </label>
            <p className="text-muted-foreground text-xs">全部任务收官后生成一份项目汇总报告。</p>
            <label className="flex items-center justify-between gap-3 text-sm">
              <span>子任务都出报告</span>
              <Switch checked={autoReportTasks} onCheckedChange={setAutoReportTasks} />
            </label>
            <p className="text-muted-foreground text-xs">
              每个子任务终态各生成一份任务报告。两个勾选可同时开启（汇总 + 每个子任务各一份）；任务级勾选始终叠加生效。
            </p>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            取消
          </Button>
          <Button onClick={submit} disabled={saving}>
            {saving ? "创建中…" : targetList.length > 0 ? `创建并下发 ${targetList.length} 个任务` : "创建"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// DeleteProjectDialog 永久删除项目：清理项与任务删除完全一致（同一个
// DeleteOptionFields），另外多一个「同时删除旗下任务」开关——关掉时任务保留，
// 只是失去项目归属（后端 FK SET NULL），与任务侧的处置动作保持同一套语义。
function DeleteProjectDialog({
  project,
  onOpenChange,
  onDeleted,
}: {
  project: ProjectWithStats | null;
  onOpenChange: (open: boolean) => void;
  onDeleted: () => void;
}) {
  const [options, setOptions] = React.useState<DeleteTaskOptions>(() => ({
    ...emptyDeleteOptions(),
    // 项目级派生数据（情报表、图谱投影）随项目必删，列表里锁定展示。
    delete_intel: true,
    delete_project_graph: true,
  }));
  const [deleteTasks, setDeleteTasks] = React.useState(false);
  const [deleting, setDeleting] = React.useState(false);

  const open = project !== null;
  const taskCount = project?.stats.task_count ?? 0;

  React.useEffect(() => {
    if (open) {
      setOptions({ ...emptyDeleteOptions(), delete_intel: true, delete_project_graph: true });
      setDeleteTasks(false);
    }
  }, [open]);

  const submit = async () => {
    if (!project) return;
    setDeleting(true);
    try {
      const r = await api.deleteProject(project.id, { ...options, delete_tasks: deleteTasks });
      const parts = [`已删除项目「${project.name}」`];
      if (r.tasks_deleted > 0) parts.push(`删除 ${r.tasks_deleted} 个任务`);
      if (r.tasks_kept > 0) parts.push(`${r.tasks_kept} 个任务保留为未分组`);
      toast.success(parts.join("，"));
      if (r.task_errors?.length) {
        toast.warning(`${r.task_errors.length} 个任务未能删除，已保留：${r.task_errors[0]}`);
      }
      onDeleted();
    } catch (e) {
      toast.error("删除失败：" + (e as Error).message);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <AlertDialog open={open} onOpenChange={(o) => !deleting && onOpenChange(o)}>
      <AlertDialogContent className="sm:max-w-xl">
        <AlertDialogHeader>
          <AlertDialogTitle>永久删除项目「{project?.name}」？</AlertDialogTitle>
          <AlertDialogDescription className="break-words">
            该项目下有 {taskCount} 个任务。项目本身删除后不可恢复。
          </AlertDialogDescription>
        </AlertDialogHeader>

        <div className="max-h-[62vh] space-y-4 overflow-y-auto pr-1">
          <div className="flex items-start justify-between gap-3 rounded-lg border p-3">
            <div className="min-w-0">
              <p className="text-sm font-medium">同时删除旗下 {taskCount} 个任务</p>
              <p className="text-muted-foreground mt-1 text-xs">
                关闭时任务会保留，但会失去项目归属（变为未分组），可稍后重新挂到其他项目。
              </p>
            </div>
            <Switch
              checked={deleteTasks}
              onCheckedChange={setDeleteTasks}
              aria-label="同时删除旗下任务"
              disabled={deleting || taskCount === 0}
            />
          </div>

          <DeleteOptionFields
            idPrefix={`project-${project?.id ?? "x"}`}
            options={options}
            onOptionsChange={setOptions}
            disabled={deleting}
            disabledKeys={deleteTasks ? [] : ["delete_assets", "delete_traffic", "delete_files", "delete_findings", "delete_llm_records"]}
            lockedKeys={["delete_intel", "delete_project_graph"]}
          />
          {taskCount > 0 && !deleteTasks && (
            <p className="text-muted-foreground text-xs">
              任务保留时，资产/流量/文件/漏洞/LLM 记录没有删除对象，仅「情境与复用记录」「项目图谱投影」随项目清除。
            </p>
          )}
        </div>

        <AlertDialogFooter>
          <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
          <AlertDialogAction
            variant="destructive"
            disabled={deleting}
            onClick={(event) => {
              event.preventDefault();
              void submit();
            }}
          >
            {deleting ? "删除中…" : "永久删除"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
