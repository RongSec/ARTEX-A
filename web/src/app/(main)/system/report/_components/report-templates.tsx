"use client";

// 报告中心·模板管理（V9-UI：上传即用）。
//
// 工作流：左侧「新建模板」建空模板并选中 → 预览区空态「请先上传模板」→
// 上传 docx 后直接绑定到当前模板（import-docx 落 staging，再 PATCH 写
// docx_path/name），不再有名称/语言/出具方/章节/字段等设置面板——渲染一律
// 以用户上传的 docx 为底稿填充。
//
// 列：左=模板列表；中=预览（无 docx 时是上传空态，有 docx 时三模式预览 +
// 「替换模板文件」）；右=对话调模板（服务端合并结果直接 PATCH 落库）+ 生成。

import * as React from "react";

import { useSearchParams } from "next/navigation";

import {
  CopyIcon,
  DownloadIcon,
  FileTextIcon,
  FileUpIcon,
  HistoryIcon,
  MoreHorizontalIcon,
  PlusIcon,
  RefreshCwIcon,
  SendIcon,
  Settings2Icon,
  SparklesIcon,
  StarIcon,
  Trash2Icon,
  UploadIcon,
} from "lucide-react";
import { toast } from "sonner";

import { SectionHeader } from "@/components/section-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Spinner } from "@/components/ui/spinner";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { api } from "@/lib/api";
import type { ReportJob, ReportSection, ReportTemplate, ReportTemplateInput, Task } from "@/lib/types";

import { TemplateChat } from "./template-chat";
import { ReportSettingsDialog } from "./report-settings-dialog";
import { TemplatePreview, type PreviewDebugForm, type PreviewSource } from "./template-preview";

// 章节 key 的展示元数据（顺序=默认骨架序；标题与后端 defaultSectionTitles 一致）。
const SECTION_META: { key: ReportSection["key"]; title: string }[] = [
  { key: "cover", title: "封面" },
  { key: "statement", title: "声明" },
  { key: "targets", title: "检测目标" },
  { key: "summary", title: "风险等级汇总" },
  { key: "vuln_detail", title: "漏洞明细" },
  { key: "conclusion", title: "结论与建议" },
];

const LOCALES = [
  { v: "zh-CN", label: "简体中文" },
  { v: "en-US", label: "English" },
];

// defaultSkeleton：默认全开六章（与后端 ParseSkeletonJSON(nil) 同构）。
function defaultSkeleton(): ReportSection[] {
  return SECTION_META.map((m) => ({ key: m.key, title: m.title, enabled: true }));
}

function readIntParam(v: string | null): number | null {
  if (!v) return null;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : null;
}

export function ReportTemplatesSection() {
  // useSearchParams 在静态导出下要求 Suspense 边界（CSR 预渲染填充）。
  return (
    <React.Suspense fallback={null}>
      <ReportTemplatesInner />
    </React.Suspense>
  );
}

function ReportTemplatesInner() {
  const searchParams = useSearchParams();
  // T19 项目详情页跳转参数（一次性消费，存 ref 防刷新列表时反复覆盖选择）。
  const urlTemplateId = React.useRef<number | null>(readIntParam(searchParams.get("template_id")));
  const urlProjectId = React.useRef<string>(searchParams.get("project_id") ?? "");

  const [templates, setTemplates] = React.useState<ReportTemplate[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [creating, setCreating] = React.useState(false);
  const [selectedId, setSelectedId] = React.useState<number | null>(null);

  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [projects, setProjects] = React.useState<{ id: number; name: string }[]>([]);
  const [previewSource, setPreviewSource] = React.useState<PreviewSource>("demo");
  const [previewForm, setPreviewForm] = React.useState<PreviewDebugForm>({
    task_id: "",
    project_id: "",
    locale: "zh-CN",
  });
  const [chatTick, setChatTick] = React.useState(0); // 对话应用补丁 +1 → 预览立即重渲

  // 模板原件上传（新建/替换共用）：选文件 → import-docx → PATCH 绑定。
  const fileRef = React.useRef<HTMLInputElement | null>(null);
  const [uploading, setUploading] = React.useState(false);

  // URL 预填（进页一次）：project_id → 预览源切项目并带上；template_id 消费在
  // loadTemplates 里（要等列表回来才知道该模板存不存在）。
  React.useEffect(() => {
    const pid = urlProjectId.current;
    if (pid) {
      setPreviewSource("project");
      setPreviewForm((f) => ({ ...f, project_id: pid }));
    }
  }, []);

  // 生成对话框（正式 job）：范围跟随预览源（demo=样例不可正式生成）。
  const [genOpen, setGenOpen] = React.useState(false);
  const [genForm, setGenForm] = React.useState<{
    scope: "task" | "project";
    task_id: string;
    project_id: string;
    locale: string;
    format: "docx" | "md";
  }>({
    scope: "project",
    task_id: "",
    project_id: "",
    locale: "zh-CN",
    format: "docx",
  });

  const [jobs, setJobs] = React.useState<ReportJob[]>([]);
  const [jobsLoading, setJobsLoading] = React.useState(false);
  const [historyOpen, setHistoryOpen] = React.useState(false);
  const [settingsOpen, setSettingsOpen] = React.useState(false);
  const pollRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

  const selected = React.useMemo(() => templates.find((t) => t.id === selectedId) ?? null, [templates, selectedId]);
  // 预览/对话统一吃模板行（只读，不再有本地编辑态）。
  const draft = React.useMemo(() => (selected ? templateToDraft(selected) : null), [selected]);

  // ---- 加载 ----
  const loadTemplates = React.useCallback(async (keepSelection = true) => {
    setLoading(true);
    try {
      const list = await api.reportTemplates();
      setTemplates(list);
      setSelectedId((cur) => {
        // URL template_id 只在首次加载时消费一次（ref 清空后不再干扰）。
        const want = urlTemplateId.current;
        if (want != null) {
          urlTemplateId.current = null;
          if (list.some((t) => t.id === want)) return want;
        }
        if (keepSelection && cur != null && list.some((t) => t.id === cur)) return cur;
        return list[0]?.id ?? null;
      });
    } catch (e) {
      toast.error(`加载模板失败：${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadJobs = React.useCallback(async () => {
    setJobsLoading(true);
    try {
      const { items } = await api.reports(1, 50);
      setJobs(items);
    } catch (e) {
      toast.error(`加载历史失败：${(e as Error).message}`);
    } finally {
      setJobsLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void loadTemplates(false);
    void loadJobs();
    api
      .tasks()
      .then((r) => setTasks(r.tasks))
      .catch(() => undefined);
    api
      .projects("active")
      .then((r) => setProjects(r.projects.map((p) => ({ id: p.id, name: p.name }))))
      .catch(() => undefined);
  }, [loadTemplates, loadJobs]);

  // 有 pending/running job 时轮询历史（终态自动停）。
  React.useEffect(() => {
    const active = jobs.some((j) => j.status === "pending" || j.status === "running");
    if (!active) {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
      return;
    }
    if (pollRef.current) return;
    pollRef.current = setInterval(() => void loadJobs(), 3000);
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [jobs, loadJobs]);

  // ---- 模板原件上传 ----

  const uploadFile = async (file: File) => {
    if (!selectedId) {
      toast.error("请先新建或选择一个模板");
      return;
    }
    setUploading(true);
    try {
      const r = await api.importTemplateDocx(file);
      const docxPath = r.draft.docx_path?.trim();
      if (!docxPath) throw new Error("导入结果缺少模板原件路径");
      const name = file.name.replace(/\.(docx|md|markdown|txt)$/i, "") || r.draft.name;
      // 同名模板已存在 → 绑定到它（提示「已更新」），否则绑定到当前模板。
      const targetId = r.matched_template?.id ?? selectedId;
      const t = await api.updateReportTemplate(targetId, { docx_path: docxPath, name });
      await loadTemplates(false);
      setSelectedId(t.id);
      setChatTick((x) => x + 1);
      if (r.matched_template) toast.success(`已更新模板「${t.name}」`);
      else toast.success(`模板已上传：${t.name}`);
    } catch (e) {
      toast.error(`上传失败：${(e as Error).message}`);
    } finally {
      setUploading(false);
    }
  };

  const pickFile = () => fileRef.current?.click();

  // ---- CRUD ----
  const createNew = async () => {
    setCreating(true);
    try {
      // 空模板：不传骨架（服务端给默认骨架），也不弹任何设置表单。
      const base = "新建模板";
      const names = new Set(templates.map((t) => t.name));
      let name = base;
      for (let i = 2; names.has(name); i += 1) name = `${base} ${i}`;
      const t = await api.createReportTemplate({ name });
      await loadTemplates(false);
      setSelectedId(t.id);
      toast.success("已新建空模板，请上传模板文件");
    } catch (e) {
      toast.error(`新建失败：${(e as Error).message}`);
    } finally {
      setCreating(false);
    }
  };

  // 复制不带模板原件（原件按模板 id 归位，共用会让两份模板抢同一文件）。
  const duplicate = async (t: ReportTemplate) => {
    try {
      const copy = await api.createReportTemplate({
        ...templateToDraft(t),
        docx_path: "",
        name: `${t.name}（副本）`,
      });
      await loadTemplates(false);
      setSelectedId(copy.id);
      toast.success("已复制");
    } catch (e) {
      toast.error(`复制失败：${(e as Error).message}`);
    }
  };

  const setDefault = async (id: number) => {
    try {
      await api.setDefaultReportTemplate(id);
      await loadTemplates(true);
      toast.success("已设为默认");
    } catch (e) {
      toast.error(`设置失败：${(e as Error).message}`);
    }
  };

  // 蒸馏为 Skill（R4；T20 端点幂等：同哨兵目录覆盖；非哨兵 409 如实报错）。
  const [toSkillBusy, setToSkillBusy] = React.useState(false);
  const [skillResult, setSkillResult] = React.useState<{
    skill_name: string;
    dir?: string;
    checks?: { skill_md: boolean; meta: boolean; size: number };
  } | null>(null);
  const [skillOpen, setSkillOpen] = React.useState(false);
  const [skillExported, setSkillExported] = React.useState<Record<number, string>>({});
  // V9-RULE：蒸馏前命名 + SKILL.md 预览。
  const DISTILL_NAME_RE = /^[a-z0-9][a-z0-9-_]{1,48}$/;
  const [distillOpen, setDistillOpen] = React.useState(false);
  const [distillName, setDistillName] = React.useState("");
  const [distillDisplay, setDistillDisplay] = React.useState("");
  const [distillErr, setDistillErr] = React.useState("");
  const [previewBusy, setPreviewBusy] = React.useState(false);
  const [skillPreview, setSkillPreview] = React.useState<{
    content: string;
    truncated: boolean;
    skill_name?: string;
    bound_skill?: string;
    target_exists?: boolean;
    target_owner_id?: number;
    target_owner_name?: string;
  } | null>(null);

  const openDistill = () => {
    if (selectedId == null) return;
    // 优先带出模板已绑定的 skill：留空即覆盖它，不会每次生成新的。
    setDistillName(selected?.skill_name || skillExported[selectedId] || "");
    setDistillDisplay(draft?.name ?? "");
    setDistillErr("");
    setSkillPreview(null);
    setDistillOpen(true);
  };

  const previewDistill = async () => {
    if (selectedId == null) return;
    const name = distillName.trim();
    if (name && !DISTILL_NAME_RE.test(name)) {
      setDistillErr("名称需以小写字母或数字开头，仅含小写字母/数字/-/_，长度 2-49");
      return;
    }
    setPreviewBusy(true);
    setDistillErr("");
    try {
      const r = await api.reportTemplateSkillPreview(selectedId, {
        name: name || undefined,
        display_name: distillDisplay.trim() || undefined,
      });
      setSkillPreview({ content: r.content, truncated: r.truncated });
    } catch (e) {
      setDistillErr(`预览失败：${(e as Error).message}`);
    } finally {
      setPreviewBusy(false);
    }
  };

  const toSkill = async () => {
    if (selectedId == null) return;
    const name = distillName.trim();
    if (name && !DISTILL_NAME_RE.test(name)) {
      setDistillErr("名称需以小写字母或数字开头，仅含小写字母/数字/-/_，长度 2-49");
      return;
    }
    setToSkillBusy(true);
    setDistillErr("");
    try {
      // 先问服务端目标状态：已存在才弹确认，避免「以为新建、实际覆盖」。
      const pv = await api.reportTemplateSkillPreview(selectedId, {
        name: name || undefined,
        display_name: distillDisplay.trim() || undefined,
      });
      let overwrite = false;
      if (pv.target_exists) {
        const owner =
          pv.target_owner_id && pv.target_owner_id !== selectedId
            ? `模板 #${pv.target_owner_id}「${pv.target_owner_name ?? ""}」`
            : pv.bound_skill
              ? "本模板已绑定"
              : "此前导出";
        const ok = window.confirm(
          `Skill「${pv.skill_name}」已存在（${owner}）。\n覆盖后，手工改过的内容会丢失。继续？`,
        );
        if (!ok) {
          setToSkillBusy(false);
          return;
        }
        overwrite = true;
      }
      const r = await api.reportTemplateToSkill(selectedId, {
        name: name || undefined,
        display_name: distillDisplay.trim() || undefined,
        overwrite,
      });
      setSkillResult(r);
      setDistillOpen(false);
      setSkillOpen(true);
      setSkillExported((m) => ({ ...m, [selectedId]: r.skill_name }));
      void loadTemplates(false);
      toast.success(`已蒸馏为 Skill：${r.skill_name}${r.overwritten ? "（已覆盖）" : ""}`);
    } catch (e) {
      setDistillErr(`蒸馏为 Skill 失败：${(e as Error).message}`);
    } finally {
      setToSkillBusy(false);
    }
  };

  // 对话合并结果：没有设置面板可点了「保存」，直接 PATCH 落库。
  const applyChatTemplate = async (t: ReportTemplateInput) => {
    if (!draft || selectedId == null) return;
    try {
      await api.updateReportTemplate(selectedId, {
        name: t.name ?? draft.name,
        output_lang: t.output_lang ?? draft.output_lang,
        skeleton: t.skeleton ?? draft.skeleton,
        style: t.style ?? draft.style,
        prompts: t.prompts ?? draft.prompts,
        issuer: t.issuer ?? draft.issuer,
        personnel: t.personnel ?? draft.personnel,
        cvss_enabled: t.cvss_enabled ?? draft.cvss_enabled,
        remark: t.remark ?? draft.remark,
      });
      await loadTemplates(true);
      setChatTick((x) => x + 1);
      toast.success("对话修改已应用");
    } catch (e) {
      toast.error(`应用修改失败：${(e as Error).message}`);
    }
  };

  const [confirmDel, setConfirmDel] = React.useState<ReportTemplate | null>(null);
  const doDelete = async () => {
    if (!confirmDel) return;
    try {
      await api.deleteReportTemplate(confirmDel.id);
      await loadTemplates(false);
      toast.success("已删除");
    } catch (e) {
      toast.error(`删除失败：${(e as Error).message}`);
    } finally {
      setConfirmDel(null);
    }
  };

  // V9-UI2：重命名只改 name（PATCH 只提交 name，docx_path/版本号不动、不触发归档）。
  const [renameTarget, setRenameTarget] = React.useState<ReportTemplate | null>(null);
  const [renameValue, setRenameValue] = React.useState("");
  const [renaming, setRenaming] = React.useState(false);
  const openRename = (t: ReportTemplate) => {
    setRenameTarget(t);
    setRenameValue(t.name);
  };
  const doRename = async () => {
    if (!renameTarget) return;
    const name = renameValue.trim();
    if (!name) {
      toast.error("名称不能为空");
      return;
    }
    if (name === renameTarget.name) {
      setRenameTarget(null);
      return;
    }
    setRenaming(true);
    try {
      await api.updateReportTemplate(renameTarget.id, { name });
      await loadTemplates(true); // 列表 + 选中项名称一起刷新
      toast.success(`已重命名为「${name}」`);
      setRenameTarget(null);
    } catch (e) {
      toast.error(`重命名失败：${(e as Error).message}`);
    } finally {
      setRenaming(false);
    }
  };

  // ---- 正式生成（建 job→轮询）：对话框确认 ----
  const openGenerate = () => {
    // 默认跟随当前预览上下文；demo 样例不可正式生成→回项目/任务首个。
    setGenForm((g) => ({
      ...g,
      scope: previewSource === "project" ? "project" : previewSource === "task" ? "task" : g.scope,
      project_id: previewSource === "project" ? previewForm.project_id : g.project_id,
      task_id: previewSource === "task" ? previewForm.task_id : g.task_id,
      locale: previewForm.locale || g.locale,
    }));
    setGenOpen(true);
  };
  const generate = async () => {
    if (genForm.scope === "task" ? !genForm.task_id : !genForm.project_id) {
      toast.error("请选择任务或项目");
      return;
    }
    try {
      const job = await api.reportGenerate({
        scope: genForm.scope,
        task_id: genForm.scope === "task" ? Number(genForm.task_id) : undefined,
        project_id: genForm.scope === "project" ? Number(genForm.project_id) : undefined,
        template_id: selectedId ?? undefined,
        locale: genForm.locale || undefined,
        format: genForm.format,
      });
      toast.success(`报告任务 #${job.id} 已提交`);
      setGenOpen(false);
      setHistoryOpen(true);
      await loadJobs();
    } catch (e) {
      toast.error(`生成失败：${(e as Error).message}`);
    }
  };

  const downloadJob = async (j: ReportJob) => {
    try {
      const { filename } = await api.downloadReportJob(j.id);
      toast.success(`已下载 ${filename}`);
    } catch (e) {
      toast.error(`下载失败：${(e as Error).message}`);
    }
  };

  const delJob = async (j: ReportJob) => {
    try {
      await api.deleteReport(j.id);
      await loadJobs();
      toast.success("已删除");
    } catch (e) {
      toast.error(`删除失败：${(e as Error).message}`);
    }
  };

  return (
    <TooltipProvider>
      <section data-section="report-templates" className="flex flex-col gap-4">
        <SectionHeader
          icon={FileTextIcon}
          title="报告中心"
          description="上传 Word 模板即可生成报告：对话调整模板、实时预览结构、导入/导出 skill 并生成 Word 报告。"
          actions={
            <>
              <Button variant="outline" size="sm" onClick={() => void loadTemplates(true)} disabled={loading}>
                <RefreshCwIcon className={loading ? "animate-spin" : ""} /> 刷新
              </Button>
              <Button variant="outline" size="sm" onClick={() => setHistoryOpen(true)}>
                <HistoryIcon /> 生成历史
              </Button>
              <Button variant="outline" size="sm" onClick={() => setSettingsOpen(true)}>
                <Settings2Icon /> 报告设置
              </Button>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={openDistill}
                    disabled={selectedId == null || toSkillBusy}
                  >
                    {toSkillBusy ? <Spinner /> : <SendIcon data-icon="inline-start" className="rotate-[-35deg]" />}{" "}
                    蒸馏为 Skill
                  </Button>
                </TooltipTrigger>
                <TooltipContent>把当前模板蒸馏为 skills/ 下的报告模板 skill（同名再次蒸馏会先确认覆盖）</TooltipContent>
              </Tooltip>
              <Button size="sm" onClick={openGenerate} disabled={selectedId == null}>
                <SparklesIcon /> 生成报告
              </Button>
            </>
          }
        />

        <input
          ref={fileRef}
          type="file"
          accept=".docx"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0] ?? null;
            e.target.value = ""; // 允许重复选择同一文件
            if (f) void uploadFile(f);
          }}
        />

        <div className="grid gap-4 lg:grid-cols-[270px_minmax(0,1.4fr)_minmax(0,1fr)] lg:items-stretch lg:gap-6">
          {/* 左：模板列表（顶部新建） */}
          <Card className="flex flex-col">
            <CardHeader className="gap-2 pb-2">
              <CardTitle className="text-sm">模板</CardTitle>
              <Button variant="outline" size="sm" className="w-full" onClick={() => void createNew()} disabled={creating}>
                {creating ? <Spinner /> : <PlusIcon />} 新建模板
              </Button>
            </CardHeader>
            <CardContent className="flex-1 p-2">
              {loading && templates.length === 0 ? (
                <div className="flex justify-center py-8">
                  <Spinner />
                </div>
              ) : templates.length === 0 ? (
                <p className="text-muted-foreground p-4 text-center text-sm">暂无模板，点「新建模板」。</p>
              ) : (
                <div className="max-h-[72vh] overflow-y-auto">
                  <div className="flex flex-col gap-1 pr-2">
                    {templates.map((t) => (
                      <button
                        key={t.id}
                        type="button"
                        onClick={() => setSelectedId(t.id)}
                        className={`flex w-full items-center justify-between gap-2 rounded-md px-3 py-2 text-left text-sm hover:bg-muted ${
                          selectedId === t.id ? "bg-muted font-medium" : ""
                        }`}
                      >
                        <span className="flex min-w-0 items-center gap-1.5">
                          {t.is_default && <StarIcon className="size-3.5 shrink-0 fill-amber-400 text-amber-400" />}
                          <span className="min-w-0 truncate" title={t.name}>
                            {t.name}
                          </span>
                          {!t.docx_path && (
                            <Badge
                              variant="outline"
                              className="shrink-0 border-amber-400 px-1 py-0 text-[10px] text-amber-600"
                            >
                              待上传
                            </Badge>
                          )}
                        </span>
                        <span className="flex shrink-0 gap-0.5">
                          {!t.is_default && (
                            <IconBtn
                              title="设为默认"
                              onClick={(e) => {
                                e.stopPropagation();
                                void setDefault(t.id);
                              }}
                            >
                              <StarIcon className="size-3.5" />
                            </IconBtn>
                          )}
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <span
                                role="button"
                                tabIndex={-1}
                                title="更多"
                                aria-label="更多操作"
                                onClick={(e) => e.stopPropagation()}
                                className="text-muted-foreground hover:text-foreground hover:bg-muted inline-flex size-6 items-center justify-center rounded"
                              >
                                <MoreHorizontalIcon className="size-4" />
                              </span>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" onClick={(e) => e.stopPropagation()}>
                              <DropdownMenuItem onSelect={() => openRename(t)}>重命名</DropdownMenuItem>
                              <DropdownMenuItem onSelect={() => void duplicate(t)}>
                                <CopyIcon /> 复制
                              </DropdownMenuItem>
                              <DropdownMenuItem variant="destructive" onSelect={() => setConfirmDel(t)}>
                                <Trash2Icon /> 删除
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* 中：实时预览；未上传模板文件时只显示上传空态。 */}
          <Card className="flex min-h-[60vh] flex-col lg:h-[calc(100dvh-10rem)] lg:min-h-0">
            <CardContent className="flex min-h-0 flex-1 flex-col p-3">
              {!selected ? (
                <div className="text-muted-foreground flex h-full items-center justify-center p-6 text-center text-sm">
                  选择或新建一个模板开始。
                </div>
              ) : !selected.docx_path ? (
                <div className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center">
                  <div className="bg-muted rounded-full p-3">
                    <FileUpIcon className="text-muted-foreground size-6" />
                  </div>
                  <p className="text-sm font-medium">请先上传模板</p>
                  <p className="text-muted-foreground max-w-xs text-xs">上传你的 Word 报告，系统按它的版式填充内容</p>
                  <Button size="sm" onClick={pickFile} disabled={uploading}>
                    {uploading ? <Spinner /> : <UploadIcon />} 上传模板
                  </Button>
                </div>
              ) : (
                <TemplatePreview
                  draft={draft}
                  source={previewSource}
                  setSource={setPreviewSource}
                  form={previewForm}
                  setForm={setPreviewForm}
                  tasks={tasks}
                  projects={projects}
                  chatTick={chatTick}
                  extraActions={
                    <Button variant="outline" size="sm" onClick={pickFile} disabled={uploading}>
                      {uploading ? <Spinner /> : <UploadIcon />} 替换模板文件
                    </Button>
                  }
                />
              )}
            </CardContent>
          </Card>

          {/* 右：对话调模板（合并结果直接落库） */}
          <div className="flex min-h-0 flex-col gap-4">
            <Card className="flex min-h-[40vh] flex-col lg:min-h-0 lg:flex-1">
              <CardContent className="flex min-h-0 flex-1 flex-col p-3">
                <TemplateChat
                  templateId={selectedId}
                  draft={draft}
                  onApplyTemplate={(t) => void applyChatTemplate(t)}
                  locale={previewForm.locale}
                  preview={
                    previewSource === "demo"
                      ? { demo: true, locale: previewForm.locale }
                      : previewSource === "task"
                        ? {
                            demo: false,
                            scope: "task",
                            task_id: Number(previewForm.task_id) || undefined,
                            locale: previewForm.locale,
                          }
                        : {
                            demo: false,
                            scope: "project",
                            project_id: Number(previewForm.project_id) || undefined,
                            locale: previewForm.locale,
                          }
                  }
                />
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* 生成历史 Dialog */}
      <Dialog open={historyOpen} onOpenChange={setHistoryOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center justify-between">
              生成历史
              <Button variant="ghost" size="icon" onClick={() => void loadJobs()} disabled={jobsLoading}>
                <RefreshCwIcon className={jobsLoading ? "animate-spin" : ""} />
              </Button>
            </DialogTitle>
          </DialogHeader>
          {jobs.length === 0 ? (
            <p className="text-muted-foreground py-8 text-center text-sm">暂无生成记录。</p>
          ) : (
            <ScrollArea className="max-h-[60vh]">
              <div className="flex flex-col gap-2 pr-2">
                {jobs.map((j) => (
                  <JobRow key={j.id} job={j} onDownload={() => void downloadJob(j)} onDelete={() => void delJob(j)} />
                ))}
              </div>
            </ScrollArea>
          )}
        </DialogContent>
      </Dialog>

      {/* V9-UI3：报告设置（名称模板） */}
      <ReportSettingsDialog
        open={settingsOpen}
        onOpenChange={setSettingsOpen}
        onSaved={() => void loadTemplates(true)}
      />

      {/* 正式生成确认 Dialog */}
      <Dialog open={genOpen} onOpenChange={setGenOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>生成报告</DialogTitle>
          </DialogHeader>
          <div className="grid gap-3 py-2">
            <Field label="范围">
              <NativeSelect
                value={genForm.scope}
                onChange={(e) => setGenForm((f) => ({ ...f, scope: e.target.value as "task" | "project" }))}
              >
                <NativeSelectOption value="task">单任务</NativeSelectOption>
                <NativeSelectOption value="project">项目汇总</NativeSelectOption>
              </NativeSelect>
            </Field>
            <Field label={genForm.scope === "task" ? "任务" : "项目"}>
              {genForm.scope === "task" ? (
                <NativeSelect
                  value={genForm.task_id}
                  onChange={(e) => setGenForm((f) => ({ ...f, task_id: e.target.value }))}
                >
                  <NativeSelectOption value="">— 选择任务 —</NativeSelectOption>
                  {tasks.map((t) => (
                    <NativeSelectOption key={t.id} value={t.id}>
                      {t.name || t.description.slice(0, 30)}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              ) : (
                <NativeSelect
                  value={genForm.project_id}
                  onChange={(e) => setGenForm((f) => ({ ...f, project_id: e.target.value }))}
                >
                  <NativeSelectOption value="">— 选择项目 —</NativeSelectOption>
                  {projects.map((pr) => (
                    <NativeSelectOption key={pr.id} value={String(pr.id)}>
                      {pr.name}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              )}
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="输出语言">
                <NativeSelect
                  value={genForm.locale}
                  onChange={(e) => setGenForm((f) => ({ ...f, locale: e.target.value }))}
                >
                  {LOCALES.map((l) => (
                    <NativeSelectOption key={l.v} value={l.v}>
                      {l.label}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              </Field>
              <Field label="格式">
                <NativeSelect
                  value={genForm.format}
                  onChange={(e) => setGenForm((f) => ({ ...f, format: e.target.value as "docx" | "md" }))}
                >
                  <NativeSelectOption value="docx">Word (.docx)</NativeSelectOption>
                  <NativeSelectOption value="md">Markdown (.md)</NativeSelectOption>
                </NativeSelect>
              </Field>
            </div>
            <p className="text-muted-foreground text-xs">
              按模板原件版式渲染（当前模板：{selected ? selected.name : "默认模板"}），进队列异步生成并落历史。
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setGenOpen(false)}>
              取消
            </Button>
            <Button onClick={() => void generate()}>提交生成</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* V9-RULE：蒸馏前命名 + 预览 SKILL.md */}
      <Dialog open={distillOpen} onOpenChange={(o) => !toSkillBusy && setDistillOpen(o)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>蒸馏为 Skill</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-1">
            <div className="space-y-1.5">
              <Label htmlFor="distill-name" className="text-xs">
                Skill 名称
              </Label>
              <Input
                id="distill-name"
                value={distillName}
                onChange={(e) => setDistillName(e.target.value)}
                placeholder="留空自动生成，如 report-mall"
                className="font-mono text-xs"
              />
              <p className="text-muted-foreground text-[11px]">
                小写字母或数字开头，仅含小写字母/数字/-/_，长度 2-49。
              </p>
              {selected?.skill_name ? (
                <p className="text-[11px] text-amber-600">
                  本模板已绑定 Skill「{selected.skill_name}」，留空将覆盖同一个；改名则新建并改绑。
                </p>
              ) : null}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="distill-display" className="text-xs">
                显示名（中文名，可选）
              </Label>
              <Input
                id="distill-display"
                value={distillDisplay}
                onChange={(e) => setDistillDisplay(e.target.value)}
                placeholder="如 商城系统渗透测试报告模板"
              />
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => void previewDistill()} disabled={previewBusy}>
                {previewBusy ? <Spinner /> : null} 预览 SKILL.md
              </Button>
              {skillPreview ? (
                <span className="text-muted-foreground text-[11px]">
                  已预览{skillPreview.truncated ? "（前 2000 字符）" : "全文"}
                </span>
              ) : null}
            </div>
            {skillPreview ? (
              <pre className="bg-muted max-h-56 overflow-auto rounded-md p-2 font-mono text-[11px] whitespace-pre-wrap">
                {skillPreview.content}
              </pre>
            ) : null}
            {distillErr ? <p className="text-destructive text-xs">{distillErr}</p> : null}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDistillOpen(false)} disabled={toSkillBusy}>
              取消
            </Button>
            <Button onClick={() => void toSkill()} disabled={toSkillBusy}>
              {toSkillBusy ? <Spinner /> : null} {skillPreview?.target_exists ? "覆盖并蒸馏" : "开始蒸馏"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* R4：蒸馏为 Skill 结果（名称 + 磁盘路径 + 再次蒸馏） */}
      <Dialog open={skillOpen} onOpenChange={setSkillOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>已蒸馏为 Skill</DialogTitle>
          </DialogHeader>
          <div className="space-y-2 py-1 text-sm">
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">Skill 名称</span>
              <code className="bg-muted rounded px-1.5 py-0.5">{skillResult?.skill_name}</code>
            </div>
            <div className="space-y-1">
              <span className="text-muted-foreground">存放路径</span>
              <code className="bg-muted block rounded px-1.5 py-0.5 text-xs break-all">{skillResult?.dir}</code>
            </div>
            {skillResult?.checks ? (
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <Badge variant={skillResult.checks.skill_md ? "secondary" : "destructive"}>SKILL.md</Badge>
                <Badge variant={skillResult.checks.meta ? "secondary" : "destructive"}>前置元数据</Badge>
                <Badge variant="outline">{skillResult.checks.size} 字节</Badge>
              </div>
            ) : null}
            <p className="text-muted-foreground text-xs">
              该 skill 含 SKILL.md / template.json / manifest.json，可拷贝到其它机器后复用到别处。
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setSkillOpen(false)}>
              关闭
            </Button>
            <Button onClick={() => void toSkill()} disabled={toSkillBusy || selectedId == null}>
              {toSkillBusy ? <Spinner /> : null} 再次蒸馏（覆盖同名）
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* V9-UI2：重命名模板（只写 name） */}
      <Dialog open={renameTarget != null} onOpenChange={(o) => !renaming && !o && setRenameTarget(null)}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle>重命名模板</DialogTitle>
          </DialogHeader>
          <div className="space-y-1.5 py-1">
            <Label htmlFor="template-rename" className="text-xs">
              模板名称
            </Label>
            <Input
              id="template-rename"
              value={renameValue}
              autoFocus
              onChange={(e) => setRenameValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void doRename();
              }}
              placeholder="请输入模板名称"
            />
            <p className="text-muted-foreground text-[11px]">只改名称，模板文件与版本号不变。</p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRenameTarget(null)} disabled={renaming}>
              取消
            </Button>
            <Button onClick={() => void doRename()} disabled={renaming}>
              {renaming ? <Spinner /> : null} 确定
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={confirmDel != null} onOpenChange={(o) => !o && setConfirmDel(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>删除模板</DialogTitle>
          </DialogHeader>
          <p className="text-sm">确定删除模板「{confirmDel?.name}」？此操作不可撤销。</p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmDel(null)}>
              取消
            </Button>
            <Button variant="destructive" onClick={() => void doDelete()}>
              删除
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </TooltipProvider>
  );
}

function IconBtn({
  title,
  onClick,
  children,
}: {
  title: string;
  onClick: (e: React.MouseEvent) => void;
  children: React.ReactNode;
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          role="button"
          tabIndex={-1}
          title={title}
          onClick={onClick}
          className="text-muted-foreground hover:text-foreground hover:bg-muted inline-flex size-6 items-center justify-center rounded"
        >
          {children}
        </span>
      </TooltipTrigger>
      <TooltipContent>{title}</TooltipContent>
    </Tooltip>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <span className="text-muted-foreground text-xs">{label}</span>
      {children}
    </div>
  );
}

// ---- 历史行 ----
function JobRow({ job, onDownload, onDelete }: { job: ReportJob; onDownload: () => void; onDelete: () => void }) {
  const isTerminal = job.status === "done" || job.status === "failed";
  return (
    <div className="flex items-center gap-2 rounded-md border px-3 py-2 text-sm">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span className="text-muted-foreground">#{job.id}</span>
          <StatusBadge status={job.status} />
          {job.warning && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Badge variant="outline" className="border-amber-400 text-amber-600">
                  警告
                </Badge>
              </TooltipTrigger>
              <TooltipContent className="max-w-xs">{job.warning}</TooltipContent>
            </Tooltip>
          )}
          {job.status === "failed" && job.error && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Badge variant="outline" className="border-rose-400 text-rose-600">
                  错误
                </Badge>
              </TooltipTrigger>
              <TooltipContent className="max-w-xs">{job.error}</TooltipContent>
            </Tooltip>
          )}
        </div>
        <div className="text-muted-foreground mt-0.5 truncate text-xs">
          {job.scope === "project" ? `项目#${job.project_id}` : `任务#${job.task_id}`} · {job.format} ·{" "}
          {fmtTime(job.created_at)}
        </div>
      </div>
      {job.status === "done" && (
        <IconBtn title="下载" onClick={onDownload}>
          <DownloadIcon className="size-4" />
        </IconBtn>
      )}
      {isTerminal && (
        <IconBtn title="删除" onClick={onDelete}>
          <Trash2Icon className="size-4" />
        </IconBtn>
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: ReportJob["status"] }) {
  const map: Record<ReportJob["status"], { label: string; cls: string }> = {
    pending: { label: "排队中", cls: "bg-muted text-muted-foreground" },
    running: { label: "生成中", cls: "bg-sky-500/15 text-sky-600" },
    done: { label: "已完成", cls: "bg-emerald-500/15 text-emerald-600" },
    failed: { label: "失败", cls: "bg-rose-500/15 text-rose-600" },
  };
  const m = map[status];
  return (
    <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium ${m.cls}`}>
      {status === "running" && <Spinner className="size-3" />}
      {m.label}
    </span>
  );
}

function fmtTime(iso: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// templateToDraft：把后端模板行投影成预览/对话用的输入形态（不再可编辑）。
function templateToDraft(t: ReportTemplate): ReportTemplateInput {
  const skeleton = t.skeleton?.length ? t.skeleton : defaultSkeleton();
  return {
    name: t.name,
    output_lang: t.output_lang,
    skeleton: skeleton.map((s) => ({ ...s })),
    style: { ...(t.style ?? {}) },
    prompts: { ...(t.prompts ?? {}) },
    issuer: t.issuer ?? "",
    logo_path: t.logo_path ?? "",
    personnel: (t.personnel ?? []).map((x) => ({ ...x })),
    cvss_enabled: !!t.cvss_enabled,
    remark: t.remark ?? "",
    docx_path: t.docx_path ?? "",
  };
}
