"use client";

// 报告中心（artex-hs T16 起，T21 改版）：模板管理 + 对话调模板 + 实时预览 +
// 导入/导出 skill + 生成历史。
//
// 三列（lg 起，设计 §1.2A）：
//   左 = 模板列表（新建/复制/设默认/删）+ 生成历史入口（Dialog）
//   中 = 实时预览（iframe，render-draft format=html；800ms 防抖+AbortController；
//        数据源=样例/任务/项目；模板走 inline 草稿=未保存也所见即所调）
//   右 = 对话调模板（template-chat，补丁合并进草稿不落库）+ 设置折叠区
//        （原 TemplateEditor 收进来，未重写）+ 正式生成
// 工具条：「导入模板」（docx/md 上传反推 / 从 skill 读预填，均不自动建）与
// 「转成 Skill」（幂等哨兵覆盖）。
// URL ?project_id=&template_id=（T19 项目页跳转的接收端）：进页预选模板并把
// 预览源切到该项目。
//
// 风格照 system/notify + function/projects 页（shadcn、既有表格/对话框，不引
// 新依赖）。章节骨架的 key 枚举与后端 db.ReportSectionKey 同步。

import * as React from "react";
import { useSearchParams } from "next/navigation";

import {
  CopyIcon,
  DownloadIcon,
  FileInputIcon,
  FileTextIcon,
  GripVerticalIcon,
  HistoryIcon,
  PlusIcon,
  RefreshCwIcon,
  SendIcon,
  SparklesIcon,
  StarIcon,
  Trash2Icon,
  WandSparklesIcon,
} from "lucide-react";
import { toast } from "sonner";

import { TemplateChat } from "./_components/template-chat";
import { TemplatePreview, type PreviewDebugForm, type PreviewSource } from "./_components/template-preview";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
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
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { api } from "@/lib/api";
import type {
  ReportImportResult,
  ReportJob,
  ReportPerson,
  ReportSection,
  ReportSectionKey,
  ReportTemplate,
  ReportTemplateInput,
  SkillItem,
  Task,
} from "@/lib/types";

// 章节 key 的展示元数据（顺序=默认骨架序；标题回退与后端 defaultSectionTitles 一致）。
const SECTION_META: { key: ReportSectionKey; title: string }[] = [
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

export default function ReportCenterPage() {
  // useSearchParams 在静态导出下要求 Suspense 边界（CSR 预渲染填充）。
  return (
    <React.Suspense fallback={null}>
      <ReportCenterInner />
    </React.Suspense>
  );
}

function ReportCenterInner() {
  const searchParams = useSearchParams();
  // T19 项目详情页跳转参数（一次性消费，存 ref 防刷新列表时反复覆盖选择）。
  const urlTemplateId = React.useRef<number | null>(readIntParam(searchParams.get("template_id")));
  const urlProjectId = React.useRef<string>(searchParams.get("project_id") ?? "");

  const [templates, setTemplates] = React.useState<ReportTemplate[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [selectedId, setSelectedId] = React.useState<number | null>(null);
  const [draft, setDraft] = React.useState<ReportTemplateInput | null>(null); // 编辑态（null=未选）
  const [dirty, setDirty] = React.useState(false);
  const [saving, setSaving] = React.useState(false);

  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [projects, setProjects] = React.useState<{ id: number; name: string }[]>([]);
  const [previewSource, setPreviewSource] = React.useState<PreviewSource>("demo");
  const [previewForm, setPreviewForm] = React.useState<PreviewDebugForm>({
    task_id: "",
    project_id: "",
    locale: "zh-CN",
  });
  const [chatTick, setChatTick] = React.useState(0); // 对话应用补丁 +1 → 预览立即重渲

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
  const [genForm, setGenForm] = React.useState<{ scope: "task" | "project"; task_id: string; project_id: string; locale: string; format: "docx" | "md" }>({
    scope: "project",
    task_id: "",
    project_id: "",
    locale: "zh-CN",
    format: "docx",
  });

  const [jobs, setJobs] = React.useState<ReportJob[]>([]);
  const [jobsLoading, setJobsLoading] = React.useState(false);
  const [historyOpen, setHistoryOpen] = React.useState(false);
  const pollRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

  // 导入对话框（docx/md）。
  const [importDocxOpen, setImportDocxOpen] = React.useState(false);
  const [importing, setImporting] = React.useState(false);
  const [importResult, setImportResult] = React.useState<ReportImportResult | null>(null);
  const [importName, setImportName] = React.useState("");
  // 导入对话框（skill）。
  const [importSkillOpen, setImportSkillOpen] = React.useState(false);
  const [skills, setSkills] = React.useState<SkillItem[]>([]);
  const [skillsLoading, setSkillsLoading] = React.useState(false);
  const [skillName, setSkillName] = React.useState("");

  const selected = React.useMemo(() => templates.find((t) => t.id === selectedId) ?? null, [templates, selectedId]);

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

  // 选中模板变化 → 载入编辑态（深拷避免污染列表）。
  React.useEffect(() => {
    if (!selected) {
      setDraft(null);
      setDirty(false);
      return;
    }
    setDraft(templateToDraft(selected));
    setDirty(false);
  }, [selected]);

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

  // ---- 编辑动作 ----
  const patch = (p: Partial<ReportTemplateInput>) => {
    setDraft((d) => (d ? { ...d, ...p } : d));
    setDirty(true);
  };

  const moveSection = (index: number, dir: -1 | 1) => {
    setDraft((d) => {
      if (!d?.skeleton) return d;
      const arr = [...d.skeleton];
      const j = index + dir;
      if (j < 0 || j >= arr.length) return d;
      [arr[index], arr[j]] = [arr[j], arr[index]];
      return { ...d, skeleton: arr };
    });
    setDirty(true);
  };

  const toggleSection = (key: ReportSectionKey, on: boolean) => {
    setDraft((d) => {
      if (!d?.skeleton) return d;
      return { ...d, skeleton: d.skeleton.map((s) => (s.key === key ? { ...s, enabled: on } : s)) };
    });
    setDirty(true);
  };

  const renameSection = (key: ReportSectionKey, title: string) => {
    setDraft((d) => {
      if (!d?.skeleton) return d;
      return { ...d, skeleton: d.skeleton.map((s) => (s.key === key ? { ...s, title } : s)) };
    });
    setDirty(true);
  };

  const setPerson = (i: number, p: Partial<ReportPerson>) => {
    setDraft((d) => {
      if (!d) return d;
      const list = [...(d.personnel ?? [])];
      list[i] = { ...list[i], ...p };
      return { ...d, personnel: list };
    });
    setDirty(true);
  };
  const addPerson = () => {
    setDraft((d) => (d ? { ...d, personnel: [...(d.personnel ?? []), { name: "", role: "" }] } : d));
    setDirty(true);
  };
  const removePerson = (i: number) => {
    setDraft((d) => (d ? { ...d, personnel: (d.personnel ?? []).filter((_, idx) => idx !== i) } : d));
    setDirty(true);
  };

  const setPrompt = (key: string, v: string) => {
    setDraft((d) => (d ? { ...d, prompts: { ...(d.prompts ?? {}), [key]: v } } : d));
    setDirty(true);
  };

  // style 关键字段编辑：空串=删除该覆盖键（回落后端默认样式常量表）；
  // 数字串转数值；未知既有键原样保留（整体是 Record 拷贝-改-回写）。
  const setStyle = (key: string, v: string | number | boolean) => {
    setDraft((d) => {
      if (!d) return d;
      const st = { ...(d.style ?? {}) };
      if (v === "") delete st[key];
      else st[key] = v;
      return { ...d, style: st };
    });
    setDirty(true);
  };

  // 对话面板应用服务端合并草稿：只取内容字段进编辑态（后端多带的
  // id/只读键忽略），并触发预览立即重渲。
  const applyChatTemplate = (t: ReportTemplateInput) => {
    setDraft((d) => {
      if (!d) return t;
      const picked: ReportTemplateInput = {
        ...d,
        name: t.name ?? d.name,
        output_lang: t.output_lang ?? d.output_lang,
        skeleton: t.skeleton ?? d.skeleton,
        style: t.style ?? d.style,
        prompts: t.prompts ?? d.prompts,
        issuer: t.issuer ?? d.issuer,
        personnel: t.personnel ?? d.personnel,
        cvss_enabled: t.cvss_enabled ?? d.cvss_enabled,
        remark: t.remark ?? d.remark,
      };
      return picked;
    });
    setDirty(true);
    setChatTick((x) => x + 1);
  };

  // ---- CRUD ----
  const save = async () => {
    if (!draft) return;
    if (!draft.name?.trim()) {
      toast.error("模板名称不能为空");
      return;
    }
    setSaving(true);
    try {
      if (selectedId == null) {
        const t = await api.createReportTemplate(draft);
        await loadTemplates(false);
        setSelectedId(t.id);
      } else {
        await api.updateReportTemplate(selectedId, draft);
        await loadTemplates(true);
      }
      setDirty(false);
      toast.success("已保存");
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  };

  const createNew = () => {
    setSelectedId(null);
    setDraft({
      name: "新建模板",
      output_lang: "zh-CN",
      skeleton: defaultSkeleton(),
      style: {},
      prompts: {},
      issuer: "",
      logo_path: "",
      personnel: [],
      cvss_enabled: false,
      remark: "",
    });
    setDirty(true);
  };

  const duplicate = async (t: ReportTemplate) => {
    try {
      const copy = await api.createReportTemplate({ ...templateToDraft(t), name: `${t.name}（副本）` });
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

  // 转成 Skill（T20 端点，幂等：同哨兵目录覆盖；非哨兵 409 如实报错）。
  const [toSkillBusy, setToSkillBusy] = React.useState(false);
  const toSkill = async () => {
    if (selectedId == null) return;
    setToSkillBusy(true);
    try {
      const r = await api.reportTemplateToSkill(selectedId);
      toast.success(`已导出 skill：${r.skill_name}（skills/ 目录，可拷贝复用/再导入）`);
    } catch (e) {
      toast.error(`转成 Skill 失败：${(e as Error).message}`);
    } finally {
      setToSkillBusy(false);
    }
  };

  // 导入：docx/md 上传反推（不自动建，确认后落库）。
  const pickImportFile = async (file: File | null) => {
    if (!file) return;
    setImporting(true);
    setImportResult(null);
    try {
      const r = await api.importTemplateDocx(file);
      setImportResult(r);
      setImportName(r.draft.name || file.name.replace(/\.(docx|md|markdown|txt)$/i, ""));
      if (r.degraded) toast.warning("LLM 归纳不可用，已按标题结构规则映射（可在详情继续调整）", { duration: 8000 });
    } catch (e) {
      toast.error(`导入失败：${(e as Error).message}`);
    } finally {
      setImporting(false);
    }
  };
  const confirmImportDocx = async () => {
    if (!importResult) return;
    const name = importName.trim() || importResult.draft.name;
    if (!name) {
      toast.error("请填写模板名");
      return;
    }
    try {
      const t = await api.createReportTemplate({ ...importResult.draft, name });
      await loadTemplates(false);
      setSelectedId(t.id);
      setImportDocxOpen(false);
      setImportResult(null);
      toast.success(`模板已导入：${t.name}`);
    } catch (e) {
      toast.error(`建模板失败：${(e as Error).message}`);
    }
  };

  // 导入：从 skill 读预填体（列 skills → 选一个 → 建模板）。
  const openImportSkill = async () => {
    setImportSkillOpen(true);
    setSkillName("");
    setSkillsLoading(true);
    try {
      setSkills(await api.skills());
    } catch (e) {
      toast.error(`加载 skills 失败：${(e as Error).message}`);
    } finally {
      setSkillsLoading(false);
    }
  };
  const confirmImportSkill = async () => {
    if (!skillName) {
      toast.error("请选择一个 skill");
      return;
    }
    setImporting(true);
    try {
      const r = await api.reportTemplateFromSkill(skillName);
      const t = await api.createReportTemplate(r.draft);
      await loadTemplates(false);
      setSelectedId(t.id);
      setImportSkillOpen(false);
      toast.success(`已从 skill 导入模板：${t.name}`);
    } catch (e) {
      toast.error(`导入失败：${(e as Error).message}`);
    } finally {
      setImporting(false);
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
    if (dirty) {
      const ok = window.confirm("当前模板有未保存修改，正式生成将使用已保存版本。是否继续？");
      if (!ok) return;
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
      <div className="flex flex-1 flex-col gap-4 md:gap-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="flex items-center gap-2 text-lg font-semibold">
              <FileTextIcon className="size-5" /> 报告中心
            </h1>
            <p className="text-muted-foreground text-sm">对话调整模板、实时预览结构、导入/导出 skill 并生成 Word 报告。</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={() => void loadTemplates(true)} disabled={loading}>
              <RefreshCwIcon className={loading ? "animate-spin" : ""} /> 刷新
            </Button>
            <Button variant="outline" size="sm" onClick={() => setHistoryOpen(true)}>
              <HistoryIcon /> 生成历史
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <FileInputIcon /> 导入模板
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => setImportDocxOpen(true)}>从 Word/Markdown 文档反推…</DropdownMenuItem>
                <DropdownMenuItem onClick={() => void openImportSkill()}>从 Skill 导入…</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="outline" size="sm" onClick={() => void toSkill()} disabled={selectedId == null || toSkillBusy}>
                  {toSkillBusy ? <Spinner /> : <SendIcon data-icon="inline-start" className="rotate-[-35deg]" />} 转成 Skill
                </Button>
              </TooltipTrigger>
              <TooltipContent>把当前模板导出为 skills/ 目录下的报告模板 skill（幂等覆盖）</TooltipContent>
            </Tooltip>
            <Button size="sm" onClick={createNew}>
              <PlusIcon /> 新建模板
            </Button>
          </div>
        </div>

        <div className="grid gap-4 lg:grid-cols-[230px_minmax(0,1.4fr)_minmax(0,1fr)] lg:items-stretch lg:gap-6">
          {/* 左：模板列表 */}
          <Card className="flex flex-col">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">模板</CardTitle>
            </CardHeader>
            <CardContent className="flex-1 p-2">
              {loading && templates.length === 0 ? (
                <div className="flex justify-center py-8">
                  <Spinner />
                </div>
              ) : templates.length === 0 ? (
                <p className="text-muted-foreground p-4 text-center text-sm">暂无模板，点「新建模板」。</p>
              ) : (
                <ScrollArea className="max-h-[72vh]">
                  <div className="flex flex-col gap-1 pr-2">
                    {templates.map((t) => (
                      <button
                        key={t.id}
                        type="button"
                        onClick={() => setSelectedId(t.id)}
                        className={`flex items-center justify-between gap-2 rounded-md px-3 py-2 text-left text-sm hover:bg-muted ${
                          selectedId === t.id ? "bg-muted font-medium" : ""
                        }`}
                      >
                        <span className="flex items-center gap-1.5 truncate">
                          {t.is_default && <StarIcon className="size-3.5 shrink-0 fill-amber-400 text-amber-400" />}
                          <span className="truncate">{t.name}</span>
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
                          <IconBtn
                            title="复制"
                            onClick={(e) => {
                              e.stopPropagation();
                              void duplicate(t);
                            }}
                          >
                            <CopyIcon className="size-3.5" />
                          </IconBtn>
                          <IconBtn
                            title="删除"
                            onClick={(e) => {
                              e.stopPropagation();
                              setConfirmDel(t);
                            }}
                          >
                            <Trash2Icon className="size-3.5" />
                          </IconBtn>
                        </span>
                      </button>
                    ))}
                  </div>
                </ScrollArea>
              )}
            </CardContent>
          </Card>

          {/* 中：实时预览。V3-R5：lg 下全列高（视口高减页头/工具条约 10rem，
              与页面顶栏+标题的实测占位对齐），iframe 内部自然滚动到全文=
              默认完整显示，不需要用户先开任何开关。 */}
          <Card className="flex min-h-[60vh] flex-col lg:h-[calc(100dvh-10rem)] lg:min-h-0">
            <CardContent className="flex min-h-0 flex-1 flex-col p-3">
              <TemplatePreview
                draft={draft}
                source={previewSource}
                setSource={setPreviewSource}
                form={previewForm}
                setForm={setPreviewForm}
                tasks={tasks}
                projects={projects}
                chatTick={chatTick}
              />
            </CardContent>
          </Card>

          {/* 右：对话 + 设置（折叠） */}
          <div className="flex min-h-0 flex-col gap-4">
            <Card className="flex min-h-[40vh] flex-col lg:min-h-0 lg:flex-1">
              <CardContent className="flex min-h-0 flex-1 flex-col p-3">
                <TemplateChat
                  templateId={selectedId}
                  draft={draft}
                  onApplyTemplate={applyChatTemplate}
                  locale={previewForm.locale}
                />
              </CardContent>
            </Card>

            <Collapsible defaultOpen={false} className="shrink-0">
              <Card>
                <CollapsibleTrigger asChild>
                  <CardHeader className="cursor-pointer py-3">
                    <div className="flex w-full items-center justify-between">
                      <CardTitle className="flex items-center gap-2 text-sm">
                        <WandSparklesIcon className="size-4" /> 设置
                      </CardTitle>
                      <div className="flex items-center gap-2">
                        {dirty && <Badge variant="secondary">未保存</Badge>}
                        <span className="text-muted-foreground text-xs">模板字段编辑</span>
                      </div>
                    </div>
                  </CardHeader>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <CardContent className="space-y-3">
                    {!draft ? (
                      <p className="text-muted-foreground py-6 text-center text-sm">选择或新建一个模板开始编辑。</p>
                    ) : (
                      <>
                        <div className="max-h-[44vh] overflow-y-auto pr-1">
                          <TemplateEditor
                            draft={draft}
                            patch={patch}
                            moveSection={moveSection}
                            toggleSection={toggleSection}
                            renameSection={renameSection}
                            setPerson={setPerson}
                            addPerson={addPerson}
                            removePerson={removePerson}
                            setPrompt={setPrompt}
                            setStyle={setStyle}
                          />
                        </div>
                        <div className="flex gap-2">
                          <Button size="sm" onClick={() => void save()} disabled={saving}>
                            {saving ? <Spinner /> : null} 保存
                          </Button>
                          <Button size="sm" variant="outline" onClick={openGenerate}>
                            <SparklesIcon /> 正式生成
                          </Button>
                        </div>
                      </>
                    )}
                  </CardContent>
                </CollapsibleContent>
              </Card>
            </Collapsible>
          </div>
        </div>
      </div>

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

      {/* 正式生成确认 Dialog */}
      <Dialog open={genOpen} onOpenChange={setGenOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>正式生成报告</DialogTitle>
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
                <NativeSelect value={genForm.task_id} onChange={(e) => setGenForm((f) => ({ ...f, task_id: e.target.value }))}>
                  <NativeSelectOption value="">— 选择任务 —</NativeSelectOption>
                  {tasks.map((t) => (
                    <NativeSelectOption key={t.id} value={t.id}>
                      {t.name || t.description.slice(0, 30)}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              ) : (
                <NativeSelect value={genForm.project_id} onChange={(e) => setGenForm((f) => ({ ...f, project_id: e.target.value }))}>
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
                <NativeSelect value={genForm.locale} onChange={(e) => setGenForm((f) => ({ ...f, locale: e.target.value }))}>
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
              正式生成使用**已保存**的模板（当前选择：{selected ? selected.name : "默认模板"}），进队列异步渲染并落历史。
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

      {/* 导入模板（docx/md） */}
      <Dialog open={importDocxOpen} onOpenChange={(o) => !importing && setImportDocxOpen(o)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>从文档导入模板</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-1">
            <input
              type="file"
              accept=".docx,.md,.markdown,.txt"
              className="text-sm"
              disabled={importing}
              onChange={(e) => void pickImportFile(e.target.files?.[0] ?? null)}
            />
            {importing && (
              <div className="text-muted-foreground flex items-center gap-2 text-sm">
                <Spinner className="size-4" /> 解析并归纳模板中…
              </div>
            )}
            {importResult && (
              <div className="space-y-2 rounded-md border p-3 text-sm">
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">识别标题 {importResult.outline.headings?.length ?? 0} 个</span>
                  {importResult.degraded && (
                    <Badge variant="outline" className="border-amber-400 text-amber-600">
                      规则映射（LLM 未参与）
                    </Badge>
                  )}
                </div>
                {importResult.draft.skeleton?.some((s) => s.enabled) ? null : (
                  <p className="text-muted-foreground text-xs">未识别出可映射章节，将使用默认骨架。</p>
                )}
                <Field label="模板名称">
                  <Input value={importName} onChange={(e) => setImportName(e.target.value)} />
                </Field>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setImportDocxOpen(false)} disabled={importing}>
              取消
            </Button>
            <Button onClick={() => void confirmImportDocx()} disabled={!importResult || importing}>
              创建模板
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 导入模板（skill） */}
      <Dialog open={importSkillOpen} onOpenChange={(o) => !importing && setImportSkillOpen(o)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>从 Skill 导入模板</DialogTitle>
          </DialogHeader>
          <div className="space-y-2 py-1">
            {skillsLoading ? (
              <div className="flex justify-center py-6">
                <Spinner />
              </div>
            ) : skills.length === 0 ? (
              <p className="text-muted-foreground py-6 text-center text-sm">没有已安装的 skills。</p>
            ) : (
              <>
                <p className="text-muted-foreground text-xs">选择带 template.json 的报告模板 skill（「转成 Skill」导出的产物）：</p>
                <NativeSelect className="w-full" value={skillName} onChange={(e) => setSkillName(e.target.value)}>
                  <NativeSelectOption value="">— 选择 skill —</NativeSelectOption>
                  {skills.map((sk) => (
                    <NativeSelectOption key={sk.name} value={sk.name}>
                      {sk.name}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              </>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setImportSkillOpen(false)} disabled={importing}>
              取消
            </Button>
            <Button onClick={() => void confirmImportSkill()} disabled={!skillName || importing}>
              {importing ? <Spinner /> : null} 导入为模板
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

function readIntParam(v: string | null): number | null {
  if (!v) return null;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : null;
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

// ---- 模板编辑器（T16 原样保留，T21 收进「设置」折叠区） ----
interface EditorProps {
  draft: ReportTemplateInput;
  patch: (p: Partial<ReportTemplateInput>) => void;
  moveSection: (i: number, dir: -1 | 1) => void;
  toggleSection: (k: ReportSectionKey, on: boolean) => void;
  renameSection: (k: ReportSectionKey, title: string) => void;
  setPerson: (i: number, p: Partial<ReportPerson>) => void;
  addPerson: () => void;
  removePerson: (i: number) => void;
  setPrompt: (k: string, v: string) => void;
  setStyle: (k: string, v: string | number | boolean) => void;
}

// 样式关键字段（与后端 pybuilder DEFAULTS 同名键；留空=用交付规范默认值）。
const STYLE_FIELDS: { key: string; label: string; kind: "text" | "number" }[] = [
  { key: "body_font", label: "正文字体(中文)", kind: "text" },
  { key: "west_font", label: "西文字体", kind: "text" },
  { key: "head_font", label: "标题字体", kind: "text" },
  { key: "body_size", label: "正文磅号", kind: "number" },
  { key: "h1_size", label: "章标题磅号", kind: "number" },
  { key: "vuln_size", label: "漏洞节标题磅号", kind: "number" },
];

function TemplateEditor(p: EditorProps) {
  const { draft } = p;
  const skeleton = draft.skeleton ?? defaultSkeleton();
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="模板名称">
          <Input value={draft.name} onChange={(e) => p.patch({ name: e.target.value })} />
        </Field>
        <Field label="输出语言">
          <NativeSelect value={draft.output_lang ?? "zh-CN"} onChange={(e) => p.patch({ output_lang: e.target.value })}>
            {LOCALES.map((l) => (
              <NativeSelectOption key={l.v} value={l.v}>
                {l.label}
              </NativeSelectOption>
            ))}
          </NativeSelect>
        </Field>
        <Field label="出具方">
          <Input
            value={draft.issuer ?? ""}
            onChange={(e) => p.patch({ issuer: e.target.value })}
            placeholder="报告封面署名单位"
          />
        </Field>
        <Field label="备注">
          <Input value={draft.remark ?? ""} onChange={(e) => p.patch({ remark: e.target.value })} />
        </Field>
      </div>

      {/* 章节骨架：勾选 + 排序 + 改名 */}
      <div>
        <Label className="text-muted-foreground mb-1 block text-xs">章节骨架（勾选启用 / 上下排序）</Label>
        <div className="flex flex-col gap-1">
          {skeleton.map((s, i) => (
            <div key={s.key} className="flex items-center gap-2 rounded-md border px-2 py-1.5">
              <Checkbox checked={s.enabled} onCheckedChange={(v) => p.toggleSection(s.key, v === true)} />
              <span className="text-muted-foreground w-16 shrink-0 text-xs">{s.key}</span>
              <Input
                className="h-7"
                value={s.title}
                onChange={(e) => p.renameSection(s.key, e.target.value)}
                placeholder={SECTION_META.find((m) => m.key === s.key)?.title}
              />
              <IconBtn title="上移" onClick={() => p.moveSection(i, -1)}>
                <GripVerticalIcon className="size-3.5 -rotate-90" />
              </IconBtn>
              <IconBtn title="下移" onClick={() => p.moveSection(i, 1)}>
                <GripVerticalIcon className="size-3.5 rotate-90" />
              </IconBtn>
            </div>
          ))}
        </div>
      </div>

      {/* 人员表 */}
      <div>
        <div className="mb-1 flex items-center justify-between">
          <Label className="text-muted-foreground text-xs">参测人员</Label>
          <Button variant="ghost" size="sm" onClick={p.addPerson}>
            <PlusIcon /> 添加
          </Button>
        </div>
        <div className="flex flex-col gap-1">
          {(draft.personnel ?? []).map((per, i) => (
            <div key={i} className="grid grid-cols-[1fr_1fr_1fr_auto] gap-2">
              <Input
                className="h-8"
                value={per.name}
                placeholder="姓名"
                onChange={(e) => p.setPerson(i, { name: e.target.value })}
              />
              <Input
                className="h-8"
                value={per.role}
                placeholder="角色"
                onChange={(e) => p.setPerson(i, { role: e.target.value })}
              />
              <Input
                className="h-8"
                value={per.contact ?? ""}
                placeholder="联系方式"
                onChange={(e) => p.setPerson(i, { contact: e.target.value })}
              />
              <IconBtn title="删除" onClick={() => p.removePerson(i)}>
                <Trash2Icon className="size-3.5" />
              </IconBtn>
            </div>
          ))}
        </div>
      </div>

      {/* style 关键字段（留空=用交付规范默认：仿宋正文/黑体标题/12pt 等） */}
      <div>
        <Label className="text-muted-foreground mb-1 block text-xs">样式（留空=交付规范默认值）</Label>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          {STYLE_FIELDS.map((f) => (
            <Field key={f.key} label={f.label}>
              <Input
                className="h-8"
                type={f.kind === "number" ? "number" : "text"}
                defaultValue={String((draft.style ?? {})[f.key] ?? "")}
                placeholder={f.kind === "number" ? "默认" : "默认"}
                onBlur={(e) => {
                  const raw = e.target.value.trim();
                  p.setStyle(f.key, f.kind === "number" && raw !== "" ? Number(raw) : raw);
                }}
              />
            </Field>
          ))}
        </div>
      </div>

      <label className="flex items-center gap-2 text-sm">
        <Checkbox checked={!!draft.cvss_enabled} onCheckedChange={(v) => p.patch({ cvss_enabled: v === true })} />
        报告呈现 CVSS 评分
      </label>

      {/* AI 叙述 prompt（按章节 key 组织；空=该章不调 AI） */}
      <div>
        <Label className="text-muted-foreground mb-1 block text-xs">AI 叙述 Prompt（留空=该章不生成 AI 文本）</Label>
        <div className="flex flex-col gap-2">
          {SECTION_META.filter((m) => ["summary", "vuln_detail", "conclusion"].includes(m.key)).map((m) => (
            <Field key={m.key} label={m.title}>
              <Textarea
                className="min-h-16"
                value={(draft.prompts ?? {})[m.key] ?? ""}
                onChange={(e) => p.setPrompt(m.key, e.target.value)}
                placeholder={`（可选）${m.title}的 AI 叙述指令`}
              />
            </Field>
          ))}
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <Label className="text-muted-foreground text-xs">{label}</Label>
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

// templateToDraft：把后端模板行拷成编辑态（深拷 skeleton/personnel/prompts/style）。
function templateToDraft(t: ReportTemplate): ReportTemplateInput {
  return {
    name: t.name,
    output_lang: t.output_lang,
    skeleton: (t.skeleton ?? defaultSkeleton()).map((s) => ({ ...s })),
    style: { ...(t.style ?? {}) },
    prompts: { ...(t.prompts ?? {}) },
    issuer: t.issuer ?? "",
    logo_path: t.logo_path ?? "",
    personnel: (t.personnel ?? []).map((x) => ({ ...x })),
    cvss_enabled: !!t.cvss_enabled,
    remark: t.remark ?? "",
  };
}
