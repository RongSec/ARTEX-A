"use client";

// 报告中心（artex-hs T16(2/3)）：模板管理 + 编辑 + 调试 + 生成历史。
//
// 三栏（lg 起）：
//   左 = 模板列表（新建/复制/设默认/删）
//   中 = 模板编辑器（名称/输出语/出具方/人员表/章节骨架勾选+排序/style 关键
//        字段/prompts 文本域） + 调试区（选任务或项目+locale+format→试渲染
//        调 render-draft→浏览器下载；「保存后正式生成」→ 建 job→轮询→下载）
//   右 = 生成历史（状态/警告 tooltip 含伪资产剔除/下载/删）
//
// 风格照 system/notify + function/projects 页（shadcn、既有表格/对话框，不引
// 新依赖）。章节骨架的 key 枚举与后端 db.ReportSectionKey 同步。

import * as React from "react";

import {
  CopyIcon,
  DownloadIcon,
  FileTextIcon,
  GripVerticalIcon,
  PlusIcon,
  RefreshCwIcon,
  StarIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { api } from "@/lib/api";
import type {
  ReportJob,
  ReportPerson,
  ReportSection,
  ReportSectionKey,
  ReportTemplate,
  ReportTemplateInput,
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

// emptySkeleton：默认全开六章（与后端 ParseSkeletonJSON(nil) 同构）。
function defaultSkeleton(): ReportSection[] {
  return SECTION_META.map((m) => ({ key: m.key, title: m.title, enabled: true }));
}

interface DraftForm {
  scope: "task" | "project";
  task_id: string;
  project_id: string;
  locale: string;
  format: "docx" | "md";
}

export default function ReportCenterPage() {
  const [templates, setTemplates] = React.useState<ReportTemplate[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [selectedId, setSelectedId] = React.useState<number | null>(null);
  const [draft, setDraft] = React.useState<ReportTemplateInput | null>(null); // 编辑态（null=未选）
  const [dirty, setDirty] = React.useState(false);
  const [saving, setSaving] = React.useState(false);

  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [projects, setProjects] = React.useState<{ id: number; name: string }[]>([]);
  const [debugForm, setDebugForm] = React.useState<DraftForm>({
    scope: "task",
    task_id: "",
    project_id: "",
    locale: "zh-CN",
    format: "docx",
  });
  const [rendering, setRendering] = React.useState(false);

  const [jobs, setJobs] = React.useState<ReportJob[]>([]);
  const [jobsLoading, setJobsLoading] = React.useState(false);
  const pollRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

  const selected = React.useMemo(() => templates.find((t) => t.id === selectedId) ?? null, [templates, selectedId]);

  // ---- 加载 ----
  const loadTemplates = React.useCallback(async (keepSelection = true) => {
    setLoading(true);
    try {
      const list = await api.reportTemplates();
      setTemplates(list);
      setSelectedId((cur) => {
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

  // 选中模板变化 → 载入编辑态（复制深避免污染列表）。
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

  // ---- 调试：试渲染（同步小样，不落库） ----
  const renderDraft = async () => {
    if (!debugFormHasTarget(debugForm)) {
      toast.error("请选择任务或项目");
      return;
    }
    setRendering(true);
    try {
      const { filename, warning } = await api.renderReportDraft({
        scope: debugForm.scope,
        task_id: debugForm.scope === "task" ? Number(debugForm.task_id) : undefined,
        project_id: debugForm.scope === "project" ? Number(debugForm.project_id) : undefined,
        template_id: selectedId ?? undefined,
        locale: debugForm.locale || undefined,
        format: debugForm.format,
      });
      toast.success(`小样已下载：${filename}`);
      if (warning) toast.warning(warning, { duration: 8000 });
    } catch (e) {
      toast.error(`试渲染失败：${(e as Error).message}`);
    } finally {
      setRendering(false);
    }
  };

  // ---- 正式生成（建 job→轮询） ----
  const generate = async () => {
    if (!debugFormHasTarget(debugForm)) {
      toast.error("请选择任务或项目");
      return;
    }
    if (dirty) {
      const ok = window.confirm("当前模板有未保存修改，正式生成将使用已保存版本。是否继续？");
      if (!ok) return;
    }
    try {
      const job = await api.reportGenerate({
        scope: debugForm.scope,
        task_id: debugForm.scope === "task" ? Number(debugForm.task_id) : undefined,
        project_id: debugForm.scope === "project" ? Number(debugForm.project_id) : undefined,
        template_id: selectedId ?? undefined,
        locale: debugForm.locale || undefined,
        format: debugForm.format,
      });
      toast.success(`报告任务 #${job.id} 已提交`);
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
            <p className="text-muted-foreground text-sm">管理交付报告模板、调试渲染并生成/下载 Word 报告。</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => void loadTemplates(true)} disabled={loading}>
              <RefreshCwIcon className={loading ? "animate-spin" : ""} /> 刷新
            </Button>
            <Button size="sm" onClick={createNew}>
              <PlusIcon /> 新建模板
            </Button>
          </div>
        </div>

        <div className="grid gap-4 lg:grid-cols-[280px_minmax(0,1fr)_360px]">
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
                <ScrollArea className="max-h-[70vh]">
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

          {/* 中：编辑器 + 调试区 */}
          <Card className="flex flex-col">
            <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm">{selectedId == null ? "新建模板" : "编辑模板"}</CardTitle>
              <div className="flex items-center gap-2">
                {dirty && <Badge variant="secondary">未保存</Badge>}
                <Button size="sm" onClick={() => void save()} disabled={saving || !draft}>
                  {saving ? <Spinner /> : null} 保存
                </Button>
              </div>
            </CardHeader>
            <CardContent className="flex-1 space-y-4">
              {!draft ? (
                <p className="text-muted-foreground py-10 text-center text-sm">选择或新建一个模板开始编辑。</p>
              ) : (
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
                />
              )}

              {draft && (
                <>
                  <Separator />
                  <DebugPanel
                    form={debugForm}
                    setForm={setDebugForm}
                    tasks={tasks}
                    projects={projects}
                    rendering={rendering}
                    onRenderDraft={() => void renderDraft()}
                    onGenerate={() => void generate()}
                  />
                </>
              )}
            </CardContent>
          </Card>

          {/* 右：生成历史 */}
          <Card className="flex flex-col">
            <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm">生成历史</CardTitle>
              <Button variant="ghost" size="icon" onClick={() => void loadJobs()} disabled={jobsLoading}>
                <RefreshCwIcon className={jobsLoading ? "animate-spin" : ""} />
              </Button>
            </CardHeader>
            <CardContent className="p-2">
              {jobs.length === 0 ? (
                <p className="text-muted-foreground p-4 text-center text-sm">暂无生成记录。</p>
              ) : (
                <ScrollArea className="max-h-[78vh]">
                  <div className="flex flex-col gap-2 pr-2">
                    {jobs.map((j) => (
                      <JobRow
                        key={j.id}
                        job={j}
                        onDownload={() => void downloadJob(j)}
                        onDelete={() => void delJob(j)}
                      />
                    ))}
                  </div>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

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

// ---- 模板编辑器 ----
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
}

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

// ---- 调试区 ----
function DebugPanel(props: {
  form: DraftForm;
  setForm: React.Dispatch<React.SetStateAction<DraftForm>>;
  tasks: Task[];
  projects: { id: number; name: string }[];
  rendering: boolean;
  onRenderDraft: () => void;
  onGenerate: () => void;
}) {
  const { form, setForm, tasks, projects } = props;
  return (
    <div className="space-y-3">
      <Label className="text-sm font-medium">调试 / 生成</Label>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="范围">
          <NativeSelect
            value={form.scope}
            onChange={(e) => setForm((f) => ({ ...f, scope: e.target.value as "task" | "project" }))}
          >
            <NativeSelectOption value="task">单任务</NativeSelectOption>
            <NativeSelectOption value="project">项目汇总</NativeSelectOption>
          </NativeSelect>
        </Field>
        <Field label={form.scope === "task" ? "任务" : "项目"}>
          {form.scope === "task" ? (
            <NativeSelect value={form.task_id} onChange={(e) => setForm((f) => ({ ...f, task_id: e.target.value }))}>
              <NativeSelectOption value="">— 选择任务 —</NativeSelectOption>
              {tasks.map((t) => (
                <NativeSelectOption key={t.id} value={t.id}>
                  {t.name || t.description.slice(0, 30)}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          ) : (
            <NativeSelect
              value={form.project_id}
              onChange={(e) => setForm((f) => ({ ...f, project_id: e.target.value }))}
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
        <Field label="输出语言">
          <NativeSelect value={form.locale} onChange={(e) => setForm((f) => ({ ...f, locale: e.target.value }))}>
            {LOCALES.map((l) => (
              <NativeSelectOption key={l.v} value={l.v}>
                {l.label}
              </NativeSelectOption>
            ))}
          </NativeSelect>
        </Field>
        <Field label="格式">
          <NativeSelect
            value={form.format}
            onChange={(e) => setForm((f) => ({ ...f, format: e.target.value as "docx" | "md" }))}
          >
            <NativeSelectOption value="docx">Word (.docx)</NativeSelectOption>
            <NativeSelectOption value="md">Markdown (.md)</NativeSelectOption>
          </NativeSelect>
        </Field>
      </div>
      <div className="flex gap-2">
        <Button variant="outline" onClick={props.onRenderDraft} disabled={props.rendering}>
          {props.rendering ? <Spinner /> : null} 试渲染小样
        </Button>
        <Button onClick={props.onGenerate}>保存后正式生成</Button>
      </div>
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

function debugFormHasTarget(f: DraftForm): boolean {
  return f.scope === "task" ? !!f.task_id : !!f.project_id;
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
