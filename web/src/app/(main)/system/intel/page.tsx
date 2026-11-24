"use client";

// 漏洞情报 V2：组件倒排（vendor/product + 结构化版本区间）+ 库配置。
//
// 页面的三件事：
//   1. 看：情报库 / 命中我的资产
//   2. 筛：KEV / CVSS / 关键词 / 时间
//   3. 配：每类库的开关、端点、同步状态、连通性
//
// 情报只给候选：组件匹配不等于可利用，版本区间才是「该打」的硬信号。

import * as React from "react";

import {
  AlertTriangleIcon,
  CloudDownloadIcon,
  DatabaseIcon,
  FlameIcon,
  GitBranchIcon,
  PlugZapIcon,
  RefreshCwIcon,
  SaveIcon,
  SearchIcon,
  SquareIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { AssetVulnHit, VulnCVESummary, VulnDetail, VulnIntelStatus, VulnPocEntry } from "@/lib/types";

const PAGE_SIZE = 50;

const severityTone: Record<string, string> = {
  CRITICAL: "bg-red-500/10 text-red-600 border-red-500/30 dark:text-red-400",
  HIGH: "bg-orange-500/10 text-orange-600 border-orange-500/30 dark:text-orange-400",
  MEDIUM: "bg-amber-500/10 text-amber-600 border-amber-500/30 dark:text-amber-400",
  LOW: "bg-emerald-500/10 text-emerald-600 border-emerald-500/30 dark:text-emerald-400",
};

function fmtDate(s?: string) {
  if (!s) return "—";
  const d = new Date(s);
  if (isNaN(d.getTime()) || d.getFullYear() < 1990) return "—";
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function fmtTime(s?: string) {
  if (!s) return "从未";
  const d = new Date(s);
  if (isNaN(d.getTime()) || d.getFullYear() < 1990) return "从未";
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

const sourceTone: Record<string, string> = {
  ok: "bg-emerald-500/10 text-emerald-600 border-emerald-500/30 dark:text-emerald-400",
  error: "bg-rose-500/10 text-rose-600 border-rose-500/30 dark:text-rose-400",
  never: "bg-muted text-muted-foreground",
};

const kindLabel: Record<string, string> = {
  api_json: "REST API",
  json_feed: "JSON feed",
  github_api: "GitHub API",
  git_repo: "Git 仓库",
};

type SyncMode = "all" | "kev" | "recent" | "full" | "poc" | "ghsa" | "templates";

export default function IntelPage() {
  const [status, setStatus] = React.useState<VulnIntelStatus | null>(null);
  const [syncing, setSyncing] = React.useState(false);

  const loadStatus = React.useCallback(async () => {
    try {
      setStatus(await api.intelStatus());
    } catch (e) {
      toast.error("读取情报状态失败：" + (e as Error).message);
    }
  }, []);

  React.useEffect(() => {
    void loadStatus();
    const t = setInterval(() => void loadStatus(), 8000);
    return () => clearInterval(t);
  }, [loadStatus]);

  const startSync = async (mode: SyncMode) => {
    setSyncing(true);
    try {
      await api.intelSync(mode);
      toast.success(mode === "all" ? "已开始一轮完整同步" : `已触发 ${mode} 同步`);
      setTimeout(() => void loadStatus(), 1500);
    } catch (e) {
      toast.error("触发失败：" + (e as Error).message);
    } finally {
      setSyncing(false);
    }
  };

  const cancelSync = async () => {
    try {
      await api.intelSyncCancel();
      toast.warning("已请求中断，当前请求结束后停止");
    } catch (e) {
      toast.error("中断失败：" + (e as Error).message);
    }
  };

  const counts = status?.counts;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-medium">
            <DatabaseIcon className="size-5" /> 漏洞情报
          </h1>
          <p className="text-muted-foreground mt-1 text-xs">
            公开源：NVD 2.0 · CISA KEV · GitHub Advisory · GitHub PoC · nuclei 模板。
            组件匹配只给候选，能否利用必须实测。
          </p>
        </div>
        <div className="flex items-center gap-2">
          {status?.sync_running ? (
            <>
              <span className="text-muted-foreground text-xs">{status.sync_phase || "同步中…"}</span>
              <Button variant="outline" size="sm" onClick={() => void cancelSync()}>
                <SquareIcon /> 中断
              </Button>
            </>
          ) : (
            <Button size="sm" disabled={syncing} onClick={() => void startSync("all")}>
              {syncing ? <Spinner data-icon="inline-start" /> : <RefreshCwIcon />} 立即同步
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {[
          { label: "CVE 记录", value: counts?.cves ?? 0, hint: "NVD + GHSA 去重后" },
          { label: "KEV 在野利用", value: counts?.kev ?? 0, hint: "CISA 已确认被利用" },
          { label: "PoC 线索", value: counts?.pocs ?? 0, hint: "仅仓库元数据" },
          { label: "组件索引", value: counts?.products ?? 0, hint: "vendor/product 倒排行" },
        ].map((c) => (
          <Card key={c.label}>
            <CardHeader className="pb-2">
              <CardTitle className="text-muted-foreground text-sm font-medium">{c.label}</CardTitle>
            </CardHeader>
            <CardContent className="px-4">
              <div className="text-2xl font-semibold tabular-nums">{c.value.toLocaleString()}</div>
              <p className="text-muted-foreground mt-1 text-[11px]">{c.hint}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Tabs defaultValue="library" className="flex flex-1 flex-col gap-3">
        <TabsList>
          <TabsTrigger value="library">情报库</TabsTrigger>
          <TabsTrigger value="hits">命中我的资产</TabsTrigger>
          <TabsTrigger value="sources">
            库配置
            {status?.sources?.some((s) => s.status === "error") && (
              <AlertTriangleIcon className="ml-1 size-3.5 text-rose-500" />
            )}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="library">
          <LibraryTab />
        </TabsContent>
        <TabsContent value="hits">
          <AssetHitsTab />
        </TabsContent>
        <TabsContent value="sources">
          <SourcesTab status={status} reload={loadStatus} onSync={startSync} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ── 情报库 ────────────────────────────────────────────────────────────

function LibraryTab() {
  const [items, setItems] = React.useState<VulnCVESummary[]>([]);
  const [total, setTotal] = React.useState(0);
  const [page, setPage] = React.useState(0);
  const [q, setQ] = React.useState("");
  const [kevOnly, setKevOnly] = React.useState(false);
  const [minCvss, setMinCvss] = React.useState("0");
  const [loading, setLoading] = React.useState(false);
  const [openCVE, setOpenCVE] = React.useState<string | null>(null);

  const load = React.useCallback(
    async (p: number, query: string, kev: boolean, cvss: string) => {
      setLoading(true);
      try {
        const r = await api.intelSearch({
          q: query,
          kev,
          minCvss: Number(cvss) || 0,
          limit: PAGE_SIZE,
          offset: p * PAGE_SIZE,
        });
        setItems(r.items);
        setTotal(r.total);
      } catch (e) {
        toast.error("查询失败：" + (e as Error).message);
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  React.useEffect(() => {
    void load(0, "", false, "0");
  }, [load]);

  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <SearchIcon className="text-muted-foreground pointer-events-none absolute top-2.5 left-2.5 size-4" />
          <Input
            className="w-80 pl-8"
            placeholder="组件 / 产品 / CVE 编号，如 nginx、http_server、CVE-2024-3094"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                setPage(0);
                void load(0, q, kevOnly, minCvss);
              }
            }}
          />
        </div>
        <Select
          value={minCvss}
          onValueChange={(v) => {
            setMinCvss(v);
            setPage(0);
            void load(0, q, kevOnly, v);
          }}
        >
          <SelectTrigger className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="0">全部等级</SelectItem>
            <SelectItem value="9">CVSS ≥ 9</SelectItem>
            <SelectItem value="7">CVSS ≥ 7</SelectItem>
            <SelectItem value="4">CVSS ≥ 4</SelectItem>
          </SelectContent>
        </Select>
        <label className="flex items-center gap-2 text-sm">
          <Switch
            checked={kevOnly}
            onCheckedChange={(v) => {
              const on = v === true;
              setKevOnly(on);
              setPage(0);
              void load(0, q, on, minCvss);
            }}
          />
          只看 KEV
        </label>
        <Button
          variant="outline"
          size="sm"
          disabled={loading}
          onClick={() => {
            setPage(0);
            void load(0, q, kevOnly, minCvss);
          }}
        >
          {loading ? <Spinner data-icon="inline-start" /> : <SearchIcon />} 查询
        </Button>
        <span className="text-muted-foreground ml-auto text-xs tabular-nums">共 {total.toLocaleString()} 条</span>
      </div>

      <div className="overflow-hidden rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-44">CVE</TableHead>
              <TableHead className="w-24">等级</TableHead>
              <TableHead className="w-16 text-right">CVSS</TableHead>
              <TableHead>标题</TableHead>
              <TableHead className="w-16 text-right">PoC</TableHead>
              <TableHead className="w-28">发布</TableHead>
              <TableHead className="w-20">KEV</TableHead>
              <TableHead className="w-20">来源</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.length === 0 && (
              <TableRow>
                <TableCell colSpan={8} className="text-muted-foreground py-8 text-center text-sm">
                  {loading ? "查询中…" : "没有数据：先点右上「立即同步」，或换个关键词"}
                </TableCell>
              </TableRow>
            )}
            {items.map((it) => (
              <TableRow key={it.cve_id} className="cursor-pointer" onClick={() => setOpenCVE(it.cve_id)}>
                <TableCell className="font-mono text-xs">{it.cve_id}</TableCell>
                <TableCell>
                  <Badge variant="outline" className={severityTone[it.severity?.toUpperCase()] || ""}>
                    {it.severity || "—"}
                  </Badge>
                </TableCell>
                <TableCell className="text-right text-xs tabular-nums">
                  {it.cvss_score != null ? it.cvss_score.toFixed(1) : "—"}
                </TableCell>
                <TableCell className="max-w-[420px] truncate text-sm">{it.title || "—"}</TableCell>
                <TableCell className="text-right text-xs tabular-nums">{it.poc_count || 0}</TableCell>
                <TableCell className="text-muted-foreground text-xs">{fmtDate(it.published)}</TableCell>
                <TableCell>
                  {it.kev ? (
                    <Badge variant="outline" className="border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400">
                      <FlameIcon className="size-3" /> KEV
                    </Badge>
                  ) : (
                    <span className="text-muted-foreground text-xs">—</span>
                  )}
                </TableCell>
                <TableCell className="text-muted-foreground text-xs uppercase">{it.source || "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <div className="flex items-center justify-end gap-2">
        <Button
          variant="outline"
          size="sm"
          disabled={page <= 0 || loading}
          onClick={() => {
            setPage(page - 1);
            void load(page - 1, q, kevOnly, minCvss);
          }}
        >
          上一页
        </Button>
        <span className="text-muted-foreground text-xs tabular-nums">
          {page + 1} / {pages}
        </span>
        <Button
          variant="outline"
          size="sm"
          disabled={page + 1 >= pages || loading}
          onClick={() => {
            setPage(page + 1);
            void load(page + 1, q, kevOnly, minCvss);
          }}
        >
          下一页
        </Button>
      </div>

      <VulnDialog cve={openCVE} onClose={() => setOpenCVE(null)} />
    </div>
  );
}

function VulnDialog({ cve, onClose }: { cve: string | null; onClose: () => void }) {
  const [detail, setDetail] = React.useState<VulnDetail | null>(null);
  const [pocs, setPocs] = React.useState<VulnPocEntry[]>([]);
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    if (!cve) {
      setDetail(null);
      setPocs([]);
      return;
    }
    setLoading(true);
    Promise.all([api.intelVuln(cve), api.intelPocs(cve)])
      .then(([d, p]) => {
        setDetail(d);
        setPocs(p.items);
      })
      .catch((e) => toast.error("读取详情失败：" + (e as Error).message))
      .finally(() => setLoading(false));
  }, [cve]);

  return (
    <Dialog
      open={!!cve}
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
    >
      <DialogContent className="max-h-[80vh] max-w-3xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="font-mono text-sm">{cve}</DialogTitle>
          <DialogDescription className="text-xs">
            {detail
              ? `${detail.severity} · CVSS ${detail.cvss_score?.toFixed(1) ?? "—"}${detail.kev ? " · KEV 在野利用" : ""} · 来源 ${detail.source || "—"}`
              : "加载中…"}
          </DialogDescription>
        </DialogHeader>
        {loading && <Spinner />}
        {detail && (
          <div className="flex flex-col gap-3 text-sm">
            <p className="leading-relaxed">{detail.description || "（无描述）"}</p>

            <div>
              <div className="mb-1 text-xs font-medium">受影响版本区间</div>
              {(detail.version_ranges?.length ?? 0) === 0 ? (
                <p className="text-muted-foreground text-xs">
                  无结构化区间（NVD 未填）：需按 cpe_criteria 自行判断，或等 GHSA 补齐。
                </p>
              ) : (
                <div className="overflow-hidden rounded border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-48">组件</TableHead>
                        <TableHead>区间</TableHead>
                        <TableHead className="w-20">来源</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {detail.version_ranges!.map((r, i) => (
                        <TableRow key={`${r.vendor}/${r.product}/${i}`}>
                          <TableCell className="font-mono text-xs">
                            {r.vendor}/{r.product}
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            {[
                              r.start_including && `>= ${r.start_including}`,
                              r.start_excluding && `> ${r.start_excluding}`,
                              r.end_including && `<= ${r.end_including}`,
                              r.end_excluding && `< ${r.end_excluding}`,
                            ]
                              .filter(Boolean)
                              .join("  ") ||
                              r.raw ||
                              "—"}
                          </TableCell>
                          <TableCell className="text-muted-foreground text-xs uppercase">{r.source || "—"}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </div>

            {(detail.cwes?.length ?? 0) > 0 && (
              <div className="flex flex-wrap items-center gap-1">
                <span className="text-xs font-medium">CWE：</span>
                {detail.cwes!.map((c) => (
                  <Badge key={c} variant="outline" className="text-[11px]">
                    {c}
                  </Badge>
                ))}
              </div>
            )}

            <div>
              <div className="mb-1 text-xs font-medium">PoC 线索（{pocs.length}）</div>
              {pocs.length === 0 ? (
                <p className="text-muted-foreground text-xs">没有聚合到公开仓库（或该 CVE 未被 PoC 聚合覆盖）。</p>
              ) : (
                <ul className="flex flex-col gap-1">
                  {pocs.map((p) => (
                    <li key={p.url} className="flex items-center gap-2 text-xs">
                      <Badge variant="outline" className="shrink-0 text-[10px]">
                        {p.source}
                      </Badge>
                      <a
                        className="truncate text-blue-600 hover:underline dark:text-blue-400"
                        href={p.url}
                        target="_blank"
                        rel="noreferrer"
                      >
                        {p.title || p.url}
                      </a>
                      <span className="text-muted-foreground ml-auto shrink-0 tabular-nums">{p.stars}★</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {(detail.references?.length ?? 0) > 0 && (
              <div>
                <div className="mb-1 text-xs font-medium">参考链接</div>
                <ul className="flex flex-col gap-1">
                  {detail.references!.slice(0, 8).map((u) => (
                    <li key={u} className="truncate text-xs">
                      <a className="text-blue-600 hover:underline dark:text-blue-400" href={u} target="_blank" rel="noreferrer">
                        {u}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

// ── 命中我的资产 ──────────────────────────────────────────────────────

function AssetHitsTab() {
  const [hits, setHits] = React.useState<AssetVulnHit[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);
  const [kevOnly, setKevOnly] = React.useState(false);
  const [minCvss, setMinCvss] = React.useState("7");

  const load = React.useCallback(async (kev: boolean, cvss: string) => {
    setLoading(true);
    try {
      const r = await api.intelAssetHits({ limit: 300, minCvss: Number(cvss) || 0, kevOnly: kev });
      setHits(r.items);
      setLoaded(true);
    } catch (e) {
      toast.error("读取命中失败：" + (e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    if (!loaded) void load(false, "7");
  }, [load, loaded]);

  return (
    <div className="flex flex-col gap-3">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">资产指纹 × 组件倒排</CardTitle>
          <CardDescription className="text-xs">
            拿资产台账的 technologies 与 vuln_cpe_products 求交集（含别名归一：httpd ↔ http_server）。
            版本不保证可靠，命中一律是「可能受影响」，必须实测。
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-2">
          <Select
            value={minCvss}
            onValueChange={(v) => {
              setMinCvss(v);
              void load(kevOnly, v);
            }}
          >
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="0">全部等级</SelectItem>
              <SelectItem value="9">CVSS ≥ 9</SelectItem>
              <SelectItem value="7">CVSS ≥ 7</SelectItem>
              <SelectItem value="4">CVSS ≥ 4</SelectItem>
            </SelectContent>
          </Select>
          <label className="flex items-center gap-2 text-sm">
            <Switch
              checked={kevOnly}
              onCheckedChange={(v) => {
                const on = v === true;
                setKevOnly(on);
                void load(on, minCvss);
              }}
            />
            只看 KEV
          </label>
          <Button variant="outline" size="sm" disabled={loading} onClick={() => void load(kevOnly, minCvss)}>
            {loading ? <Spinner data-icon="inline-start" /> : <RefreshCwIcon />} 刷新
          </Button>
          <span className="text-muted-foreground ml-auto text-xs tabular-nums">{hits.length} 条命中</span>
        </CardContent>
      </Card>

      <div className="overflow-hidden rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-56">资产</TableHead>
              <TableHead className="w-40">命中指纹</TableHead>
              <TableHead className="w-44">CVE</TableHead>
              <TableHead className="w-24">等级</TableHead>
              <TableHead className="w-16 text-right">CVSS</TableHead>
              <TableHead className="w-20">KEV</TableHead>
              <TableHead>组件</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {hits.length === 0 && (
              <TableRow>
                <TableCell colSpan={7} className="text-muted-foreground py-8 text-center text-sm">
                  {loading ? "计算中…" : "没有命中：要么资产没采到技术指纹，要么情报库还没同步。"}
                </TableCell>
              </TableRow>
            )}
            {hits.map((h, i) => (
              <TableRow key={`${h.asset_id}-${h.cve_id}-${i}`}>
                <TableCell className="max-w-[220px] truncate font-mono text-xs">{h.asset || `asset#${h.asset_id}`}</TableCell>
                <TableCell className="text-muted-foreground font-mono text-xs">{h.matched_on}</TableCell>
                <TableCell className="font-mono text-xs">{h.cve_id}</TableCell>
                <TableCell>
                  <Badge variant="outline" className={severityTone[h.severity?.toUpperCase()] || ""}>
                    {h.severity || "—"}
                  </Badge>
                </TableCell>
                <TableCell className="text-right text-xs tabular-nums">
                  {h.cvss_score != null ? h.cvss_score.toFixed(1) : "—"}
                </TableCell>
                <TableCell>
                  {h.kev ? (
                    <Badge variant="outline" className="border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400">
                      KEV
                    </Badge>
                  ) : (
                    <span className="text-muted-foreground text-xs">—</span>
                  )}
                </TableCell>
                <TableCell className="font-mono text-xs">{h.product}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

// ── 库配置 ────────────────────────────────────────────────────────────

function SourcesTab({
  status,
  reload,
  onSync,
}: {
  status: VulnIntelStatus | null;
  reload: () => Promise<void>;
  onSync: (mode: SyncMode) => Promise<void>;
}) {
  const sources = status?.sources ?? [];
  const [drafts, setDrafts] = React.useState<Record<string, string>>({});
  const [saving, setSaving] = React.useState<string | null>(null);
  const [probing, setProbing] = React.useState(false);
  const [probes, setProbes] = React.useState<
    { source: string; ok: boolean; status: number; latency_ms: number; error?: string; hint?: string }[] | null
  >(null);

  const patch = async (id: string, p: Parameters<typeof api.intelSourceUpdate>[1]) => {
    setSaving(id);
    try {
      await api.intelSourceUpdate(id, p);
      await reload();
      toast.success("已保存");
    } catch (e) {
      toast.error("保存失败：" + (e as Error).message);
    } finally {
      setSaving(null);
    }
  };

  const probe = async () => {
    setProbing(true);
    try {
      const r = await api.intelProbe();
      setProbes(r.results);
      const bad = r.results.filter((x) => !x.ok).length;
      if (bad === 0) toast.success("所有数据源连通正常");
      else toast.warning(`${bad} 个数据源不可用，展开看修复建议`);
    } catch (e) {
      toast.error("探测失败：" + (e as Error).message);
    } finally {
      setProbing(false);
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <Card>
        <CardHeader className="pb-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <CardTitle className="flex items-center gap-2 text-sm font-medium">
                <GitBranchIcon className="size-4" /> 已接入的库
              </CardTitle>
              <CardDescription className="text-xs">
                每类库一行：开关、端点、凭据、条数、上次同步都在这。加新源由后端注册 adapter，页面自动出现。
                <br />
                端点填<b>基址</b>：NVD / KEV / GitHub 填到域名或镜像根（具体路径由程序拼），模板库填 git 地址；
                改完保存即生效，模板库换源会自动重建模板树。
              </CardDescription>
            </div>
            <Button variant="outline" size="sm" disabled={probing} onClick={() => void probe()}>
              {probing ? <Spinner data-icon="inline-start" /> : <PlugZapIcon />} 测试连通性
            </Button>
          </div>
        </CardHeader>
        <CardContent className="px-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-56 pl-4">库</TableHead>
                <TableHead className="w-16">启用</TableHead>
                <TableHead>端点</TableHead>
                <TableHead className="w-40">凭据</TableHead>
                <TableHead className="w-20 text-right">条数</TableHead>
                <TableHead className="w-28">上次同步</TableHead>
                <TableHead className="w-24">状态</TableHead>
                <TableHead className="w-24 pr-4 text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sources.map((s) => (
                <TableRow key={s.id}>
                  <TableCell className="pl-4">
                    <div className="text-sm font-medium">{s.name}</div>
                    <div className="text-muted-foreground text-[11px]">
                      {kindLabel[s.kind] || s.kind} · id={s.id} · 优先级 {s.priority}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={s.enabled}
                      disabled={saving === s.id}
                      onCheckedChange={(v) => void patch(s.id, { enabled: v === true })}
                    />
                  </TableCell>
                  <TableCell>
                    <Input
                      className="h-8 font-mono text-[11px]"
                      value={drafts[s.id] ?? s.endpoint}
                      onChange={(e) => setDrafts((d) => ({ ...d, [s.id]: e.target.value }))}
                      onBlur={() => {
                        const v = drafts[s.id];
                        if (v != null && v !== s.endpoint) void patch(s.id, { endpoint: v });
                      }}
                    />
                  </TableCell>
                  <TableCell className="text-xs">
                    {s.credential_setting ? (
                      s.credential_set ? (
                        <Badge
                          variant="outline"
                          className="border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                        >
                          已配置
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground">{s.credential_hint || "未配置凭据"}</span>
                      )
                    ) : (
                      <span className="text-muted-foreground">无需凭据</span>
                    )}
                  </TableCell>
                  <TableCell className="text-right text-xs tabular-nums">{s.count.toLocaleString()}</TableCell>
                  <TableCell className="text-muted-foreground text-xs">{fmtTime(s.last_sync_at)}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className={sourceTone[s.status]}>
                      {s.status === "ok" ? "正常" : s.status === "error" ? "异常" : "未同步"}
                    </Badge>
                  </TableCell>
                  <TableCell className="pr-4 text-right">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={status?.sync_running}
                      onClick={() => {
                        const mode: SyncMode =
                          s.id === "nvd"
                            ? "recent"
                            : s.id === "kev"
                              ? "kev"
                              : s.id === "ghsa"
                                ? "ghsa"
                                : s.id === "github_poc"
                                  ? "poc"
                                  : "templates";
                        void onSync(mode);
                      }}
                    >
                      <CloudDownloadIcon /> 同步
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>

          {sources
            .filter((s) => s.last_error)
            .map((s) => (
              <div key={`err-${s.id}`} className="mx-4 mt-3 rounded border border-rose-500/30 bg-rose-500/5 p-2 text-xs">
                <span className="font-medium text-rose-600 dark:text-rose-400">{s.name}：</span>
                <span className="text-muted-foreground">{s.error_hint || s.last_error}</span>
                <div className="text-muted-foreground/70 mt-1 font-mono text-[10px] break-all">{s.last_error}</div>
              </div>
            ))}
        </CardContent>
      </Card>

      {probes && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">连通性诊断</CardTitle>
            <CardDescription className="text-xs">
              走当前「上网代理」逐源探测；失败时给的是可执行建议，不是错误码。
            </CardDescription>
          </CardHeader>
          <CardContent className="px-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-4">数据源</TableHead>
                  <TableHead className="w-20">结果</TableHead>
                  <TableHead className="w-20 text-right">耗时</TableHead>
                  <TableHead>说明</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {probes.map((p) => (
                  <TableRow key={p.source}>
                    <TableCell className="pl-4 font-mono text-xs">{p.source}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className={p.ok ? sourceTone.ok : sourceTone.error}>
                        {p.ok ? "通" : p.status || "失败"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right text-xs tabular-nums">{p.latency_ms}ms</TableCell>
                    <TableCell className="text-xs">
                      {p.ok ? (
                        <span className="text-muted-foreground">正常</span>
                      ) : (
                        <span className="text-rose-600 dark:text-rose-400">{p.hint || p.error}</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <GlobalConfig status={status} reload={reload} />
    </div>
  );
}

function GlobalConfig({ status, reload }: { status: VulnIntelStatus | null; reload: () => Promise<void> }) {
  const cfg = status?.config;
  const [nvdKey, setNvdKey] = React.useState("");
  const [ghToken, setGhToken] = React.useState("");
  const [backfill, setBackfill] = React.useState("0");
  const [maxRuntime, setMaxRuntime] = React.useState("30");
  const [fastMin, setFastMin] = React.useState("30");
  const [fastDays, setFastDays] = React.useState("7");
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    if (!cfg) return;
    setBackfill(String(cfg.backfill_days));
    setMaxRuntime(String(cfg.max_runtime_minutes));
    setFastMin(String(cfg.fast_lane_minutes));
    setFastDays(String(cfg.fast_lane_days));
  }, [cfg]);

  const save = async (extra: Record<string, unknown> = {}) => {
    setSaving(true);
    try {
      await api.intelConfigSave({
        backfill_days: Number(backfill) || 0,
        max_runtime_minutes: Number(maxRuntime) || 30,
        fast_lane_minutes: Number(fastMin) || 30,
        fast_lane_days: Number(fastDays) || 7,
        ...(nvdKey.trim() ? { nvd_api_key: nvdKey.trim() } : {}),
        ...(ghToken.trim() ? { github_token: ghToken.trim() } : {}),
        ...extra,
      });
      setNvdKey("");
      setGhToken("");
      await reload();
      toast.success("已保存，下一轮同步生效");
    } catch (e) {
      toast.error("保存失败：" + (e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          <SaveIcon className="size-4" /> 全局参数
        </CardTitle>
        <CardDescription className="text-xs">
          凭据留空 = 保持不变；填了才覆盖。同步出口复用「系统 → 设置」里的上网代理。
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3 md:grid-cols-2">
        <div className="flex flex-col gap-1">
          <span className="text-xs font-medium">NVD API Key</span>
          <Input
            className="font-mono text-xs"
            placeholder={cfg?.nvd_key_set ? `已配置 ${cfg.nvd_api_key}` : "未配置：匿名 5 次/30 秒"}
            value={nvdKey}
            onChange={(e) => setNvdKey(e.target.value)}
          />
          <span className="text-muted-foreground text-[11px]">
            {cfg?.nvd_key_set ? "留空保持不变，填 - 清除" : "填 Key 后限速提升 10 倍"}
          </span>
        </div>
        <div className="flex flex-col gap-1">
          <span className="text-xs font-medium">GitHub Token（GHSA + PoC 共用）</span>
          <Input
            className="font-mono text-xs"
            placeholder={cfg?.github_token_set ? `已配置 ${cfg.github_token}` : "未配置：匿名 10 次/分钟"}
            value={ghToken}
            onChange={(e) => setGhToken(e.target.value)}
          />
          <span className="text-muted-foreground text-[11px]">
            {cfg?.github_token_set ? "留空保持不变，填 - 清除" : "public_repo 读权限即可"}
          </span>
        </div>
        <div className="flex flex-col gap-1">
          <span className="text-xs font-medium">上网代理</span>
          <Input className="font-mono text-xs" value={cfg?.proxy || "（直连）"} readOnly />
          <span className="text-muted-foreground text-[11px]">在「系统 → 设置 → 上网代理」修改</span>
        </div>
        <div className="flex flex-col gap-1">
          <span className="text-xs font-medium">回填天数（首次/手动全量）</span>
          <Input type="number" value={backfill} onChange={(e) => setBackfill(e.target.value)} />
          <span className="text-muted-foreground text-[11px]">0 = 从最早目录开始（按游标推进，一轮跑不完下轮续）</span>
        </div>
        <div className="flex flex-col gap-1">
          <span className="text-xs font-medium">单轮上限（分钟）</span>
          <Input type="number" value={maxRuntime} onChange={(e) => setMaxRuntime(e.target.value)} />
          <span className="text-muted-foreground text-[11px]">到点保存游标退出，下轮续跑</span>
        </div>
        <div className="flex flex-col gap-1">
          <span className="text-xs font-medium">快通道（近期高危）</span>
          <div className="flex items-center gap-2">
            <Switch
              checked={cfg?.fast_lane_enabled ?? true}
              onCheckedChange={(v) => void save({ fast_lane_enabled: v === true })}
            />
            <Input className="w-20" type="number" value={fastMin} onChange={(e) => setFastMin(e.target.value)} />
            <span className="text-muted-foreground text-xs">分钟一轮，回看</span>
            <Input className="w-16" type="number" value={fastDays} onChange={(e) => setFastDays(e.target.value)} />
            <span className="text-muted-foreground text-xs">天</span>
          </div>
          <span className="text-muted-foreground text-[11px]">按 publishedDate 拉新披露的 CRITICAL，不等主同步游标</span>
        </div>
        <div className="flex flex-wrap items-center gap-3 md:col-span-2">
          <Button size="sm" disabled={saving} onClick={() => void save()}>
            {saving ? <Spinner data-icon="inline-start" /> : <SaveIcon />} 保存参数
          </Button>
          <label className="flex items-center gap-2 text-sm">
            <Switch checked={status?.enabled ?? true} onCheckedChange={(v) => void save({ enabled: v === true })} />
            启用情报同步
          </label>
          <label className="flex items-center gap-2 text-sm">
            <Switch checked={cfg?.poc_enabled ?? false} onCheckedChange={(v) => void save({ poc_enabled: v === true })} />
            聚合 GitHub PoC（仅元数据）
          </label>
        </div>
      </CardContent>
    </Card>
  );
}
