"use client";

// 漏洞情报（V10-INTEL）：NVD 全量 + CISA KEV 在野利用，两个公开源。
//
// 页面只有三件事：看（情报库/命中我的资产）、筛（KEV / CVSS / 时间 / 关键词）、
// 触发同步。情报本身是「候选」：组件名匹配不带版本，命中了也要实测。

import * as React from "react";

import { AlertTriangleIcon, CloudDownloadIcon, DatabaseIcon, ExternalLinkIcon, FlameIcon, GitBranchIcon, RefreshCwIcon, SaveIcon, SearchIcon } from "lucide-react";
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
import type { AssetVulnHit, GitHubConfig, VulnIntelEntry, VulnIntelStatus, VulnPoc } from "@/lib/types";

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

export default function IntelPage() {
  const [status, setStatus] = React.useState<VulnIntelStatus | null>(null);
  const [items, setItems] = React.useState<VulnIntelEntry[]>([]);
  const [total, setTotal] = React.useState(0);
  const [page, setPage] = React.useState(0);
  const [q, setQ] = React.useState("");
  const [kevOnly, setKevOnly] = React.useState(false);
  const [minCvss, setMinCvss] = React.useState("0");
  const [loading, setLoading] = React.useState(false);
  const [syncing, setSyncing] = React.useState(false);
  const [hits, setHits] = React.useState<AssetVulnHit[]>([]);
  const [hitsLoaded, setHitsLoaded] = React.useState(false);
  // GitHub PoC 聚合：token 只在保存时上送，读回只有末四位。
  const [gh, setGh] = React.useState<GitHubConfig | null>(null);
  const [ghToken, setGhToken] = React.useState("");
  const [ghEnabled, setGhEnabled] = React.useState(true);
  const [savingCfg, setSavingCfg] = React.useState(false);
  const [pocCVE, setPocCVE] = React.useState<string | null>(null);
  const [pocItems, setPocItems] = React.useState<VulnPoc[]>([]);
  const [pocLoading, setPocLoading] = React.useState(false);

  const loadStatus = React.useCallback(async () => {
    try {
      const s = await api.intelStatus();
      setStatus(s);
      if (s.github) {
        setGh(s.github);
        setGhEnabled(s.github.enabled);
      }
    } catch (e) {
      toast.error("读取情报状态失败：" + (e as Error).message);
    }
  }, []);

  const loadPage = React.useCallback(
    async (nextPage: number, query: string, kev: boolean, cvss: string) => {
      setLoading(true);
      try {
        const r = await api.intelSearch({
          q: query.trim() || undefined,
          kev,
          minCvss: Number(cvss) || 0,
          limit: PAGE_SIZE,
          offset: nextPage * PAGE_SIZE,
        });
        setItems(r.items);
        setTotal(r.total);
        setPage(nextPage);
      } catch (e) {
        toast.error("查询失败：" + (e as Error).message);
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  React.useEffect(() => {
    void loadStatus();
    void loadPage(0, "", false, "0");
  }, [loadStatus, loadPage]);

  // 同步在后台跑，running 非空时每 5 秒刷一次状态与列表。
  React.useEffect(() => {
    if (!status?.running) return;
    const t = setInterval(() => {
      void loadStatus();
      void loadPage(page, q, kevOnly, minCvss);
    }, 5000);
    return () => clearInterval(t);
  }, [status?.running, loadStatus, loadPage, page, q, kevOnly, minCvss]);

  async function sync(mode: "kev" | "recent" | "full" | "poc") {
    setSyncing(true);
    try {
      await api.intelSync(mode, mode === "full" ? 120 : undefined);
      toast.success(
        mode === "full"
          ? "已开始回填最近 120 天（后台执行，可继续用页面）"
          : mode === "poc"
            ? "已开始聚合 PoC 线索（后台按配额逐条查，star 高的先入库）"
            : "已触发同步（后台执行）",
      );
      setTimeout(() => void loadStatus(), 1500);
    } catch (e) {
      toast.error("触发失败：" + (e as Error).message);
    } finally {
      setSyncing(false);
    }
  }

  async function saveGitHub(next?: { enabled?: boolean; token?: string }) {
    setSavingCfg(true);
    try {
      const cfg = await api.intelConfigSave(next ?? {
        enabled: ghEnabled,
        // 空输入 = 不改（避免误清空已存的 token）；显式清空要走「清除」按钮。
        ...(ghToken.trim() ? { token: ghToken.trim() } : {}),
      });
      setGh(cfg);
      setGhEnabled(cfg.enabled);
      setGhToken("");
      toast.success("GitHub 配置已保存，下一轮同步生效");
      void loadStatus();
    } catch (e) {
      toast.error("保存失败：" + (e as Error).message);
    } finally {
      setSavingCfg(false);
    }
  }

  async function openPocs(cve: string) {
    setPocCVE(cve);
    setPocItems([]);
    setPocLoading(true);
    try {
      const r = await api.intelPocs(cve);
      setPocItems(r.items);
    } catch (e) {
      toast.error("读取 PoC 线索失败：" + (e as Error).message);
    } finally {
      setPocLoading(false);
    }
  }

  async function loadHits() {
    try {
      const r = await api.intelAssetHits(200);
      setHits(r.items);
      setHitsLoaded(true);
    } catch (e) {
      toast.error("读取资产命中失败：" + (e as Error).message);
    }
  }

  const stats = status?.stats;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">漏洞情报</h1>
          <p className="text-muted-foreground text-sm">
            NVD 全量 + CISA KEV 在野利用 + GitHub 公开仓库线索，都是公开数据；情报只给候选，可利用性必须在授权目标上实测。
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void loadStatus()} disabled={loading}>
            <RefreshCwIcon /> 刷新状态
          </Button>
          <Button variant="outline" size="sm" onClick={() => void sync("kev")} disabled={syncing || Boolean(status?.running)}>
            <FlameIcon /> 同步 KEV
          </Button>
          <Button variant="outline" size="sm" onClick={() => void sync("recent")} disabled={syncing || Boolean(status?.running)}>
            <CloudDownloadIcon /> 同步近 7 天
          </Button>
          <Button variant="outline" size="sm" onClick={() => void sync("poc")} disabled={syncing || Boolean(status?.running)}>
            <GitBranchIcon /> 聚合 PoC
          </Button>
          <Button size="sm" onClick={() => void sync("full")} disabled={syncing || Boolean(status?.running)}>
            {status?.running ? <Spinner data-icon="inline-start" /> : <DatabaseIcon />}
            {status?.running ? `同步中（${status.running}）` : "回填 120 天"}
          </Button>
        </div>
      </div>

      {status?.last_error && (
        <div className="flex items-start gap-2 rounded-lg border border-destructive/40 bg-destructive/5 p-3 text-sm">
          <AlertTriangleIcon className="text-destructive mt-0.5 size-4 shrink-0" />
          <div>
            <p className="font-medium">上次同步报错</p>
            <p className="text-muted-foreground break-all text-xs">{status.last_error}</p>
          </div>
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        {[
          { label: "情报条目", value: stats?.total ?? 0, hint: "NVD + KEV 去重后" },
          { label: "KEV 在野利用", value: stats?.kev ?? 0, hint: "CISA 已确认被利用" },
          { label: "CVSS ≥ 9", value: stats?.critical ?? 0, hint: "严重" },
          { label: "近 7 天新增", value: stats?.last_7_days ?? 0, hint: "按发布时间" },
          {
            label: "PoC 线索",
            value: status?.poc?.repos ?? 0,
            hint: `覆盖 ${status?.poc?.cves ?? 0} 个 CVE · 待查 ${status?.poc?.queue ?? 0}`,
          },
        ].map((c) => (
          <Card key={c.label} className="gap-0 py-4">
            <CardHeader className="px-4 pb-1">
              <CardDescription className="text-xs">{c.label}</CardDescription>
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
          <TabsTrigger value="hits" onClick={() => { if (!hitsLoaded) void loadHits(); }}>
            命中我的资产
          </TabsTrigger>
          <TabsTrigger value="github">GitHub 配置</TabsTrigger>
        </TabsList>

        <TabsContent value="library" className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <SearchIcon className="text-muted-foreground pointer-events-none absolute top-2.5 left-2.5 size-4" />
              <Input
                className="w-72 pl-8"
                placeholder="组件 / 产品 / CVE 编号，如 nginx、CVE-2024-3094"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") void loadPage(0, q, kevOnly, minCvss);
                }}
              />
            </div>
            <Select value={minCvss} onValueChange={(v) => { setMinCvss(v); void loadPage(0, q, kevOnly, v); }}>
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
                onCheckedChange={(v) => { setKevOnly(v === true); void loadPage(0, q, v === true, minCvss); }}
              />
              只看 KEV
            </label>
            <Button variant="outline" size="sm" onClick={() => void loadPage(0, q, kevOnly, minCvss)} disabled={loading}>
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
                  <TableHead className="w-28">发布</TableHead>
                  <TableHead className="w-20">KEV</TableHead>
                  <TableHead className="w-20">PoC</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} className="text-muted-foreground py-10 text-center text-sm">
                      {loading ? "查询中…" : "还没有情报。点右上角「同步 KEV」先拉一份在野利用目录（约 1800 条，几秒）。"}
                    </TableCell>
                  </TableRow>
                )}
                {items.map((e) => (
                  <TableRow key={e.cve_id}>
                    <TableCell className="font-mono text-xs">{e.cve_id}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className={severityTone[e.severity?.toUpperCase()] ?? ""}>
                        {e.severity || "—"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{e.cvss ? e.cvss.toFixed(1) : "—"}</TableCell>
                    <TableCell className="max-w-[520px]">
                      <p className="truncate text-sm" title={e.title || e.description}>
                        {e.title || e.description || "—"}
                      </p>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-xs">{fmtDate(e.published_at)}</TableCell>
                    <TableCell>
                      {e.kev ? (
                        <Badge variant="outline" className="border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400">
                          在野
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground text-xs">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {e.poc_count ? (
                        <button
                          type="button"
                          className="text-primary text-xs font-medium underline-offset-2 hover:underline"
                          onClick={() => void openPocs(e.cve_id)}
                        >
                          {e.poc_count} 个
                        </button>
                      ) : (
                        <span className="text-muted-foreground text-xs">—</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-muted-foreground text-xs">
              第 {page + 1} / {pages} 页
            </span>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page === 0 || loading}
                onClick={() => void loadPage(page - 1, q, kevOnly, minCvss)}
              >
                上一页
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={page + 1 >= pages || loading}
                onClick={() => void loadPage(page + 1, q, kevOnly, minCvss)}
              >
                下一页
              </Button>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="hits" className="flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <p className="text-muted-foreground text-xs">
              拿资产台账里的 technologies 反查情报库（CVSS ≥ 7 或在 KEV）。版本未采集，命中一律「可能受影响」。
            </p>
            <Button variant="outline" size="sm" onClick={() => void loadHits()}>
              <RefreshCwIcon /> 重新匹配
            </Button>
          </div>
          <div className="overflow-hidden rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-40">资产</TableHead>
                  <TableHead className="w-40">技术指纹</TableHead>
                  <TableHead className="w-44">CVE</TableHead>
                  <TableHead className="w-20">等级</TableHead>
                  <TableHead>标题</TableHead>
                  <TableHead className="w-24">版本判定</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {hits.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-muted-foreground py-10 text-center text-sm">
                      {hitsLoaded ? "没有命中：要么资产没采到技术指纹，要么情报库还没同步。" : "加载中…"}
                    </TableCell>
                  </TableRow>
                )}
                {hits.map((h) => (
                  <TableRow key={`${h.asset_id}-${h.cve_id}`}>
                    <TableCell className="font-mono text-xs">{h.host || `#${h.asset_id}`}</TableCell>
                    <TableCell className="text-xs">{h.technology}</TableCell>
                    <TableCell className="font-mono text-xs">{h.cve_id}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className={severityTone[h.severity?.toUpperCase()] ?? ""}>
                        {h.severity || "—"}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-[420px]">
                      <p className="truncate text-sm" title={h.title}>{h.title || "—"}</p>
                    </TableCell>
                    <TableCell>
                      <span className="text-muted-foreground text-xs">未知（无版本）</span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </TabsContent>

        <TabsContent value="github" className="flex flex-col gap-3">
          <Card className="max-w-3xl">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <GitBranchIcon className="size-4" /> GitHub PoC 线索
              </CardTitle>
              <CardDescription>
                拿 CVE 编号在 GitHub 公开搜索里查仓库名/描述，只落元数据（repo、star、描述、URL），
                不克隆、不执行、不托管任何代码。带 token 时 30 次/分钟，匿名 10 次/分钟。
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <div className="flex items-center justify-between rounded-lg border p-3">
                <div>
                  <p className="text-sm font-medium">自动聚合</p>
                  <p className="text-muted-foreground text-xs">
                    每 30 分钟随 KEV/NVD 快通道补一批（KEV 与 CVSS ≥ 9 优先，只查没查过的）。
                  </p>
                </div>
                <Switch
                  checked={ghEnabled}
                  onCheckedChange={(v) => {
                    setGhEnabled(v === true);
                    void saveGitHub({ enabled: v === true });
                  }}
                  disabled={savingCfg}
                />
              </div>

              <div className="flex flex-col gap-2">
                <label htmlFor="gh-token" className="text-sm font-medium">
                  Personal access token
                </label>
                <div className="flex gap-2">
                  <Input
                    id="gh-token"
                    className="min-w-0 flex-1"
                    type="password"
                    autoComplete="off"
                    placeholder={gh?.token_set ? `已配置 ${gh.token_tip}（留空 = 不修改）` : "ghp_… 或 github_pat_…（可留空，匿名也能跑但更慢）"}
                    value={ghToken}
                    onChange={(e) => setGhToken(e.target.value)}
                  />
                  <Button onClick={() => void saveGitHub()} disabled={savingCfg}>
                    {savingCfg ? <Spinner data-icon="inline-start" /> : <SaveIcon />} 保存
                  </Button>
                  {gh?.token_set && (
                    <Button
                      variant="outline"
                      onClick={() => void saveGitHub({ token: "" })}
                      disabled={savingCfg}
                    >
                      清除
                    </Button>
                  )}
                </div>
                <p className="text-muted-foreground text-[11px]">
                  只需 public_repo 读权限（fine-grained token 勾 Public repositories 即可）。token 存库、只在服务端使用，
                  页面上只回显末四位。上次聚合：{gh?.last_sync || "从未"}
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2 border-t pt-3">
                <Button variant="outline" onClick={() => void sync("poc")} disabled={syncing || Boolean(status?.running)}>
                  <GitBranchIcon /> 立即聚合一批
                </Button>
                <span className="text-muted-foreground text-xs">
                  待查 {status?.poc?.queue ?? 0} 个 CVE · 已有线索 {status?.poc?.repos ?? 0} 条（覆盖{" "}
                  {status?.poc?.cves ?? 0} 个 CVE）
                </span>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <Dialog open={pocCVE !== null} onOpenChange={(v) => { if (!v) setPocCVE(null); }}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="font-mono text-base">{pocCVE}</DialogTitle>
            <DialogDescription>
              公开仓库线索，按 star 排序。这是「别人写了 EXP」的信号，不是可利用性结论；陌生代码不要直接执行。
            </DialogDescription>
          </DialogHeader>
          {pocLoading ? (
            <div className="text-muted-foreground flex items-center gap-2 py-6 text-sm">
              <Spinner /> 加载中…
            </div>
          ) : pocItems.length === 0 ? (
            <p className="text-muted-foreground py-6 text-sm">没有查到公开仓库线索（或还没聚合到这条）。</p>
          ) : (
            <ul className="flex flex-col gap-2">
              {pocItems.map((p) => (
                <li key={p.repo} className="rounded-lg border p-3">
                  <div className="flex items-center gap-2">
                    <a
                      href={p.url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="text-primary flex items-center gap-1 font-mono text-sm hover:underline"
                    >
                      {p.repo} <ExternalLinkIcon className="size-3" />
                    </a>
                    <Badge variant="outline" className="text-[10px]">★ {p.stars}</Badge>
                    {p.lang && <span className="text-muted-foreground text-[11px]">{p.lang}</span>}
                  </div>
                  {p.description && (
                    <p className="text-muted-foreground mt-1 text-xs">{p.description}</p>
                  )}
                </li>
              ))}
            </ul>
          )}
        </DialogContent>
      </Dialog>

      {status && (
        <p className="text-muted-foreground text-[11px]">
          数据源：NVD API 2.0 / CISA KEV · 上次 KEV 同步 {status.last_kev_sync || "从未"} · 上次 NVD 同步{" "}
          {status.last_nvd_sync || "从未"}
          {status.enabled ? "" : " · 自动同步已关闭"}
        </p>
      )}
    </div>
  );
}
