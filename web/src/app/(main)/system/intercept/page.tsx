"use client";

// 拦截规则（V9-UI2 / V12-RULES）：顶部 segmented tabs 在「拦截规则 / 资产拦截」
// 之间切换，只显示当前 tab 的区块；当前 tab 记在 URL query（?tab=assets），
// 刷新/分享不丢。
//
// 「短路规则」tab 在规则合并后删除：三类规则（内置 / 短路 / DB）只剩
// intercept_rules 一套，平台地址改成设置项 + 规则里的占位符（见页面顶部
// 的「平台自身地址」卡片）。

import * as React from "react";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

import { BanIcon, ShieldAlertIcon } from "lucide-react";

import { SectionHeader } from "@/components/section-header";
import { SegmentedTabs } from "@/components/segmented-tabs";

import { AssetInterceptSection } from "./_components/asset-intercept-section";
import { InterceptSection } from "./_components/intercept-section";

type InterceptTab = "rules" | "assets";

const TABS: { value: InterceptTab; label: string }[] = [
  { value: "rules", label: "拦截规则" },
  { value: "assets", label: "资产拦截" },
];

function readTab(v: string | null): InterceptTab {
  // 旧的 ?tab=short 链接落到「拦截规则」：短路规则已并入规则表。
  return v === "assets" ? v : "rules";
}

function InterceptPageInner() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const tab = readTab(searchParams.get("tab"));

  const onTabChange = (v: InterceptTab) => {
    const q = new URLSearchParams(searchParams.toString());
    if (v === "rules") q.delete("tab");
    else q.set("tab", v);
    const qs = q.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  };

  return (
    <div className="flex flex-1 flex-col gap-4">
      <SegmentedTabs value={tab} items={TABS} onChange={onTabChange} ariaLabel="拦截视图" />

      {tab === "rules" ? (
        <section data-section="intercept-rules" className="flex flex-col gap-4">
          <SectionHeader
            icon={ShieldAlertIcon}
            title="拦截规则"
            description="工具执行前先按拦截规则匹配（唯一一套规则）；未命中的命令可交由模型兜底判定。"
          />
          <InterceptSection />
        </section>
      ) : null}

      {tab === "assets" ? (
        <section data-section="asset-intercept" className="flex flex-col gap-4">
          <SectionHeader
            icon={BanIcon}
            title="资产拦截"
            description="全局资产黑名单：命中的域名 / IP / URL / 网段将被拦截，不对其执行任何操作。"
          />
          <AssetInterceptSection />
        </section>
      ) : null}
    </div>
  );
}

export default function InterceptPage() {
  // useSearchParams 在静态导出下要求 Suspense 边界。
  return (
    <React.Suspense fallback={null}>
      <InterceptPageInner />
    </React.Suspense>
  );
}
