"use client";

import * as React from "react";

import Link from "next/link";

import { BellRingIcon } from "lucide-react";
import { useShallow } from "zustand/react/shallow";

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";
import { APP_CONFIG } from "@/config/app-config";
import { useCurrentUser } from "@/hooks/use-current-user";
import { api } from "@/lib/api";
import { sidebarItems } from "@/navigation/sidebar/sidebar-items";
import { usePreferencesStore } from "@/stores/preferences/preferences-provider";

import { NavMain } from "./nav-main";
import { NavUser } from "./nav-user";
import { SidebarSupportCard } from "./sidebar-support-card";


export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const currentUser = useCurrentUser();
  const { sidebarVariant, sidebarCollapsible, isSynced } = usePreferencesStore(
    useShallow((s) => ({
      sidebarVariant: s.sidebarVariant,
      sidebarCollapsible: s.sidebarCollapsible,
      isSynced: s.isSynced,
    })),
  );

  const variant = isSynced ? sidebarVariant : props.variant;
  const collapsible = isSynced ? sidebarCollapsible : props.collapsible;

  // 待审批提示：顶栏品牌右侧常驻一个计数徽标，有待审批内容时醒目显示。
  // 20s 轮询一次；接口失败静默（不打扰主流程），下轮再试。
  const [pendingApprovals, setPendingApprovals] = React.useState(0);
  React.useEffect(() => {
    let alive = true;
    const load = () => {
      api
        .interceptPending()
        .then((list) => {
          if (alive) setPendingApprovals(list.length);
        })
        .catch(() => {
          /* 静默：审批服务异常不该影响导航 */
        });
    };
    void load();
    const timer = window.setInterval(load, 20_000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  return (
    <Sidebar {...props} variant={variant} collapsible={collapsible}>
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem className="relative">
            <SidebarMenuButton asChild>
              <Link prefetch={false} href="/function/tasks">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src="/logo.png" alt="ARTEX" width={40} height={40} className="shrink-0" />
                <span className="font-semibold text-base">{APP_CONFIG.name}</span>
              </Link>
            </SidebarMenuButton>
            {pendingApprovals > 0 && (
              <Link
                prefetch={false}
                href="/system/intercept/approvals"
                aria-label={`${pendingApprovals} 条待审批`}
                title={`${pendingApprovals} 条待审批，点击处理`}
                className="absolute top-1/2 right-2 z-10 flex -translate-y-1/2 items-center gap-1 rounded-full border border-amber-500/50 bg-amber-500/15 px-2 py-0.5 text-[11px] font-semibold text-amber-700 shadow-sm transition-colors hover:bg-amber-500/25 dark:text-amber-300"
              >
                <BellRingIcon className="size-3.5 animate-pulse" />
                {pendingApprovals > 99 ? "99+" : pendingApprovals}
              </Link>
            )}
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <NavMain items={sidebarItems} />
        {/* <NavDocuments items={data.documents} /> */}
        {/* <NavSecondary items={data.navSecondary} className="mt-auto" /> */}
      </SidebarContent>
      <SidebarFooter>
        <NavUser user={currentUser} />
      </SidebarFooter>
    </Sidebar>
  );
}
