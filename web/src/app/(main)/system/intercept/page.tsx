// 拦截规则（V9-UI）：拦截规则与短路规则合并到同一页（路由仍为
// /system/intercept）。两个区块各自带「图标 + 大标题 + 灰色副标题」；
// 资产拦截 / 审批记录仍在左侧导航里，入口不受影响。旧的 /system/shortcircuit
// 只做重定向到这里。

import { ShieldAlertIcon, ShieldCheckIcon } from "lucide-react";

import { SectionHeader } from "@/components/section-header";

import { InterceptSection } from "./_components/intercept-section";
import { ShortCircuitSection } from "./_components/shortcircuit-section";

export default function InterceptPage() {
  return (
    <div className="flex flex-1 flex-col gap-8">
      <section data-section="intercept-rules" className="flex flex-col gap-4">
        <SectionHeader
          icon={ShieldAlertIcon}
          title="拦截规则"
          description="工具执行前先按拦截规则匹配；未命中的命令可交由模型兜底判定。"
        />
        <InterceptSection />
      </section>

      <section data-section="short-circuit" className="flex flex-col gap-4">
        <SectionHeader
          icon={ShieldCheckIcon}
          title="短路规则"
          description="代码级红线（不进 DB、不受设置热改影响），只能改文件 + 重启服务端生效。"
        />
        <ShortCircuitSection />
      </section>
    </div>
  );
}
