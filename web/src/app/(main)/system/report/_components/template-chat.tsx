"use client";

// 报告中心·对话调模板面板（artex-hs T21，设计 §1.2B）。
//
// 消息流=组件本地态（工具性调试会话，刷新即清可接受——不建 conversations
// 表）。每轮发送：当前 draft（inline 模板）+ 历史 messages →
// POST /api/report-templates/{id}/chat → 服务端护栏 parseChatPatch 合并 →
// 回 {reply, template(全量草稿), warnings}：
//   - template 直接 setDraft 进右栏编辑态（用户点「保存」才落库）；
//   - warnings 黄条展示（骨架非法被拦/未知 style 键等护栏拦截说明）；
//   - 失败（400/502）toast，会话保留可重发。
//
// 新建未保存模板（无 id）时禁用发送——chat 端点挂 /report-templates/{id}
// 且以 DB 行为底，无行可依托（提示先保存）。

import * as React from "react";

import { SendIcon, SparklesIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { ReportTemplateInput, TemplateChatMessage } from "@/lib/types";

export function TemplateChat(props: {
  templateId: number | null; // null=未保存新建，禁用发送
  draft: ReportTemplateInput | null;
  onApplyTemplate: (t: ReportTemplateInput) => void; // 合并草稿进编辑态（dirty 由父级管）
  locale: string;
}) {
  const { templateId, draft, onApplyTemplate, locale } = props;
  const [messages, setMessages] = React.useState<TemplateChatMessage[]>([]);
  const [input, setInput] = React.useState("");
  const [sending, setSending] = React.useState(false);
  const [warnings, setWarnings] = React.useState<string[]>([]);
  const scrollRef = React.useRef<HTMLDivElement | null>(null);

  // 切模板=新调试会话（消息流与模板强相关，留着会误导模型）。
  React.useEffect(() => {
    setMessages([]);
    setWarnings([]);
    setInput("");
  }, [templateId]);

  const send = async () => {
    const text = input.trim();
    if (!text || !draft || templateId == null || sending) return;
    const next: TemplateChatMessage[] = [...messages, { role: "user", content: text }];
    setMessages(next);
    setInput("");
    setSending(true);
    setWarnings([]);
    try {
      const resp = await api.reportTemplateChat(templateId, {
        messages: next,
        template: draft,
        locale: locale || undefined,
      });
      setMessages((cur) => [...cur, { role: "assistant", content: resp.reply }]);
      onApplyTemplate(resp.template);
      setWarnings(resp.warnings ?? []);
    } catch (e) {
      // 失败回滚本轮用户消息（可编辑重发），错误 toast。
      setMessages(messages);
      setInput(text);
      toast.error(`对话失败：${(e as Error).message}`);
    } finally {
      setSending(false);
      // 滚到底。
      requestAnimationFrame(() => {
        scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
      });
    }
  };

  const disabled = templateId == null || !draft;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2">
      <div className="flex items-center gap-1.5">
        <SparklesIcon className="text-muted-foreground size-4" />
        <span className="text-sm font-medium">对话调模板</span>
        {disabled && (
          <span className="text-muted-foreground text-xs">（先保存模板后可用）</span>
        )}
      </div>

      <div ref={scrollRef} className="max-h-52 min-h-32 flex-1 space-y-2 overflow-y-auto rounded-lg border p-2 text-sm">
        {messages.length === 0 ? (
          <p className="text-muted-foreground py-6 text-center text-xs">
            用自然语言描述想改的模板设定，例如：把漏洞明细标题改成「发现事项」、正文字体换成宋体、关掉声明章。
            改动先进草稿（右侧设置区同步可见），点保存才落库。
          </p>
        ) : (
          messages.map((m, i) => (
            <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
              <div
                className={`max-w-[85%] whitespace-pre-wrap rounded-lg px-3 py-1.5 ${
                  m.role === "user" ? "bg-primary text-primary-foreground" : "bg-muted"
                }`}
              >
                {m.content}
              </div>
            </div>
          ))
        )}
        {sending && (
          <div className="text-muted-foreground flex items-center gap-2 px-1 text-xs">
            <Spinner className="size-3" /> 模型思考中…
          </div>
        )}
      </div>

      {warnings.length > 0 && (
        <div className="rounded-md border border-amber-400/60 bg-amber-500/10 px-2.5 py-1.5 text-xs text-amber-700 dark:text-amber-400">
          {warnings.map((wn, i) => (
            <p key={i}>{wn}</p>
          ))}
        </div>
      )}

      <div className="flex items-end gap-2">
        <Textarea
          // 单行起步、内容自动增高（field-sizing-content），上限约 3 行；
          // 默认 min-h-16（≈4行）压掉，让对话区整体更矮、右列免滚动看全。
          rows={1}
          className="max-h-[7.5rem] min-h-8 flex-1"
          placeholder={disabled ? "模板保存后才能对话调整" : "描述要改的模板设定…（Enter 发送，Shift+Enter 换行）"}
          value={input}
          disabled={disabled || sending}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              void send();
            }
          }}
        />
        <Button size="sm" onClick={() => void send()} disabled={disabled || sending || !input.trim()}>
          {sending ? <Spinner /> : <SendIcon />} 发送
        </Button>
      </div>
    </div>
  );
}
