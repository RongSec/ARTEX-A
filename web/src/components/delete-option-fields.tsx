"use client";

// 删除时的「同时清理关联数据」勾选块：任务删除与项目删除共用同一套选项与文案，
// 保证两处操作口径一致（用户要求「项目和任务操作一致」）。
//
// 抽出来的原因：两个页面各写一份必然会漂移——加一个新清理项时容易只改一处。

import * as React from "react";

import { Checkbox } from "@/components/ui/checkbox";
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet,
} from "@/components/ui/field";
import type { DeleteTaskOptions } from "@/lib/types";

export const emptyDeleteOptions = (): DeleteTaskOptions => ({
  delete_assets: false,
  delete_traffic: false,
  delete_files: false,
  delete_findings: false,
  delete_llm_records: false,
  delete_intel: false,
  delete_project_graph: false,
});

export const deleteOptionKeys: (keyof DeleteTaskOptions)[] = [
  "delete_assets",
  "delete_traffic",
  "delete_files",
  "delete_findings",
  "delete_llm_records",
  "delete_intel",
  "delete_project_graph",
];

/** DeleteOptionFields 渲染「同时清理关联数据」勾选块（单任务 / 批量 / 项目删除共用）。 */
export function DeleteOptionFields({
  idPrefix,
  options,
  onOptionsChange,
  disabled,
  disabledKeys,
  lockedKeys,
}: {
  idPrefix: string;
  options: DeleteTaskOptions;
  onOptionsChange: React.Dispatch<React.SetStateAction<DeleteTaskOptions>>;
  disabled: boolean;
  /** 单项禁用（例如项目删除且不删旗下任务时，任务级清理项没有作用对象）。 */
  disabledKeys?: (keyof DeleteTaskOptions)[];
  /** 强制勾选且不可取消（项目级派生数据随项目必删）。 */
  lockedKeys?: (keyof DeleteTaskOptions)[];
}) {
  const locked = new Set(lockedKeys ?? []);
  const disabledSet = new Set(disabledKeys ?? []);
  const isOff = (key: keyof DeleteTaskOptions) => disabled || disabledSet.has(key);
  const isLocked = (key: keyof DeleteTaskOptions) => locked.has(key);
  const isChecked = (key: keyof DeleteTaskOptions) => isLocked(key) || options[key];
  const selectedCount = deleteOptionKeys.filter((key) => isChecked(key)).length;
  let allChecked: boolean | "indeterminate" = false;
  if (selectedCount === deleteOptionKeys.length) {
    allChecked = true;
  } else if (selectedCount > 0) {
    allChecked = "indeterminate";
  }

  const updateOption = (key: keyof DeleteTaskOptions, checked: boolean) => {
    if (isLocked(key)) return;
    onOptionsChange((current) => ({ ...current, [key]: checked }));
  };

  const updateAllOptions = (checked: boolean) => {
    onOptionsChange({
      delete_assets: checked,
      delete_traffic: checked,
      delete_files: checked,
      delete_findings: checked,
      delete_llm_records: checked,
      delete_intel: checked || isLocked("delete_intel"),
      delete_project_graph: checked || isLocked("delete_project_graph"),
    });
  };

  return (
    <FieldSet>
      <FieldLegend variant="label">同时清理关联数据</FieldLegend>
      <FieldGroup className="gap-3">
        <Field orientation="horizontal">
          <Checkbox
            id={`delete-all-${idPrefix}`}
            checked={allChecked}
            onCheckedChange={(checked) => updateAllOptions(checked === true)}
          />
          <FieldContent>
            <FieldLabel htmlFor={`delete-all-${idPrefix}`}>全部删除</FieldLabel>
            <FieldDescription>
              选中下方全部关联数据：资产、流量、文件、漏洞（含证据快照）、LLM 记录、情境与复用记录、项目图谱投影。
            </FieldDescription>
          </FieldContent>
        </Field>
        <Field orientation="horizontal">
          <Checkbox
            id={`delete-assets-${idPrefix}`}
            checked={isChecked("delete_assets")}
            disabled={isOff("delete_assets")}
            onCheckedChange={(checked) => updateOption("delete_assets", checked === true)}
          />
          <FieldContent>
            <FieldLabel htmlFor={`delete-assets-${idPrefix}`}>关联资产</FieldLabel>
            <FieldDescription>删除仅属于该任务的资产；共享资产只解除当前任务关联。</FieldDescription>
          </FieldContent>
        </Field>
        <Field orientation="horizontal">
          <Checkbox
            id={`delete-traffic-${idPrefix}`}
            checked={isChecked("delete_traffic")}
            disabled={isOff("delete_traffic")}
            onCheckedChange={(checked) => updateOption("delete_traffic", checked === true)}
          />
          <FieldContent>
            <FieldLabel htmlFor={`delete-traffic-${idPrefix}`}>关联流量</FieldLabel>
            <FieldDescription>按关联资产的精确主机名删除；仍被其他任务引用的共享主机流量会保留。</FieldDescription>
          </FieldContent>
        </Field>
        <Field orientation="horizontal">
          <Checkbox
            id={`delete-files-${idPrefix}`}
            checked={isChecked("delete_files")}
            disabled={isOff("delete_files")}
            onCheckedChange={(checked) => updateOption("delete_files", checked === true)}
          />
          <FieldContent>
            <FieldLabel htmlFor={`delete-files-${idPrefix}`}>任务文件</FieldLabel>
            <FieldDescription>删除该任务工作目录中的上传文件、命令输出和其他产物。</FieldDescription>
          </FieldContent>
        </Field>
        <Field orientation="horizontal">
          <Checkbox
            id={`delete-findings-${idPrefix}`}
            checked={isChecked("delete_findings")}
            disabled={isOff("delete_findings")}
            onCheckedChange={(checked) => updateOption("delete_findings", checked === true)}
          />
          <FieldContent>
            <FieldLabel htmlFor={`delete-findings-${idPrefix}`}>关联漏洞</FieldLabel>
            <FieldDescription>
              永久删除该任务产生的独立漏洞记录与漏洞报告；随漏洞绑定的流量证据快照一并清除。不勾选时漏洞保留，但会失去任务来源（task_id 置空）。
            </FieldDescription>
          </FieldContent>
        </Field>
        <Field orientation="horizontal">
          <Checkbox
            id={`delete-llm-records-${idPrefix}`}
            checked={isChecked("delete_llm_records")}
            disabled={isOff("delete_llm_records")}
            onCheckedChange={(checked) => updateOption("delete_llm_records", checked === true)}
          />
          <FieldContent>
            <FieldLabel htmlFor={`delete-llm-records-${idPrefix}`}>LLM 请求/响应记录</FieldLabel>
            <FieldDescription>永久删除该任务录制的 LLM 请求、响应、Token 与错误详情。</FieldDescription>
          </FieldContent>
        </Field>
        <Field orientation="horizontal">
          <Checkbox
            id={`delete-intel-${idPrefix}`}
            checked={isChecked("delete_intel")}
            disabled={isOff("delete_intel") || isLocked("delete_intel")}
            onCheckedChange={(checked) => updateOption("delete_intel", checked === true)}
          />
          <FieldContent>
            <FieldLabel htmlFor={`delete-intel-${idPrefix}`}>情境与复用记录</FieldLabel>
            <FieldDescription>
              删除该任务的情报表、阅读者勾连记录与下钻审计。关联任务里的对应记录一并清除——否则会留下指向已删任务的 id。
              {isLocked("delete_intel") && "（项目删除时必然执行）"}
            </FieldDescription>
          </FieldContent>
        </Field>
        <Field orientation="horizontal">
          <Checkbox
            id={`delete-project-graph-${idPrefix}`}
            checked={isChecked("delete_project_graph")}
            disabled={isOff("delete_project_graph") || isLocked("delete_project_graph")}
            onCheckedChange={(checked) => updateOption("delete_project_graph", checked === true)}
          />
          <FieldContent>
            <FieldLabel htmlFor={`delete-project-graph-${idPrefix}`}>项目图谱投影</FieldLabel>
            <FieldDescription>
              删除该任务在项目图谱里的索引行与变更事件。项目仍在时只清本任务的行，其他任务不受影响。
              {isLocked("delete_project_graph") && "（项目删除时必然执行）"}
            </FieldDescription>
          </FieldContent>
        </Field>
      </FieldGroup>
    </FieldSet>
  );
}
