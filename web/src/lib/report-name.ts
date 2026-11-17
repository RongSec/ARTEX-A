// V9-UI3：报告名称占位符模板的前端渲染（与后端 report/name_template.go 同口径）。
//
// 仅用于「报告设置」弹窗里的示例实时预览；真正生成文件时文件名一律由后端
// RenderReportName/ReportFileName 决定，前端不拼文件名。
//
// 口径：
//   - 空模板 = 默认 `{system}渗透测试报告-{YYYY-MM-DD}`；
//   - 时间分量固定 UTC+8（与后端 ReportTimezone 一致），不受浏览器时区影响；
//   - 未知 / 未闭合占位符原样保留；
//   - 示例额外做文件名清洗（非法字符→_），与后端 SanitizeReportFileName 一致。

export const DEFAULT_REPORT_NAME_TEMPLATE = "{system}渗透测试报告-{YYYY-MM-DD}";

export interface ReportNameData {
  system: string;
  title: string;
  taskId?: number;
  projectId?: number;
  taskName?: string;
  projectName?: string;
}

interface TimeParts {
  year: string;
  year2: string;
  month: string;
  month1: string;
  day: string;
  day1: string;
  hour: string;
  minute: string;
  second: string;
}

// 用 Intl 直接取 UTC+8 的日历分量，避免浏览器本地时区干扰。
function shanghaiParts(at: Date): TimeParts {
  const fmt = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
  const bag: Record<string, string> = {};
  for (const p of fmt.formatToParts(at)) {
    if (p.type !== "literal") bag[p.type] = p.value;
  }
  const year = bag.year ?? "1970";
  const month = bag.month ?? "01";
  const day = bag.day ?? "01";
  const hour = bag.hour === "24" ? "00" : (bag.hour ?? "00");
  const minute = bag.minute ?? "00";
  const second = bag.second ?? "00";
  return {
    year,
    year2: year.slice(-2),
    month,
    month1: String(Number(month)),
    day,
    day1: String(Number(day)),
    hour,
    minute,
    second,
  };
}

// 布局 token 白名单（长 token 在前，避免 M 吃掉 MM），与后端 nameLayoutTokens 一致。
const LAYOUT_TOKENS: { key: string; pick: (p: TimeParts) => string }[] = [
  { key: "YYYY", pick: (p) => p.year },
  { key: "YY", pick: (p) => p.year2 },
  { key: "MM", pick: (p) => p.month },
  { key: "DD", pick: (p) => p.day },
  { key: "HH", pick: (p) => p.hour },
  { key: "mm", pick: (p) => p.minute },
  { key: "ss", pick: (p) => p.second },
  { key: "M", pick: (p) => p.month1 },
  { key: "D", pick: (p) => p.day1 },
];

function formatLayout(layout: string, p: TimeParts): string {
  let out = "";
  for (let i = 0; i < layout.length; ) {
    const hit = LAYOUT_TOKENS.find((t) => layout.startsWith(t.key, i));
    if (hit) {
      out += hit.pick(p);
      i += hit.key.length;
      continue;
    }
    out += layout[i];
    i += 1;
  }
  return out;
}

// 复合时间 token（如 `YYYY-MM-DD`）：只有整段由已知 token 或非字母数字字面量
// 组成时才按布局渲染，否则视为未知占位符。
function tryFormatLayoutToken(token: string, p: TimeParts): string | null {
  let out = "";
  let consumed = false;
  for (let i = 0; i < token.length; ) {
    const hit = LAYOUT_TOKENS.find((t) => token.startsWith(t.key, i));
    if (hit) {
      out += hit.pick(p);
      i += hit.key.length;
      consumed = true;
      continue;
    }
    const ch = token[i];
    if (/[a-zA-Z0-9]/.test(ch)) return null;
    out += ch;
    i += 1;
  }
  return consumed ? out : null;
}

export function renderReportName(
  template: string,
  data: ReportNameData,
  at: Date = new Date(),
): string {
  const tmpl = template.trim() === "" ? DEFAULT_REPORT_NAME_TEMPLATE : template;
  const p = shanghaiParts(at);

  let system = (data.system ?? "").trim();
  if (!system) {
    if ((data.taskId ?? 0) > 0) system = `任务${data.taskId}`;
    else if ((data.projectId ?? 0) > 0) system = `项目${data.projectId}`;
    else system = "目标系统";
  }
  const title = (data.title ?? "").trim() || `${system}渗透测试报告`;

  const tokenValue = (token: string): string | null => {
    if (token.length > 5 && token.slice(0, 5).toLowerCase() === "date:") {
      return formatLayout(token.slice(5), p);
    }
    // mm=分钟、MM=月份：大小写敏感优先。
    if (token === "mm") return p.minute;
    if (token === "MM") return p.month;
    switch (token.toLowerCase()) {
      case "system":
        return system;
      case "title":
        return title;
      case "yyyy":
        return p.year;
      case "yy":
        return p.year2;
      case "m":
        return p.month1;
      case "dd":
        return p.day;
      case "d":
        return p.day1;
      case "hh":
        return p.hour;
      case "ss":
        return p.second;
      case "date":
        return `${p.year}-${p.month}-${p.day}`;
      case "task_id":
        return (data.taskId ?? 0) > 0 ? String(data.taskId) : "";
      case "project_id":
        return (data.projectId ?? 0) > 0 ? String(data.projectId) : "";
      case "task":
        return (data.taskName ?? "").trim();
      case "project":
        return (data.projectName ?? "").trim();
    }
    return tryFormatLayoutToken(token, p);
  };

  let out = "";
  for (let i = 0; i < tmpl.length; ) {
    if (tmpl[i] !== "{") {
      out += tmpl[i];
      i += 1;
      continue;
    }
    const close = tmpl.indexOf("}", i + 1);
    if (close < 0) {
      out += tmpl.slice(i);
      break;
    }
    const token = tmpl.slice(i + 1, close);
    const value = tokenValue(token);
    out += value == null ? tmpl.slice(i, close + 1) : value;
    i = close + 1;
  }
  return out;
}

// 与后端 SanitizeReportFileName 等价：非法字符→_，折叠首尾空白/点，限长 120。
export function sanitizeReportFileName(name: string): string {
  const replaced = name.replace(/[/\\:*?"<>|\r\n\t]/g, "_").trim().replace(/^[ .]+|[ .]+$/g, "");
  const out = replaced || "渗透测试报告";
  const runes = Array.from(out);
  return runes.length > 120 ? runes.slice(0, 120).join("") : out;
}

// 示例预览用：渲染并补 .docx（不参与真实生成）。
export function previewReportFileName(
  template: string,
  data: ReportNameData,
  at: Date = new Date(),
): string {
  return `${sanitizeReportFileName(renderReportName(template, data, at))}.docx`;
}
