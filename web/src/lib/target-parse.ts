// 批量目标解析（V12-TARGET）。与后端 server/target_parse.go 同语义——
// 「解析」按钮显示的数量必须等于后端实际建的任务数，否则用户会以为少建了。
//
// 接受：URL / 裸 IP / IP:port / CIDR / 域名 / 域名:port / 单标签内网主机名。
// 丢弃：空行、# 与 // 注释、含空白残句、非法 host/端口、重复项。
// 一行里用逗号/分号/空格分隔的粘贴会被切开逐个解析。

export interface ParsedTargets {
  targets: string[]; // 有效目标（规范化、去重、保序）
  duplicate: string[]; // 重复项（保留首条）
  invalid: string[]; // 非法项
}

const URL_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;
const PORT_RE = /^\d{1,5}$/;

function validPort(p: string): boolean {
  if (!PORT_RE.test(p)) return false;
  const n = Number(p);
  return n >= 1 && n <= 65535;
}

function isIPv4(h: string): boolean {
  const parts = h.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

function isIPv6(h: string): boolean {
  // 浏览器只在 IPv6 字面量上接受 URL 解析；这里用 URL 兜底判合法性。
  if (!h.includes(":")) return false;
  try {
    const u = new URL(`http://[${h.replace(/^\[|\]$/g, "")}]`);
    return u.hostname !== "";
  } catch {
    return false;
  }
}

function validHost(h: string): boolean {
  if (!h || h.length > 253) return false;
  const bare = h.replace(/^\[|\]$/g, "");
  if (isIPv4(bare) || isIPv6(bare)) return true;
  if (bare.includes("..") || bare.startsWith(".") || bare.endsWith(".")) return false;
  const labels = bare.split(".");
  for (const label of labels) {
    if (!label || label.length > 63) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
    if (!/^[A-Za-z0-9-]+$/.test(label)) return false;
  }
  // 纯数字单标签多半是端口写串行，不是主机
  if (labels.length === 1 && /^\d+$/.test(labels[0])) return false;
  return true;
}

/** 校验并规范化单个目标；非法返回 null。 */
export function normalizeTarget(raw: string): string | null {
  const s = raw.trim().replace(/^["']|["']$/g, "");
  if (!s || /\s/.test(s)) return null;

  // URL
  if (URL_SCHEME.test(s)) {
    try {
      const u = new URL(s);
      if (!u.hostname || !validHost(u.hostname)) return null;
      if (u.port && !validPort(u.port)) return null;
      return s;
    } catch {
      return null;
    }
  }

  // CIDR
  if (s.includes("/")) {
    const [addr, bits] = s.split("/");
    if (!addr || bits === undefined || !/^\d{1,3}$/.test(bits)) return null;
    const n = Number(bits);
    if (isIPv4(addr)) {
      return n >= 0 && n <= 32 ? s : null;
    }
    if (isIPv6(addr)) {
      return n >= 0 && n <= 128 ? s : null;
    }
    return null;
  }

  // host:port（IPv6 必须写成 [::1]:80）
  const v6 = s.match(/^\[([^\]]+)\]:(\d+)$/);
  if (v6) {
    if (!isIPv6(v6[1]) || !validPort(v6[2])) return null;
    return `[${v6[1].toLowerCase()}]:${v6[2]}`;
  }
  const hp = s.match(/^([^:]+):(\d+)$/);
  if (hp) {
    if (!validHost(hp[1]) || !validPort(hp[2])) return null;
    return `${hp[1].toLowerCase()}:${hp[2]}`;
  }

  // 裸 host（IP / 域名 / 单标签主机名）
  if (!validHost(s)) return null;
  return s.toLowerCase();
}

function splitTokens(line: string): string[] {
  return line
    .split(/[,，;；\t ]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

/** 解析整段文本（与后端 ParseTargets 同语义）。 */
export function parseTargets(text: string): ParsedTargets {
  const targets: string[] = [];
  const duplicate: string[] = [];
  const invalid: string[] = [];
  const seen = new Set<string>();

  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("//")) continue;
    // 整行能解析就直接用，避免把 URL path 里的逗号切开
    const candidates = normalizeTarget(line) ? [line] : splitTokens(line);
    for (const cand of candidates) {
      const norm = normalizeTarget(cand);
      if (!norm) {
        invalid.push(cand);
        continue;
      }
      if (seen.has(norm)) {
        duplicate.push(norm);
        continue;
      }
      seen.add(norm);
      targets.push(norm);
    }
  }
  return { targets, duplicate, invalid };
}
