#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARTEX 报告模板填充器（以用户上传的 docx 为底稿，python-docx）。

用法:
    python3 template_filler.py <template.docx> <input.json> <output.docx>

与 report_builder.py 的区别：本脚本**不新建 Document()**，而是在模板原件上
只改内容——插入/复制一律 deepcopy 原 XML 节点（copy.deepcopy），因此页眉
页脚、页面设置、样式表、编号、表格框线、封面版式全部原样保留。

锚点（按结构而非固定索引定位，模板微调后仍可工作）：
  - 封面标题段落：正文中的 `xx系统渗透测试报告`
  - 封面日期：首个 Heading 之前的 `YYYY年M月D日` 独立段落
  - 文档信息表：含 `目标/责任主体/联系人` 标签的表格
  - 检测目标表：表头 `系统名称|域名`
  - 漏洞统计表：表头 `漏洞数量|高危|中危|低危`
  - 详细漏洞统计：表头 `序号|系统名称|漏洞名称|风险等级`
  - 漏洞明细块：`检测记录` 章节后的 `cncert标题3` 段落 + 紧随的单列
    `漏洞名称：` 表格（成对复制 N 份）
  - 总结段落：含 `安全评估后结果为：` 的段落

占位替换纪律：
  - 封面标题段（首个 Heading 之前的 `^xx系统.*报告$`）**整段**替换为
    data["title"]；缺省退化为 `system_name + "渗透测试报告"`
  - 其余 `xx系统` → system_name（system_name → targets[0] → title 去报告/
    样例/日期后缀 → "目标系统"）。注意 title 是「报告名」，不是「系统名」，
    二者不可混用，否则封面会重复出现「渗透测试报告」
  - 封面日期段落 → data["generated_at"][:10] 转「YYYY年M月D日」
  - `xx危` 只在漏洞块标题/等级单元格内按实际等级替换（严重/高危/中危/低危）
  - 单独的 `xx` **只在明确单元格/明确 run 内**替换，绝不做全文通配
"""
import copy
import json
import re
import sys
from urllib.parse import urlparse

from docx import Document
from docx.oxml.ns import qn
from docx.table import Table
from docx.text.paragraph import Paragraph

SEV_LABELS = {
    "critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
    "info": "其他", "": "其他",
}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}

# 模板已知占位/文案锚点（集中在这里，模板改字只需改这一处）。
COVER_TITLE_SUFFIX = "渗透测试报告"
INFO_LABELS = ("目标", "责任主体", "所属区域", "联系人", "联系方式")
TARGETS_HEADER = ["系统名称", "域名"]
STATS_HEADER = ["漏洞数量", "高危", "中危", "低危"]
DETAIL_HEADER = ["序号", "系统名称", "漏洞名称", "风险等级"]
RECORDS_HEADING = "检测记录"
SUMMARY_ANCHOR = "安全评估后结果为："


# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------

def _iter_body_paragraphs(doc):
    """遍历正文全部段落（含表格单元格内的段落；不含页眉页脚）。"""
    for el in doc.element.body.iter(qn("w:p")):
        yield Paragraph(el, doc)


def _unique_cells(row):
    """返回一行里的唯一单元格（合并单元格在 row.cells 中会重复出现）。"""
    seen, out = set(), []
    for cell in row.cells:
        key = id(cell._tc)
        if key in seen:
            continue
        seen.add(key)
        out.append(cell)
    return out


def _set_cell_text(cell, text):
    """覆盖单元格首段文本，保留首个 run 的字体/字号（只换字，不换版式）。"""
    p = cell.paragraphs[0]
    runs = p.runs
    if not runs:
        p.add_run(str(text))
        return
    runs[0].text = str(text)
    for r in runs[1:]:
        r._element.getparent().remove(r._element)


def _set_para_text(p, text):
    """覆盖段落文本：保留首 run 的 rPr，删除其余 run。"""
    runs = p.runs
    if not runs:
        p.add_run(str(text))
        return
    runs[0].text = str(text)
    for r in runs[1:]:
        r._element.getparent().remove(r._element)


def _fill_prefixed_cell(cell, value):
    """填充 `标签：值` 形态的单元格。

    模板行 2–5 用 run 里的换行表达换行（`漏洞描述：` + `\\n` + `xx`）。
    这里保留标签 run 与其后的纯换行 run，只替换值 run——「漏洞证明：」后面
    的两个空行因此原样保留（与交付规范③一致）。
    """
    p = cell.paragraphs[0]
    runs = list(p.runs)
    if not runs:
        p.add_run(str(value))
        return
    keep = [runs[0]]
    for r in runs[1:]:
        if r.text.strip() == "" and "\n" in r.text:
            keep.append(r)
        else:
            break
    # 取被替换值 run 的 rPr 作为新 run 的字体模板；没有则留空交给样式继承。
    value_rpr = None
    for r in runs[len(keep):]:
        rpr = r._element.find(qn("w:rPr"))
        if rpr is not None:
            value_rpr = copy.deepcopy(rpr)
            break
    for r in runs[len(keep):]:
        r._element.getparent().remove(r._element)
    run = p.add_run(str(value))
    if value_rpr is not None:
        run._element.insert(0, value_rpr)


def _table_header(table):
    if not table.rows:
        return []
    return [c.text.strip() for c in _unique_cells(table.rows[0])]


def _find_table(doc, header=None, predicate=None):
    for table in doc.tables:
        if header is not None and _table_header(table) == header:
            return table
        if predicate is not None and predicate(table):
            return table
    return None


def _insert_before(body, anchor, element):
    if anchor is not None:
        anchor.addprevious(element)
        return
    sect = body.find(qn("w:sectPr"))
    if sect is not None:
        sect.addprevious(element)
    else:
        body.append(element)


# ---------------------------------------------------------------------------
# 数据归一化
# ---------------------------------------------------------------------------

def _hostname(url):
    """从 `http(s)://host/path` 或裸 `host/path` 中取主机名（失败原样返回）。"""
    text = str(url or "").strip()
    if not text:
        return ""
    parsed = urlparse(text if "://" in text else "//" + text)
    return parsed.hostname or text


def _target_system_name(target):
    """targets 元素 → 系统名：字符串直用；对象取 name，再退 url 主机名。"""
    if isinstance(target, dict):
        name = str(target.get("name") or "").strip()
        if name:
            return name
        return _hostname(target.get("url") or target.get("domain"))
    return str(target or "").strip()


REPORT_SUFFIXES = ("渗透测试报告", "安全评估报告", "安全检测报告", "报告")
# title 尾部的样例/示例括注、-YYYYMMDD 与「YYYY年M月D日」式日期。
TITLE_TAIL_RE = re.compile(r"(?:[-_· ]?\d{8}|[-_· ]?\d{4}年\d{1,2}月\d{1,2}日)$")
SAMPLE_TAIL_RE = re.compile(r"[（(](?:样例|示例)[)）]$")


def _strip_title_suffix(title):
    """去掉 title 尾部的报告名/样例/日期后缀，得到「系统名」口径。"""
    text = str(title or "").strip()
    while True:
        before = text
        text = text.rstrip()
        m = SAMPLE_TAIL_RE.search(text)
        if m:
            text = text[: m.start()]
        else:
            m = TITLE_TAIL_RE.search(text)
            if m:
                text = text[: m.start()]
            else:
                for suffix in REPORT_SUFFIXES:
                    if text.endswith(suffix):
                        text = text[: -len(suffix)]
                        break
        text = text.strip(" -_·")
        if text == before:
            return text


def _system_name(data):
    """xx系统占位的值：显式 → targets[0] → title 去后缀 → 目标系统。

    注意 title 是报告名（含「渗透测试报告」「（样例）」），不是系统名；
    旧实现优先用 title，导致封面与正文出现重复后缀。
    """
    name = str(data.get("system_name") or "").strip()
    if name:
        return name
    for t in data.get("targets") or []:
        name = _target_system_name(t)
        if name:
            return name
    name = _strip_title_suffix(data.get("title"))
    if name:
        return name
    return "目标系统"


def _normalize_targets(data, system_name):
    out = []
    for t in data.get("targets") or []:
        if isinstance(t, dict):
            out.append((str(t.get("name") or system_name), str(t.get("url") or t.get("domain") or "")))
        else:
            text = str(t or "").strip()
            out.append((system_name, text))
    return out or [(system_name, "")]


def _findings(data):
    return [f for f in (data.get("findings") or []) if isinstance(f, dict)]


def _sev_label(sev):
    return SEV_LABELS.get(str(sev or "").strip().lower(), "其他")


def _highest_severity(findings):
    if not findings:
        return ""
    return min((str(f.get("severity") or "").strip().lower() for f in findings),
               key=lambda s: SEV_RANK.get(s, len(SEV_RANK)))


def _fmt_date(raw):
    text = str(raw or "").strip()
    m = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})", text)
    if not m:
        return ""
    return "{0}年{1}月{2}日".format(int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _proof_text(finding):
    """漏洞证明纯文本：与 report_builder.py 的口径一致（入口点/步骤N/
    逐字请求响应），无结构化复现时回退 report_md 纯文本。"""
    rp = finding.get("reproduction")
    if isinstance(rp, str):
        try:
            rp = json.loads(rp)
        except Exception:
            rp = None
    rp = rp or {}
    steps = rp.get("steps") or []
    if steps:
        lines = []
        if rp.get("entry_point"):
            lines.append("入口点：{0}".format(rp["entry_point"]))
        for pre in rp.get("prerequisites") or []:
            lines.append("前置条件：{0}".format(pre))
        for i, st in enumerate(steps):
            desc = st.get("expected") or st.get("proves") or ""
            head = "步骤{0}".format(i + 1)
            if desc:
                head += "：{0}".format(desc)
            lines.append(head)
            if st.get("request"):
                lines.append("请求：\n{0}".format(st["request"]))
            if st.get("response"):
                lines.append("响应：\n{0}".format(st["response"]))
        return "\n".join(lines)
    md = str(finding.get("report_md") or "").strip()
    if md:
        return _md_to_plain(md)
    return "（暂无逐字复现证据，请补充后重新生成）"


def _md_to_plain(md):
    out, buf, in_code = [], [], False
    for line in md.splitlines():
        if line.strip().startswith("```"):
            if in_code:
                out.append("\n".join(buf))
                buf, in_code = [], False
            else:
                if buf:
                    out.append("\n".join(buf))
                    buf = []
                in_code = True
            continue
        if not in_code and not line.strip():
            if buf:
                out.append("\n".join(buf))
                buf = []
            continue
        if not in_code and line.lstrip().startswith("#"):
            line = line.lstrip("# ")
        buf.append(line)
    if buf:
        out.append("\n".join(buf))
    return "\n".join(b for b in out if b.strip())


# ---------------------------------------------------------------------------
# 各区块填充
# ---------------------------------------------------------------------------

def _fill_cover_title(doc, data, system_name):
    """封面标题段整段替换为报告名 title（首个 Heading 之前）。

    封面原句 `xx系统渗透测试报告` 中 `xx系统` 是「系统名」占位，而 title 是
    「报告名」；按占位替换会得到 `系统名渗透测试报告` 与 title 重复。因此这里
    先按整段覆盖，保留首个 run 的字体/字号/加粗与段落对齐。
    """
    title = str(data.get("title") or "").strip()
    if not title:
        title = system_name + COVER_TITLE_SUFFIX
    for p in doc.paragraphs:
        if p.style.name.startswith("Heading"):
            break
        if re.match(r"^xx系统.*报告$", (p.text or "").strip()):
            _set_para_text(p, title)
            return


def _replace_system_name(doc, system_name):
    """`xx系统` 是全文统一占位（正文/表格），一次性替换为系统名。"""
    for p in _iter_body_paragraphs(doc):
        for r in p.runs:
            if "xx系统" in r.text:
                r.text = r.text.replace("xx系统", system_name)


def _fill_cover_date(doc, generated_at):
    date_text = _fmt_date(generated_at)
    if not date_text:
        return
    for p in doc.paragraphs:
        if p.style.name.startswith("Heading"):
            break
        if re.fullmatch(r"\s*\d{4}年\d{1,2}月\d{1,2}日\s*", p.text or ""):
            _set_para_text(p, date_text)
            return


def _fill_info_table(doc, data, system_name):
    table = _find_table(doc, predicate=lambda t: any(
        c.text.strip() == "责任主体" for row in t.rows for c in _unique_cells(row)))
    if table is None:
        return
    wanted = {
        "目标": system_name,
        "责任主体": str(data.get("org") or "").strip(),
        "所属区域": str(data.get("region") or "").strip(),
        "联系人": str(data.get("contact") or "").strip(),
        "联系方式": str(data.get("phone") or "").strip(),
    }
    for row in table.rows:
        cells = _unique_cells(row)
        for i, cell in enumerate(cells[:-1]):
            label = cell.text.strip()
            if label not in wanted:
                continue
            value = wanted[label]
            if value:  # 缺省保留模板原值
                _set_cell_text(cells[i + 1], value)


def _fill_targets_table(doc, data, system_name):
    table = _find_table(doc, header=TARGETS_HEADER)
    if table is None or len(table.rows) < 2:
        return
    proto = copy.deepcopy(table.rows[1]._tr)
    for row in list(table.rows)[1:]:
        table._tbl.remove(row._tr)
    for name, url in _normalize_targets(data, system_name):
        tr = copy.deepcopy(proto)
        table._tbl.append(tr)
        cells = _unique_cells(table.rows[-1])
        _set_cell_text(cells[0], name)
        if len(cells) > 1:
            _set_cell_text(cells[1], url)


def _fill_stats_table(doc, findings):
    table = _find_table(doc, header=STATS_HEADER)
    if table is None or len(table.rows) < 2:
        return
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = str(f.get("severity") or "").strip().lower()
        if sev in counts:
            counts[sev] += 1
    # 模板只有高危/中危/低危三档：critical 并入高危列（口径与总结一致）。
    values = [len(findings), counts["critical"] + counts["high"],
              counts["medium"], counts["low"]]
    cells = _unique_cells(table.rows[1])
    for cell, value in zip(cells, values):
        _set_cell_text(cell, value)


def _fill_detail_table(doc, findings, system_name):
    table = _find_table(doc, header=DETAIL_HEADER)
    if table is None or len(table.rows) < 2:
        return
    proto = copy.deepcopy(table.rows[1]._tr)
    for row in list(table.rows)[1:]:
        table._tbl.remove(row._tr)
    for i, f in enumerate(findings):
        tr = copy.deepcopy(proto)
        table._tbl.append(tr)
        cells = _unique_cells(table.rows[-1])
        values = [
            i + 1,
            f.get("asset") or system_name,
            f.get("name") or "未分类",
            _sev_label(f.get("severity")),
        ]
        for cell, value in zip(cells, values):
            _set_cell_text(cell, value)


def _is_vuln_block_table(table):
    if len(table.columns) != 1 or not table.rows:
        return False
    return table.rows[0].cells[0].text.strip().startswith("漏洞名称")


def _take_vuln_prototypes(doc):
    """定位 `cncert标题3` 段落 + 紧随的单列漏洞表（成对模板）。"""
    body = doc.element.body
    children = list(body.iterchildren())
    for i, el in enumerate(children):
        if el.tag != qn("w:p"):
            continue
        p = Paragraph(el, doc)
        if p.style.name != "cncert标题3" and not re.match(r"^\s*\d+\.\d+\.\d+\s", p.text or ""):
            continue
        for nxt in children[i + 1:]:
            if nxt.tag == qn("w:tbl"):
                t = Table(nxt, doc)
                if _is_vuln_block_table(t):
                    return el, nxt
                break
            if nxt.tag == qn("w:p") and (Paragraph(nxt, doc).text or "").strip():
                break
    return None, None


def _fill_vuln_block(heading_el, table_el, finding, index, doc):
    p = Paragraph(heading_el, doc)
    title = "3.2.{0} {1}【{2}】".format(index + 1, finding.get("name") or "未分类",
                                       _sev_label(finding.get("severity")))
    _set_para_text(p, title)

    table = Table(table_el, doc)
    values = {
        "漏洞名称": finding.get("name") or "未分类",
        "漏洞等级": _sev_label(finding.get("severity")),
        "漏洞描述": finding.get("description") or "（无概述）",
        "影响": finding.get("harm") or "（暂无）",
        "漏洞证明": _proof_text(finding),
        "修复建议": finding.get("remediation") or "（暂无）",
    }
    for row in table.rows:
        cell = row.cells[0]
        label = (cell.text.split("：", 1)[0] or "").strip()
        if label in values:
            _fill_prefixed_cell(cell, values[label])


def _fill_vuln_blocks(doc, findings):
    heading_el, table_el = _take_vuln_prototypes(doc)
    if heading_el is None or table_el is None:
        return
    body = doc.element.body
    anchor = table_el.getnext()
    for el in (heading_el, table_el):
        el.getparent().remove(el)
    if not findings:
        p = doc.add_paragraph("本次未发现可复现漏洞")
        _insert_before(body, anchor, p._p)
        return
    for i, f in enumerate(findings):
        h = copy.deepcopy(heading_el)
        t = copy.deepcopy(table_el)
        _insert_before(body, anchor, h)
        _insert_before(body, anchor, t)
        _fill_vuln_block(h, t, f, i, doc)


def _fill_summary(doc, data, system_name, findings):
    overall = str(data.get("overall") or "").strip()
    if not overall:
        sev = _highest_severity(findings)
        overall = _sev_label(sev) if sev else "未发现可复现漏洞"
    for p in doc.paragraphs:
        if SUMMARY_ANCHOR not in (p.text or ""):
            continue
        for r in p.runs:
            if r.text.strip() == "xx":
                r.text = overall
        return


def fill(template_path, data, output_path):
    """在模板原件上填充 data，另存为 output_path（模板文件本身不改）。"""
    doc = Document(template_path)
    system_name = _system_name(data)
    findings = _findings(data)

    _fill_cover_title(doc, data, system_name)
    _replace_system_name(doc, system_name)
    _fill_cover_date(doc, data.get("generated_at"))
    _fill_info_table(doc, data, system_name)
    _fill_targets_table(doc, data, system_name)
    _fill_stats_table(doc, findings)
    _fill_detail_table(doc, findings, system_name)
    _fill_vuln_blocks(doc, findings)
    _fill_summary(doc, data, system_name, findings)

    doc.save(output_path)


def main():
    if len(sys.argv) != 4:
        sys.stderr.write("用法: template_filler.py <template.docx> <input.json> <output.docx>\n")
        return 2
    with open(sys.argv[2], "r", encoding="utf-8") as f:
        data = json.load(f)
    fill(sys.argv[1], data, sys.argv[3])
    return 0


if __name__ == "__main__":
    sys.exit(main())
