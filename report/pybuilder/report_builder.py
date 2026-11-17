#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARTEX 渗透测试报告构建器（JSON 驱动，python-docx 渲染）—— artex-hs T16(1/3)。

用法:
    python3 report_builder.py <input.json> <output.docx>

输入 JSON = Go 侧 report.ReportInput 的序列化（数据契约 v2，T15 定、T16 扩展），
结构关键字段: title/scope/locale/issuer/logo_abs/generated_at/style/prompts/
personnel/chapters[{key,title,enabled}]/tasks[]/targets[]/
findings[{name,severity,vulnclass,asset,url_template,description,
           reproduction{entry_point,prerequisites,steps[{request,response,expected,proves}]},
           report_md,harm,remediation,source_tasks,images[{step_index,path,caption}]}]。
style JSONB 可覆盖本文件顶部 DEFAULTS 的任何样式键；缺省即用默认值——
默认值即【用户交付硬规范（最高优先级）】，逐条落点：

  规范① 字体字号:
      - 全文默认字体仿宋(FangSong, w:eastAsia)，西文 Times New Roman；
        正文小四 12pt                          → configure_styles()/body 段落
      - 章标题黑体(SimHei)三号 16pt            → add_heading(level=1)
      - 漏洞节标题=黑体 Pt(18)（H3 语义，等价原版模板 sz=36 半角字号；
        python-docx 用 Pt(18)）                → build_vuln() 节标题
  规范② 表格:
      - 字段标签列/行加粗、值不加粗；样式 Table Grid(grid 边框)
                                              → build_table()/add_vuln_info_table()
  规范③ 漏洞小节结构（每 finding）:
      受控短名标题 → 危险等级 → 描述 →
      「漏洞证明：」标签独立成段【加粗】，其后【两个空段落】再进明细；
      明细=复现过程(入口点/前置条件/步骤1..N：每步=文字说明段 + request/
      response 等宽代码块段落；step 命中 images[].step_index 时穿插证据图)；
      无 reproduction 的步骤证据回退 report_md 文本段（原版模板格式）→
      危害 → 修复建议
  规范④ 章节序=skeleton(chapters) 中 enabled 项:
      封面(标题+出具方+日期+logo) → 声明 → 检测目标表(targets 逐行) →
      风险等级汇总统计表(severity 计数；无「严重」档时并入「高危及以上」
      口径注释) → 漏洞详章(项目级 scope=project 按资产分组分节) → 结论
  规范⑤ 输出文件名 = Go 侧第二参数（ReportBaseName 已防穿越），本脚本不自行
      拼名，只写传入路径。
"""
import sys
import json
import os

from docx import Document
from docx.shared import Pt, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

# ---------------------------------------------------------------------------
# 样式默认值常量表（规范①② 的单一事实源；style JSONB 同名键可覆盖）
# ---------------------------------------------------------------------------
DEFAULTS = {
    "body_font": "仿宋",            # 中文字体（w:eastAsia）——规范① 全文默认
    "west_font": "Times New Roman",  # 西文字体——规范①
    "head_font": "黑体",             # 标题字体——规范①
    "code_font": "Consolas",         # 代码块等宽字体——规范③
    "body_size": 12.0,               # 正文小四 12pt——规范①
    "h1_size": 16.0,                 # 章=黑体三号(16pt)——规范①
    "h2_size": 15.0,                 # 资产分组小节标题（黑体小三）
    "vuln_size": 18.0,               # 漏洞节标题 Pt(18)（sz=36 半角等价）——规范①
    "label_size": 12.0,              # 「漏洞证明：」等独立标签段
    "table_size": 10.5,              # 表格内文字（五号）
    "code_size": 9.0,                # 代码块内文字
    "line_spacing": 1.5,             # 正文行距
    "first_line_indent": True,       # 正文首行缩进 2 字符
    "proof_gap_paragraphs": 2,       # 「漏洞证明：」后空段数——规范③ 两个换行
    "proof_label": "漏洞证明：",       # 标签原文（独立成段加粗）——规范③
    "table_style": "Table Grid",     # grid 边框——规范②
    "code_bg": "F5F5F5",             # 代码块底色
    "proves_label": "漏洞证明",        # proves 行前缀（明细内，非标签段）
}

SEV_LABELS = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
              "": "其他", "info": "其他"}

# ---------------------------------------------------------------------------
# 样式原语
# ---------------------------------------------------------------------------


_NUMERIC_STYLE_KEYS = {
    "body_size", "h1_size", "h2_size", "vuln_size", "label_size",
    "table_size", "code_size", "line_spacing", "proof_gap_paragraphs",
}
# 只接受布尔语义的键；空串按"未设置"处理（模板编辑器清空输入框会写 ""）。
_BOOL_STYLE_KEYS = {"first_line_indent"}

# 必须是整数的键：JSON 数字一律解析成 float，直接进 range() 会抛
# TypeError（"float object cannot be interpreted as an integer"），
# 所以这几个键单独收敛成 int。
_INT_STYLE_KEYS = {"proof_gap_paragraphs"}


def _sanitize_style(raw):
    """把模板里存的样式表收敛成可用值。

    报告模板编辑器会把未填写的输入框写成空字符串（`body_size: ""`），
    这些键一旦直接覆盖 DEFAULTS，后面 `Pt("")` 就会抛 TypeError，整份报告
    渲染 502。这里的纪律：空值=没设置（保留默认），数值键必须能转成数字，
    布尔键只认真假；未知键丢弃。纯函数，无副作用，便于单测。
    """
    out = {}
    if not isinstance(raw, dict):
        return out
    for key, val in raw.items():
        if key not in DEFAULTS:
            continue
        if val is None:
            continue
        if isinstance(val, str):
            text = val.strip()
            if not text:
                continue
            if key in _NUMERIC_STYLE_KEYS:
                try:
                    num = float(text)
                except ValueError:
                    continue
                out[key] = int(round(num)) if key in _INT_STYLE_KEYS else num
            elif key in _BOOL_STYLE_KEYS:
                out[key] = text.lower() in {"1", "true", "yes", "是"}
            else:
                out[key] = text
            continue
        if key in _NUMERIC_STYLE_KEYS:
            try:
                num = float(val)
            except (TypeError, ValueError):
                continue
            out[key] = int(round(num)) if key in _INT_STYLE_KEYS else num
        elif key in _BOOL_STYLE_KEYS:
            out[key] = bool(val)
        elif isinstance(val, (int, float, str)):
            out[key] = val
    return out


class Builder:
    """渲染上下文：合并后的样式表 + Document。"""

    def __init__(self, style_overrides):
        self.s = dict(DEFAULTS)
        if isinstance(style_overrides, dict):
            self.s.update(_sanitize_style(style_overrides))
        self.doc = Document()
        self._configure_styles()

    # -- 底层字体：run 级同时设 w:ascii/w:hAnsi（西文）与 w:eastAsia（中文） --
    def _fmt_run(self, run, font=None, size=None, bold=None, color=None, mono=False):
        s = self.s
        run.font.name = s["west_font"] if not mono else s["code_font"]
        rpr = run._element.get_or_add_rPr()
        rfonts = rpr.find(qn("w:rFonts"))
        if rfonts is None:
            rfonts = OxmlElement("w:rFonts")
            rpr.append(rfonts)
        rfonts.set(qn("w:ascii"), s["code_font"] if mono else s["west_font"])
        rfonts.set(qn("w:hAnsi"), s["code_font"] if mono else s["west_font"])
        rfonts.set(qn("w:eastAsia"), font or (s["code_font"] if mono else s["body_font"]))
        if size is not None:
            run.font.size = Pt(size)
        if bold is not None:
            run.font.bold = bold
        if color is not None:
            run.font.color.rgb = color

    def _configure_styles(self):
        """规范①: Normal 样式=仿宋+TNR 12pt，全文默认字体由此兜底。"""
        s = self.s
        normal = self.doc.styles["Normal"]
        normal.font.name = s["west_font"]
        normal.font.size = Pt(s["body_size"])
        rpr = normal.element.get_or_add_rPr()
        rfonts = rpr.find(qn("w:rFonts"))
        if rfonts is None:
            rfonts = OxmlElement("w:rFonts")
            rpr.append(rfonts)
        rfonts.set(qn("w:ascii"), s["west_font"])
        rfonts.set(qn("w:hAnsi"), s["west_font"])
        rfonts.set(qn("w:eastAsia"), s["body_font"])

    # -- 段落 --
    def para(self, text="", size=None, bold=None, font=None, align=None,
             mono=False, space_before=None, space_after=None, indent=None):
        p = self.doc.add_paragraph()
        if align is not None:
            p.alignment = align
        pf = p.paragraph_format
        pf.line_spacing = self.s["line_spacing"]
        if space_before is not None:
            pf.space_before = Pt(space_before)
        if space_after is not None:
            pf.space_after = Pt(space_after)
        if indent is not None:
            pf.first_line_indent = Pt(indent)
        if text:
            r = p.add_run(text)
            self._fmt_run(r, font=font, size=size, bold=bold, mono=mono)
        return p

    def body(self, text):
        """正文段：仿宋 12pt、首行缩进 2 字符（规范①）。"""
        s = self.s
        return self.para(text, size=s["body_size"],
                         indent=(s["body_size"] * 2) if s["first_line_indent"] else None)

    def h1(self, text):
        """章标题：黑体三号（规范①）。"""
        return self.para(text, size=self.s["h1_size"], bold=True,
                         font=self.s["head_font"], space_before=12, space_after=6)

    def h2(self, text):
        return self.para(text, size=self.s["h2_size"], bold=True,
                         font=self.s["head_font"], space_before=10, space_after=4)

    def h_vuln(self, text):
        """漏洞节标题：黑体 Pt(18)（规范①；H3 语义段）。"""
        p = self.para(text, size=self.s["vuln_size"], bold=True,
                      font=self.s["head_font"], space_before=10, space_after=4)
        p.style = self.doc.styles["Heading 3"]
        # 覆写 style 带来的默认字体（Heading 3 原色/原字体不合规）
        for r in p.runs:
            self._fmt_run(r, font=self.s["head_font"], size=self.s["vuln_size"], bold=True)
            r.font.color.rgb = RGBColor(0, 0, 0)
        return p

    def code_block(self, code):
        """request/response 等宽代码块段落（规范③）：灰底、逐字不省略。"""
        s = self.s
        p = self.doc.add_paragraph()
        pf = p.paragraph_format
        pf.line_spacing = 1.0
        pf.left_indent = Cm(0.5)
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), s["code_bg"])
        p._p.get_or_add_pPr().append(shd)
        for i, line in enumerate(str(code).split("\n")):
            if i > 0:
                p.add_run().add_break()
            r = p.add_run(line)
            self._fmt_run(r, size=s["code_size"], mono=True)
        return p

    def empty(self, n=1):
        # 防御：样式表里的空段数可能是字符串或 float（JSON 数字解析结果），
        # range() 只吃 int，这里统一收敛。
        try:
            count = int(round(float(n)))
        except (TypeError, ValueError):
            count = 0
        for _ in range(max(0, count)):
            self.doc.add_paragraph()

    def page_break(self):
        self.doc.add_page_break()

    # -- 表格（规范②：标签列/行加粗值不加粗，Table Grid）--
    def table(self, header, rows, widths=None, header_shade="D9E2F3",
              label_col=None):
        """header=None → 无表头（纵向属性表）；label_col=0 → 首列标签加粗
        值列不加粗；header 行加粗+浅蓝底。"""
        s = self.s
        ncols = len(header) if header else (len(rows[0]) if rows else 0)
        t = self.doc.add_table(rows=0, cols=ncols)
        try:
            t.style = s["table_style"]
        except KeyError:
            pass  # 模板缺样式时保持默认边框
        t.alignment = WD_TABLE_ALIGNMENT.CENTER

        def fill(row_vals, bold, shade=None):
            row = t.add_row()
            for ci, val in enumerate(row_vals):
                cell = row.cells[ci]
                p = cell.paragraphs[0]  # 新建 cell 自带一个空段落，直接写，勿再塞空 run
                p.paragraph_format.line_spacing = 1.0
                r = p.add_run(str(val))
                cell_bold = bold if not callable(bold) else bold(ci)
                self._fmt_run(r, size=s["table_size"], bold=cell_bold)
                if shade:
                    shd = OxmlElement("w:shd")
                    shd.set(qn("w:val"), "clear")
                    shd.set(qn("w:color"), "auto")
                    shd.set(qn("w:fill"), shade)
                    cell._tc.get_or_add_tcPr().append(shd)

        if header:
            fill(header, True, header_shade)
        for rv in rows:
            if label_col is not None:
                fill(rv, lambda ci, lc=label_col: (ci == lc))
            else:
                fill(rv, False)
        if widths:
            for ci, w in enumerate(widths):
                for row in t.rows:
                    row.cells[ci].width = Cm(w)
        return t

    def picture(self, path, width_cm=14.5, caption=None):
        if not path or not os.path.isfile(path):
            return False
        try:
            self.doc.add_picture(path, width=Cm(width_cm))
        except Exception:
            return False
        if caption:
            self.para(caption, size=9, align=WD_ALIGN_PARAGRAPH.CENTER)
        return True

    # ------------------------------------------------------------------
    # 章节渲染（规范④ 顺序由调用方按 skeleton 驱动）
    # ------------------------------------------------------------------

    def cover(self, data):
        s = self.s
        self.empty(4)
        if data.get("logo_abs"):
            self.picture(data["logo_abs"], width_cm=5, caption=None)
            self.doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        self.para(data.get("title") or "渗透测试报告", size=26, bold=True,
                  font=s["head_font"], align=WD_ALIGN_PARAGRAPH.CENTER, space_after=6)
        self.para("渗透测试报告", size=16, font=s["head_font"],
                  align=WD_ALIGN_PARAGRAPH.CENTER, space_after=24)
        rows = []
        if data.get("issuer"):
            rows.append(["出具方", data["issuer"]])
        targets = data.get("targets") or []
        if targets:
            rows.append(["检测目标", "、".join(targets[:5]) + ("…" if len(targets) > 5 else "")])
        rows.append(["报告日期", (data.get("generated_at") or "")[:10]])
        self.table(None, rows, widths=[4, 10], label_col=0)
        self.empty(2)
        # 人员表（模板 personnel JSON，可空）
        personnel = data.get("personnel")
        if isinstance(personnel, str):
            try:
                personnel = json.loads(personnel)
            except Exception:
                personnel = None
        if isinstance(personnel, list) and personnel:
            self.table(["姓名", "角色", "联系方式"],
                       [[p.get("name", ""), p.get("role", ""), p.get("contact", "")]
                        for p in personnel if isinstance(p, dict)],
                       widths=[4, 6, 4])
        self.page_break()

    def statement(self, data):
        self.h1(_chapter_title(data, "statement", "声明"))
        self.body("本报告由报告所列出具方在委托方授权范围内编制，所载内容仅反映测试时点的"
                  "安全状况，供委托方内部安全改进使用。未经出具方书面许可，本报告全部或"
                  "部分内容不得向第三方披露或用于任何非法用途。委托方应在收到报告后尽快"
                  "组织修复，并在修复完成后安排复测以验证处置效果。")

    def targets_table(self, data):
        self.h1(_chapter_title(data, "targets", "检测目标"))
        rows = [[str(i + 1), t] for i, t in enumerate(data.get("targets") or [])]
        if not rows:
            self.body("（无可验证的漏洞目标）")
            return
        self.table(["序号", "目标地址"], rows, widths=[2, 12])
        self.body("注：以上目标均已在后续漏洞明细中给出可复现的请求证据；无证据的目标已从"
                  "本表剔除（见生成任务警告信息）。")

    def summary_table(self, data):
        self.h1(_chapter_title(data, "summary", "风险等级汇总"))
        counts = {}
        for f in data.get("findings") or []:
            counts[f.get("severity") or ""] = counts.get(f.get("severity") or "", 0) + 1
        rows = []
        for key in ("critical", "high", "medium", "low", ""):
            label = SEV_LABELS.get(key, "其他")
            rows.append([label, str(counts.get(key, 0))])
        # 规范④：无「严重」档计数为 0 时给口径注释，避免高危及以上被误读。
        note = "注：本次未发现「严重」级漏洞；风险最高的问题按「高危」口径统计。" \
            if not counts.get("critical") else ""
        self.table(["严重等级", "数量"], rows, widths=[5, 5])
        if note:
            self.para(note, size=9)

    def vuln_chapter(self, data):
        self.h1(_chapter_title(data, "vuln_detail", "漏洞明细"))
        findings = data.get("findings") or []
        if not findings:
            self.body("本次测试未确认安全漏洞。")
            return
        if data.get("scope") == "project":
            # 项目级：按资产分组（Go 已分好组的结构未传，这里按 asset 字段聚次）。
            groups = {}
            for f in findings:
                groups.setdefault(f.get("asset") or "未关联资产", []).append(f)
            ordered = sorted(groups.items(), key=_asset_group_sort_key)
            n = 0
            for asset, fs in ordered:
                self.h2("资产：{0}".format(asset))
                for f in fs:
                    n += 1
                    self.build_vuln(f, n)
        else:
            for i, f in enumerate(findings):
                self.build_vuln(f, i + 1)

    def build_vuln(self, v, n):
        """规范③ 漏洞小节：短名标题→危险等级→描述→漏洞证明→复现→危害→修复。"""
        s = self.s
        sev = SEV_LABELS.get(v.get("severity") or "", "其他")
        title = "{0}. {1}（{2}）".format(n, v.get("name") or "未分类", sev)
        srcs = v.get("source_tasks") or []
        if len(srcs) > 1:
            title += "（来源任务 {0}）".format("、".join("#{0}".format(t) for t in srcs))
        self.h_vuln(title)

        # 属性表：标签列加粗、值不加粗（规范②）——危险等级/所属资产/URL。
        rows = [
            ["危险等级", sev],
            ["所属资产", v.get("asset") or "—"],
            ["漏洞 URL", v.get("url_template") or "—"],
        ]
        self.table(None, rows, widths=[3.5, 10.5], label_col=0)

        # 描述
        self.para("漏洞描述", size=s["label_size"], bold=True,
                  font=s["head_font"], space_before=8, space_after=2)
        self.body(v.get("description") or "（无概述）")

        # 「漏洞证明：」独立成段加粗 + 其后两个空段落（规范③ 原版模板格式），
        # 明细块内换行也在标签之后。
        self.para(s["proof_label"], size=s["label_size"], bold=True, space_before=8)
        self.empty(s["proof_gap_paragraphs"])

        repro = v.get("reproduction") or {}
        steps = repro.get("steps") or []
        if steps:
            if repro.get("entry_point"):
                self.body("入口点：{0}".format(repro["entry_point"]))
            for pre in repro.get("prerequisites") or []:
                self.body("前置条件：{0}".format(pre))
            for i, st in enumerate(steps):
                desc = st.get("expected") or st.get("proves") or ""
                self.body("步骤{0}{1}".format(i + 1, "：{0}".format(desc) if desc else ""))
                if st.get("request"):
                    self.code_block(st["request"])
                if st.get("response"):
                    self.code_block(st["response"])
                # 证据图按 step_index 穿插（step_index 从 1 计，0=漏洞级）。
                for img in v.get("images") or []:
                    if img.get("step_index") == i + 1 or (i == 0 and img.get("step_index") == 0):
                        self.picture(img.get("path"), caption=img.get("caption"))
        elif (v.get("report_md") or "").strip():
            # 无逐字复现 → 回退详细报告 Markdown 的纯文本段（剥代码围栏/井号，
            # 保留逐字内容；不引入 MD 富渲染以保持交付规范一致性）。
            for block in _md_to_plain_blocks(v["report_md"]):
                if block.startswith("```"):
                    self.code_block(block.strip("` \n"))
                else:
                    self.body(block)
        else:
            self.body("（暂无逐字复现证据，请补充后重新生成）")

        # 危害 / 修复建议（无 AI 叙述时留占位，后续棒注入 harm/remediation）。
        self.para("危害分析", size=s["label_size"], bold=True,
                  font=s["head_font"], space_before=8, space_after=2)
        self.body(v.get("harm") or "（危害说明待补充）")
        self.para("修复建议", size=s["label_size"], bold=True,
                  font=s["head_font"], space_before=8, space_after=2)
        self.body(v.get("remediation") or "（修复建议待补充）")

    def conclusion(self, data):
        self.h1(_chapter_title(data, "conclusion", "结论与建议"))
        total = len(data.get("findings") or [])
        self.body("本次渗透测试共确认安全问题 {0} 个。建议委托方按危险等级从高到低优先"
                  "处置，修复完成后安排复测验证；对暂不整改的风险履行风险接受流程。"
                  .format(total))


def _chapter_title(data, key, default):
    for c in data.get("chapters") or []:
        if c.get("key") == key and c.get("title"):
            return c["title"]
    return default


def _asset_group_sort_key(item):
    """项目级资产组排序：组内最高 severity 靠前，「未关联资产」恒最后。"""
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    best = min(sev_rank.get(f.get("severity") or "", 9) for f in item[1])
    return (item[0] == "未关联资产", best, item[0])


def _md_to_plain_blocks(md):
    """把 Markdown 详细报告粗转纯文本块：代码围栏整体成一块（保持 ``` 包裹供
    上层识别转代码段），标题剥 #，其余按空行分段。"""
    out, buf, in_code = [], [], False
    for line in md.splitlines():
        if line.strip().startswith("```"):
            if in_code:
                out.append("```" + "\n".join(buf) + "\n```")
                buf = []
                in_code = False
            else:
                if buf:
                    out.append("\n".join(buf))
                    buf = []
                in_code = True
            continue
        if not in_code and line.strip() == "":
            if buf:
                out.append("\n".join(buf))
                buf = []
            continue
        if not in_code and line.lstrip().startswith("#"):
            line = line.lstrip("# ")
        buf.append(line)
    if buf:
        out.append("\n".join(buf))
    return [b for b in out if b.strip()]


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

RENDERERS = {
    "cover": "cover",
    "statement": "statement",
    "targets": "targets_table",
    "summary": "summary_table",
    "vuln_detail": "vuln_chapter",
    "conclusion": "conclusion",
}


def build(data, output_path):
    b = Builder(data.get("style") or {})
    chapters = data.get("chapters") or []
    enabled = [c for c in chapters if c.get("enabled")]
    if not enabled:  # 无骨架 = 全默认序
        enabled = [{"key": k, "title": "", "enabled": True} for k in RENDERERS]
    for c in enabled:
        fn = RENDERERS.get(c.get("key"))
        if fn:
            getattr(b, fn)(data)
    b.doc.save(output_path)


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("用法: report_builder.py <input.json> <output.docx>\n")
        return 2
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)
    build(data, sys.argv[2])
    return 0


if __name__ == "__main__":
    sys.exit(main())
