#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""report_builder.py 交付硬规范读回断言（python-docx 打开产物逐项校验）。

运行: cd report/pybuilder && python -m unittest test_report_builder -v
（Go 侧 report/docxgen_test.go 会调用本文件；无 python/python-docx 环境 Go 测 skip。）
断言编号 A1–A23 与 T16(1/3) 验收清单一一对应：规范① 字体字号 / 规范② 表格
标签粗值不粗+Grid / 规范③ 漏洞证明独立段+双空段+逐字代码块+report_md 回退 /
规范④ 章节序+资产分组+口径注释 / 规范⑤ 输出名由调用方决定（本测试断言
产物按传入路径生成）。
"""
import json
import os
import tempfile
import unittest

from docx import Document
from docx.shared import Pt
from docx.oxml.ns import qn

from report_builder import build

CHAPTERS = [
    {"key": "cover", "title": "封面", "enabled": True},
    {"key": "statement", "title": "声明", "enabled": True},
    {"key": "targets", "title": "检测目标", "enabled": True},
    {"key": "summary", "title": "风险等级汇总", "enabled": True},
    {"key": "vuln_detail", "title": "漏洞明细", "enabled": True},
    {"key": "conclusion", "title": "结论与建议", "enabled": True},
]


def sample_findings():
    return [
        {"finding_id": 101, "name": "SQL注入", "severity": "critical", "vulnclass": "sqli",
         "asset": "mall.example.com", "url_template": "mall.example.com/login",
         "description": "登录处布尔盲注", "source_tasks": [7, 9],
         "reproduction": {"entry_point": "https://mall.example.com/login",
                          "prerequisites": ["需普通账号"],
                          "steps": [{"request": "POST /login HTTP/1.1\r\nHost: mall.example.com\r\n\r\nuser=1",
                                     "response": "HTTP/1.1 200 OK",
                                     "expected": "返回200", "proves": "注入成立"}]},
         "harm": "可拖库", "remediation": "参数化查询"},
        {"finding_id": 102, "name": "反射XSS", "severity": "low", "vulnclass": "xss",
         "asset": "", "url_template": "", "description": "搜索回显未转义",
         "source_tasks": [7],
         "report_md": "## 复现\n\n访问 /search?q=1<img>\n\n```\nGET /search?q=xss HTTP/1.1\nHost: mall.example.com\n```"},
    ]


def sample_data():
    return {
        "title": "示例门户渗透", "scope": "project", "locale": "zh-CN",
        "generated_at": "2026-11-11T10:00:00+08:00", "issuer": "示例安全团队",
        "logo_abs": "", "cvss_enabled": False,
        "personnel": [{"name": "张三", "role": "安全工程师", "contact": "a@b.c"}],
        "chapters": CHAPTERS, "tasks": [{"id": 7, "name": "门户外网"}],
        "targets": ["mall.example.com"],
        "findings": sample_findings(),
    }


class BuilderSpecTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = os.path.join(self.tmp.name, "任务A-20261111.docx")  # 规范⑤：按传入路径出文件
        data = sample_data()
        build(data, self.out)
        self.doc = Document(self.out)
        self.paras = self.doc.paragraphs

    def tearDown(self):
        self.tmp.cleanup()

    # ---- 规范① ----
    def test_a1_a3_body_font(self):
        n = self.doc.styles["Normal"]
        rf = n.element.rPr.find(qn("w:rFonts"))
        self.assertEqual(rf.get(qn("w:eastAsia")), "仿宋")          # A1
        self.assertEqual(rf.get(qn("w:ascii")), "Times New Roman")  # A2
        self.assertEqual(n.font.size, Pt(12))                        # A3

    def test_a4_a6_vuln_heading_18pt(self):
        h = [p for p in self.paras if p.text.startswith("1. SQL注入")]
        self.assertEqual(len(h), 1)                                  # A4
        r = h[0].runs[0]
        self.assertEqual(r.font.size, Pt(18))                        # A5
        self.assertEqual(r._element.rPr.find(qn("w:rFonts")).get(qn("w:eastAsia")), "黑体")  # A6

    def test_a7_a8_chapter_hei_16pt(self):
        h = [p for p in self.paras if p.text == "漏洞明细"][0]
        r = h.runs[0]
        self.assertEqual(r.font.size, Pt(16))                        # A7
        self.assertEqual(r._element.rPr.find(qn("w:rFonts")).get(qn("w:eastAsia")), "黑体")  # A8

    # ---- 规范③ ----
    def test_a9_a11_proof_label_paragraph(self):
        idxs = [i for i, p in enumerate(self.paras) if p.text == "漏洞证明："]
        self.assertEqual(len(idxs), 2)                               # A9 两个漏洞各一
        lab = self.paras[idxs[0]]
        self.assertTrue(all(r.font.bold for r in lab.runs if r.text))  # A10 加粗独立成段
        gap = [self.paras[j].text.strip() for j in range(idxs[0] + 1, idxs[0] + 3)]
        self.assertEqual(gap, ["", ""])                              # A11 其后两个空段

    def test_a15_request_verbatim(self):
        hit = any("POST /login HTTP/1.1" in p.text and "mall.example.com" in p.text
                  for p in self.paras)                               # A15 逐字代码段
        self.assertTrue(hit)

    def test_a16_report_md_fallback(self):
        self.assertTrue(any("/search?q=1<img>" in p.text for p in self.paras))  # A16

    def test_a20_a21_harm_remediation(self):
        self.assertTrue(any(p.text == "危害分析" for p in self.paras))          # A20
        self.assertTrue(any(p.text == "修复建议" for p in self.paras))          # A21

    # ---- 规范② ----
    def test_a12_a14_a22_tables(self):
        grid = [t for t in self.doc.tables if t.style and "Grid" in t.style.name]
        self.assertGreaterEqual(len(grid), 3)                        # A12 多表均 grid
        attr = [t for t in grid if len(t.columns) == 2 and t.rows[0].cells[0].text == "危险等级"][0]
        self.assertTrue(attr.rows[0].cells[0].paragraphs[0].runs[0].font.bold)   # A13 标签列粗
        self.assertFalse(bool(attr.rows[0].cells[1].paragraphs[0].runs[0].font.bold))  # A14 值不粗
        head = [t for t in grid if t.rows[0].cells[0].text == "严重等级"][0]
        self.assertTrue(head.rows[0].cells[0].paragraphs[0].runs[0].font.bold)   # A22 表头行粗

    # ---- 规范④ ----
    def test_a17_asset_grouping(self):
        self.assertTrue(any(p.text == "资产：mall.example.com" for p in self.paras))  # A17

    def test_a18_cover_title(self):
        self.assertTrue(any(p.text == "示例门户渗透" for p in self.paras))      # A18

    def test_a19_summary_table(self):
        tbl = [t for t in self.doc.tables if len(t.columns) == 2 and t.rows[0].cells[0].text == "严重等级"]
        self.assertEqual(len(tbl), 1)                                          # A19

    def test_a23_no_critical_note(self):
        data = sample_data()
        data["findings"] = [f for f in data["findings"] if f["severity"] != "critical"]
        out = os.path.join(self.tmp.name, "no-critical.docx")
        build(data, out)
        doc = Document(out)
        self.assertTrue(any("高危" in p.text and "口径" in p.text for p in doc.paragraphs))  # A23

    # ---- 规范⑤ ----
    def test_a24_output_path_respected(self):
        self.assertTrue(os.path.isfile(self.out))  # 产物严格生成在传入路径


if __name__ == "__main__":
    unittest.main()
