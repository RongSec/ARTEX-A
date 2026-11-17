#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""template_filler.fill 的读回断言套件（python-docx）。

运行:
    cd report/pybuilder && python -m unittest test_template_filler -v

Go 侧 report/docxgen_tpl_test.go 会调用本套件；无 python/python-docx 环境
Go 测 skip。模板样本 = testdata/tpl_cn.docx（用户真实报告模板）。
"""
import os
import tempfile
import unittest

from docx import Document

from template_filler import fill

TPL = os.path.join(os.path.dirname(__file__), "testdata", "tpl_cn.docx")
HEADER_TEXT = "                                      示例科技有限公司"
FOOTER_TEXT = "第 32 页 共 32 页"


def sample_data():
    return {
        "title": "示例电商系统渗透测试报告",
        "generated_at": "2026-11-17T10:00:00+08:00",
        "system_name": "示例电商系统",
        "org": "示例某公司",
        "region": "北京",
        "contact": "张三",
        "phone": "010-12345678",
        "targets": ["shop.example.com", "admin.example.com"],
        "findings": [
            {"name": "SQL注入", "severity": "critical", "asset": "shop.example.com",
             "description": "登录处布尔盲注",
             "reproduction": {
                 "entry_point": "https://shop.example.com/login",
                 "prerequisites": ["需普通账号"],
                 "steps": [{"request": "POST /login HTTP/1.1\r\nHost: shop.example.com",
                            "response": "HTTP/1.1 200 OK", "expected": "返回200"}],
             },
             "harm": "可拖库", "remediation": "参数化查询"},
            {"name": "反射XSS", "severity": "medium", "description": "搜索回显未转义",
             "report_md": "## 复现\n\nGET /search?q=xss"},
            {"name": "弱口令", "severity": "low", "description": "admin/admin",
             "harm": "后台被控", "remediation": "强口令策略"},
        ],
        "overall": "",
    }


def unique_cells(row):
    seen, out = set(), []
    for cell in row.cells:
        if id(cell._tc) in seen:
            continue
        seen.add(id(cell._tc))
        out.append(cell)
    return out


def find_table(doc, header):
    for t in doc.tables:
        if t.rows and [c.text.strip() for c in unique_cells(t.rows[0])] == header:
            return t
    return None


def vuln_block_tables(doc):
    out = []
    for t in doc.tables:
        if len(t.columns) == 1 and t.rows and t.rows[0].cells[0].text.strip().startswith("漏洞名称："):
            out.append(t)
    return out


def paragraph_by_contains(doc, needle):
    for p in doc.paragraphs:
        if needle in p.text:
            return p
    return None


def fingerprint(doc):
    return {
        "paras": [p.text for p in doc.paragraphs],
        "tables": [[[c.text for c in unique_cells(r)] for r in t.rows] for t in doc.tables],
        "header": [p.text for p in doc.sections[0].header.paragraphs],
        "footer": [p.text for p in doc.sections[0].footer.paragraphs],
    }


class TemplateFillerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = sample_data()
        cls.path = os.path.join(tempfile.mkdtemp(prefix="artex-tpl-"), "out.docx")
        fill(TPL, cls.data, cls.path)
        cls.doc = Document(cls.path)

    def test_output_openable_and_keeps_header_footer(self):
        doc = Document(self.path)
        self.assertEqual([p.text for p in doc.sections[0].header.paragraphs], [HEADER_TEXT])
        self.assertEqual([p.text for p in doc.sections[0].footer.paragraphs], [FOOTER_TEXT])

    def test_cover_title_replaced(self):
        self.assertIn("示例电商系统渗透测试报告", [p.text for p in self.doc.paragraphs])
        self.assertNotIn("xx系统渗透测试报告", [p.text for p in self.doc.paragraphs])

    def test_cover_date_replaced(self):
        texts = [p.text for p in self.doc.paragraphs]
        self.assertIn("2026年11月17日", texts)

    def test_info_table_overrides(self):
        target = None
        for t in self.doc.tables:
            for row in t.rows:
                if unique_cells(row) and unique_cells(row)[0].text.strip() == "目标":
                    target = t
                    break
            if target is not None:
                break
        self.assertIsNotNone(target)
        values = {}
        for row in target.rows:
            cells = unique_cells(row)
            for i, cell in enumerate(cells[:-1]):
                values[cell.text.strip()] = cells[i + 1].text
        self.assertEqual(values["目标"], "示例电商系统")
        self.assertEqual(values["责任主体"], "示例某公司")
        self.assertEqual(values["所属区域"], "北京")
        self.assertEqual(values["联系人"], "张三")
        self.assertEqual(values["联系方式"], "010-12345678")

    def test_targets_table_rows(self):
        table = find_table(self.doc, ["系统名称", "域名"])
        self.assertIsNotNone(table)
        self.assertEqual(len(table.rows), 3)
        self.assertEqual([c.text for c in unique_cells(table.rows[1])],
                         ["示例电商系统", "shop.example.com"])
        self.assertEqual([c.text for c in unique_cells(table.rows[2])],
                         ["示例电商系统", "admin.example.com"])

    def test_stats_table(self):
        table = find_table(self.doc, ["漏洞数量", "高危", "中危", "低危"])
        self.assertIsNotNone(table)
        self.assertEqual([c.text for c in unique_cells(table.rows[1])], ["3", "1", "1", "1"])

    def test_detail_table_rows(self):
        table = find_table(self.doc, ["序号", "系统名称", "漏洞名称", "风险等级"])
        self.assertIsNotNone(table)
        self.assertEqual(len(table.rows), 1 + 3)
        self.assertEqual([c.text for c in unique_cells(table.rows[1])],
                         ["1", "shop.example.com", "SQL注入", "严重"])
        self.assertEqual([c.text for c in unique_cells(table.rows[3])],
                         ["3", "示例电商系统", "弱口令", "低危"])

    def test_vuln_blocks(self):
        blocks = vuln_block_tables(self.doc)
        self.assertEqual(len(blocks), 3)
        for block in blocks:
            self.assertIn("漏洞名称：", block.rows[0].cells[0].text)
        headings = [p.text for p in self.doc.paragraphs if p.text.startswith("3.2.")]
        self.assertEqual(headings, ["3.2.1 SQL注入【严重】", "3.2.2 反射XSS【中危】", "3.2.3 弱口令【低危】"])
        proof = blocks[0].rows[4].cells[0].text
        self.assertIn("入口点：https://shop.example.com/login", proof)
        self.assertIn("步骤1", proof)
        self.assertIn("POST /login", proof)
        self.assertIn("HTTP/1.1 200 OK", proof)

    def test_summary_replaced(self):
        p = paragraph_by_contains(self.doc, "安全评估后结果为：")
        self.assertIsNotNone(p)
        self.assertIn("示例电商系统在本次人工渗透测试中", p.text)
        self.assertIn("结果为：严重", p.text)

    def test_second_render_is_stable(self):
        path2 = os.path.join(tempfile.mkdtemp(prefix="artex-tpl2-"), "out.docx")
        fill(TPL, sample_data(), path2)
        self.assertEqual(fingerprint(Document(path2)), fingerprint(self.doc))

    def test_empty_findings(self):
        path = os.path.join(tempfile.mkdtemp(prefix="artex-tpl3-"), "out.docx")
        data = sample_data()
        data["findings"] = []
        fill(TPL, data, path)
        doc = Document(path)
        table = find_table(doc, ["序号", "系统名称", "漏洞名称", "风险等级"])
        self.assertEqual(len(table.rows), 1)  # 仅表头
        stats = find_table(doc, ["漏洞数量", "高危", "中危", "低危"])
        self.assertEqual([c.text for c in unique_cells(stats.rows[1])], ["0", "0", "0", "0"])
        self.assertTrue(any("本次未发现可复现漏洞" in p.text for p in doc.paragraphs))
        self.assertEqual(vuln_block_tables(doc), [])


if __name__ == "__main__":
    unittest.main()
