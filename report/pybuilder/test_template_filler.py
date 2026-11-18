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
from docx.oxml.ns import qn

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


def bug_data():
    """复现实测问题：title 是报告名，system_name 需要从 targets/title 推导。"""
    return {
        "title": "demo.example.com 渗透测试报告（样例）",
        "generated_at": "2026-11-17T10:00:00+08:00",
        "targets": ["demo.example.com"],
        "findings": [],
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
        # 报文现在放在嵌套表格（文本框）里，cell.text 只含直接段落，
        # 取整棵 tc 的文本才能覆盖到框内报文。
        cell = blocks[0].rows[4].cells[0]
        proof = "\n".join(cell._tc.itertext())
        self.assertIn("入口点：https://shop.example.com/login", proof)
        self.assertIn("步骤1", proof)
        self.assertIn("POST /login", proof)
        self.assertIn("HTTP/1.1 200 OK", proof)
        # 请求/响应各一个文本框：本 finding 只有 1 步，所以是 2 个。
        self.assertEqual(len(cell._tc.findall(qn("w:tbl"))), 2)
        self.assertIn("F6F7F9", cell._tc.xml, "文本框必须带浅灰底纹")

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


class CoverTitleSemanticsTest(unittest.TestCase):
    """封面标题 = 报告名 title；正文/表格的 `xx系统` = 系统名（两者不等价）。"""

    SYSTEM_NAME = "demo.example.com"

    @classmethod
    def setUpClass(cls):
        cls.path = os.path.join(tempfile.mkdtemp(prefix="artex-tpl-bug-"), "out.docx")
        fill(TPL, bug_data(), cls.path)
        cls.doc = Document(cls.path)

    def test_cover_title_is_title_without_duplicate_report_suffix(self):
        title = bug_data()["title"]
        texts = [p.text for p in self.doc.paragraphs]
        self.assertIn(title, texts)
        cover = texts[texts.index(title)]
        self.assertEqual(cover, title)
        self.assertEqual(cover.count("渗透测试报告"), 1)
        self.assertNotIn("xx系统", cover)

    def test_body_system_name_has_no_report_suffix(self):
        p = paragraph_by_contains(self.doc, "为了解")
        self.assertIsNotNone(p)
        self.assertIn(self.SYSTEM_NAME + "的安全现状", p.text)
        self.assertNotIn("渗透测试报告", p.text)
        self.assertNotIn("（样例）", p.text)

    def test_info_target_equals_system_name(self):
        target = None
        for t in self.doc.tables:
            for row in t.rows:
                cells = unique_cells(row)
                if cells and cells[0].text.strip() == "目标":
                    target = cells[1].text
                    break
            if target is not None:
                break
        self.assertEqual(target, self.SYSTEM_NAME)


class FindingImagesTest(unittest.TestCase):
    """V9-SHOT：漏洞证明单元格里的报文截图注入（顺序/图注/缺图降级）。"""

    @staticmethod
    def make_png(path, rgb):
        import struct
        import zlib
        w = h = 8
        raw = b"".join(b"\x00" + bytes(rgb) * w for _ in range(h))

        def chunk(tag, data):
            return (struct.pack(">I", len(data)) + tag + data +
                    struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

        png = (b"\x89PNG\r\n\x1a\n" +
               chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) +
               chunk(b"IDAT", zlib.compress(raw)) +
               chunk(b"IEND", b""))
        with open(path, "wb") as f:
            f.write(png)

    def test_two_images_into_proof_cells_in_order(self):
        tmp = tempfile.mkdtemp(prefix="artex-tpl-img-")
        img1 = os.path.join(tmp, "req_resp_1.png")
        img2 = os.path.join(tmp, "req_resp_2.png")
        self.make_png(img1, (200, 40, 40))
        self.make_png(img2, (40, 120, 200))
        data = sample_data()
        data["findings"][0]["images"] = [
            {"step_index": 1, "path": img1, "caption": "该文案不应出现在报告里"}]
        data["findings"][1]["images"] = [
            {"step_index": 0, "path": img2, "caption": "该文案不应出现在报告里"}]
        out = os.path.join(tmp, "out.docx")
        fill(TPL, data, out)

        # 媒体条目：模板自带 2 张 + 新插 2 张。
        import zipfile
        with zipfile.ZipFile(out) as z:
            media = [n for n in z.namelist() if n.startswith("word/media/") and not n.endswith("/")]
        with zipfile.ZipFile(TPL) as z:
            base = [n for n in z.namelist() if n.startswith("word/media/") and not n.endswith("/")]
        self.assertEqual(len(media), len(base) + 2)

        doc = Document(out)
        blocks = vuln_block_tables(doc)
        self.assertEqual(len(blocks), 3)
        # 图按 finding 进各自「漏洞证明」单元格，图注是全报告连续编号「图N」。
        for block, needle in ((blocks[0], "图1"), (blocks[1], "图2")):
            proof = block.rows[4].cells[0]
            self.assertEqual(proof._tc.xml.count("<w:drawing"), 1)
            self.assertIn(needle, "\n".join(p.text for p in proof.paragraphs))
        # 没有图的第三条 finding 不带 drawing。
        self.assertEqual(blocks[2].rows[4].cells[0]._tc.xml.count("<w:drawing"), 0)

    def test_images_follow_their_own_step(self):
        """多步骤：图必须落在对应步骤的响应之后，不能全部堆在单元格末尾。"""
        tmp = tempfile.mkdtemp(prefix="artex-tpl-steps-")
        paths = []
        for i in range(3):
            p = os.path.join(tmp, "s%d.png" % (i + 1))
            self.make_png(p, (40 + i * 60, 80, 160))
            paths.append(p)
        data = sample_data()
        f = data["findings"][0]
        f["reproduction"]["steps"] = [
            {"expected": "预期%d" % (i + 1), "proves": "证明%d" % (i + 1),
             "request": "GET /s%d HTTP/1.1" % (i + 1),
             "response": "HTTP/1.1 200 OK\r\n\r\nok%d" % (i + 1)}
            for i in range(3)
        ]
        f["images"] = [
            {"step_index": i + 1, "path": paths[i], "caption": "ignored"}
            for i in range(3)
        ]
        out = os.path.join(tmp, "out.docx")
        fill(TPL, data, out)

        doc = Document(out)
        proof = vuln_block_tables(doc)[0].rows[4].cells[0]
        seq = []
        for idx, para in enumerate(proof.paragraphs):
            has_pic = "w:drawing" in para._p.xml
            seq.append((idx, "pic" if has_pic else "txt", para.text or ""))
        self.assertEqual(sum(1 for x in seq if x[1] == "pic"), 3, "三张图必须都在单元格内")

        def idx_of(needle, kind=None):
            for idx, k, text in seq:
                if needle in text and (kind is None or k == kind):
                    return idx
            self.fail("找不到段落: %s（%s）" % (needle, kind))

        s1, s2, s3 = idx_of("步骤1"), idx_of("步骤2"), idx_of("步骤3")
        c1, c2, c3 = idx_of("图1"), idx_of("图2"), idx_of("图3")
        # 步骤1 → 图注1 → 步骤2 → 图注2 → 步骤3 → 图注3，严格递增。
        self.assertLess(s1, c1, "图注1 必须在步骤1 之后")
        self.assertLess(c1, s2, "步骤2 必须在图注1 之后（图不能堆到末尾）")
        self.assertLess(s2, c2)
        self.assertLess(c2, s3, "步骤3 必须在图注2 之后")
        self.assertLess(s3, c3)

    def test_missing_image_is_skipped_with_warning(self):
        tmp = tempfile.mkdtemp(prefix="artex-tpl-noimg-")
        data = sample_data()
        data["findings"][0]["images"] = [
            {"step_index": 1, "path": os.path.join(tmp, "nope.png"), "caption": "缺失"}]
        out = os.path.join(tmp, "out.docx")
        with self.assertLogs("template_filler", level="WARNING"):
            fill(TPL, data, out)  # 不抛异常
        doc = Document(out)
        blocks = vuln_block_tables(doc)
        self.assertEqual(len(blocks), 3)
        self.assertEqual(blocks[0].rows[4].cells[0]._tc.xml.count("<w:drawing"), 0)


if __name__ == "__main__":
    unittest.main()
