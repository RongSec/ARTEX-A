#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""仓库敏感内容闸门：提交前与 CI 共用同一份规则。

设计口径：
  - 只扫 **git 跟踪的文件**（未跟踪的产物由 .gitignore 挡）；
  - 文本文件按行扫；docx/xlsx/pptx 解压后扫 XML；其余二进制按字节扫；
  - 分「硬失败」与「警告」两级：硬失败直接拦住提交，警告只提醒不阻断，
    避免大量无关告警把人练成"看见红灯就 --no-verify"。

用法：
    python scripts/scan_repo_secrets.py            # 扫全部跟踪文件
    python scripts/scan_repo_secrets.py --staged   # 只扫暂存区（pre-commit 用）
    python scripts/scan_repo_secrets.py -v         # 同时打印通过的文件数

退出码：0 干净；1 有硬失败项。
"""
from __future__ import annotations

import argparse
import io
import os
import re
import subprocess
import sys
import zipfile

# 本文件自身包含规则字面量（sinochem / 10.24 等），必须排除，否则自锁。
SELF = "scripts/scan_repo_secrets.py"

# 文档类容器：解压后扫内部的 XML 文本，比直接扫压缩字节可靠。
OOXML = (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm")

# ── 硬失败：命中即阻断 ────────────────────────────────────────────────
# 规则串拆成拼接形式，避免本文件自己被扫中（同上）。
HARD_RULES: list[tuple[str, str]] = [
    ("凭据/GitHub", r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,}"),
    ("凭据/OpenAI", r"sk-[A-Za-z0-9]{32,}"),
    ("凭据/AWS", r"AKIA[0-9A-Z]{16}"),
    ("凭据/私钥", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("凭据/密码赋值", r"(?i)\b(password|passwd|pwd)\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']"),
    ("标识/机构", "sino" + "chem|sino" + "intl|sino" + "mach|" + "中化"),
    ("地址/部署网段", r"\b10\.24\.\d{1,3}\.\d{1,3}\b"),
    ("隐私/手机号", r"(?<!\d)1[3-9]\d{9}(?!\d)"),
]

# ── 警告：不阻断，只列出来让人肉判断 ──────────────────────────────────
# 测试文件里大量通用私网段是正常造数据，只在非 _test 文件里提醒，否则
# 每次提交几十条告警，人会直接养成忽略习惯。
WARN_RULES: list[tuple[str, str]] = [
    ("地址/私网", r"\b(192\.168|172\.(1[6-9]|2\d|3[01])|10\.(?!24\.)\d{1,3})\.\d{1,3}\.\d{1,3}\b"),
]

# 允许出现的占位值：把规则命中后仍属虚构的串剔掉，减少误报。
ALLOW = re.compile(
    r"13800138000|13800138001|17000000000|tester@example\.com|"
    r"example\.(com|org|net|invalid)|acme\.com|demo\.example\.com|"
    r"192\.0\.2\.\d{1,3}|198\.51\.100\.\d{1,3}|203\.0\.113\.\d{1,3}|"
    r"127\.0\.0\.1|0\.0\.0\.0|10\.0\.0\.\d{1,3}"
)

# 路径硬失败：这些路径出现在跟踪列表里就说明有人绕过 .gitignore。
HARD_PATHS = [
    (re.compile(r"(^|/)\.env$"), "部署环境文件（含口令/密钥）"),
    (re.compile(r"(^|/)config\.json$"), "本地配置（含库口令）"),
    (re.compile(r"(^|/)jwt\.key$"), "JWT 签名密钥"),
    (re.compile(r"(^|/)(docker/)?data/"), "运行时数据目录"),
    (re.compile(r"(^|/)(docker/)?state/"), "运行时状态目录"),
    (re.compile(r"^backups/"), "升级备份（含数据库快照）"),
    (re.compile(r"\.db(-wal|-shm)?$"), "SQLite 数据库文件"),
    (re.compile(r"dist\.bak"), "陈旧构建产物"),
    (re.compile(r"\.(pcap|pcapng)$"), "抓包文件"),
    (re.compile(r"report/pybuilder/testdata/.*\.(docx|xlsx|pptx|pdf)$"), "报告模板样本（使用数据，不入库）"),
]

SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".ttf", ".ttc", ".woff", ".woff2",
            ".mp4", ".zip", ".gz", ".tar", ".7z", ".exe", ".dll", ".so", ".dylib", ".bin",
            ".wasm", ".pdf"}
MAX_BYTES = 64 * 1024 * 1024


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def tracked_files(staged: bool) -> list[str]:
    if staged:
        out = git("diff", "--cached", "--name-only", "--diff-filter=ACMR")
    else:
        out = git("ls-files")
    return [p for p in out.splitlines() if p.strip()]


def read_text(path: str) -> str | None:
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_BYTES)
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", "ignore")


def ooxml_text(path: str) -> str:
    try:
        with zipfile.ZipFile(path) as z:
            parts = [z.read(n) for n in z.namelist() if n.endswith(".xml")]
    except (OSError, zipfile.BadZipFile):
        return ""
    out = []
    for blob in parts:
        text = blob.decode("utf-8", "ignore")
        out.append(re.sub(r"<[^>]+>", " ", text))
    return "\n".join(out)


def binary_text(path: str) -> str:
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_BYTES)
    except OSError:
        return ""
    # 把可打印片段抽出来，避免整块乱码影响匹配与截断。
    return "\n".join(m.group(0).decode("ascii", "ignore") for m in re.finditer(rb"[\x20-\x7e]{8,}", raw))


def scan_text(name: str, text: str, rules, hits: list[tuple[str, int, str, str]]):
    for lineno, line in enumerate(text.splitlines(), 1):
        if ALLOW.search(line):
            continue
        for label, pat in rules:
            if re.search(pat, line):
                hits.append((name, lineno, label, line.strip()[:160]))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--staged", action="store_true", help="只扫暂存区（pre-commit）")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    files = tracked_files(args.staged)
    hard: list[tuple[str, int, str, str]] = []
    warn: list[tuple[str, int, str, str]] = []

    for name in files:
        if name == SELF:
            continue
        for rx, why in HARD_PATHS:
            if rx.search(name):
                hard.append((name, 0, "路径/" + why, "不应被跟踪"))
                break
        if not os.path.exists(name):
            continue
        ext = os.path.splitext(name)[1].lower()
        if ext in SKIP_EXT:
            continue
        text = ooxml_text(name) if ext in OOXML else read_text(name)
        if text is None:
            text = binary_text(name)
        if not text:
            continue
        scan_text(name, text, HARD_RULES, hard)
        # mock 数据与测试是刻意造的内网地址，不提醒；其余文件才值得看一眼。
        if "_test." not in name and "/testdata/" not in name and "/mock/" not in name:
            scan_text(name, text, WARN_RULES, warn)

    if warn:
        print(f"\n⚠️  警告 {len(warn)} 处（不阻断，请自行确认是否虚构）：")
        for n, ln, label, snip in warn[:20]:
            print(f"   {n}:{ln}  [{label}]  {snip}")
        if len(warn) > 20:
            print(f"   … 另有 {len(warn) - 20} 处")

    if hard:
        print(f"\n❌ 硬失败 {len(hard)} 处：")
        for n, ln, label, snip in hard:
            loc = f"{n}:{ln}" if ln else n
            print(f"   {loc}  [{label}]  {snip}")
        print("\n处理办法：改成示例值（example.com / 192.0.2.x / 13800138000），"
              "或把该文件加进 .gitignore / .dockerignore。")
        return 1

    print(f"✅ 敏感内容检查通过（{len(files)} 个跟踪文件）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
