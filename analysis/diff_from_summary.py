#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys
import json
import argparse
from pathlib import Path
from collections import Counter

try:
    import msg_maps
except Exception:
    msg_maps = None

# 匹配 capture_summary.log
PATTERNS = [
    re.compile(r"\[NGAP\].*?NGAP Message Type:\s*(.+)", re.I),
    re.compile(r"\[NAS-MM\]\s*Message Type:\s*([A-Za-z0-9_ \-]+)", re.I),
    re.compile(r"\[NAS-SM\]\s*Message Type:\s*([A-Za-z0-9_ \-]+)", re.I),
]

def norm_msg(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"\(.*?\)", "", s)
    s = re.sub(r"[\s\-]+", "_", s)
    s = re.sub(r"[^0-9a-z_]", "", s) 
    return s

def normalize_with_mapping(name: str) -> str:
    """用 msg_maps 统一名称"""
    raw = (name or "").strip()
    if not raw:
        return ""
    if msg_maps is not None:
        get_abbr = getattr(msg_maps, "get_abbreviation", None)
        if callable(get_abbr):
            try:
                abbr = get_abbr(raw)
                if abbr:
                    return norm_msg(abbr)
            except Exception:
                pass
        mapping = getattr(msg_maps, "message_mapping", None)
        if isinstance(mapping, dict):
            s = norm_msg(raw)
            for key, variants in mapping.items():
                if s == norm_msg(key):
                    return norm_msg(key)
                for v in variants:
                    if s == norm_msg(v):
                        return norm_msg(key)
    return norm_msg(raw)

def extract_types_from_summary(path: Path) -> Counter:
    cnt = Counter()
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            for pat in PATTERNS:
                m = pat.search(line)
                if m:
                    key = normalize_with_mapping(m.group(1))
                    if key:
                        cnt[key] += 1
                    break
    return cnt

def load_baseline(baseline_path: Path) -> set:
    base = set()
    with baseline_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            base.add(normalize_with_mapping(s))
    return base

def main():
    ap = argparse.ArgumentParser(description="Diff message types")
    ap.add_argument("--summary", default="logs/capture_summary.log", help="capture_worker生成的日志")
    ap.add_argument("--baseline", default="baseline_types.txt", help="基准文件")
    ap.add_argument("--out", default="msg_type_diff_report.json", help="结果输出 JSON")
    args = ap.parse_args()

    summary = Path(args.summary)
    baseline_file = Path(args.baseline)
    if not summary.exists():
        print(f"[ERR] summary not found: {summary}"); sys.exit(1)
    if not baseline_file.exists():
        print(f"[ERR] baseline not found: {baseline_file}"); sys.exit(1)

    cur_cnt = extract_types_from_summary(summary)

    cur_set = set(cur_cnt.keys())
    base_set = load_baseline(baseline_file)

    added = cur_set - base_set
    added_list = sorted([(t, cur_cnt[t]) for t in added], key=lambda x: (-x[1], x[0]))

    print(f"=== 对比: {summary} ===")
    print(f"总消息数: {sum(cur_cnt.values())} | 种类数: {len(cur_set)}")
    print(f"新增种类数(相对基准): {len(added)}")
    if added_list:
        print("新增种类(按频次↓):")
        for t, c in added_list:
            print(f"  - {t}: {c}")
    else:
        print("  无新增信令种类")
    print(f"[基准] {baseline_file}")

    report = {
        "summary_file": str(summary),
        "baseline_file": str(baseline_file),
        "total_messages": sum(cur_cnt.values()),
        "unique_types": len(cur_set),
        "added_types_count": len(added),
        "added_types": [{"type": t, "count": c} for t, c in added_list],
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()

