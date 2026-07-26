#!/usr/bin/env python3


import argparse
import json
from pathlib import Path
from collections import defaultdict
from generate_report import CATEGORY_MAP, DETECTOR_PRIORITY

CATEGORY_PREFIXES = list(CATEGORY_MAP.keys())



def load_eval_records(path):
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("entry_type") == "eval":
                records.append(rec)
    return records


def category_for(probe_classname):
    prefix = probe_classname.split(".")[0]
    return prefix if prefix in CATEGORY_PREFIXES else None


def main():
    parser = argparse.ArgumentParser(description="Print raw eval data per category for manual auditing")
    parser.add_argument("report_path", type=str)
    args = parser.parse_args()

    report_path = Path(args.report_path)
    if not report_path.exists():
        raise SystemExit(f"File not found: {report_path}")

    print(f"Reading: {report_path}\n")
    records = load_eval_records(report_path)
    print(f"Found {len(records)} 'eval' entries in this report.\n")

    by_category = defaultdict(list)
    unmapped_probes = set()
    for rec in records:
        cat = category_for(rec.get("probe", ""))
        if cat:
            by_category[cat].append(rec)
        else:
            unmapped_probes.add(rec.get("probe", ""))

    
    if unmapped_probes:                              
        print(f"WARNING: {len(unmapped_probes)} probe(s) not in any category were "
        f"excluded from this audit: {sorted(unmapped_probes)}\n")

    for cat in CATEGORY_PREFIXES:
        recs = by_category.get(cat, [])
        if not recs:
            print(f"=== {cat} === (no data found)\n")
            continue

        print(f"=== {cat} ===")

        
        by_probe = defaultdict(list)
        for r in recs:
            by_probe[r.get("probe")].append(r)

        cat_passed = 0
        cat_fails = 0

        for probe, probe_recs in sorted(by_probe.items()):
            for r in probe_recs:
                marker = "  "
                print(f'{marker}{probe:55s} detector={r.get("detector",""):30s} '
                      f'passed={r.get("passed",0):5d} fails={r.get("fails",0):5d} '
                      f'total={r.get("total_evaluated",0):5d}')

           
            chosen = None
            for pref in DETECTOR_PRIORITY:
                for r in probe_recs:
                    if pref in r.get("detector", ""):
                        chosen = r
                        break
                if chosen:
                    break
            if chosen is None:
                chosen = probe_recs[0]

            print(f'{"":2s}  -> counted toward subtotal: detector={chosen.get("detector","")} '
                  f'(passed={chosen.get("passed",0)}, fails={chosen.get("fails",0)})\n')

            cat_passed += chosen.get("passed", 0)
            cat_fails += chosen.get("fails", 0)

        total = cat_passed + cat_fails
        rate = round(100 * cat_fails / total, 1) if total else 0.0
        print(f'  SUBTOTAL for "{cat}": {cat_fails} fails / {total} total = {rate}% attack success rate')
        print(f'  (this is the number that should match the dashboard for this category)\n')


if __name__ == "__main__":
    main()
