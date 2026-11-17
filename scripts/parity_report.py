#!/usr/bin/env python
"""Train/serve parity on recorded traffic: our extractor vs. the published CICFlowMeter rows.

Extracts every flow from a per-host PCAP of CSE-CIC-IDS2018 (14-02-2018, victim
172.31.69.25) into parquet parts, then joins them to the canonical rows of the same day and
scores all 68 features (see ``nids.features.parity``). Runs under the same memory watchdog,
thread cap and low priority as the CLI.

Writes reports/parity_report.md and reports/parity_report.json (``_corrected`` suffix for
``--no-compat``).

Usage: python scripts/parity_report.py [--pcap PATH] [--limit N] [--compat/--no-compat]
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from nids import resources
from nids.config import get_settings


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--pcap",
        type=Path,
        default=Path("data/pcaps/cseids2018/Wednesday-14-02-2018_UCAP172.31.69.25.pcap"),
    )
    ap.add_argument("--day", default="2018-02-14-wed")
    ap.add_argument("--limit", type=int, default=None, help="max packets to read")
    ap.add_argument("--compat", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--out", type=Path, default=Path("reports"))
    args = ap.parse_args()

    s = get_settings()
    dog = resources.guard(s.mem_limit_mb, s.min_free_mb, s.threads)
    import polars as pl  # imported after cap_threads so the pool size applies

    from nids.data.loaders import scan_days
    from nids.features.parity import compare, to_markdown
    from nids.features.pcap import extract_flows_to_parquet

    mode = "compat" if args.compat else "corrected"
    parts = s.interim_dir / "parity" / mode
    t0 = time.time()
    n = extract_flows_to_parquet(args.pcap, parts, compat=args.compat, limit=args.limit)
    t_extract = time.time() - t0
    summary = compare(
        pl.scan_parquet(parts / "part-*.parquet"), scan_days(s.processed_dir, days=(args.day,))
    )
    summary |= {
        "pcap": str(args.pcap),
        "mode": mode,
        "packets_limit": args.limit,
        "extract_seconds": round(t_extract, 1),
        "peak_rss_mb": round(dog.stop()),
    }
    if summary["flows_extracted"] != n:
        raise RuntimeError("flow count mismatch between extraction and comparison")
    args.out.mkdir(parents=True, exist_ok=True)
    stem = "parity_report" if args.compat else "parity_report_corrected"
    (args.out / f"{stem}.json").write_text(json.dumps(summary, indent=2))
    label = "CICFlowMeter-compatible" if args.compat else "corrected"
    title = (
        f"PCAP `{args.pcap.name}`, {label} mode; extraction {t_extract:.0f} s, "
        f"peak memory {summary['peak_rss_mb']} MB."
    )
    md = to_markdown(summary, title)
    (args.out / f"{stem}.md").write_text(md)
    print("\n".join(md.splitlines()[:11]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
