#!/usr/bin/env python
"""Train/serve parity on recorded traffic: our extractor vs. the published CICFlowMeter CSV.

Extracts every flow from a per-host PCAP of CSE-CIC-IDS2018 (14-02-2018, victim 172.31.69.25),
matches each flow to a row of the published labelled CSV of the same day and compares all 68
features. Matching key: flow start second (CSV timestamps are local AST = UTC-4), destination
port, protocol, forward/backward packet counts and byte totals. Features are compared with a
relative tolerance of 1e-3 (durations and IATs: 1 us absolute + 1e-3 relative since the CSV
timestamps are truncated).

Writes reports/parity_report.md and reports/parity_report.json.

Usage: python scripts/parity_report.py [--pcap PATH] [--limit N] [--compat/--no-compat]
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import timedelta
from pathlib import Path

import polars as pl

from nids.data.loaders import load_canonical
from nids.data.schema import FLOW_FEATURES
from nids.features.pcap import extract_flows

CSV_UTC_OFFSET = timedelta(hours=-4)
KEY = [
    "start_s",
    "dst_port",
    "protocol",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "totlen_fwd_pkts",
    "totlen_bwd_pkts",
]
DURATION_LIKE = {
    s for s in FLOW_FEATURES if "iat" in s or "duration" in s or "active" in s or "idle" in s
}


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

    t0 = time.time()
    ours = extract_flows(args.pcap, compat=args.compat, limit=args.limit)
    t_extract = time.time() - t0
    ours = ours.with_columns(
        (pl.from_epoch(pl.col("start_us"), time_unit="us") + CSV_UTC_OFFSET)
        .dt.truncate("1s")
        .alias("start_s")
    )
    csv = load_canonical(Path("data/processed"), days=(args.day,)).filter(
        pl.col("timestamp").is_not_null()
    )
    csv = csv.with_columns(pl.col("timestamp").dt.truncate("1s").alias("start_s"))
    # the CSV covers all hosts; keep rows that could involve our victim (any row, matched by key)
    joined = ours.join(csv, on=KEY, how="inner", suffix="_csv")
    # a key may match several CSV rows (identical flows); keep one per extracted flow
    joined = joined.unique(subset=["flow_id", "start_us"], keep="first")

    per_feature: dict[str, dict[str, float]] = {}
    for f in FLOW_FEATURES:
        a, b = joined.get_column(f), joined.get_column(f"{f}_csv")
        both_inf = a.is_infinite() & b.is_infinite()
        if f in DURATION_LIKE:
            ok = ((a - b).abs() <= 1 + 1e-3 * b.abs()) | both_inf
        else:
            ok = (
                (a - b).abs()
                <= 1e-3
                * pl.Series([1.0] * len(b)).clip(lower_bound=1.0)
                * b.abs().clip(lower_bound=1.0)
            ) | both_inf
        ok = ok.fill_null(False)
        diff = (a - b).abs().filter(~ok & a.is_finite() & b.is_finite())
        per_feature[f] = {
            "agreement": round(float(ok.mean()) if len(ok) else 0.0, 5),
            "max_abs_diff": float(diff.max()) if len(diff) else 0.0,
            "median_abs_diff": float(diff.median()) if len(diff) else 0.0,
        }

    labels = joined.group_by("label").len().sort("len", descending=True)
    summary = {
        "pcap": str(args.pcap),
        "compat": args.compat,
        "packets_limit": args.limit,
        "extract_seconds": round(t_extract, 1),
        "flows_extracted": ours.height,
        "flows_matched": joined.height,
        "match_rate": round(joined.height / max(ours.height, 1), 4),
        "csv_rows_day": csv.height,
        "matched_labels": dict(labels.iter_rows()),
        "features_fully_agreeing": sum(1 for v in per_feature.values() if v["agreement"] >= 0.999),
        "per_feature": per_feature,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "parity_report.json").write_text(json.dumps(summary, indent=2))

    lines = [
        "# Train/serve parity report",
        "",
        f"PCAP: `{args.pcap.name}` ({'CICFlowMeter-compatible' if args.compat else 'corrected'} mode)",
        "",
        f"* flows extracted: **{ours.height:,}** in {t_extract:.0f} s",
        f"* flows matched to a labelled CSV row: **{joined.height:,}** ({summary['match_rate']:.1%})",
        f"* matched labels: {', '.join(f'{k}: {v:,}' for k, v in summary['matched_labels'].items())}",
        f"* features agreeing on >= 99.9% of matched flows: **{summary['features_fully_agreeing']} / {len(FLOW_FEATURES)}**",
        "",
        "| Feature | Agreement | Median abs diff (disagreeing) | Max abs diff |",
        "|---|---:|---:|---:|",
    ]
    for f, v in sorted(per_feature.items(), key=lambda kv: kv[1]["agreement"]):
        lines.append(
            f"| `{f}` | {v['agreement']:.2%} | {v['median_abs_diff']:.4g} | {v['max_abs_diff']:.4g} |"
        )
    (args.out / "parity_report.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines[:9]))
    print(f"wrote {args.out / 'parity_report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
