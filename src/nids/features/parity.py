"""Train/serve parity: compare extracted flows with published CICFlowMeter rows.

Both sides are lazy frames and the comparison is one streaming join plus aggregations, so a
full-day comparison (about a million flows on each side) runs in bounded memory.

Matching key: flow start second (published timestamps are local time, ``utc_offset`` from
UTC, truncated to the second), destination port, protocol, and the forward/backward packet
and byte totals. The published 2018 rows carry no source address or port, so a brute-force
burst can put dozens of flows with the same key into one second. Inside such a group the
flows of both sides are paired by flow-duration rank (the pairing that minimises the summed
duration difference); agreement is also reported on the *unambiguous* matches alone, where
the key occurs exactly once on each side and no pairing assumption is involved.
Tolerances: durations and inter-arrival times 1 us + 0.1% (published timestamps are
truncated); everything else 0.1% relative (absolute below 1).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import polars as pl

from nids.data.schema import FEATURES, FLOW_FEATURES, UNREPRODUCIBLE

KEY: tuple[str, ...] = (
    "start_s",
    "dst_port",
    "protocol",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "totlen_fwd_pkts",
    "totlen_bwd_pkts",
)
KEY_FEATURES: tuple[str, ...] = KEY[3:]
COMPARED: tuple[str, ...] = tuple(f for f in FLOW_FEATURES if f not in KEY_FEATURES)
DURATION_LIKE = frozenset(
    f for f in FLOW_FEATURES if any(k in f for k in ("iat", "duration", "active", "idle"))
)
DEFAULT_UTC_OFFSET = timedelta(hours=-4)
"""CSE-CIC-IDS2018 timestamps are Atlantic Standard Time (UTC-4)."""


def _ok(f: str) -> pl.Expr:
    a, b = pl.col(f), pl.col(f"{f}_csv")
    if f in DURATION_LIKE:
        tol = 1 + 1e-3 * b.abs()
    else:
        tol = 1e-3 * pl.max_horizontal(b.abs(), pl.lit(1.0))
    both_finite = a.is_finite() & b.is_finite()
    same_inf = a.is_infinite() & b.is_infinite() & (a.sign() == b.sign())
    return ((both_finite & ((a - b).abs() <= tol)) | same_inf).fill_null(False)


def compare(
    ours: pl.LazyFrame, published: pl.LazyFrame, utc_offset: timedelta = DEFAULT_UTC_OFFSET
) -> dict[str, Any]:
    """Match ``ours`` (extractor output) to ``published`` (canonical rows) and score features."""
    ours = ours.with_columns(
        (pl.from_epoch(pl.col("start_us"), time_unit="us") + utc_offset)
        .dt.truncate("1s")
        .alias("start_s")
    )
    window = ours.select(
        pl.col("start_s").min().alias("lo"), pl.col("start_s").max().alias("hi")
    ).collect(engine="streaming")
    lo, hi = window.item(0, "lo"), window.item(0, "hi")
    pub = (
        published.filter(pl.col("timestamp").is_not_null())
        .with_columns(pl.col("timestamp").dt.truncate("1s").alias("start_s"))
        .filter(pl.col("start_s").is_between(lo, hi))
        .select([*KEY, *[pl.col(f).alias(f"{f}_csv") for f in COMPARED], "label"])
    )
    keys = list(KEY)
    ours_r = ours.select([*KEY, *COMPARED]).with_columns(
        _rank=pl.col("flow_duration").rank("ordinal").over(keys),
        _n=pl.len().over(keys),
    )
    pub_r = pub.with_columns(
        _rank=pl.col("flow_duration_csv").rank("ordinal").over(keys),
        _n_csv=pl.len().over(keys),
    )
    joined = ours_r.join(pub_r, on=[*keys, "_rank"], how="inner").with_columns(
        _unique=(pl.col("_n") == 1) & (pl.col("_n_csv") == 1)
    )
    exprs: list[pl.Expr] = [pl.len().alias("matched"), pl.col("_unique").sum().alias("unique")]
    for f in COMPARED:
        ok = _ok(f)
        bad = ~ok & pl.col(f).is_finite() & pl.col(f"{f}_csv").is_finite()
        diff = (pl.col(f) - pl.col(f"{f}_csv")).abs()
        exprs += [
            ok.mean().alias(f"{f}__agree"),
            ok.filter(pl.col("_unique")).mean().alias(f"{f}__agree_u"),
            diff.filter(bad).max().alias(f"{f}__max"),
            diff.filter(bad).mean().alias(f"{f}__mean"),
        ]
    agg = joined.select(exprs).collect(engine="streaming").row(0, named=True)
    labels = joined.group_by("label").len().sort("len", descending=True).collect(engine="streaming")
    n_ours = int(ours.select(pl.len()).collect(engine="streaming").item())
    n_pub = int(pub.select(pl.len()).collect(engine="streaming").item())
    matched = int(agg["matched"])
    unique = int(agg["unique"] or 0)
    per_feature: dict[str, dict[str, float]] = {
        f: {
            "agreement": round(float(agg[f"{f}__agree"] or 0.0), 5),
            "agreement_unambiguous": round(float(agg[f"{f}__agree_u"] or 0.0), 5),
            "max_abs_diff": float(agg[f"{f}__max"] or 0.0),
            "mean_abs_diff": float(agg[f"{f}__mean"] or 0.0),
        }
        for f in COMPARED
    }
    for f in KEY_FEATURES:  # equal by construction of the match key
        per_feature[f] = {
            "agreement": 1.0 if matched else 0.0,
            "agreement_unambiguous": 1.0 if unique else 0.0,
            "max_abs_diff": 0.0,
            "mean_abs_diff": 0.0,
        }
    return {
        "flows_extracted": n_ours,
        "published_rows_in_window": n_pub,
        "flows_matched": matched,
        "match_rate": round(matched / max(n_ours, 1), 4),
        "flows_matched_unambiguous": unique,
        "matched_labels": {str(k): int(v) for k, v in labels.iter_rows()},
        "features_compared": len(per_feature),
        "features_fully_agreeing": sum(1 for v in per_feature.values() if v["agreement"] >= 0.999),
        "model_inputs_compared": sum(1 for f in per_feature if f in FEATURES),
        "model_inputs_fully_agreeing": sum(
            1 for f, v in per_feature.items() if f in FEATURES and v["agreement"] >= 0.999
        ),
        "per_feature": per_feature,
    }


def to_markdown(summary: dict[str, Any], title: str) -> str:
    """Render a :func:`compare` summary as a Markdown report (worst features first)."""
    labels = ", ".join(f"{k}: {v:,}" for k, v in summary["matched_labels"].items()) or "none"
    lines = [
        "# Train/serve parity report",
        "",
        title,
        "",
        f"* flows extracted: **{summary['flows_extracted']:,}**",
        f"* published rows in the capture's time window: {summary['published_rows_in_window']:,}",
        f"* flows matched to a published row: **{summary['flows_matched']:,}** "
        f"({summary['match_rate']:.1%}); unambiguous (key unique on both sides): "
        f"{summary['flows_matched_unambiguous']:,}",
        f"* matched labels: {labels}",
        "* features agreeing on >= 99.9% of matched flows: "
        f"**{summary['features_fully_agreeing']} / {summary['features_compared']}**; "
        f"model inputs: **{summary['model_inputs_fully_agreeing']} / "
        f"{summary['model_inputs_compared']}**",
        "* columns marked (excluded) are published values that cannot be recomputed from "
        "packets and are not model inputs (`schema.UNREPRODUCIBLE`)",
        "",
        "| Feature | Agreement | Agreement (unambiguous) | Mean abs diff (disagreeing) "
        "| Max abs diff |",
        "|---|---:|---:|---:|---:|",
    ]
    for f, v in sorted(summary["per_feature"].items(), key=lambda kv: (kv[1]["agreement"], kv[0])):
        name = f"`{f}` (excluded)" if f in UNREPRODUCIBLE else f"`{f}`"
        lines.append(
            f"| {name} | {v['agreement']:.2%} | {v['agreement_unambiguous']:.2%} "
            f"| {v['mean_abs_diff']:.4g} | {v['max_abs_diff']:.4g} |"
        )
    return "\n".join(lines) + "\n"
