"""Data validation: fast native expectations plus an exported Great Expectations suite.

The native checks run on every pipeline step (they take seconds on millions of rows). The
same expectations are also emitted as a Great Expectations suite JSON so that teams using GE
can run them in their own data-quality tooling, and the CI job runs the GE suite on a sample.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import polars as pl

from nids.data.schema import DAYS, FEATURE_SPECS, FLOW_FEATURES, LABEL_TO_CLASS, META_COLUMNS


@dataclass
class Expectation:
    name: str
    passed: bool
    detail: str = ""
    observed: dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationReport:
    rows: int
    expectations: list[Expectation] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(e.passed for e in self.expectations)

    @property
    def failures(self) -> list[Expectation]:
        return [e for e in self.expectations if not e.passed]

    def as_dict(self) -> dict[str, Any]:
        return {
            "rows": self.rows,
            "passed": self.passed,
            "expectations": [asdict(e) for e in self.expectations],
        }

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.as_dict(), indent=2, default=str))


def _expect(rep: ValidationReport, name: str, ok: bool, detail: str = "", **obs: Any) -> None:
    rep.expectations.append(Expectation(name, bool(ok), detail, dict(obs)))


def validate_canonical(
    df: pl.DataFrame, *, allow_inf: bool = True, max_duplicate_frac: float = 0.35
) -> ValidationReport:
    """Validate a canonical (pre- or post-cleaning) frame.

    ``allow_inf`` is True for raw canonical frames (known CICFlowMeter artefact) and must be
    False after cleaning.
    """
    rep = ValidationReport(rows=df.height)
    cols = set(df.columns)

    expected = {*META_COLUMNS, *FLOW_FEATURES, "dst_port_bucket"}
    missing = sorted(expected - cols)
    extra = sorted(cols - expected - {"fold", "group_id", "time_order", "flow_id"})
    _expect(rep, "columns_match_schema", not missing and not extra, missing=missing, extra=extra)

    bad_types = [f for f in FLOW_FEATURES if f in cols and df.schema[f] != pl.Float64]
    _expect(rep, "features_are_float64", not bad_types, bad=bad_types)

    if "label" in cols:
        labels = set(df.get_column("label").unique().to_list())
        unknown = sorted(labels - set(LABEL_TO_CLASS))
        _expect(rep, "labels_in_taxonomy", not unknown, unknown=unknown)
        _expect(
            rep,
            "is_attack_consistent",
            bool(df.select(((pl.col("label") != "benign") == pl.col("is_attack")).all()).item()),
        )

    if "dst_port" in cols:
        port_ok = df.select(pl.col("dst_port").is_between(0, 65535).all()).item()
        _expect(rep, "dst_port_in_range", bool(port_ok))
    if "protocol" in cols and df.get_column("protocol").null_count() < df.height:
        protos = set(df.get_column("protocol").drop_nulls().unique().to_list())
        _expect(rep, "protocol_known", protos <= {0, 6, 17}, protocols=sorted(protos))

    feats_present = [f for f in FLOW_FEATURES if f in cols]
    n_inf = int(
        df.select(pl.sum_horizontal([pl.col(f).is_infinite().sum() for f in feats_present])).item()
        or 0
    )
    n_null = int(
        df.select(pl.sum_horizontal([pl.col(f).is_null().sum() for f in feats_present])).item() or 0
    )
    _expect(rep, "no_infinite_values", allow_inf or n_inf == 0, infinite=n_inf)
    _expect(rep, "no_null_features", allow_inf or n_null == 0, nulls=n_null)

    neg = {
        s.name: int(df.select((pl.col(s.name) < 0).sum()).item() or 0)
        for s in FEATURE_SPECS
        if s.nonneg and s.name in cols
    }
    neg = {k: v for k, v in neg.items() if v}
    _expect(
        rep,
        "nonnegative_features",
        allow_inf or not neg,
        "informational before cleaning" if allow_inf else "",
        negatives=neg,
    )

    if {"tot_fwd_pkts", "tot_bwd_pkts"} <= cols:
        zero_pkts = int(
            df.select(((pl.col("tot_fwd_pkts") + pl.col("tot_bwd_pkts")) <= 0).sum()).item() or 0
        )
        _expect(rep, "flows_have_packets", zero_pkts == 0, zero_packet_flows=zero_pkts)
    if {"fwd_pkt_len_max", "fwd_pkt_len_min"} <= cols:
        bad = int(
            df.select((pl.col("fwd_pkt_len_max") < pl.col("fwd_pkt_len_min")).sum()).item() or 0
        )
        _expect(rep, "fwd_len_max_ge_min", bad == 0, violations=bad)

    if "dst_port" in cols and "label" in cols:
        dup = df.height - df.unique(subset=[*feats_present, "dst_port", "label"]).height
        frac = dup / max(df.height, 1)
        _expect(
            rep,
            "duplicate_fraction_bounded",
            frac <= max_duplicate_frac,
            duplicates=dup,
            fraction=round(frac, 4),
        )

    if "day" in cols:
        counts = dict(df.group_by("day").len().iter_rows())
        expected_rows = {d.day: d.expected_rows for d in DAYS if d.expected_rows}
        mism = {
            k: (v, expected_rows[k])
            for k, v in counts.items()
            if k in expected_rows and v != expected_rows[k]
        }
        _expect(rep, "row_counts_match_published", not mism, mismatches=mism)
    return rep


def ge_suite(name: str = "nids_canonical") -> dict[str, Any]:
    """The same expectations as a Great Expectations suite (JSON-serialisable, GE 1.x shape)."""
    exps: list[dict[str, Any]] = [
        {
            "type": "expect_table_columns_to_match_set",
            "kwargs": {
                "column_set": [*META_COLUMNS, *FLOW_FEATURES, "dst_port_bucket"],
                "exact_match": False,
            },
        },
        {
            "type": "expect_column_values_to_be_in_set",
            "kwargs": {"column": "label", "value_set": sorted(LABEL_TO_CLASS)},
        },
        {
            "type": "expect_column_values_to_be_between",
            "kwargs": {"column": "dst_port", "min_value": 0, "max_value": 65535},
        },
        {
            "type": "expect_column_values_to_be_in_set",
            "kwargs": {"column": "dst_port_bucket", "value_set": [0, 1, 2, 3]},
        },
        {
            "type": "expect_compound_columns_to_be_unique",
            "kwargs": {"column_list": ["dataset", "day", "row_id"]},
        },
    ]
    for s in FEATURE_SPECS:
        exps.append({"type": "expect_column_values_to_not_be_null", "kwargs": {"column": s.name}})
        if s.nonneg:
            exps.append(
                {
                    "type": "expect_column_values_to_be_between",
                    "kwargs": {"column": s.name, "min_value": 0},
                }
            )
    return {
        "name": name,
        "expectations": exps,
        "meta": {"generated_by": "nids.data.validation.ge_suite"},
    }


def write_ge_suite(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(ge_suite(), indent=2))
    return path
