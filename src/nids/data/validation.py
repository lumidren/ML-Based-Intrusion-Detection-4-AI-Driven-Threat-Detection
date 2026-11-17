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

from nids.data.cleaning import row_hash
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


MAX_DUPLICATE_FRAC = 0.5
"""Per-day bound on exact duplicates. The measured maximum is 46.5% (CSE-CIC-IDS2018 21-02,
DDoS); a file ingested twice would show 50% or more."""


def validate_canonical(
    data: pl.DataFrame | pl.LazyFrame,
    *,
    allow_inf: bool = True,
    max_duplicate_frac: float = MAX_DUPLICATE_FRAC,
) -> ValidationReport:
    """Validate a canonical (pre- or post-cleaning) frame or lazy scan of one day.

    All row-level checks are computed in one streaming aggregation, so passing
    ``pl.scan_parquet(path)`` validates a day file without loading it into memory.
    ``allow_inf`` is True for raw canonical data (known CICFlowMeter artefact) and must be
    False after cleaning.
    """
    lf = data.lazy()
    schema = lf.collect_schema()
    cols = set(schema.names())
    feats = [f for f in FLOW_FEATURES if f in cols]
    nonneg = [s.name for s in FEATURE_SPECS if s.nonneg and s.name in cols]

    aggs: list[pl.Expr] = [
        pl.len().alias("rows"),
        pl.sum_horizontal([pl.col(f).is_infinite().sum() for f in feats]).alias("inf"),
        pl.sum_horizontal([pl.col(f).is_null().sum() for f in feats]).alias("null"),
        *[(pl.col(c) < 0).sum().alias(f"neg_{c}") for c in nonneg],
    ]
    if "label" in cols:
        aggs.append(((pl.col("label") != "benign") == pl.col("is_attack")).all().alias("attack_ok"))
    if "dst_port" in cols:
        aggs.append(pl.col("dst_port").is_between(0, 65535).all().alias("port_ok"))
    if {"tot_fwd_pkts", "tot_bwd_pkts"} <= cols:
        aggs.append(
            ((pl.col("tot_fwd_pkts") + pl.col("tot_bwd_pkts")) <= 0).sum().alias("zero_pkts")
        )
    if {"fwd_pkt_len_max", "fwd_pkt_len_min"} <= cols:
        aggs.append(
            (pl.col("fwd_pkt_len_max") < pl.col("fwd_pkt_len_min")).sum().alias("max_lt_min")
        )
    if "dst_port" in cols and "label" in cols:
        aggs.append(row_hash([*feats, "dst_port", "label"]).n_unique().alias("distinct"))
    a = lf.select(aggs).collect(engine="streaming").row(0, named=True)

    rows = int(a["rows"])
    rep = ValidationReport(rows=rows)
    expected = {*META_COLUMNS, *FLOW_FEATURES, "dst_port_bucket"}
    missing = sorted(expected - cols)
    extra = sorted(cols - expected - {"fold", "group_id", "time_order", "flow_id", "row_hash"})
    _expect(rep, "columns_match_schema", not missing and not extra, missing=missing, extra=extra)
    bad_types = [f for f in feats if schema[f] != pl.Float64]
    _expect(rep, "features_are_float64", not bad_types, bad=bad_types)

    if "label" in cols:
        labels = set(lf.select(pl.col("label").unique()).collect(engine="streaming").to_series())
        unknown = sorted(labels - set(LABEL_TO_CLASS))
        _expect(rep, "labels_in_taxonomy", not unknown, unknown=unknown)
        _expect(rep, "is_attack_consistent", bool(a["attack_ok"]))
    if "dst_port" in cols:
        _expect(rep, "dst_port_in_range", bool(a["port_ok"]))
    if "protocol" in cols:
        protos = set(
            lf.select(pl.col("protocol").drop_nulls().unique())
            .collect(engine="streaming")
            .to_series()
        )
        if protos:
            _expect(rep, "protocol_known", protos <= {0, 6, 17}, protocols=sorted(protos))

    n_inf, n_null = int(a["inf"] or 0), int(a["null"] or 0)
    _expect(rep, "no_infinite_values", allow_inf or n_inf == 0, infinite=n_inf)
    _expect(rep, "no_null_features", allow_inf or n_null == 0, nulls=n_null)
    neg = {c: int(a[f"neg_{c}"]) for c in nonneg if a[f"neg_{c}"]}
    _expect(
        rep,
        "nonnegative_features",
        allow_inf or not neg,
        "informational before cleaning" if allow_inf else "",
        negatives=neg,
    )
    if "zero_pkts" in a:
        _expect(
            rep, "flows_have_packets", a["zero_pkts"] == 0, zero_packet_flows=int(a["zero_pkts"])
        )
    if "max_lt_min" in a:
        _expect(rep, "fwd_len_max_ge_min", a["max_lt_min"] == 0, violations=int(a["max_lt_min"]))
    if "distinct" in a:
        dup = rows - int(a["distinct"])
        frac = dup / max(rows, 1)
        _expect(
            rep,
            "duplicate_fraction_bounded",
            frac <= max_duplicate_frac,
            duplicates=dup,
            fraction=round(frac, 4),
        )
    if "day" in cols:
        counts = dict(lf.group_by("day").len().collect(engine="streaming").iter_rows())
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
