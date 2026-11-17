"""Read the raw CSVs of both datasets into canonical, typed per-day parquet files.

Each raw file is read lazily, column names are normalised (CIC-IDS2017 has leading spaces),
the header rows repeated inside the CSE-CIC-IDS2018 files are removed, every feature is cast
to Float64 (``Infinity`` strings become ``inf`` and are handled by ``cleaning``), labels are
mapped to the canonical taxonomy and metadata columns are added.

Memory: every step is a lazy query sunk straight to parquet, so a day file is never held in
memory as a whole. Downstream code reads one day at a time through :func:`iter_day_files` or
:func:`scan_days`; :func:`load_canonical` exists for small selections and tests only.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Literal

import polars as pl

from nids.data.schema import (
    CIC2017_RENAME,
    CSE2018_RENAME,
    DAYS,
    FLOW_FEATURES,
    LABEL_TO_CLASS,
    META_COLUMNS,
    Dataset,
    DayInfo,
    normalise_label,
)

CANONICAL_COLUMNS: tuple[str, ...] = (*META_COLUMNS, *FLOW_FEATURES, "dst_port_bucket")
Stage = Literal["canonical", "clean"]

PM_CUTOFF_HOUR = 8
"""CSE-CIC-IDS2018 prints its timestamps on a 12-hour clock without AM/PM. The captures run
from about 08:30 to 17:30 local time, so a printed hour below 8 is an afternoon hour. Verified
on all six days: printed hours are 1-5, 7 and 8-12 (never 0, 6 or 13+), and the attack windows
match the published schedule only with this correction (e.g. SSH brute force 14:01-15:32 on
14-02 is printed as 02:01-03:32, DoS-Hulk 13:45 on 16-02 as 01:45)."""


def timestamp_expr(dataset: Dataset) -> pl.Expr:
    """Parse the raw ``Timestamp`` column into naive local time on a 24-hour clock."""
    ts = pl.col("timestamp").str.strip_chars().str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False)
    if dataset is not Dataset.CSE2018:
        return ts
    return pl.when(ts.dt.hour() < PM_CUTOFF_HOUR).then(ts + pl.duration(hours=12)).otherwise(ts)


def _strip_names(df: pl.LazyFrame) -> pl.LazyFrame:
    return df.rename({c: c.strip() for c in df.collect_schema().names()})


def read_raw(day: DayInfo, raw_root: Path) -> pl.LazyFrame:
    """Lazy read of one raw CSV with dataset-specific quirks handled."""
    path = raw_root / day.dataset.value / day.filename
    if not path.exists():
        raise FileNotFoundError(path)
    lf = pl.scan_csv(
        path,
        infer_schema_length=0,  # everything as Utf8 first; we cast explicitly below
        encoding="utf8-lossy",
        ignore_errors=False,
        truncate_ragged_lines=False,
    )
    lf = _strip_names(lf)
    names = lf.collect_schema().names()
    if day.dataset is Dataset.CIC2017:
        # the duplicate 'Fwd Header Length' becomes 'Fwd Header Length_duplicated_0' in polars
        dup = [c for c in names if c.startswith("Fwd Header Length") and c != "Fwd Header Length"]
        lf = lf.drop(dup)
        rename = {k: v for k, v in CIC2017_RENAME.items() if k in names}
    else:
        rename = {k: v for k, v in CSE2018_RENAME.items() if k in names}
        # repeated header rows inside the 2018 files
        lf = lf.filter(pl.col("Dst Port") != "Dst Port")
    lf = lf.rename(rename)
    keep = [
        c for c in lf.collect_schema().names() if c in {*FLOW_FEATURES, *META_COLUMNS, "flow_id"}
    ]
    return lf.select(keep)


def dst_port_bucket_expr(col: str = "dst_port") -> pl.Expr:
    """Vectorised :func:`nids.data.schema.dst_port_bucket` (null -> 3)."""
    p = pl.col(col)
    return (
        pl.when(p.is_null() | (p < 0) | (p > 65535))
        .then(3)
        .when(p < 1024)
        .then(0)
        .when(p < 49152)
        .then(1)
        .otherwise(2)
        .cast(pl.Int64)
    )


def canonical_lazy(day: DayInfo, raw_root: Path) -> pl.LazyFrame:
    """The canonical typed query for one day (nothing is read until it is collected/sunk)."""
    lf = read_raw(day, raw_root)
    schema = lf.collect_schema().names()

    # labels: map the handful of distinct raw strings once (cheap one-column scan)
    raw_label = pl.col("label_raw").str.strip_chars()
    uniques = lf.select(raw_label.unique()).collect(engine="streaming").to_series().to_list()
    mapping = {u: normalise_label(u) for u in uniques}
    label = raw_label.replace_strict(mapping, return_dtype=pl.Utf8)
    attack_class = label.replace_strict(
        {k: v.value for k, v in LABEL_TO_CLASS.items()}, return_dtype=pl.Utf8
    )

    feat_exprs = [
        pl.col(f)
        .str.strip_chars()
        .str.replace("^Infinity$", "inf")
        .str.replace("^-Infinity$", "-inf")
        .cast(pl.Float64, strict=False)
        .alias(f)
        for f in FLOW_FEATURES
    ]
    meta_exprs: list[pl.Expr] = [
        pl.lit(day.dataset.value).alias("dataset"),
        pl.lit(day.day).alias("day"),
        pl.col("row_id").cast(pl.Int64),
        pl.col("dst_port").cast(pl.Int64, strict=False).alias("dst_port"),
        (
            pl.col("protocol").cast(pl.Int64, strict=False)
            if "protocol" in schema
            else pl.lit(None, dtype=pl.Int64)
        ).alias("protocol"),
        (
            timestamp_expr(day.dataset)
            if "timestamp" in schema
            else pl.lit(None, dtype=pl.Datetime("us"))
        ).alias("timestamp"),
        *[
            (pl.col(c) if c in schema else pl.lit(None, dtype=pl.Utf8)).alias(c)
            for c in ("src_ip", "dst_ip")
        ],
        (
            pl.col("src_port").cast(pl.Int64, strict=False)
            if "src_port" in schema
            else pl.lit(None, dtype=pl.Int64)
        ).alias("src_port"),
        raw_label.alias("label_raw"),
        label.alias("label"),
        attack_class.alias("attack_class"),
        (label != "benign").alias("is_attack"),
        pl.lit(day.label_reliable).alias("label_reliable"),
    ]
    return (
        lf.with_row_index("row_id")
        .select([*meta_exprs, *feat_exprs])
        .with_columns(dst_port_bucket_expr().alias("dst_port_bucket"))
        .select(list(CANONICAL_COLUMNS))
    )


def canonicalise(day: DayInfo, raw_root: Path) -> pl.DataFrame:
    """Canonical frame for one day, in memory (tests and small files; use the sink for days)."""
    return canonical_lazy(day, raw_root).collect()


def day_path(day: DayInfo, processed_root: Path, stage: Stage = "canonical") -> Path:
    return processed_root / stage / day.dataset.value / f"{day.day}.parquet"


def canonical_path(day: DayInfo, processed_root: Path) -> Path:
    return day_path(day, processed_root, "canonical")


def _selected_days(
    datasets: tuple[Dataset, ...] | None, days: tuple[str, ...] | None
) -> Iterator[DayInfo]:
    for day in DAYS:
        if datasets and day.dataset not in datasets:
            continue
        if days and day.day not in days:
            continue
        yield day


def canonicalise_all(
    raw_root: Path, processed_root: Path, datasets: tuple[Dataset, ...] | None = None
) -> list[Path]:
    """Stream every registered day whose raw file exists to parquet; return written paths."""
    written: list[Path] = []
    for day in _selected_days(datasets, None):
        if not (raw_root / day.dataset.value / day.filename).exists():
            continue
        out = canonical_path(day, processed_root)
        out.parent.mkdir(parents=True, exist_ok=True)
        canonical_lazy(day, raw_root).sink_parquet(out, compression="zstd")
        written.append(out)
    return written


def iter_day_files(
    processed_root: Path,
    stage: Stage = "canonical",
    datasets: tuple[Dataset, ...] | None = None,
    days: tuple[str, ...] | None = None,
) -> Iterator[tuple[DayInfo, Path]]:
    """Yield (day, parquet path) for every selected day file that exists, in registry order."""
    for day in _selected_days(datasets, days):
        p = day_path(day, processed_root, stage)
        if p.exists():
            yield day, p


def scan_days(
    processed_root: Path,
    stage: Stage = "canonical",
    datasets: tuple[Dataset, ...] | None = None,
    days: tuple[str, ...] | None = None,
) -> pl.LazyFrame:
    """Lazy scan over the selected day files (filter/select before collecting)."""
    paths = [p for _, p in iter_day_files(processed_root, stage, datasets, days)]
    if not paths:
        raise FileNotFoundError(f"no {stage} parquet files under {processed_root}")
    return pl.scan_parquet(paths)


def load_canonical(
    processed_root: Path,
    datasets: tuple[Dataset, ...] | None = None,
    days: tuple[str, ...] | None = None,
    columns: list[str] | None = None,
    stage: Stage = "canonical",
) -> pl.DataFrame:
    """Read the selected days into memory. Only for small selections: a full dataset does not
    fit on a laptop; iterate with :func:`iter_day_files` instead."""
    lf = scan_days(processed_root, stage, datasets, days)
    if columns:
        lf = lf.select(columns)
    return lf.collect()
