"""Read the raw CSVs of both datasets into one canonical, typed Polars frame.

Each raw file is read lazily, column names are normalised (CIC-IDS2017 has leading spaces),
the known header rows embedded inside the CSE-CIC-IDS2018 files are removed, every feature
is cast to Float64 (``Infinity`` strings become ``inf`` and are handled by ``cleaning``),
labels are mapped to the canonical taxonomy and metadata columns are added.
"""

from __future__ import annotations

from pathlib import Path

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
    dst_port_bucket,
    normalise_label,
)

CANONICAL_COLUMNS: tuple[str, ...] = (*META_COLUMNS, *FLOW_FEATURES, "dst_port_bucket")


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


def canonicalise(day: DayInfo, raw_root: Path) -> pl.DataFrame:
    """Return the canonical typed frame for one day. Eager: ~1M rows fit comfortably in memory."""
    lf = read_raw(day, raw_root)
    df = lf.collect()

    # --- labels ------------------------------------------------------------------------
    raw_labels = df.get_column("label_raw").str.strip_chars()
    uniques = raw_labels.unique().to_list()
    mapping = {u: normalise_label(u) for u in uniques}
    label = raw_labels.replace_strict(mapping, return_dtype=pl.Utf8)
    attack_class = label.replace_strict(
        {k: v.value for k, v in LABEL_TO_CLASS.items()}, return_dtype=pl.Utf8
    )

    # --- features ----------------------------------------------------------------------
    feat_exprs = [
        pl.col(f)
        .str.strip_chars()
        .str.replace("^Infinity$", "inf")
        .str.replace("^-Infinity$", "-inf")
        .cast(pl.Float64, strict=False)
        .alias(f)
        for f in FLOW_FEATURES
    ]
    # --- metadata ----------------------------------------------------------------------
    meta_exprs: list[pl.Expr] = [
        pl.lit(day.dataset.value).alias("dataset"),
        pl.lit(day.day).alias("day"),
        pl.int_range(0, pl.len(), dtype=pl.Int64).alias("row_id"),
        pl.col("dst_port").cast(pl.Int64, strict=False).alias("dst_port"),
    ]
    schema = df.collect_schema().names()
    if "protocol" in schema:
        meta_exprs.append(pl.col("protocol").cast(pl.Int64, strict=False).alias("protocol"))
    else:
        meta_exprs.append(pl.lit(None, dtype=pl.Int64).alias("protocol"))
    if "timestamp" in schema:
        meta_exprs.append(
            pl.col("timestamp")
            .str.strip_chars()
            .str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False)
            .alias("timestamp")
        )
    else:
        meta_exprs.append(pl.lit(None, dtype=pl.Datetime("us")).alias("timestamp"))
    meta_exprs.extend(
        pl.col(col).alias(col) if col in schema else pl.lit(None, dtype=pl.Utf8).alias(col)
        for col in ("src_ip", "dst_ip")
    )
    meta_exprs.append(
        pl.col("src_port").cast(pl.Int64, strict=False).alias("src_port")
        if "src_port" in schema
        else pl.lit(None, dtype=pl.Int64).alias("src_port")
    )

    out = df.select([*meta_exprs, *feat_exprs]).with_columns(
        label_raw=raw_labels,
        label=label,
        attack_class=attack_class,
        is_attack=(label != "benign"),
        label_reliable=pl.lit(day.label_reliable),
    )
    out = out.with_columns(
        pl.col("dst_port")
        .map_elements(
            lambda p: dst_port_bucket(int(p)) if p is not None else 3, return_dtype=pl.Int64
        )
        .alias("dst_port_bucket")
    )
    return out.select(list(CANONICAL_COLUMNS))


def canonical_path(day: DayInfo, processed_root: Path) -> Path:
    return processed_root / "canonical" / day.dataset.value / f"{day.day}.parquet"


def canonicalise_all(
    raw_root: Path, processed_root: Path, datasets: tuple[Dataset, ...] | None = None
) -> list[Path]:
    """Canonicalise every registered day whose raw file exists; return written paths."""
    written: list[Path] = []
    for day in DAYS:
        if datasets and day.dataset not in datasets:
            continue
        src = raw_root / day.dataset.value / day.filename
        if not src.exists():
            continue
        out = canonical_path(day, processed_root)
        out.parent.mkdir(parents=True, exist_ok=True)
        canonicalise(day, raw_root).write_parquet(out, compression="zstd")
        written.append(out)
    return written


def load_canonical(
    processed_root: Path,
    datasets: tuple[Dataset, ...] | None = None,
    days: tuple[str, ...] | None = None,
) -> pl.DataFrame:
    """Concatenate canonical parquet files (optionally filtered by dataset/day)."""
    frames = []
    for day in DAYS:
        if datasets and day.dataset not in datasets:
            continue
        if days and day.day not in days:
            continue
        p = canonical_path(day, processed_root)
        if p.exists():
            frames.append(pl.read_parquet(p))
    if not frames:
        raise FileNotFoundError(f"no canonical parquet files under {processed_root}")
    return pl.concat(frames, how="vertical_relaxed")
