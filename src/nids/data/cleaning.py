"""Deterministic clean-up of canonical flows. Every rule is documented in docs/DATA_CARD.md.

Rules (applied in this order, each one counted in the returned report):

1. ``inf``/``-inf`` in rate features (``flow_byts_s``, ``flow_pkts_s``) -> null. These arise
   when CICFlowMeter divides by a zero duration.
2. Null features -> imputed with 0 for counts/bytes/durations and with the per-day median for
   rates (fit on the *training* portion only when used inside the model pipeline; here, the
   file-level imputation is for exploratory profiling and validation and is recorded).
3. Rows whose ``flow_duration`` is negative are dropped (clock-skew artefacts, a handful).
3b. Remaining negative values in features that are non-negative by definition (e.g.
   ``fwd_seg_size_min``, a CICFlowMeter initialisation artefact) are clipped to 0.
4. Exact duplicate feature vectors (all 68 statistics + dst_port + label) are dropped,
   keeping the first occurrence. The CIC datasets contain hundreds of thousands of these
   because the same flow is emitted twice by the flow-timeout logic.
5. Rows whose label is not reliable (``label_reliable == False``) are *kept* but flagged so
   that training can exclude them (default) and evaluation can report them separately.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

import polars as pl

from nids.data.schema import FEATURE_SPECS, FLOW_FEATURES

RATE_FEATURES: tuple[str, ...] = ("flow_byts_s", "flow_pkts_s", "fwd_pkts_s", "bwd_pkts_s")


@dataclass
class CleaningReport:
    rows_in: int = 0
    rows_out: int = 0
    inf_replaced: int = 0
    nulls_imputed: int = 0
    negative_duration_dropped: int = 0
    negatives_clipped: int = 0
    duplicates_dropped: int = 0
    unreliable_label_rows: int = 0
    per_day: dict[str, dict[str, int]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def replace_inf(df: pl.DataFrame) -> tuple[pl.DataFrame, int]:
    n = 0
    exprs = []
    for f in FLOW_FEATURES:
        col = pl.col(f)
        n += int(df.select(col.is_infinite().sum()).item() or 0)
        exprs.append(pl.when(col.is_infinite()).then(None).otherwise(col).alias(f))
    return df.with_columns(exprs), n


def impute_nulls(
    df: pl.DataFrame, medians: dict[str, float] | None = None
) -> tuple[pl.DataFrame, int, dict[str, float]]:
    """Impute nulls. Rates use ``medians`` (fit elsewhere) or the frame median; others use 0."""
    n = int(
        df.select(pl.sum_horizontal([pl.col(f).is_null().sum() for f in FLOW_FEATURES])).item() or 0
    )
    fitted = dict(medians or {})
    exprs = []
    for f in FLOW_FEATURES:
        if f in RATE_FEATURES:
            if f not in fitted:
                med = df.get_column(f).median()
                fitted[f] = float(med) if isinstance(med, (int, float)) else 0.0
            exprs.append(pl.col(f).fill_null(fitted[f]).alias(f))
        else:
            exprs.append(pl.col(f).fill_null(0.0).alias(f))
    return df.with_columns(exprs), n, fitted


def drop_negative_duration(df: pl.DataFrame) -> tuple[pl.DataFrame, int]:
    mask = pl.col("flow_duration") < 0
    n = int(df.select(mask.sum()).item() or 0)
    return df.filter(~mask), n


def clip_negatives(df: pl.DataFrame) -> tuple[pl.DataFrame, int]:
    """Clip negative values of non-negative-by-definition features to 0; return count clipped."""
    cols = [s.name for s in FEATURE_SPECS if s.nonneg]
    n = int(df.select(pl.sum_horizontal([(pl.col(c) < 0).sum() for c in cols])).item() or 0)
    if n:
        df = df.with_columns([pl.col(c).clip(lower_bound=0.0).alias(c) for c in cols])
    return df, n


def row_hash(columns: list[str]) -> pl.Expr:
    """64-bit hash of a row over ``columns`` (fixed seed, so stable within a polars version).

    Used for de-duplication and cross-fold leakage checks instead of materialising row
    copies: memory is 8 bytes per row. With n rows the chance of any collision is about
    n^2 / 2^65, i.e. below 3e-8 for the largest day (1M rows).
    """
    return pl.struct(columns).hash(seed=20170703)


def drop_duplicates(df: pl.DataFrame) -> tuple[pl.DataFrame, int]:
    """Drop exact duplicates over features + dst_port + label, keeping the first occurrence."""
    subset = [*FLOW_FEATURES, "dst_port", "label"]
    before = df.height
    out = df.filter(row_hash(subset).is_first_distinct())
    return out, before - out.height


def _no_inf(f: str) -> pl.Expr:
    return pl.when(pl.col(f).is_infinite()).then(None).otherwise(pl.col(f))


_DUR_OK = pl.col("flow_duration").fill_null(0.0) >= 0
_CLIPPED = tuple(s.name for s in FEATURE_SPECS if s.nonneg and s.name != "flow_duration")
_DEDUP_KEY = [*FLOW_FEATURES, "dst_port", "label"]


def _stats_exprs(fitted: dict[str, float]) -> list[pl.Expr]:
    """Counts for the report plus medians of rate features that were not supplied."""
    return [
        pl.sum_horizontal([pl.col(f).is_infinite().sum() for f in FLOW_FEATURES]).alias("inf"),
        pl.sum_horizontal([pl.col(f).is_null().sum() for f in FLOW_FEATURES]).alias("null"),
        (~_DUR_OK).sum().alias("neg_dur"),
        *[_no_inf(f).median().alias(f"med_{f}") for f in RATE_FEATURES if f not in fitted],
    ]


def _feature_exprs(fitted: dict[str, float]) -> list[pl.Expr]:
    """inf -> null -> imputed (rate medians or 0); non-negative features clipped at 0."""
    out = []
    for f in FLOW_FEATURES:
        e = _no_inf(f).fill_null(fitted.get(f, 0.0))
        if f in _CLIPPED:
            e = e.clip(lower_bound=0.0)
        out.append(e.alias(f))
    return out


def _clip_count_expr(fitted: dict[str, float]) -> pl.Expr:
    return pl.sum_horizontal(
        [((_no_inf(c).fill_null(fitted.get(c, 0.0)) < 0) & _DUR_OK).sum() for c in _CLIPPED]
    ).alias("clip")


def _fill_report(rep: CleaningReport, stats: dict[str, object], fitted: dict[str, float]) -> None:
    for f in RATE_FEATURES:
        if f not in fitted:
            med = stats[f"med_{f}"]
            fitted[f] = float(med) if isinstance(med, (int, float)) else 0.0
    rep.inf_replaced = int(stats["inf"] or 0)  # type: ignore[call-overload]
    rep.nulls_imputed = rep.inf_replaced + int(stats["null"] or 0)  # type: ignore[call-overload]
    rep.negative_duration_dropped = int(stats["neg_dur"] or 0)  # type: ignore[call-overload]


def clean(
    df: pl.DataFrame, rate_medians: dict[str, float] | None = None
) -> tuple[pl.DataFrame, CleaningReport]:
    """Apply all rules in memory; return the cleaned frame and a report. Order is preserved.

    Same result as applying :func:`replace_inf`, :func:`impute_nulls`,
    :func:`drop_negative_duration`, :func:`clip_negatives` and :func:`drop_duplicates` in
    turn. For whole day files use :func:`clean_file`, which streams and never holds the day
    in memory.
    """
    rep = CleaningReport(rows_in=df.height)
    fitted = dict(rate_medians or {})
    _fill_report(rep, df.select(_stats_exprs(fitted)).row(0, named=True), fitted)
    rep.negatives_clipped = int(df.select(_clip_count_expr(fitted)).item() or 0)
    df = df.with_columns(_DUR_OK.alias("_keep"), *_feature_exprs(fitted))
    first = pl.when(pl.col("_keep")).then(row_hash(_DEDUP_KEY))
    kept_rows = df.height - rep.negative_duration_dropped
    df = df.filter(pl.col("_keep") & first.is_first_distinct()).drop("_keep")
    rep.duplicates_dropped = kept_rows - df.height
    rep.unreliable_label_rows = int(df.select((~pl.col("label_reliable")).sum()).item() or 0)
    rep.rows_out = df.height
    if "day" in df.columns:
        for (day,), g in df.group_by("day"):
            rep.per_day[str(day)] = {
                "rows": g.height,
                "attacks": int(g.get_column("is_attack").sum()),
            }
    return df, rep


def clean_file(
    src: Path, dst: Path, rate_medians: dict[str, float] | None = None
) -> CleaningReport:
    """Clean one canonical parquet file into ``dst`` without loading it into memory.

    Three streaming passes over the file: (1) report counts and rate medians, (2) one 64-bit
    hash per row to find duplicates (8 bytes per row in memory), (3) transform, filter and
    sink to ``dst``. Produces exactly the rows and values of :func:`clean`.
    """
    fitted = dict(rate_medians or {})
    lf = pl.scan_parquet(src)
    rows_in = int(lf.select(pl.len()).collect(engine="streaming").item())
    rep = CleaningReport(rows_in=rows_in)
    stats = lf.select(*_stats_exprs(fitted)).collect(engine="streaming").row(0, named=True)
    _fill_report(rep, stats, fitted)
    rep.negatives_clipped = int(
        lf.select(_clip_count_expr(fitted)).collect(engine="streaming").item() or 0
    )
    cleaned = lf.with_columns(_DUR_OK.alias("_keep"), *_feature_exprs(fitted))
    hashes = (
        cleaned.select(pl.when(pl.col("_keep")).then(row_hash(_DEDUP_KEY)).alias("h"))
        .collect(engine="streaming")
        .get_column("h")
    )
    keep_idx = (hashes.is_not_null() & hashes.is_first_distinct()).arg_true()
    del hashes
    dst.parent.mkdir(parents=True, exist_ok=True)
    (
        cleaned.with_row_index("_i")
        .filter(pl.col("_i").is_in(keep_idx))
        .drop("_i", "_keep")
        .sink_parquet(dst, compression="zstd")
    )
    out = pl.scan_parquet(dst)
    agg = (
        out.select(
            pl.len().alias("rows"),
            (~pl.col("label_reliable")).sum().alias("unreliable"),
            pl.col("is_attack").sum().alias("attacks"),
            pl.col("day").first().alias("day"),
        )
        .collect(engine="streaming")
        .row(0, named=True)
    )
    rep.rows_out = int(agg["rows"])
    rep.duplicates_dropped = rows_in - rep.negative_duration_dropped - rep.rows_out
    rep.unreliable_label_rows = int(agg["unreliable"] or 0)
    if agg["day"] is not None:
        rep.per_day[str(agg["day"])] = {"rows": rep.rows_out, "attacks": int(agg["attacks"] or 0)}
    return rep
