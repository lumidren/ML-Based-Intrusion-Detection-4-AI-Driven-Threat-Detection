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


def drop_duplicates(df: pl.DataFrame) -> tuple[pl.DataFrame, int]:
    """Drop exact duplicates over features + dst_port + label, keeping the first occurrence."""
    subset = [*FLOW_FEATURES, "dst_port", "label"]
    before = df.height
    out = df.unique(subset=subset, keep="first", maintain_order=True)
    return out, before - out.height


def clean(
    df: pl.DataFrame, rate_medians: dict[str, float] | None = None
) -> tuple[pl.DataFrame, CleaningReport]:
    """Apply all rules; return the cleaned frame and a report. Order is preserved."""
    rep = CleaningReport(rows_in=df.height)
    df, rep.inf_replaced = replace_inf(df)
    df, rep.nulls_imputed, _ = impute_nulls(df, rate_medians)
    df, rep.negative_duration_dropped = drop_negative_duration(df)
    df, rep.negatives_clipped = clip_negatives(df)
    df, rep.duplicates_dropped = drop_duplicates(df)
    rep.unreliable_label_rows = int(df.select((~pl.col("label_reliable")).sum()).item() or 0)
    rep.rows_out = df.height
    if "day" in df.columns:
        for (day,), g in df.group_by("day"):
            rep.per_day[str(day)] = {
                "rows": g.height,
                "attacks": int(g.get_column("is_attack").sum()),
            }
    return df, rep
