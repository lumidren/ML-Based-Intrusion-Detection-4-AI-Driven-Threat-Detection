"""Leak-free dataset splitting (docs/METHODOLOGY.md section 3).

Two complementary strategies, both deterministic:

* :func:`temporal_split` - within each day, order flows by time (``timestamp`` when present,
  otherwise ``row_id``), bucket them into contiguous *groups* and assign whole groups to
  train / validation / test in time order. A group never straddles a boundary, so a burst
  of attack flows cannot be split across folds.
* :func:`holdout_days` - whole days (or whole datasets) held out for out-of-time and
  cross-dataset evaluation. Nothing from a held-out day is ever seen during fitting.

:func:`assert_no_leakage` is the test oracle: it checks group disjointness, time ordering
and the absence of identical feature vectors across folds.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

import polars as pl

from nids.data.schema import FLOW_FEATURES

GROUP_ROWS = 5_000
"""Rows per time group when no timestamp exists (CIC-IDS2017 ML CSVs)."""
GROUP_SECONDS = 300
"""Seconds per time group when timestamps exist (CSE-CIC-IDS2018)."""


class Fold(StrEnum):
    TRAIN = "train"
    VAL = "val"
    TEST = "test"
    HOLDOUT = "holdout"


@dataclass(frozen=True)
class SplitConfig:
    train_frac: float = 0.6
    val_frac: float = 0.2
    holdout_days: tuple[str, ...] = ()
    holdout_datasets: tuple[str, ...] = ()
    exclude_unreliable_from_train: bool = True

    def __post_init__(self) -> None:
        if (
            not 0 < self.train_frac < 1
            or not 0 < self.val_frac < 1
            or self.train_frac + self.val_frac >= 1
        ):
            raise ValueError("train_frac + val_frac must be < 1 and both in (0, 1)")


def add_time_group(df: pl.DataFrame) -> pl.DataFrame:
    """Add ``time_order`` (sortable within a day) and ``group_id`` (contiguous time bucket).

    ``group_id`` is globally unique: ``"<day>:<bucket>"``.
    """
    has_ts = "timestamp" in df.columns and df.get_column("timestamp").null_count() < df.height
    if has_ts:
        ts_us = pl.col("timestamp").cast(pl.Int64)  # microseconds since epoch
        order = pl.coalesce([ts_us, pl.col("row_id")])
        bucket = (order // (GROUP_SECONDS * 1_000_000)).cast(pl.Int64)
    else:
        order = pl.col("row_id")
        bucket = (pl.col("row_id") // GROUP_ROWS).cast(pl.Int64)
    return df.with_columns(
        time_order=order,
        group_id=pl.concat_str([pl.col("day"), pl.lit(":"), bucket.cast(pl.Utf8)]),
    )


def temporal_split(df: pl.DataFrame, cfg: SplitConfig | None = None) -> pl.DataFrame:
    """Assign a ``fold`` column. Held-out days/datasets get ``holdout``; the rest is split
    per day by time into train/val/test on *group* boundaries.
    """
    cfg = cfg or SplitConfig()
    df = add_time_group(df)
    is_holdout = pl.col("day").is_in(list(cfg.holdout_days)) | pl.col("dataset").is_in(
        list(cfg.holdout_datasets)
    )

    # rank groups within each day by their first time_order; a group is assigned by the
    # position of its midpoint so that every fold receives whole groups and none is empty
    # when at least three groups exist
    grp = (
        df.group_by(["day", "group_id"])
        .agg(pl.col("time_order").min().alias("g_start"), pl.len().alias("g_rows"))
        .sort(["day", "g_start"])
        .with_columns(
            cum=pl.col("g_rows").cum_sum().over("day"),
            total=pl.col("g_rows").sum().over("day"),
        )
        .with_columns(frac=(pl.col("cum") - pl.col("g_rows") / 2) / pl.col("total"))
        .with_columns(
            fold=pl.when(pl.col("frac") < cfg.train_frac)
            .then(pl.lit(Fold.TRAIN.value))
            .when(pl.col("frac") < cfg.train_frac + cfg.val_frac)
            .then(pl.lit(Fold.VAL.value))
            .otherwise(pl.lit(Fold.TEST.value))
        )
        .select(["group_id", "fold"])
    )
    out = df.join(grp, on="group_id", how="left").with_columns(
        fold=pl.when(is_holdout).then(pl.lit(Fold.HOLDOUT.value)).otherwise(pl.col("fold"))
    )
    if cfg.exclude_unreliable_from_train:
        out = out.with_columns(
            fold=pl.when((pl.col("fold") == Fold.TRAIN.value) & ~pl.col("label_reliable"))
            .then(pl.lit(Fold.HOLDOUT.value))
            .otherwise(pl.col("fold"))
        )
    return out


def holdout_days(df: pl.DataFrame, days: tuple[str, ...]) -> tuple[pl.DataFrame, pl.DataFrame]:
    """Return (kept, held_out) frames by whole day."""
    mask = pl.col("day").is_in(list(days))
    return df.filter(~mask), df.filter(mask)


class LeakageError(AssertionError):
    pass


def assert_no_leakage(df: pl.DataFrame) -> None:
    """Raise :class:`LeakageError` if the fold assignment violates any protocol rule."""
    if "fold" not in df.columns or "group_id" not in df.columns:
        raise LeakageError("frame has no fold/group_id columns")
    # 1. a group lives in exactly one fold
    g = df.group_by("group_id").agg(pl.col("fold").n_unique().alias("n"))
    if g.filter(pl.col("n") > 1).height:
        raise LeakageError("a time group is assigned to more than one fold")
    # 2. within a day, every train row precedes every val row which precedes every test row
    order = {Fold.TRAIN.value: 0, Fold.VAL.value: 1, Fold.TEST.value: 2}
    ordered = df.filter(pl.col("fold").is_in(list(order))).with_columns(
        rank=pl.col("fold").replace_strict(order, return_dtype=pl.Int64)
    )
    bounds = ordered.group_by(["day", "rank"]).agg(
        pl.col("time_order").min().alias("t_min"), pl.col("time_order").max().alias("t_max")
    )
    for (day,), part in bounds.group_by("day"):
        srt = part.sort("rank")
        maxes = srt.get_column("t_max").to_list()
        mins = srt.get_column("t_min").to_list()
        for i in range(1, len(maxes)):
            if mins[i] < maxes[i - 1]:
                raise LeakageError(
                    f"time ordering violated on {day}: fold {i} starts before fold {i - 1} ends"
                )
    # 3. no identical feature vector in train and any evaluation fold
    feats = list(FLOW_FEATURES)
    train = df.filter(pl.col("fold") == Fold.TRAIN.value).select(feats).unique()
    evals = df.filter(pl.col("fold") != Fold.TRAIN.value).select(feats).unique()
    dup = train.join(evals, on=feats, how="inner").height
    if dup:
        raise LeakageError(f"{dup} identical feature vectors appear in train and evaluation folds")


def fold_summary(df: pl.DataFrame) -> pl.DataFrame:
    return (
        df.group_by(["dataset", "day", "fold"])
        .agg(pl.len().alias("rows"), pl.col("is_attack").sum().alias("attacks"))
        .sort(["dataset", "day", "fold"])
    )
