"""Leakage-control tests for nids.data.splits (methodology section 3)."""

from __future__ import annotations

import polars as pl
import pytest

from nids.data.splits import (
    GROUP_ROWS,
    Fold,
    LeakageError,
    SplitConfig,
    add_time_group,
    assert_no_leakage,
    fold_summary,
    holdout_days,
    temporal_split,
)
from tests.conftest import make_canonical


def test_split_config_validation() -> None:
    with pytest.raises(ValueError):
        SplitConfig(train_frac=0.8, val_frac=0.3)
    with pytest.raises(ValueError):
        SplitConfig(train_frac=0.0)
    with pytest.raises(ValueError):
        SplitConfig(protocol="random")  # type: ignore[arg-type]


def test_groups_follow_row_order_without_timestamps() -> None:
    df = add_time_group(make_canonical(n=12_000, days=("d1",)))
    assert df.get_column("group_id").n_unique() == 12_000 // GROUP_ROWS + 1
    assert df.get_column("time_order").to_list() == list(range(12_000))


def test_groups_follow_timestamps_when_present() -> None:
    df = add_time_group(make_canonical(n=1200, days=("d1",), with_ts=True))
    # 1200 seconds => 4 or 5 buckets of 300 s
    assert 4 <= df.get_column("group_id").n_unique() <= 5


def test_temporal_split_is_ordered_and_leak_free() -> None:
    df = temporal_split(make_canonical(n=50_000, days=("d1", "d2")), SplitConfig(protocol="day"))
    assert_no_leakage(df)
    summary = fold_summary(df)
    folds = set(summary.get_column("fold"))
    assert folds == {"train", "val", "test"}
    for (day,), sub in df.group_by("day"):
        tr = sub.filter(pl.col("fold") == "train").get_column("time_order").max()
        va = sub.filter(pl.col("fold") == "val").get_column("time_order")
        te = sub.filter(pl.col("fold") == "test").get_column("time_order").min()
        assert tr < va.min() <= va.max() < te, day  # type: ignore[operator]
    train_frac = df.filter(pl.col("fold") == "train").height / df.height
    assert 0.5 < train_frac < 0.75


def test_holdout_days_and_datasets() -> None:
    df = make_canonical(n=6000, days=("d1", "d2", "d3"))
    out = temporal_split(df, SplitConfig(holdout_days=("d3",)))
    assert set(out.filter(pl.col("day") == "d3").get_column("fold")) == {Fold.HOLDOUT.value}
    assert "holdout" not in set(out.filter(pl.col("day") != "d3").get_column("fold"))
    out2 = temporal_split(df, SplitConfig(holdout_datasets=("cicids2017",)))
    assert set(out2.get_column("fold")) == {"holdout"}
    kept, held = holdout_days(df, ("d1",))
    assert held.height == 6000 and kept.height == 12_000


def test_unreliable_rows_leave_training() -> None:
    df = make_canonical(n=6000, days=("d1",)).with_columns(label_reliable=pl.lit(False))
    out = temporal_split(df)
    assert "train" not in set(out.get_column("fold"))
    out2 = temporal_split(df, SplitConfig(exclude_unreliable_from_train=False))
    assert "train" in set(out2.get_column("fold"))


def test_assert_no_leakage_catches_random_split() -> None:
    df = add_time_group(make_canonical(n=30_000, days=("d1",)))
    rnd = df.with_columns(
        fold=pl.when(pl.col("row_id") % 2 == 0).then(pl.lit("train")).otherwise(pl.lit("test"))
    )
    with pytest.raises(LeakageError, match="more than one fold"):
        assert_no_leakage(rnd)


def test_assert_no_leakage_catches_duplicate_vectors() -> None:
    df = temporal_split(make_canonical(n=30_000, days=("d1",)))
    first_train = df.filter(pl.col("fold") == "train").head(1)
    last_test = df.filter(pl.col("fold") == "test").tail(1)
    # copy the train feature vector into a test row
    feats = [
        c
        for c in df.columns
        if c not in {"fold", "group_id", "time_order", "row_id", "day", "dataset"}
    ]
    patched = pl.concat(
        [
            df.filter(pl.col("row_id") != last_test.get_column("row_id")[0]),
            last_test.with_columns(
                [
                    first_train.get_column(f).alias(f)
                    for f in feats
                    if f.startswith(
                        (
                            "flow_",
                            "tot_",
                            "fwd_",
                            "bwd_",
                            "pkt_",
                            "fin_",
                            "syn_",
                            "rst_",
                            "psh_",
                            "ack_",
                            "urg_",
                            "cwe_",
                            "ece_",
                            "down_",
                            "subflow_",
                            "init_",
                            "active_",
                            "idle_",
                            "totlen_",
                        )
                    )
                ]
            ),
        ]
    )
    with pytest.raises(LeakageError, match="identical feature vectors"):
        assert_no_leakage(patched)


def test_assert_no_leakage_requires_fold_columns() -> None:
    with pytest.raises(LeakageError):
        assert_no_leakage(make_canonical(n=10))


def test_time_ordering_violation_detected() -> None:
    df = temporal_split(make_canonical(n=30_000, days=("d1",)))
    # move the test fold to the *start* of time (an impossible order) while keeping groups intact
    broken = df.with_columns(
        time_order=pl.when(pl.col("fold") == "test")
        .then(pl.col("time_order") - 1_000_000)
        .otherwise(pl.col("time_order"))
    )
    with pytest.raises(LeakageError, match="time ordering"):
        assert_no_leakage(broken)


def test_purge_removes_eval_rows_matching_train_inputs() -> None:
    from nids.data.splits import purge_eval_duplicates

    df = temporal_split(make_canonical(n=30_000, days=("d1",)))
    train_row = df.filter(pl.col("fold") == "train").head(1)
    # same model inputs as a train row but a different raw port and label: survives cleaning
    clone = train_row.with_columns(
        fold=pl.lit("test"), dst_port=pl.lit(1, dtype=pl.Int64), label=pl.lit("portscan")
    )
    purged, counts = purge_eval_duplicates(pl.concat([df, clone]))
    assert purged.height == df.height
    assert dict(counts.iter_rows()) == {"test": 1}
    assert_no_leakage(purged)


def _burst_day() -> pl.DataFrame:
    """Benign all day long plus one 3-minute attack burst at the very end of the day."""
    df = make_canonical(n=20_000, days=("d1",), with_ts=True, attack_frac=0.0)
    burst = make_canonical(n=3_000, days=("d1",), with_ts=True, attack_frac=1.0, seed=5)
    start = df.get_column("timestamp").max()
    burst = burst.with_columns(
        row_id=pl.col("row_id") + df.height,
        timestamp=start + pl.duration(milliseconds=pl.int_range(pl.len()) * 60),
    )
    return pl.concat([df, burst])


def test_campaign_split_puts_every_family_in_every_fold() -> None:
    df = _burst_day()
    day = temporal_split(df, SplitConfig(protocol="day"))
    camp = temporal_split(df, SplitConfig(protocol="campaign"))
    assert_no_leakage(camp)
    def attack_folds(x: pl.DataFrame) -> set[str]:
        return set(x.filter(pl.col("is_attack")).get_column("fold"))

    assert attack_folds(day) == {"test"}  # the day protocol never trains on the burst
    assert attack_folds(camp) == {"train", "val", "test"}
    # the 3-minute burst has < MIN_CAMPAIGN_GROUPS minute blocks, so it is cut on row blocks
    burst = camp.filter(pl.col("is_attack"))
    assert burst.get_column("group_id").str.contains(":r").all()
    frac = burst.filter(pl.col("fold") == "train").height / burst.height
    assert 0.55 < frac < 0.65
    # within the campaign, training flows precede evaluation flows
    tr = burst.filter(pl.col("fold") == "train").get_column("time_order").max()
    te = burst.filter(pl.col("fold") == "test").get_column("time_order").min()
    assert tr <= te  # type: ignore[operator]


def test_campaign_ordering_is_checked_per_campaign() -> None:
    camp = temporal_split(_burst_day(), SplitConfig(protocol="campaign"))
    broken = camp.with_columns(
        time_order=pl.when(pl.col("is_attack") & (pl.col("fold") == "test"))
        .then(pl.col("time_order") - 10**12)
        .otherwise(pl.col("time_order"))
    )
    with pytest.raises(LeakageError, match="time ordering"):
        assert_no_leakage(broken)
