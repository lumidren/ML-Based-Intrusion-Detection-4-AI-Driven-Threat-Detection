"""Resource guards and the per-day streaming data stages."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import polars as pl
import pytest
from typer.testing import CliRunner

from nids import resources
from nids.data import cleaning
from nids.data.loaders import (
    canonical_path,
    canonicalise,
    canonicalise_all,
    day_path,
    dst_port_bucket_expr,
    iter_day_files,
    load_canonical,
    scan_days,
)
from nids.data.profile import clean_day, profile_dir
from nids.data.schema import DAYS, FLOW_FEATURES, DayInfo, dst_port_bucket
from nids.data.splits import Fold, SplitConfig, count_shared, feature_hash, split_dir
from tests.conftest import make_canonical

# ---------------------------------------------------------------- resource guards


def test_cap_threads_respects_existing_values(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in resources.THREAD_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("OMP_NUM_THREADS", "1")
    eff = resources.cap_threads(3)
    assert eff["OMP_NUM_THREADS"] == "1"
    assert eff["POLARS_MAX_THREADS"] == "3"
    assert resources.cap_threads(0)["MKL_NUM_THREADS"] == "3"  # already set, floor of 1 unused


def test_lower_priority_runs() -> None:
    assert resources.lower_priority() in (True, False)


def test_watchdog_trips_on_process_limit() -> None:
    messages: list[str] = []
    dog = resources.MemoryWatchdog(
        limit_mb=1, min_free_mb=0, interval_s=0.01, on_breach=messages.append
    )
    dog.start()
    dog._thread.join(timeout=5)  # type: ignore[union-attr]
    assert dog.breach is not None and "process memory" in dog.breach.reason
    assert messages and "stopped to protect the machine" in messages[0]
    assert dog.stop() > 1


def test_watchdog_trips_on_low_system_memory() -> None:
    dog = resources.MemoryWatchdog(
        limit_mb=10**6, min_free_mb=10**9, significant_mb=0, on_breach=lambda _: None
    )
    breach = dog.check()
    assert breach is not None and "system free memory" in breach.reason


def test_watchdog_quiet_within_budget() -> None:
    with resources.MemoryWatchdog(limit_mb=10**6, min_free_mb=0, interval_s=0.01) as dog:
        assert dog.check() is None
    assert dog.breach is None and dog.peak_mb > 0


def test_guard_starts_watchdog(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in resources.THREAD_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    dog = resources.guard(limit_mb=10**6, min_free_mb=0, threads=2)
    try:
        assert os.environ["POLARS_MAX_THREADS"] == "2"
    finally:
        dog.stop()


# ---------------------------------------------------------------- streaming stages


@pytest.mark.parametrize("port", [None, -5, 0, 80, 1023, 1024, 49151, 49152, 65535, 70000])
def test_port_bucket_expr_matches_python(port: int | None) -> None:
    got = (
        pl.DataFrame({"dst_port": [port]}, schema={"dst_port": pl.Int64})
        .select(dst_port_bucket_expr())
        .item()
    )
    assert got == (3 if port is None else dst_port_bucket(port))


@pytest.fixture
def processed(raw_root: Path, tmp_path: Path) -> Path:
    out = tmp_path / "processed"
    assert len(canonicalise_all(raw_root, out)) == 2
    return out


def test_sink_matches_in_memory(raw_root: Path, processed: Path, day_2018: DayInfo) -> None:
    assert pl.read_parquet(canonical_path(day_2018, processed)).equals(
        canonicalise(day_2018, raw_root)
    )
    assert [d.day for d, _ in iter_day_files(processed)] == ["2017-07-04-tue", "2018-02-14-wed"]
    assert scan_days(processed).select(pl.len()).collect().item() == 403
    assert load_canonical(processed, columns=["day"]).columns == ["day"]
    with pytest.raises(FileNotFoundError):
        scan_days(processed, "clean")


def test_clean_file_equals_in_memory_clean(
    processed: Path, day_2017: DayInfo, tmp_path: Path
) -> None:
    src = canonical_path(day_2017, processed)
    rep = cleaning.clean_file(src, tmp_path / "c.parquet")
    mem, rep2 = cleaning.clean(pl.read_parquet(src))
    assert pl.read_parquet(tmp_path / "c.parquet").equals(mem)
    a, b = rep.as_dict(), rep2.as_dict()
    assert a == b
    assert rep.duplicates_dropped == 1 and rep.inf_replaced == 1


def test_clean_keeps_negative_duration_semantics() -> None:
    df = make_canonical(n=50, days=("d1",)).with_columns(
        flow_duration=pl.when(pl.col("row_id") < 3).then(-7.0).otherwise(pl.col("flow_duration"))
    )
    out, rep = cleaning.clean(df)
    assert rep.negative_duration_dropped == 3 and out.height == 47
    assert out.get_column("flow_duration").min() >= 0  # type: ignore[operator]


def test_clean_day_caches_report(processed: Path, day_2017: DayInfo) -> None:
    rep = clean_day(day_2017, processed)
    report = day_path(day_2017, processed, "clean").with_suffix(".report.json")
    assert report.exists() and json.loads(report.read_text())["rows_out"] == rep.rows_out
    assert clean_day(day_2017, processed).as_dict() == rep.as_dict()  # served from cache


def test_profile_dir_streams_per_day(processed: Path) -> None:
    p = profile_dir(processed)
    assert p["rows"] == 403
    assert set(p["datasets"]) == {"cicids2017", "cseids2018"}
    d17 = p["datasets"]["cicids2017"]
    assert d17["days"][0]["duplicates"] == 1 and d17["days"][0]["rows_after_clean"] == 202
    assert d17["top_attack_ports"][0]["port"] in {21, 22}


def test_split_dir_per_day_with_cross_day_purge(tmp_path: Path) -> None:
    processed = tmp_path / "p"
    days = [d for d in DAYS if d.dataset.value == "cicids2017"][:2]
    frames = []
    for i, day in enumerate(days):
        df = make_canonical(n=30_000, days=(day.day,), seed=10 + i)
        frames.append(df)
    # make the last row of day 2 (which lands in its test fold) identical to a day-1 train row
    shared = frames[0].head(1).select(FLOW_FEATURES)
    last = frames[1].tail(1).with_columns([shared.get_column(f).alias(f) for f in FLOW_FEATURES])
    frames[1] = pl.concat([frames[1].head(frames[1].height - 1), last])
    for day, df in zip(days, frames, strict=True):
        dst = day_path(day, processed, "clean")
        dst.parent.mkdir(parents=True, exist_ok=True)
        df.write_parquet(dst)
    summary = split_dir(processed, SplitConfig())
    assert int(summary.get_column("purged_cross_day").sum()) == 1
    train = pl.read_parquet(processed / "splits" / Fold.TRAIN.value)
    test = pl.read_parquet(processed / "splits" / Fold.TEST.value)
    assert count_shared(train.get_column("row_hash"), test.get_column("row_hash")) == 0
    assert test.select(feature_hash().eq(pl.col("row_hash")).all()).item()
    assert int(summary.get_column("rows").sum()) == 59_999
    with pytest.raises(FileNotFoundError):
        split_dir(tmp_path / "empty")


# ---------------------------------------------------------------- CLI end to end


def test_cli_data_commands(raw_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from nids.cli import app

    root = tmp_path / "d"
    for name in ("cicids2017", "cseids2018"):
        shutil.copytree(raw_root / name, root / "raw" / name)
    monkeypatch.setenv("NIDS_DATA_ROOT", str(root))
    monkeypatch.setenv("NIDS_ARTIFACTS_ROOT", str(tmp_path / "art"))
    card = tmp_path / "CARD.md"
    card.write_text(
        "<!-- BEGIN MEASURED (generated by `nids data profile`; do not edit by hand) -->\n<!-- END MEASURED -->\n"
    )
    run = CliRunner().invoke
    assert run(app, ["--no-json-logs", "data", "canonicalise"]).exit_code == 0
    assert run(app, ["--no-json-logs", "data", "clean"]).exit_code == 0
    # tiny fixture files do not have the published row counts -> canonical validation fails
    assert run(app, ["--no-json-logs", "data", "validate"]).exit_code == 1
    assert run(app, ["--no-json-logs", "data", "validate", "--strict"]).exit_code == 0
    assert json.loads((tmp_path / "art" / "reports" / "validation_clean.json").read_text())[
        "passed"
    ]
    assert run(app, ["--no-json-logs", "data", "profile", "--card", str(card)]).exit_code == 0
    assert "Total canonical rows" in card.read_text()
    res = run(app, ["--no-json-logs", "data", "split"])
    assert res.exit_code == 0, res.output
    assert (tmp_path / "art" / "reports" / "split_summary.csv").exists()
