"""Schema, loaders, cleaning and validation tests (phase 2)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import polars as pl
import pytest

from nids.data import cleaning, validation
from nids.data.loaders import (
    CANONICAL_COLUMNS,
    canonical_path,
    canonicalise,
    canonicalise_all,
    load_canonical,
)
from nids.data.schema import (
    DAYS,
    DROPPED_2017,
    DROPPED_2018,
    FEATURE_SPECS,
    FEATURES,
    FLOW_FEATURES,
    LABEL_TO_CLASS,
    UNREPRODUCIBLE,
    Dataset,
    DayInfo,
    days_for,
    dst_port_bucket,
    normalise_label,
)


class TestSchema:
    def test_feature_count_and_uniqueness(self) -> None:
        assert len(FLOW_FEATURES) == 68
        assert len(set(FLOW_FEATURES)) == 68
        assert len(FEATURES) == 59
        assert not set(UNREPRODUCIBLE) & set(FEATURES) and set(UNREPRODUCIBLE) <= set(FLOW_FEATURES)
        assert len({s.cic2017 for s in FEATURE_SPECS}) == 68
        assert len({s.cse2018 for s in FEATURE_SPECS}) == 68

    def test_dropped_columns_not_in_specs(self) -> None:
        raw17 = {s.cic2017 for s in FEATURE_SPECS}
        raw18 = {s.cse2018 for s in FEATURE_SPECS}
        assert not (set(DROPPED_2017) - {"Fwd Header Length.1"}) & raw17
        assert not set(DROPPED_2018) & raw18

    @pytest.mark.parametrize(
        ("raw", "canon"),
        [
            ("BENIGN", "benign"),
            ("Benign", "benign"),
            ("DoS Hulk", "dos_hulk"),
            ("DoS attacks-Hulk", "dos_hulk"),
            ("Web Attack � Brute Force", "web_bruteforce"),
            ("Web Attack \x96 XSS", "web_xss"),
            ("Brute Force -XSS", "web_xss"),
            ("Web Attack � Sql Injection", "web_sqli"),
            ("SQL Injection", "web_sqli"),
            ("DDoS", "ddos_loic_http"),
            ("DDoS attacks-LOIC-HTTP", "ddos_loic_http"),
            ("DDOS attack-HOIC", "ddos_hoic"),
            ("DDOS attack-LOIC-UDP", "ddos_loic_udp"),
            ("FTP-Patator", "bruteforce_ftp"),
            ("FTP-BruteForce", "bruteforce_ftp"),
            ("SSH-Bruteforce", "bruteforce_ssh"),
            ("Infiltration", "infiltration"),
            ("Infilteration", "infiltration"),
            ("Bot", "botnet"),
            ("PortScan", "portscan"),
            ("Heartbleed", "heartbleed"),
            ("DoS Slowhttptest", "dos_slowhttptest"),
            ("DoS attacks-SlowHTTPTest", "dos_slowhttptest"),
            ("DoS slowloris", "dos_slowloris"),
            ("DoS GoldenEye", "dos_goldeneye"),
        ],
    )
    def test_normalise_label(self, raw: str, canon: str) -> None:
        assert normalise_label(raw) == canon
        assert canon in LABEL_TO_CLASS

    def test_unknown_label_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown label"):
            normalise_label("Zero Day")

    @pytest.mark.parametrize(
        ("port", "bucket"),
        [
            (0, 0),
            (80, 0),
            (1023, 0),
            (1024, 1),
            (49151, 1),
            (49152, 2),
            (65535, 2),
            (-1, 3),
            (70000, 3),
        ],
    )
    def test_dst_port_bucket(self, port: int, bucket: int) -> None:
        assert dst_port_bucket(port) == bucket

    def test_registry(self) -> None:
        assert len(days_for(Dataset.CIC2017)) == 8
        assert len(days_for(Dataset.CSE2018)) == 6
        assert len({d.day for d in DAYS}) == len(DAYS)
        for d in DAYS:
            for a in d.attacks:
                assert a in LABEL_TO_CLASS


class TestLoaders:
    def test_canonicalise_2017(self, raw_root: Path, day_2017: DayInfo) -> None:
        df = canonicalise(day_2017, raw_root)
        assert df.columns == list(CANONICAL_COLUMNS)
        assert df.height == 203
        assert set(df.get_column("label").unique()) == {
            "benign",
            "bruteforce_ftp",
            "bruteforce_ssh",
            "web_bruteforce",
        }
        assert df.filter(pl.col("label") == "web_bruteforce").height == 1
        assert df.get_column("protocol").null_count() == df.height  # not in 2017 CSVs
        assert df.get_column("timestamp").null_count() == df.height
        assert df.select(pl.col("flow_byts_s").is_infinite().sum()).item() == 1
        assert df.get_column("dataset").unique().to_list() == ["cicids2017"]
        assert df.get_column("label_reliable").all()
        for f in FLOW_FEATURES:
            assert df.schema[f] == pl.Float64

    def test_canonicalise_2018_removes_embedded_header(
        self, raw_root: Path, day_2018: DayInfo
    ) -> None:
        df = canonicalise(day_2018, raw_root)
        assert df.height == 200
        assert df.get_column("protocol").unique().to_list() == [6]
        assert df.get_column("timestamp").null_count() == 0
        assert df.get_column("timestamp").min() == datetime(2018, 2, 14, 8, 0, 0)
        assert df.select(pl.col("dst_port_bucket").is_in([0, 1, 2, 3]).all()).item()

    def test_2018_twelve_hour_clock_is_corrected(self) -> None:
        from nids.data.loaders import timestamp_expr

        raw = pl.DataFrame(
            {
                "timestamp": [
                    "14/02/2018 08:30:00",
                    "14/02/2018 12:10:31",
                    "14/02/2018 02:01:50 ",
                    "x",
                ]
            }
        )
        got = raw.select(timestamp_expr(Dataset.CSE2018)).to_series().to_list()
        assert got == [
            datetime(2018, 2, 14, 8, 30),
            datetime(2018, 2, 14, 12, 10, 31),
            datetime(2018, 2, 14, 14, 1, 50),
            None,
        ]
        plain = raw.select(timestamp_expr(Dataset.CIC2017)).to_series().to_list()
        assert plain[2] == datetime(2018, 2, 14, 2, 1, 50)

    def test_missing_file_raises(self, tmp_path: Path, day_2017: DayInfo) -> None:
        with pytest.raises(FileNotFoundError):
            canonicalise(day_2017, tmp_path)

    def test_canonicalise_all_and_load(self, raw_root: Path, tmp_path: Path) -> None:
        out = tmp_path / "processed"
        written = canonicalise_all(raw_root, out)
        assert len(written) == 2
        both = load_canonical(out)
        assert both.height == 403
        only17 = load_canonical(out, datasets=(Dataset.CIC2017,))
        assert only17.get_column("dataset").unique().to_list() == ["cicids2017"]
        byday = load_canonical(out, days=("2018-02-14-wed",))
        assert byday.height == 200
        with pytest.raises(FileNotFoundError):
            load_canonical(tmp_path / "nothing")
        day = next(d for d in DAYS if d.day == "2018-02-14-wed")
        assert canonical_path(day, out).exists()


class TestCleaning:
    def test_clean_pipeline(self, raw_root: Path, day_2017: DayInfo) -> None:
        df = canonicalise(day_2017, raw_root)
        out, rep = cleaning.clean(df)
        assert rep.rows_in == 203
        assert rep.inf_replaced == 1
        assert rep.nulls_imputed == 1
        assert rep.duplicates_dropped == 1
        assert rep.rows_out == 202
        assert out.select(pl.col("flow_byts_s").is_infinite().sum()).item() == 0
        assert rep.per_day["2017-07-04-tue"]["rows"] == 202
        assert "rows_out" in rep.as_dict()

    def test_negative_duration_dropped(self, canonical_df: pl.DataFrame) -> None:
        df = canonical_df.with_columns(
            flow_duration=pl.when(pl.col("row_id") < 5)
            .then(-1.0)
            .otherwise(pl.col("flow_duration"))
        )
        out, n = cleaning.drop_negative_duration(df)
        assert n == 10  # 5 per day, two days
        assert out.height == df.height - 10

    def test_clip_negatives(self, canonical_df: pl.DataFrame) -> None:
        df = canonical_df.with_columns(
            fwd_seg_size_min=pl.when(pl.col("row_id") < 3)
            .then(-5.0)
            .otherwise(pl.col("fwd_seg_size_min")),
            init_fwd_win_byts=pl.lit(-1.0),  # legitimately negative (window not seen)
        )
        out, n = cleaning.clip_negatives(df)
        assert n == 6
        assert out.get_column("fwd_seg_size_min").min() == 0.0
        assert out.get_column("init_fwd_win_byts").min() == -1.0
        _, rep = cleaning.clean(df)
        assert rep.negatives_clipped == 6

    def test_impute_uses_given_medians(self, canonical_df: pl.DataFrame) -> None:
        df = canonical_df.with_columns(
            flow_pkts_s=pl.when(pl.col("row_id") == 0).then(None).otherwise(pl.col("flow_pkts_s"))
        )
        out, n, fitted = cleaning.impute_nulls(df, {"flow_pkts_s": 42.0})
        assert n == 2
        assert fitted["flow_pkts_s"] == 42.0
        assert out.filter(pl.col("row_id") == 0).get_column("flow_pkts_s").to_list() == [42.0, 42.0]

    def test_unreliable_counted(self, canonical_df: pl.DataFrame) -> None:
        df = canonical_df.with_columns(label_reliable=pl.col("day") == "d1")
        _, rep = cleaning.clean(df)
        assert rep.unreliable_label_rows == 1000


class TestValidation:
    def test_raw_canonical_passes_with_inf_allowed(self, raw_root: Path, day_2017: DayInfo) -> None:
        df = canonicalise(day_2017, raw_root)
        rep = validation.validate_canonical(df, allow_inf=True)
        names = {e.name for e in rep.expectations}
        assert {"columns_match_schema", "labels_in_taxonomy", "duplicate_fraction_bounded"} <= names
        failed = {e.name for e in rep.failures}
        # the tiny fixture does not have the published row count
        assert failed <= {"row_counts_match_published"}

    def test_cleaned_passes_strict(self, raw_root: Path, day_2017: DayInfo) -> None:
        df, _ = cleaning.clean(canonicalise(day_2017, raw_root))
        rep = validation.validate_canonical(df, allow_inf=False)
        assert {e.name for e in rep.failures} <= {"row_counts_match_published"}

    def test_detects_problems(self, canonical_df: pl.DataFrame, tmp_path: Path) -> None:
        bad = canonical_df.with_columns(
            tot_fwd_pkts=pl.lit(-1.0),
            label=pl.lit("zero_day"),
            dst_port=pl.lit(70000, dtype=pl.Int64),
        ).drop("idle_min")
        rep = validation.validate_canonical(bad, allow_inf=False)
        failed = {e.name for e in rep.failures}
        assert {
            "columns_match_schema",
            "labels_in_taxonomy",
            "is_attack_consistent",
            "dst_port_in_range",
            "nonnegative_features",
        } <= failed
        assert not rep.passed
        p = tmp_path / "r" / "report.json"
        rep.write(p)
        assert p.exists() and "nonnegative_features" in p.read_text()

    def test_ge_suite_export(self, tmp_path: Path) -> None:
        p = validation.write_ge_suite(tmp_path / "suite.json")
        suite = validation.ge_suite()
        assert p.exists()
        types = {e["type"] for e in suite["expectations"]}
        assert "expect_column_values_to_be_between" in types
        assert any(e["kwargs"].get("column") == "flow_duration" for e in suite["expectations"])


@pytest.mark.realdata
@pytest.mark.slow
def test_real_tuesday_matches_published_counts() -> None:
    raw = Path("data/raw")
    day = next(d for d in DAYS if d.day == "2017-07-04-tue")
    if not (raw / day.dataset.value / day.filename).exists():
        pytest.skip("real data not downloaded")
    df = canonicalise(day, raw)
    assert df.height == 445_909
    counts = dict(df.group_by("label").len().iter_rows())
    assert counts == {"benign": 432_074, "bruteforce_ftp": 7_938, "bruteforce_ssh": 5_897}
    rep = validation.validate_canonical(df)
    assert rep.passed, rep.failures
