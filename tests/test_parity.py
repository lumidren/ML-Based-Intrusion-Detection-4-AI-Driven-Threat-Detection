"""Parity comparison (extractor output vs. published rows) and streamed extraction."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import polars as pl

from nids.data.schema import FLOW_FEATURES
from nids.features import synth
from nids.features.parity import COMPARED, KEY_FEATURES, compare, to_markdown
from nids.features.pcap import extract_flows, extract_flows_to_parquet


def _pair(tmp_path: Path) -> tuple[pl.DataFrame, pl.DataFrame]:
    """Extract real flows from a synthetic capture and build 'published' rows from them."""
    pkts = synth.benign_web(1_518_611_000.0, ["192.168.1.2"], "10.0.0.7", n=6, seed=7)
    path = tmp_path / "p.pcap"
    synth.write_pcap(path, pkts)
    ours = extract_flows(path)
    published = ours.with_columns(
        timestamp=(pl.from_epoch(pl.col("start_us"), time_unit="us") - timedelta(hours=4)),
        label=pl.lit("benign"),
    ).drop("start_us", "end_us")
    return ours, published


def test_identical_rows_agree_on_every_feature(tmp_path: Path) -> None:
    ours, published = _pair(tmp_path)
    s = compare(ours.lazy(), published.lazy())
    assert s["flows_extracted"] == ours.height == s["flows_matched"]
    assert s["match_rate"] == 1.0 and s["matched_labels"] == {"benign": ours.height}
    assert s["features_compared"] == len(FLOW_FEATURES)
    assert s["features_fully_agreeing"] == len(FLOW_FEATURES)
    assert s["model_inputs_fully_agreeing"] == s["model_inputs_compared"] == 58
    assert "`syn_flag_cnt` (excluded)" in to_markdown(s, "t")
    assert set(KEY_FEATURES) | set(COMPARED) == set(FLOW_FEATURES)


def test_disagreements_are_measured(tmp_path: Path) -> None:
    ours, published = _pair(tmp_path)
    off = published.with_columns(
        pkt_len_mean=pl.col("pkt_len_mean") * 1.5 + 10,  # outside 0.1%
        flow_iat_max=pl.col("flow_iat_max") + 0.5,  # within 1 us
        idle_mean=pl.lit(float("inf")),
    )
    s = compare(ours.lazy(), off.lazy())
    pf = s["per_feature"]
    assert pf["pkt_len_mean"]["agreement"] == 0.0 and pf["pkt_len_mean"]["max_abs_diff"] > 0
    assert pf["flow_iat_max"]["agreement"] == 1.0
    assert pf["idle_mean"]["agreement"] == 0.0 and pf["idle_mean"]["max_abs_diff"] == 0.0
    assert s["features_fully_agreeing"] == len(FLOW_FEATURES) - 2
    md = to_markdown(s, "title")
    assert md.index("`idle_mean`") < md.index("`syn_flag_cnt`")  # worst first


def test_rows_outside_window_or_key_do_not_match(tmp_path: Path) -> None:
    ours, published = _pair(tmp_path)
    shifted = published.with_columns(pl.col("timestamp") + timedelta(hours=1))
    assert compare(ours.lazy(), shifted.lazy())["flows_matched"] == 0
    s = compare(ours.lazy(), published.with_columns(pl.col("dst_port") + 1000).lazy())
    assert s["flows_matched"] == 0 and s["per_feature"]["tot_fwd_pkts"]["agreement"] == 0.0
    assert "none" in to_markdown(s, "t")
    assert datetime(2018, 2, 14) < published.get_column("timestamp").min()  # type: ignore[operator]


def test_extract_to_parquet_parts(tmp_path: Path) -> None:
    pkts = synth.benign_web(0.0, ["192.168.1.2"], "10.0.0.7", n=5, seed=1)
    path = tmp_path / "x.pcap"
    synth.write_pcap(path, pkts)
    out = tmp_path / "parts"
    out.mkdir()
    (out / "part-99999.parquet").write_bytes(b"stale")
    n = extract_flows_to_parquet(path, out, batch=3)
    files = sorted(out.glob("part-*.parquet"))
    assert n == 10 and len(files) == 4
    assert pl.read_parquet(files).equals(extract_flows(path))
    empty = tmp_path / "empty.pcap"
    synth.write_pcap(empty, [])
    assert extract_flows_to_parquet(empty, tmp_path / "e") == 0
    assert pl.read_parquet(tmp_path / "e" / "part-00000.parquet").height == 0


def test_same_key_flows_are_paired_by_duration_rank(tmp_path: Path) -> None:
    ours, published = _pair(tmp_path)
    twin = ours.head(1).with_columns(pl.col("flow_duration") + 100.0)
    twin_pub = published.head(1).with_columns(pl.col("flow_duration") + 100.0)
    ours2 = pl.concat([twin, ours])  # the twin first on our side ...
    pub2 = pl.concat([published, twin_pub])  # ... and last on the published side
    s = compare(ours2.lazy(), pub2.lazy())
    assert s["flows_matched"] == ours2.height
    assert s["flows_matched_unambiguous"] == ours.height - 1
    assert s["per_feature"]["flow_duration"]["agreement"] == 1.0
    assert s["per_feature"]["flow_duration"]["agreement_unambiguous"] == 1.0
    assert "unambiguous" in to_markdown(s, "t")
