"""Shared fixtures: tiny raw CSVs in both datasets' dialects and synthetic canonical frames."""

from __future__ import annotations

import random
from pathlib import Path

import numpy as np
import polars as pl
import pytest

from nids.data.schema import DAYS, FEATURE_SPECS, FLOW_FEATURES, META_COLUMNS, Dataset, DayInfo

RNG_SEED = 1234


def _raw_row_2017(rng: random.Random, label: str, port: int) -> list[str]:
    vals: list[str] = [str(port)]
    for spec in FEATURE_SPECS:
        v = rng.randint(0, 1000) if spec.kind in {"count", "bytes", "flag"} else rng.random() * 1e4
        if spec.name == "fwd_header_len":
            fwd_header = v
        vals.append(str(v))
    _fix_max_min(vals, 6, 7)
    return _reorder_2017(vals, label, fwd_header)


def _fix_max_min(row: list[str], i_max: int, i_min: int) -> None:
    """Keep the synthetic row internally consistent (max >= min)."""
    hi, lo = float(row[i_max]), float(row[i_min])
    if hi < lo:
        row[i_max], row[i_min] = row[i_min], row[i_max]


def _reorder_2017(vals: list[str], label: str, fwd_header: float) -> list[str]:
    """Build the 79-column CIC-IDS2017 row from (dst_port, 68 canonical features)."""
    by_name = dict(zip(["dst_port", *FLOW_FEATURES], vals, strict=True))
    layout = [
        " Destination Port",
        " Flow Duration",
        " Total Fwd Packets",
        " Total Backward Packets",
        "Total Length of Fwd Packets",
        " Total Length of Bwd Packets",
        " Fwd Packet Length Max",
        " Fwd Packet Length Min",
        " Fwd Packet Length Mean",
        " Fwd Packet Length Std",
        "Bwd Packet Length Max",
        " Bwd Packet Length Min",
        " Bwd Packet Length Mean",
        " Bwd Packet Length Std",
        "Flow Bytes/s",
        " Flow Packets/s",
        " Flow IAT Mean",
        " Flow IAT Std",
        " Flow IAT Max",
        " Flow IAT Min",
        "Fwd IAT Total",
        " Fwd IAT Mean",
        " Fwd IAT Std",
        " Fwd IAT Max",
        " Fwd IAT Min",
        "Bwd IAT Total",
        " Bwd IAT Mean",
        " Bwd IAT Std",
        " Bwd IAT Max",
        " Bwd IAT Min",
        "Fwd PSH Flags",
        " Bwd PSH Flags",
        " Fwd URG Flags",
        " Bwd URG Flags",
        " Fwd Header Length",
        " Bwd Header Length",
        "Fwd Packets/s",
        " Bwd Packets/s",
        " Min Packet Length",
        " Max Packet Length",
        " Packet Length Mean",
        " Packet Length Std",
        " Packet Length Variance",
        "FIN Flag Count",
        " SYN Flag Count",
        " RST Flag Count",
        " PSH Flag Count",
        " ACK Flag Count",
        " URG Flag Count",
        " CWE Flag Count",
        " ECE Flag Count",
        " Down/Up Ratio",
        " Average Packet Size",
        " Avg Fwd Segment Size",
        " Avg Bwd Segment Size",
        " Fwd Header Length",
        "Fwd Avg Bytes/Bulk",
        " Fwd Avg Packets/Bulk",
        " Fwd Avg Bulk Rate",
        " Bwd Avg Bytes/Bulk",
        " Bwd Avg Packets/Bulk",
        "Bwd Avg Bulk Rate",
        "Subflow Fwd Packets",
        " Subflow Fwd Bytes",
        " Subflow Bwd Packets",
        " Subflow Bwd Bytes",
        "Init_Win_bytes_forward",
        " Init_Win_bytes_backward",
        " act_data_pkt_fwd",
        " min_seg_size_forward",
        "Active Mean",
        " Active Std",
        " Active Max",
        " Active Min",
        "Idle Mean",
        " Idle Std",
        " Idle Max",
        " Idle Min",
        " Label",
    ]
    raw2canon = {s.cic2017: s.name for s in FEATURE_SPECS}
    row = []
    for col in layout:
        c = col.strip()
        if c == "Destination Port":
            row.append(by_name["dst_port"])
        elif c == "Label":
            row.append(label)
        elif c in raw2canon:
            row.append(by_name[raw2canon[c]])
        else:  # dropped (constant-zero) columns
            row.append("0")
    return row


HEADER_2017 = (
    " Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets,Total Length of Fwd Packets,"
    " Total Length of Bwd Packets, Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean,"
    " Fwd Packet Length Std,Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean,"
    " Bwd Packet Length Std,Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max,"
    " Flow IAT Min,Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min,Bwd IAT Total,"
    " Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min,Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags,"
    " Bwd URG Flags, Fwd Header Length, Bwd Header Length,Fwd Packets/s, Bwd Packets/s, Min Packet Length,"
    " Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance,FIN Flag Count,"
    " SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, CWE Flag Count,"
    " ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size,"
    " Fwd Header Length,Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk,"
    " Bwd Avg Packets/Bulk,Bwd Avg Bulk Rate,Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets,"
    " Subflow Bwd Bytes,Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd,"
    " min_seg_size_forward,Active Mean, Active Std, Active Max, Active Min,Idle Mean, Idle Std, Idle Max,"
    " Idle Min, Label"
)

HEADER_2018 = (
    "Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,TotLen Bwd Pkts,"
    "Fwd Pkt Len Max,Fwd Pkt Len Min,Fwd Pkt Len Mean,Fwd Pkt Len Std,Bwd Pkt Len Max,Bwd Pkt Len Min,"
    "Bwd Pkt Len Mean,Bwd Pkt Len Std,Flow Byts/s,Flow Pkts/s,Flow IAT Mean,Flow IAT Std,Flow IAT Max,"
    "Flow IAT Min,Fwd IAT Tot,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,Bwd IAT Tot,Bwd IAT Mean,"
    "Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,"
    "Fwd Header Len,Bwd Header Len,Fwd Pkts/s,Bwd Pkts/s,Pkt Len Min,Pkt Len Max,Pkt Len Mean,Pkt Len Std,"
    "Pkt Len Var,FIN Flag Cnt,SYN Flag Cnt,RST Flag Cnt,PSH Flag Cnt,ACK Flag Cnt,URG Flag Cnt,"
    "CWE Flag Count,ECE Flag Cnt,Down/Up Ratio,Pkt Size Avg,Fwd Seg Size Avg,Bwd Seg Size Avg,"
    "Fwd Byts/b Avg,Fwd Pkts/b Avg,Fwd Blk Rate Avg,Bwd Byts/b Avg,Bwd Pkts/b Avg,Bwd Blk Rate Avg,"
    "Subflow Fwd Pkts,Subflow Fwd Byts,Subflow Bwd Pkts,Subflow Bwd Byts,Init Fwd Win Byts,"
    "Init Bwd Win Byts,Fwd Act Data Pkts,Fwd Seg Size Min,Active Mean,Active Std,Active Max,Active Min,"
    "Idle Mean,Idle Std,Idle Max,Idle Min,Label"
)


def _row_2018(rng: random.Random, label: str, port: int, ts: str) -> list[str]:
    cols = HEADER_2018.split(",")
    raw2canon = {s.cse2018: s.name for s in FEATURE_SPECS}
    row = []
    for c in cols:
        if c == "Dst Port":
            row.append(str(port))
        elif c == "Protocol":
            row.append("6")
        elif c == "Timestamp":
            row.append(ts)
        elif c == "Label":
            row.append(label)
        elif c in raw2canon:
            spec = next(s for s in FEATURE_SPECS if s.name == raw2canon[c])
            v = (
                rng.randint(1, 1000)
                if spec.kind in {"count", "bytes", "flag"}
                else rng.random() * 1e4
            )
            row.append(str(v))
        else:
            row.append("0")
    _fix_max_min(row, cols.index("Fwd Pkt Len Max"), cols.index("Fwd Pkt Len Min"))
    return row


@pytest.fixture
def raw_root(tmp_path: Path) -> Path:
    """Raw directory with one tiny file per dataset, in the registry's filenames."""
    rng = random.Random(RNG_SEED)
    d17 = tmp_path / "cicids2017"
    d18 = tmp_path / "cseids2018"
    d17.mkdir()
    d18.mkdir()
    tue = next(d for d in DAYS if d.day == "2017-07-04-tue")
    lines = [HEADER_2017]
    for i in range(200):
        label = "BENIGN" if i % 4 else ("FTP-Patator" if i % 8 else "SSH-Patator")
        lines.append(
            ",".join(
                _raw_row_2017(rng, label, 21 if "FTP" in label else 22 if "SSH" in label else 443)
            )
        )
    # label-encoding glitch and an Infinity + duplicate row
    glitch = _raw_row_2017(rng, "Web Attack – Brute Force", 80)  # noqa: RUF001 - cp1252 0x96
    lines.append(",".join(glitch))
    inf_row = _raw_row_2017(rng, "BENIGN", 53)
    inf_row[14] = "Infinity"
    lines.append(",".join(inf_row))
    lines.append(lines[1])  # exact duplicate of first data row
    (d17 / tue.filename).write_bytes(("\n".join(lines) + "\n").encode("cp1252"))

    wed = next(d for d in DAYS if d.day == "2018-02-14-wed")
    lines = [HEADER_2018]
    for i in range(200):
        label = "Benign" if i % 4 else ("FTP-BruteForce" if i % 8 else "SSH-Bruteforce")
        ts = f"14/02/2018 {8 + i // 60:02d}:{i % 60:02d}:00"
        lines.append(
            ",".join(
                _row_2018(rng, label, 21 if "FTP" in label else 22 if "SSH" in label else 443, ts)
            )
        )
        if i == 100:
            lines.append(HEADER_2018)  # embedded repeated header
    (d18 / wed.filename).write_text("\n".join(lines) + "\n")
    return tmp_path


def make_canonical(
    n: int = 1000,
    days: tuple[str, ...] = ("d1", "d2"),
    attack_frac: float = 0.2,
    seed: int = RNG_SEED,
    with_ts: bool = False,
    dataset: str = "cicids2017",
) -> pl.DataFrame:
    """Synthetic canonical frame with separable attack/benign distributions."""
    rng = np.random.default_rng(seed)
    frames = []
    for day in days:
        is_attack = rng.random(n) < attack_frac
        feats = {}
        for spec in FEATURE_SPECS:
            base = rng.gamma(2.0, 100.0, n)
            shift = np.where(is_attack, 3.0, 1.0) if spec.kind in {"count", "rate", "flag"} else 1.0
            feats[spec.name] = (base * shift).astype(np.float64)
        label = np.where(is_attack, "bruteforce_ssh", "benign")
        ts = (
            pl.datetime_range(
                pl.datetime(2018, 2, 14, 8),
                pl.datetime(2018, 2, 14, 8) + pl.duration(seconds=n - 1),
                "1s",
                eager=True,
            )
            if with_ts
            else pl.Series([None] * n, dtype=pl.Datetime("us"))
        )
        df = pl.DataFrame(
            {
                "dataset": [dataset] * n,
                "day": [day] * n,
                "row_id": np.arange(n, dtype=np.int64),
                "timestamp": ts,
                "src_ip": [None] * n,
                "src_port": pl.Series([None] * n, dtype=pl.Int64),
                "dst_ip": [None] * n,
                "dst_port": np.where(is_attack, 22, 443).astype(np.int64),
                "protocol": pl.Series([6] * n, dtype=pl.Int64),
                "label_raw": label,
                "label": label,
                "attack_class": np.where(is_attack, "bruteforce", "benign"),
                "is_attack": is_attack,
                "label_reliable": [True] * n,
                **feats,
                "dst_port_bucket": pl.Series([0] * n, dtype=pl.Int64),
            }
        )
        frames.append(df.select([*META_COLUMNS, *FLOW_FEATURES, "dst_port_bucket"]))
    return pl.concat(frames)


@pytest.fixture
def canonical_df() -> pl.DataFrame:
    return make_canonical()


@pytest.fixture
def day_2017() -> DayInfo:
    return next(d for d in DAYS if d.dataset is Dataset.CIC2017 and d.day == "2017-07-04-tue")


@pytest.fixture
def day_2018() -> DayInfo:
    return next(d for d in DAYS if d.dataset is Dataset.CSE2018 and d.day == "2018-02-14-wed")
