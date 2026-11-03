"""Offline PCAP -> flow features (used for replay validation, parity tests and batch scoring)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import dpkt
import polars as pl

from nids.data.schema import FLOW_FEATURES
from nids.features.flow import FlowBuilder, FlowRecord
from nids.features.packets import PacketInfo, decode_bytes

FLOW_META_COLUMNS: tuple[str, ...] = (
    "flow_id",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "start_us",
    "end_us",
)


def iter_packets(path: Path, limit: int | None = None) -> Iterator[PacketInfo]:
    """Yield decoded IPv4 packets from a pcap/pcapng file in capture order."""
    with path.open("rb") as fh:
        magic = fh.read(4)
        fh.seek(0)
        reader = dpkt.pcapng.Reader(fh) if magic == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(fh)
        linktype = reader.datalink()
        n = 0
        for ts, buf in reader:
            p = decode_bytes(ts, buf, linktype)
            if p is not None:
                yield p
                n += 1
                if limit is not None and n >= limit:
                    return


def iter_flows(
    path: Path, builder: FlowBuilder | None = None, limit: int | None = None
) -> Iterator[FlowRecord]:
    """Stream finished flows from a capture file (flushes open flows at the end)."""
    b = builder or FlowBuilder()
    for p in iter_packets(path, limit):
        yield from b.add_packet(p)
    yield from b.flush()


def records_to_frame(records: list[FlowRecord]) -> pl.DataFrame:
    """Flow records -> typed frame with metadata, 68 features and ``dst_port_bucket``."""
    if not records:
        schema: dict[str, pl.DataType] = {
            "flow_id": pl.Utf8(),
            "src_ip": pl.Utf8(),
            "src_port": pl.Int64(),
            "dst_ip": pl.Utf8(),
            "dst_port": pl.Int64(),
            "protocol": pl.Int64(),
            "start_us": pl.Int64(),
            "end_us": pl.Int64(),
            **{f: pl.Float64() for f in FLOW_FEATURES},
            "dst_port_bucket": pl.Int64(),
        }
        return pl.DataFrame(schema=schema)
    df = pl.DataFrame([r.to_row() for r in records])
    return df.with_columns(
        [pl.col(f).cast(pl.Float64) for f in FLOW_FEATURES]
        + [
            pl.col(c).cast(pl.Int64)
            for c in ("src_port", "dst_port", "protocol", "start_us", "end_us", "dst_port_bucket")
        ]
    ).select([*FLOW_META_COLUMNS, *FLOW_FEATURES, "dst_port_bucket"])


def extract_flows(
    path: Path,
    compat: bool = True,
    limit: int | None = None,
    flow_timeout_us: int = 120_000_000,
    activity_timeout_us: int = 5_000_000,
) -> pl.DataFrame:
    """Extract all flows of a capture into a frame (convenience wrapper)."""
    builder = FlowBuilder(flow_timeout_us, activity_timeout_us, compat=compat)
    return records_to_frame(list(iter_flows(path, builder, limit)))
