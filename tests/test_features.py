"""Feature extractor tests: decoder parity, analytic flow statistics, CICFlowMeter quirks."""

from __future__ import annotations

import math
from pathlib import Path

import dpkt
import polars as pl
import pytest
from scapy.layers.inet import IP, TCP

from nids.data.schema import FLOW_FEATURES
from nids.features import synth
from nids.features.flow import (
    DEFAULT_ACTIVITY_TIMEOUT_US,
    FlowBuilder,
    FlowRecord,
    FlowState,
    _Stats,
    flow_key,
)
from nids.features.packets import (
    LINKTYPE_LINUX_SLL,
    LINKTYPE_RAW,
    TCP_ACK,
    TCP_FIN,
    TCP_SYN,
    PacketInfo,
    decode_bytes,
    decode_scapy,
)
from nids.features.pcap import extract_flows, iter_flows, iter_packets, records_to_frame

A, B = "10.0.0.1", "10.0.0.2"


def pkt(
    ts_us: int,
    src: str = A,
    dst: str = B,
    sport: int = 1234,
    dport: int = 80,
    proto: int = 6,
    payload: int = 0,
    header: int = 20,
    flags: int = TCP_ACK,
    window: int = 1000,
) -> PacketInfo:
    return PacketInfo(ts_us, src, dst, sport, dport, proto, payload, header, flags, window)


def rev(p: PacketInfo, ts_us: int, **kw: int) -> PacketInfo:
    d = {"payload": 0, "header": 20, "flags": TCP_ACK, "window": 2000}
    d.update(kw)
    return PacketInfo(
        ts_us,
        p.dst,
        p.src,
        p.dport,
        p.sport,
        p.proto,
        d["payload"],
        d["header"],
        d["flags"],
        d["window"],
    )


# ---------------------------------------------------------------- statistics helper


def test_stats_sample_std_and_empty() -> None:
    s = _Stats()
    assert s.mean == 0 and s.std == 0 and s.minimum == 0 and s.maximum == 0
    for v in (300, 329, 300):
        s.add(v)
    assert s.mean == pytest.approx(309.6667, abs=1e-3)
    assert s.var == pytest.approx(280.3333, abs=1e-3)
    assert s.std == pytest.approx(math.sqrt(280.3333), abs=1e-3)
    one = _Stats()
    one.add(5)
    assert one.var == 0.0


# ---------------------------------------------------------------- decoders


def _frame(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    payload: bytes,
    flags: int = dpkt.tcp.TH_ACK,
    win: int = 512,
    pad: int = 0,
) -> bytes:
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, win=win, data=payload)
    ip = dpkt.ip.IP(
        src=bytes(map(int, src.split("."))),
        dst=bytes(map(int, dst.split("."))),
        p=dpkt.ip.IP_PROTO_TCP,
        data=tcp,
    )
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    return bytes(eth) + b"\x00" * pad


def test_decode_bytes_tcp_ignores_ethernet_padding() -> None:
    p = decode_bytes(1.5, _frame(A, B, 1111, 80, b"abc", pad=10))
    assert p is not None
    assert (p.src, p.dst, p.sport, p.dport, p.proto) == (A, B, 1111, 80, 6)
    assert p.payload_len == 3 and p.header_len == 20 and p.window == 512 and p.ts_us == 1_500_000
    assert p.has(TCP_ACK) and not p.has(TCP_SYN) and p.is_tcp


def test_decode_bytes_udp_other_and_garbage() -> None:
    udp = dpkt.udp.UDP(sport=53, dport=5353, data=b"q" * 12)
    udp.ulen = 8 + 12
    ip = dpkt.ip.IP(
        src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02", p=dpkt.ip.IP_PROTO_UDP, data=udp
    )
    ip.len = len(ip)
    p = decode_bytes(2.0, bytes(ip), LINKTYPE_RAW)
    assert (
        p is not None
        and p.proto == 17
        and p.payload_len == 12
        and p.header_len == 8
        and p.window == -1
    )
    icmp = dpkt.ip.IP(
        src=b"\x0a\x00\x00\x01",
        dst=b"\x0a\x00\x00\x02",
        p=dpkt.ip.IP_PROTO_ICMP,
        data=dpkt.icmp.ICMP(type=8, code=0, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"ping")),
    )
    icmp.len = len(icmp)
    q = decode_bytes(2.0, bytes(icmp), LINKTYPE_RAW)
    assert q is not None and (q.proto, q.sport, q.dport, q.payload_len, q.header_len) == (
        0,
        0,
        0,
        0,
        0,
    )
    assert decode_bytes(0.0, b"\x00\x01", 1) is None
    arp = dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_ARP, data=b"\x00" * 28)
    assert decode_bytes(0.0, bytes(arp), 1) is None
    sll = dpkt.sll.SLL(ethtype=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    r = decode_bytes(3.0, bytes(sll), LINKTYPE_LINUX_SLL)
    assert r is not None and r.proto == 17
    assert decode_bytes(0.0, b"\x00" * 40, 999) is None


def test_decoder_parity_scapy_vs_dpkt() -> None:
    pkts = synth.tcp_session(100.0, A, B, 4321, 22, [("c", 40), ("s", 70)])
    pkts += synth.udp_exchange(101.0, A, B, 5000, 53, [("c", 30), ("s", 90)])
    for sp in pkts:
        via_scapy = decode_scapy(sp)
        via_dpkt = decode_bytes(float(sp.time), bytes(sp), 1)
        assert via_scapy == via_dpkt, (via_scapy, via_dpkt)
    assert decode_scapy(IP(dst=B) / TCP()) is not None
    from scapy.layers.l2 import ARP

    assert decode_scapy(ARP()) is None


# ---------------------------------------------------------------- flow key / state


def test_flow_key_is_direction_independent() -> None:
    p = pkt(0)
    assert flow_key(p) == flow_key(rev(p, 1))
    assert flow_key(p) != flow_key(pkt(0, dport=81))


def test_two_packet_flow_matches_cicflowmeter_quirks() -> None:
    """1 fwd (300 B) + 1 bwd (329 B): the published CSV shows mean 309.67, var 280.33, avg 464.5."""
    b = FlowBuilder()
    p1 = pkt(0, proto=17, payload=300, header=8, flags=0, window=-1, sport=5000, dport=53)
    assert b.add_packet(p1) == []
    assert b.add_packet(rev(p1, 676, payload=329, header=8, flags=0, window=-1)) == []
    (rec,) = b.flush()
    f = rec.features
    assert f["flow_duration"] == 676
    assert f["tot_fwd_pkts"] == 1 and f["tot_bwd_pkts"] == 1
    assert f["totlen_fwd_pkts"] == 300 and f["totlen_bwd_pkts"] == 329
    assert f["pkt_len_mean"] == pytest.approx(309.6667, abs=1e-3)
    assert f["pkt_len_var"] == pytest.approx(280.3333, abs=1e-3)
    assert f["pkt_size_avg"] == pytest.approx(464.5)
    assert f["fwd_pkt_len_mean"] == 300 and f["bwd_pkt_len_mean"] == 329
    assert f["flow_iat_mean"] == 676 and f["fwd_iat_tot"] == 0 and f["bwd_iat_tot"] == 0
    assert f["fwd_header_len"] == 8 and f["bwd_header_len"] == 8 and f["fwd_seg_size_min"] == 0
    assert f["init_fwd_win_byts"] == -1 and f["init_bwd_win_byts"] == -1
    assert f["flow_byts_s"] == pytest.approx(629 / 676e-6)
    assert f["flow_pkts_s"] == pytest.approx(2 / 676e-6)
    assert f["down_up_ratio"] == 1 and f["subflow_fwd_pkts"] == 1 and f["subflow_bwd_byts"] == 329
    assert f["active_mean"] == 0 and f["idle_mean"] == 0
    assert tuple(f) == FLOW_FEATURES
    assert rec.flow_id == f"{A}-{B}-5000-53-17" and rec.to_row()["dst_port_bucket"] == 0


def test_tcp_session_fin_terminates_in_compat_and_full_close_in_corrected() -> None:
    pkts = synth.to_packet_infos(
        synth.tcp_session(10.0, A, B, 4000, 80, [("c", 100), ("s", 1000), ("s", 500)])
    )
    assert len(pkts) == 9
    compat = FlowBuilder(compat=True)
    recs: list[FlowRecord] = []
    for p in pkts:
        recs.extend(compat.add_packet(p))
    assert len(recs) == 1  # ended on the first FIN (packet 7)
    f = recs[0].features
    assert f["tot_fwd_pkts"] == 4 and f["tot_bwd_pkts"] == 3
    assert (
        f["fin_flag_cnt"] == 1
        and f["syn_flag_cnt"] == 1
        and f["psh_flag_cnt"] == 1
        and f["ack_flag_cnt"] == 1
    )
    assert f["fwd_psh_flags"] == 1  # Q5: equals SYN indicator in compat mode
    assert (
        f["fwd_act_data_pkts"] == 1
        and f["init_fwd_win_byts"] == 29200
        and f["init_bwd_win_byts"] == 29200
    )
    assert f["totlen_fwd_pkts"] == 100 and f["totlen_bwd_pkts"] == 1500
    assert f["fwd_seg_size_min"] == 20 and f["fwd_header_len"] == 80
    # the trailing FIN/ACK + ACK form a new 2-packet flow, emitted on flush
    tail = compat.flush()
    assert (
        len(tail) == 1 and tail[0].features["tot_fwd_pkts"] + tail[0].features["tot_bwd_pkts"] == 2
    )
    assert compat.flows_emitted == 2

    corrected = FlowBuilder(compat=False)
    recs = []
    for p in pkts:
        recs.extend(corrected.add_packet(p))
    assert len(recs) == 1 and corrected.flush() == []
    f2 = recs[0].features
    assert f2["tot_fwd_pkts"] == 5 and f2["tot_bwd_pkts"] == 4
    assert f2["fwd_psh_flags"] == 1  # a forward PSH really occurred
    assert f2["pkt_len_mean"] == pytest.approx(1600 / 9)  # first packet counted once
    assert f2["active_mean"] > 0  # final active period recorded


def test_rst_closes_only_in_corrected_mode() -> None:
    pkts = synth.to_packet_infos(synth.tcp_session(0.0, A, B, 4000, 80, [("c", 10)], rst=True))
    compat, corrected = FlowBuilder(compat=True), FlowBuilder(compat=False)
    assert all(compat.add_packet(p) == [] for p in pkts)
    assert len(compat.flush()) == 1
    out: list[FlowRecord] = []
    for p in pkts:
        out.extend(corrected.add_packet(p))
    assert len(out) == 1 and out[0].features["rst_flag_cnt"] == 1


def test_backward_window_is_last_in_compat_first_in_corrected() -> None:
    syn = pkt(0, flags=TCP_SYN, window=1000)
    pkts = [syn, rev(syn, 10, window=26847), rev(syn, 20, window=230), pkt(30, window=999)]
    for compat, want in ((True, 230.0), (False, 26847.0)):
        b = FlowBuilder(compat=compat)
        for p in pkts:
            b.add_packet(p)
        f = b.flush()[0].features
        assert f["init_bwd_win_byts"] == want and f["init_fwd_win_byts"] == 1000


def test_single_packet_flows_dropped_in_compat_only() -> None:
    b = FlowBuilder(compat=True)
    b.add_packet(pkt(0, flags=TCP_SYN))
    assert b.flush() == [] and b.flows_dropped_single == 1
    c = FlowBuilder(compat=False)
    c.add_packet(pkt(0, flags=TCP_SYN))
    assert len(c.flush()) == 1


def test_flow_timeout_splits_and_keeps_orientation() -> None:
    b = FlowBuilder(flow_timeout_us=1_000_000)
    p0 = pkt(0, payload=10)
    b.add_packet(p0)
    b.add_packet(rev(p0, 100, payload=20))
    # a backward packet arriving after the timeout: old flow emitted, new flow keeps A->B orientation
    out = b.add_packet(rev(p0, 1_500_000, payload=30))
    assert (
        len(out) == 1
        and out[0].features["tot_fwd_pkts"] == 1
        and out[0].features["tot_bwd_pkts"] == 1
    )
    b.add_packet(pkt(1_500_100, payload=5))
    (rec,) = b.flush()
    assert rec.src == A and rec.features["tot_fwd_pkts"] == 1 and rec.features["tot_bwd_pkts"] == 1
    assert rec.features["totlen_bwd_pkts"] == 30 and rec.features["totlen_fwd_pkts"] == 5
    assert rec.features["pkt_len_mean"] == pytest.approx((30 + 30 + 5) / 3)  # first packet doubled
    # forward packet after timeout: plain restart
    c = FlowBuilder(flow_timeout_us=1_000)
    c.add_packet(p0)
    c.add_packet(rev(p0, 10))
    out = c.add_packet(pkt(5_000, payload=7))
    assert len(out) == 1
    c.add_packet(rev(p0, 5_010))
    (rec2,) = c.flush()
    assert rec2.features["totlen_fwd_pkts"] == 7


def test_single_packet_flow_dropped_on_timeout_and_expire() -> None:
    b = FlowBuilder(flow_timeout_us=1_000)
    b.add_packet(pkt(0))
    assert b.add_packet(pkt(5_000)) == []  # the old 1-packet flow is discarded (Q2)
    assert b.flows_dropped_single == 1
    assert len(b) == 1
    b.add_packet(rev(pkt(5_000), 5_100))
    assert b.expire(5_500) == []
    exp = b.expire(10_000)
    assert len(exp) == 1 and len(b) == 0


def test_active_idle_statistics() -> None:
    b = FlowBuilder()
    t = 0
    p = pkt(t, payload=1)
    b.add_packet(p)
    # active burst 0..2s, idle 2s..9s, active 9..10s (final, not recorded in compat)
    for t in (1_000_000, 2_000_000):
        b.add_packet(rev(p, t, payload=1))
    b.add_packet(pkt(9_000_000, payload=1))
    b.add_packet(rev(p, 10_000_000, payload=1))
    (rec,) = b.flush()
    f = rec.features
    assert f["active_mean"] == 2_000_000 and f["active_max"] == 2_000_000 and f["active_std"] == 0
    assert f["idle_mean"] == 7_000_000 and f["idle_min"] == 7_000_000
    assert f["flow_iat_max"] == 7_000_000 and f["fwd_iat_tot"] == 9_000_000
    assert DEFAULT_ACTIVITY_TIMEOUT_US == 5_000_000


def test_down_up_ratio_and_rates_without_duration() -> None:
    b = FlowBuilder()
    p = pkt(0, payload=4)
    b.add_packet(p)
    for _ in range(3):
        b.add_packet(rev(p, 0, payload=2))
    (rec,) = b.flush()
    f = rec.features
    assert f["down_up_ratio"] == 3 and f["flow_duration"] == 0
    assert (
        math.isinf(f["flow_byts_s"])
        and math.isinf(f["flow_pkts_s"])
        and math.isinf(f["bwd_pkts_s"])
    )
    assert f["flow_iat_mean"] == 0


def test_flowstate_feature_order_guard() -> None:
    fs = FlowState.start(pkt(0), compat=True, activity_timeout_us=5_000_000)
    assert tuple(fs.features()) == FLOW_FEATURES


# ---------------------------------------------------------------- pcap round trip


def test_pcap_round_trip_and_frame(tmp_path: Path) -> None:
    pkts = synth.brute_force(0.0, "192.168.1.9", "10.0.0.5", 22, attempts=5)
    pkts += synth.benign_web(0.0, ["192.168.1.2", "192.168.1.3"], "10.0.0.7", n=5, seed=1)
    pkts += synth.syn_scan(3.0, "192.168.1.9", "10.0.0.5", range(60, 70))
    pkts += synth.udp_exchange(4.0, "192.168.1.2", "10.0.0.53", 40000, 53, [("c", 40), ("s", 120)])
    path = tmp_path / "synthetic.pcap"
    n = synth.write_pcap(path, pkts)
    assert n == len(pkts)
    assert sum(1 for _ in iter_packets(path)) == n
    assert len(list(iter_packets(path, limit=7))) == 7
    df = extract_flows(path)
    assert set(df.columns) >= set(FLOW_FEATURES) | {
        "flow_id",
        "dst_port",
        "dst_port_bucket",
        "protocol",
    }
    ssh = (pl.col("dst_port") == 22) | (pl.col("src_port") == 22)
    # 5 sessions, each split at the first FIN; the FIN/ACK + ACK tail becomes a
    # server-initiated 2-packet flow (CICFlowMeter quirk Q1)
    assert df.filter(ssh).height == 10
    assert df.filter(pl.col("dst_port") == 22).height == 5
    assert df.filter((pl.col("dst_port") == 443) | (pl.col("src_port") == 443)).height == 10
    assert df.filter(pl.col("protocol") == 17).height == 1
    assert df.filter((pl.col("dst_port") >= 60) & (pl.col("dst_port") < 70)).height == 10
    assert df.filter(pl.col("dst_port") == 443)["pkt_len_std"].min() >= 0
    corrected = extract_flows(path, compat=False)
    assert corrected.filter(pl.col("dst_port") == 22).height == 5
    assert list(iter_flows(path, limit=3)) != []
    empty = records_to_frame([])
    assert empty.height == 0 and set(FLOW_FEATURES) <= set(empty.columns)


def test_pcapng_reader(tmp_path: Path) -> None:
    from scapy.utils import PcapNgWriter

    pkts = synth.udp_exchange(0.0, A, B, 1000, 53, [("c", 10), ("s", 20)])
    path = tmp_path / "x.pcapng"
    with PcapNgWriter(str(path)) as w:
        for p in pkts:
            w.write(p)
    assert len(list(iter_packets(path))) == 2


def test_fin_packet_opening_a_flow_is_dropped_as_single() -> None:
    b = FlowBuilder()
    b.add_packet(pkt(0, flags=TCP_FIN | TCP_ACK))
    assert b.flush() == []


def test_extract_flows_batches_and_concats(tmp_path: Path) -> None:
    pkts = synth.benign_web(0.0, ["192.168.1.2"], "10.0.0.7", n=7, seed=3)
    path = tmp_path / "b.pcap"
    synth.write_pcap(path, pkts)
    whole = extract_flows(path)
    batched = extract_flows(path, batch=2)
    assert batched.height == whole.height == 14
    assert batched.equals(whole)
