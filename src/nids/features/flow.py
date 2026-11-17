"""Bidirectional flow assembly and CICFlowMeter-v3-compatible feature computation.

The datasets were produced by CICFlowMeter v3. For train/serve parity the extractor must
reproduce that tool's *actual* behaviour, including its documented quirks, when
``compat=True`` (default). Each quirk below was verified row-wise on the published CSVs
(see docs/DATA_CARD.md and tests/test_parity.py):

Q1  Flow termination: a flow ends on the first packet carrying FIN, on ``flow_timeout``
    measured from the flow *start*, or at end of capture. RST does not end a flow.
Q2  Single-packet flows are never emitted.
Q3  Whole-flow packet-length statistics (``pkt_len_*``) include the first packet twice;
    per-direction statistics do not. ``pkt_size_avg`` divides that inflated sum by the true
    packet count.
Q4  Flag "counts" are 0/1 indicators of presence anywhere in the flow.
Q5  ``fwd_psh_flags`` is identical to the SYN indicator (mislabelled column); ``fwd_urg_flags``
    is the forward URG indicator.
Q6  ``subflow_*`` equal the flow totals (the sub-flow counter is always 1).
Q7  Active/idle statistics only record periods that end with an idle gap > ``activity_timeout``;
    the final active period is never recorded.
Q8  Standard deviations are sample (n-1) statistics; a single value gives 0.
Q9  Rates divide by the duration in seconds; a zero duration yields ``inf`` (the CSVs contain
    ``Infinity``), which the cleaning step imputes.
Q10 UDP and other non-TCP flows report TCP windows of -1 and header length 8 (UDP) or 0.
Q11 ``init_bwd_win_byts`` is the window of the *last* backward packet: CICFlowMeter assigns
    ``Init_Win_bytes_backward`` on every backward packet (BasicFlow.addPacket). Verified on
    the 14-02-2018 victim capture: 99.99% of 382,586 matched flows, against 75% for the
    first backward window.

The published TCP flag columns (``*_flag_cnt``, ``fwd_psh_flags``, ``fwd_urg_flags``) of
CSE-CIC-IDS2018 cannot be reproduced from packets: on the matched flows the published
``psh_flag_cnt`` follows the SYN bit and ``ack``/``urg`` follow FIN, while SYN, FIN and RST
are always 0. The released CICFlowMeter source decodes flags correctly, so the CSVs come
from an earlier build. The extractor keeps the Q4/Q5 semantics measured on CIC-IDS2017 and
the flag columns are excluded from the model inputs (``schema.UNREPRODUCIBLE``).

With ``compat=False`` the *corrected* semantics are used: flows end after FIN from both
sides (plus the final ACK) or on RST, single-packet flows are emitted, the first packet is
counted once, ``fwd_psh_flags`` is the forward-PSH indicator, and the final active period
is recorded. The corrected mode is what a fresh deployment should use once the model has been
retrained on features produced by it; the paper quantifies the difference.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from nids.data.schema import FLOW_FEATURES, dst_port_bucket
from nids.features.packets import (
    TCP_ACK,
    TCP_CWR,
    TCP_ECE,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    TCP_URG,
    PacketInfo,
)

DEFAULT_FLOW_TIMEOUT_US = 120_000_000
DEFAULT_ACTIVITY_TIMEOUT_US = 5_000_000

FlowKey = tuple[str, int, str, int, int]


def flow_key(p: PacketInfo) -> FlowKey:
    """Direction-independent 5-tuple key."""
    a = (p.src, p.sport)
    b = (p.dst, p.dport)
    if a <= b:
        return (a[0], a[1], b[0], b[1], p.proto)
    return (b[0], b[1], a[0], a[1], p.proto)


class _Stats:
    """Running sum / sum of squares / min / max; sample std like Apache Commons Math."""

    __slots__ = ("mn", "mx", "n", "s", "s2")

    def __init__(self) -> None:
        self.n = 0
        self.s = 0.0
        self.s2 = 0.0
        self.mn = math.inf
        self.mx = -math.inf

    def add(self, v: float) -> None:
        self.n += 1
        self.s += v
        self.s2 += v * v
        self.mn = min(self.mn, v)
        self.mx = max(self.mx, v)

    @property
    def mean(self) -> float:
        return self.s / self.n if self.n else 0.0

    @property
    def var(self) -> float:
        if self.n < 2:
            return 0.0
        m = self.s / self.n
        v = (self.s2 - self.n * m * m) / (self.n - 1)
        return v if v > 0 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.var)

    @property
    def minimum(self) -> float:
        return self.mn if self.n else 0.0

    @property
    def maximum(self) -> float:
        return self.mx if self.n else 0.0


@dataclass(slots=True)
class FlowState:
    """Mutable per-flow accumulator. Forward = direction of the first packet."""

    src: str
    sport: int
    dst: str
    dport: int
    proto: int
    start_us: int
    compat: bool
    activity_timeout_us: int
    last_us: int = 0
    fwd_n: int = 0
    bwd_n: int = 0
    fwd_len: _Stats = field(default_factory=_Stats)
    bwd_len: _Stats = field(default_factory=_Stats)
    all_len: _Stats = field(default_factory=_Stats)
    flow_iat: _Stats = field(default_factory=_Stats)
    fwd_iat: _Stats = field(default_factory=_Stats)
    bwd_iat: _Stats = field(default_factory=_Stats)
    active: _Stats = field(default_factory=_Stats)
    idle: _Stats = field(default_factory=_Stats)
    fwd_last_us: int = -1
    bwd_last_us: int = -1
    fwd_header: int = 0
    bwd_header: int = 0
    fwd_act_data: int = 0
    fwd_seg_min: int = -1
    init_fwd_win: int = -1
    init_bwd_win: int = -1
    flags_any: int = 0
    flags_fwd: int = 0
    flags_bwd: int = 0
    fin_fwd: bool = False
    fin_bwd: bool = False
    start_active_us: int = 0
    end_active_us: int = 0

    @property
    def n_packets(self) -> int:
        return self.fwd_n + self.bwd_n

    def is_forward(self, p: PacketInfo) -> bool:
        return p.src == self.src and p.sport == self.sport

    # -- CICFlowMeter BasicFlow.firstPacket -------------------------------------------------
    @classmethod
    def start(cls, p: PacketInfo, compat: bool, activity_timeout_us: int) -> FlowState:
        fs = cls(
            p.src,
            p.sport,
            p.dst,
            p.dport,
            p.proto,
            p.ts_us,
            compat,
            activity_timeout_us,
            last_us=p.ts_us,
            start_active_us=p.ts_us,
            end_active_us=p.ts_us,
        )
        if compat:
            fs.all_len.add(p.payload_len)  # Q3: first packet counted here *and* in add()
        fs.add(p)
        return fs

    # -- CICFlowMeter BasicFlow.addPacket ---------------------------------------------------
    def add(self, p: PacketInfo) -> None:
        if self.n_packets:
            self.flow_iat.add(p.ts_us - self.last_us)
        if self.is_forward(p):
            if p.payload_len >= 1:
                self.fwd_act_data += 1
            self.fwd_len.add(p.payload_len)
            self.fwd_header += p.header_len
            if self.fwd_n:
                self.fwd_iat.add(p.ts_us - self.fwd_last_us)
            else:
                self.init_fwd_win = p.window if p.is_tcp else -1
            self.fwd_last_us = p.ts_us
            self.fwd_n += 1
            if p.is_tcp and (self.fwd_seg_min < 0 or p.header_len < self.fwd_seg_min):
                self.fwd_seg_min = p.header_len
            self.flags_fwd |= p.flags
            if p.flags & TCP_FIN:
                self.fin_fwd = True
        else:
            self.bwd_len.add(p.payload_len)
            self.bwd_header += p.header_len
            if self.bwd_n:
                self.bwd_iat.add(p.ts_us - self.bwd_last_us)
            if self.compat or not self.bwd_n:  # Q11: compat keeps the last backward window
                self.init_bwd_win = p.window if p.is_tcp else -1
            self.bwd_last_us = p.ts_us
            self.bwd_n += 1
            self.flags_bwd |= p.flags
            if p.flags & TCP_FIN:
                self.fin_bwd = True
        self.all_len.add(p.payload_len)
        self.flags_any |= p.flags
        self.last_us = p.ts_us

    # -- CICFlowMeter BasicFlow.updateActiveIdleTime ----------------------------------------
    def update_active_idle(self, now_us: int) -> None:
        if now_us - self.end_active_us > self.activity_timeout_us:
            if self.end_active_us - self.start_active_us > 0:
                self.active.add(self.end_active_us - self.start_active_us)
            self.idle.add(now_us - self.end_active_us)
            self.start_active_us = now_us
            self.end_active_us = now_us
        else:
            self.end_active_us = now_us

    def finish(self) -> None:
        if not self.compat and self.end_active_us - self.start_active_us > 0:
            self.active.add(self.end_active_us - self.start_active_us)

    # -- feature vector ---------------------------------------------------------------------
    def features(self) -> dict[str, float]:
        dur = self.last_us - self.start_us
        dur_s = dur / 1_000_000
        n = self.n_packets
        fwd_bytes, bwd_bytes = self.fwd_len.s, self.bwd_len.s
        total_bytes = fwd_bytes + bwd_bytes

        def rate(x: float) -> float:
            return x / dur_s if dur_s > 0 else (math.inf if x > 0 else 0.0)

        if self.compat:
            syn = 1.0 if self.flags_any & TCP_SYN else 0.0
            fwd_psh = syn  # Q5
        else:
            fwd_psh = 1.0 if self.flags_fwd & TCP_PSH else 0.0
        flag = self.flags_any
        feats = {
            "flow_duration": float(dur),
            "tot_fwd_pkts": float(self.fwd_n),
            "tot_bwd_pkts": float(self.bwd_n),
            "totlen_fwd_pkts": fwd_bytes,
            "totlen_bwd_pkts": bwd_bytes,
            "fwd_pkt_len_max": self.fwd_len.maximum,
            "fwd_pkt_len_min": self.fwd_len.minimum,
            "fwd_pkt_len_mean": self.fwd_len.mean,
            "fwd_pkt_len_std": self.fwd_len.std,
            "bwd_pkt_len_max": self.bwd_len.maximum,
            "bwd_pkt_len_min": self.bwd_len.minimum,
            "bwd_pkt_len_mean": self.bwd_len.mean,
            "bwd_pkt_len_std": self.bwd_len.std,
            "flow_byts_s": rate(total_bytes),
            "flow_pkts_s": rate(float(n)),
            "flow_iat_mean": self.flow_iat.mean,
            "flow_iat_std": self.flow_iat.std,
            "flow_iat_max": self.flow_iat.maximum,
            "flow_iat_min": self.flow_iat.minimum,
            "fwd_iat_tot": self.fwd_iat.s,
            "fwd_iat_mean": self.fwd_iat.mean,
            "fwd_iat_std": self.fwd_iat.std,
            "fwd_iat_max": self.fwd_iat.maximum,
            "fwd_iat_min": self.fwd_iat.minimum,
            "bwd_iat_tot": self.bwd_iat.s,
            "bwd_iat_mean": self.bwd_iat.mean,
            "bwd_iat_std": self.bwd_iat.std,
            "bwd_iat_max": self.bwd_iat.maximum,
            "bwd_iat_min": self.bwd_iat.minimum,
            "fwd_psh_flags": fwd_psh,
            "fwd_urg_flags": 1.0 if self.flags_fwd & TCP_URG else 0.0,
            "fwd_header_len": float(self.fwd_header),
            "bwd_header_len": float(self.bwd_header),
            "fwd_pkts_s": rate(float(self.fwd_n)),
            "bwd_pkts_s": rate(float(self.bwd_n)),
            "pkt_len_min": self.all_len.minimum,
            "pkt_len_max": self.all_len.maximum,
            "pkt_len_mean": self.all_len.mean,
            "pkt_len_std": self.all_len.std,
            "pkt_len_var": self.all_len.var,
            "fin_flag_cnt": 1.0 if flag & TCP_FIN else 0.0,
            "syn_flag_cnt": 1.0 if flag & TCP_SYN else 0.0,
            "rst_flag_cnt": 1.0 if flag & TCP_RST else 0.0,
            "psh_flag_cnt": 1.0 if flag & TCP_PSH else 0.0,
            "ack_flag_cnt": 1.0 if flag & TCP_ACK else 0.0,
            "urg_flag_cnt": 1.0 if flag & TCP_URG else 0.0,
            "cwe_flag_cnt": 1.0 if flag & TCP_CWR else 0.0,
            "ece_flag_cnt": 1.0 if flag & TCP_ECE else 0.0,
            "down_up_ratio": float(self.bwd_n // self.fwd_n) if self.fwd_n else 0.0,
            "pkt_size_avg": self.all_len.s / n if n else 0.0,
            "fwd_seg_size_avg": self.fwd_len.mean,
            "bwd_seg_size_avg": self.bwd_len.mean,
            "subflow_fwd_pkts": float(self.fwd_n),  # Q6
            "subflow_fwd_byts": fwd_bytes,
            "subflow_bwd_pkts": float(self.bwd_n),
            "subflow_bwd_byts": bwd_bytes,
            "init_fwd_win_byts": float(self.init_fwd_win),
            "init_bwd_win_byts": float(self.init_bwd_win),
            "fwd_act_data_pkts": float(self.fwd_act_data),
            "fwd_seg_size_min": float(max(self.fwd_seg_min, 0)),
            "active_mean": self.active.mean,
            "active_std": self.active.std,
            "active_max": self.active.maximum,
            "active_min": self.active.minimum,
            "idle_mean": self.idle.mean,
            "idle_std": self.idle.std,
            "idle_max": self.idle.maximum,
            "idle_min": self.idle.minimum,
        }
        assert tuple(feats) == FLOW_FEATURES, "feature order drifted from schema"
        return feats


@dataclass(slots=True, frozen=True)
class FlowRecord:
    src: str
    sport: int
    dst: str
    dport: int
    proto: int
    start_us: int
    end_us: int
    features: dict[str, float]

    @property
    def flow_id(self) -> str:
        return f"{self.src}-{self.dst}-{self.sport}-{self.dport}-{self.proto}"

    def to_row(self) -> dict[str, float | int | str]:
        row: dict[str, float | int | str] = {
            "flow_id": self.flow_id,
            "src_ip": self.src,
            "src_port": self.sport,
            "dst_ip": self.dst,
            "dst_port": self.dport,
            "protocol": self.proto,
            "start_us": self.start_us,
            "end_us": self.end_us,
        }
        row.update(self.features)
        row["dst_port_bucket"] = dst_port_bucket(self.dport)
        return row


class FlowBuilder:
    """Stateful packet -> flow assembler (CICFlowMeter ``FlowGenerator`` semantics)."""

    def __init__(
        self,
        flow_timeout_us: int = DEFAULT_FLOW_TIMEOUT_US,
        activity_timeout_us: int = DEFAULT_ACTIVITY_TIMEOUT_US,
        compat: bool = True,
    ) -> None:
        self.flow_timeout_us = flow_timeout_us
        self.activity_timeout_us = activity_timeout_us
        self.compat = compat
        self._flows: dict[FlowKey, FlowState] = {}
        self.packets_seen = 0
        self.flows_emitted = 0
        self.flows_dropped_single = 0

    def __len__(self) -> int:
        return len(self._flows)

    def _emit(self, fs: FlowState) -> FlowRecord | None:
        if self.compat and fs.n_packets < 2:  # Q2
            self.flows_dropped_single += 1
            return None
        fs.finish()
        self.flows_emitted += 1
        return FlowRecord(
            fs.src, fs.sport, fs.dst, fs.dport, fs.proto, fs.start_us, fs.last_us, fs.features()
        )

    def add_packet(self, p: PacketInfo) -> list[FlowRecord]:
        """Feed one packet; return any flows that finished because of it."""
        self.packets_seen += 1
        out: list[FlowRecord] = []
        key = flow_key(p)
        fs = self._flows.get(key)
        if fs is None:
            self._flows[key] = FlowState.start(p, self.compat, self.activity_timeout_us)
            return out
        if p.ts_us - fs.start_us > self.flow_timeout_us:
            rec = self._emit(fs)
            if rec:
                out.append(rec)
            # the new flow keeps the old orientation (CICFlowMeter passes src/dst through)
            nfs = FlowState.start(p, self.compat, self.activity_timeout_us)
            if not fs.is_forward(p):
                nfs.src, nfs.sport, nfs.dst, nfs.dport = fs.src, fs.sport, fs.dst, fs.dport
                nfs.fwd_n, nfs.bwd_n = 0, 0
                nfs.fwd_len, nfs.bwd_len, nfs.all_len = _Stats(), _Stats(), _Stats()
                nfs.fwd_header = nfs.bwd_header = nfs.fwd_act_data = 0
                nfs.init_fwd_win = nfs.init_bwd_win = -1
                nfs.flags_any = nfs.flags_fwd = nfs.flags_bwd = 0
                nfs.fin_fwd = nfs.fin_bwd = False
                nfs.fwd_seg_min = -1
                if self.compat:
                    nfs.all_len.add(p.payload_len)
                nfs.add(p)
            self._flows[key] = nfs
            return out
        if self.compat:
            if p.flags & TCP_FIN:  # Q1: first FIN ends the flow
                fs.add(p)
                rec = self._emit(fs)
                if rec:
                    out.append(rec)
                del self._flows[key]
                return out
            fs.update_active_idle(p.ts_us)
            fs.add(p)
            return out
        # corrected semantics
        fs.update_active_idle(p.ts_us)
        fs.add(p)
        both_fin = fs.fin_fwd and fs.fin_bwd
        if (p.flags & TCP_RST) or (both_fin and (p.flags & TCP_ACK) and not (p.flags & TCP_FIN)):
            rec = self._emit(fs)
            if rec:
                out.append(rec)
            del self._flows[key]
        return out

    def expire(self, now_us: int) -> list[FlowRecord]:
        """Emit flows whose timeout has elapsed without new packets (live-capture housekeeping)."""
        out: list[FlowRecord] = []
        for key in [
            k for k, fs in self._flows.items() if now_us - fs.start_us > self.flow_timeout_us
        ]:
            rec = self._emit(self._flows.pop(key))
            if rec:
                out.append(rec)
        return out

    def flush(self) -> list[FlowRecord]:
        """Emit everything still open (end of capture)."""
        out: list[FlowRecord] = []
        for fs in self._flows.values():
            rec = self._emit(fs)
            if rec:
                out.append(rec)
        self._flows.clear()
        return out
