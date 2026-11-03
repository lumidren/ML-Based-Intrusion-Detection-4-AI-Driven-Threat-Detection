"""Synthetic traffic with analytically known flow statistics (tests, CI replay, demos).

Everything here builds real packets with scapy, so the same bytes can be written to a PCAP
(for tcpreplay / the offline extractor) or decoded directly into :class:`PacketInfo` records.
"""

from __future__ import annotations

import random
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter

from nids.features.packets import PacketInfo, decode_scapy


def _eth(pkt: Any, ts: float) -> Any:
    frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / pkt
    frame.time = ts
    return frame


def tcp_session(
    t0: float,
    client: str,
    server: str,
    sport: int,
    dport: int,
    payloads: Iterable[tuple[str, int]],
    gap: float = 0.01,
    fin: bool = True,
    rst: bool = False,
    window: int = 29200,
) -> list[Any]:
    """A TCP connection: handshake, data segments ((direction, size) pairs), FIN or RST close.

    ``direction`` is ``"c"`` (client -> server) or ``"s"``. Timestamps advance by ``gap``.
    """
    pkts: list[Any] = []
    t = t0
    seq_c, seq_s = 1000, 5000

    def add(pkt: Any) -> None:
        nonlocal t
        pkts.append(_eth(pkt, t))
        t += gap

    add(
        IP(src=client, dst=server)
        / TCP(sport=sport, dport=dport, flags="S", seq=seq_c, window=window)
    )
    add(
        IP(src=server, dst=client)
        / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1, window=window)
    )
    add(
        IP(src=client, dst=server)
        / TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1, window=window)
    )
    for direction, size in payloads:
        if direction == "c":
            add(
                IP(src=client, dst=server)
                / TCP(
                    sport=sport,
                    dport=dport,
                    flags="PA",
                    seq=seq_c + 1,
                    ack=seq_s + 1,
                    window=window,
                )
                / Raw(b"x" * size)
            )
        else:
            add(
                IP(src=server, dst=client)
                / TCP(
                    sport=dport,
                    dport=sport,
                    flags="PA",
                    seq=seq_s + 1,
                    ack=seq_c + 1,
                    window=window,
                )
                / Raw(b"y" * size)
            )
    if rst:
        add(
            IP(src=client, dst=server)
            / TCP(sport=sport, dport=dport, flags="R", seq=seq_c + 1, window=window)
        )
    elif fin:
        add(
            IP(src=client, dst=server)
            / TCP(sport=sport, dport=dport, flags="FA", seq=seq_c + 1, ack=seq_s + 1, window=window)
        )
        add(
            IP(src=server, dst=client)
            / TCP(sport=dport, dport=sport, flags="FA", seq=seq_s + 1, ack=seq_c + 2, window=window)
        )
        add(
            IP(src=client, dst=server)
            / TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 2, ack=seq_s + 2, window=window)
        )
    return pkts


def udp_exchange(
    t0: float,
    client: str,
    server: str,
    sport: int,
    dport: int,
    sizes: Iterable[tuple[str, int]],
    gap: float = 0.005,
) -> list[Any]:
    pkts: list[Any] = []
    t = t0
    for direction, size in sizes:
        if direction == "c":
            pkt = IP(src=client, dst=server) / UDP(sport=sport, dport=dport) / Raw(b"d" * size)
        else:
            pkt = IP(src=server, dst=client) / UDP(sport=dport, dport=sport) / Raw(b"r" * size)
        pkts.append(_eth(pkt, t))
        t += gap
    return pkts


def syn_scan(
    t0: float,
    attacker: str,
    victim: str,
    ports: Iterable[int],
    gap: float = 0.001,
    closed: bool = True,
) -> list[Any]:
    """SYN scan: one SYN per port, victim answers RST/ACK (closed) or SYN/ACK (open)."""
    pkts: list[Any] = []
    t = t0
    sport = 40000
    for port in ports:
        pkts.append(
            _eth(IP(src=attacker, dst=victim) / TCP(sport=sport, dport=port, flags="S", seq=1), t)
        )
        t += gap / 2
        flags = "RA" if closed else "SA"
        pkts.append(
            _eth(
                IP(src=victim, dst=attacker)
                / TCP(sport=port, dport=sport, flags=flags, seq=1, ack=2),
                t,
            )
        )
        t += gap / 2
        sport += 1
    return pkts


def brute_force(
    t0: float,
    attacker: str,
    victim: str,
    dport: int,
    attempts: int,
    gap: float = 0.2,
    seed: int = 0,
) -> list[Any]:
    """Repeated short authenticated sessions against one service (SSH/FTP-style)."""
    rng = random.Random(seed)
    pkts: list[Any] = []
    t = t0
    for i in range(attempts):
        payloads = [
            ("c", rng.randint(20, 60)),
            ("s", rng.randint(20, 90)),
            ("c", rng.randint(10, 40)),
            ("s", 30),
        ]
        pkts += tcp_session(t, attacker, victim, 50000 + i, dport, payloads, gap=0.004)
        t += gap
    return pkts


def benign_web(t0: float, clients: Iterable[str], server: str, n: int, seed: int = 0) -> list[Any]:
    rng = random.Random(seed)
    pkts: list[Any] = []
    t = t0
    clients = list(clients)
    for i in range(n):
        c = rng.choice(clients)
        payloads = [
            ("c", rng.randint(200, 900)),
            ("s", rng.randint(500, 1460)),
            ("s", rng.randint(100, 1460)),
        ]
        pkts += tcp_session(t, c, server, 30000 + i, 443, payloads, gap=rng.uniform(0.002, 0.05))
        t += rng.uniform(0.05, 0.5)
    return pkts


def to_packet_infos(pkts: Iterable[Any]) -> list[PacketInfo]:
    out = []
    for p in sorted(pkts, key=lambda x: float(x.time)):
        info = decode_scapy(p)
        if info is not None:
            out.append(info)
    return out


def write_pcap(path: Path, pkts: Iterable[Any]) -> int:
    """Write packets in timestamp order; returns the number written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(pkts, key=lambda x: float(x.time))
    with PcapWriter(str(path), linktype=1, sync=True) as w:
        for p in ordered:
            w.write(p)
    return len(ordered)
