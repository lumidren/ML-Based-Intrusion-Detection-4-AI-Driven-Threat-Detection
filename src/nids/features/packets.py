"""Packet decoding into the minimal record the flow builder needs.

Two adapters produce identical :class:`PacketInfo` records from the same bytes:

* :func:`decode_bytes` - dpkt-based, used for PCAP files (fast, pure Python);
* :func:`decode_scapy` - scapy-based, used by the live capture agent.

Only IPv4 is decoded (CICFlowMeter v3, which produced both datasets, is IPv4-only). Packets
that are not TCP/UDP are still flowed with ports 0, protocol 0, zero payload and zero header
length, which is exactly how the datasets represent ICMP/other traffic.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

import dpkt

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80


@dataclass(slots=True, frozen=True)
class PacketInfo:
    ts_us: int
    src: str
    dst: str
    sport: int
    dport: int
    proto: int  # 6, 17 or 0 (other IPv4)
    payload_len: int
    header_len: int  # transport header bytes (TCP data offset * 4, UDP 8, else 0)
    flags: int  # TCP flag byte, 0 for non-TCP
    window: int  # TCP window, -1 for non-TCP

    @property
    def is_tcp(self) -> bool:
        return self.proto == 6

    def has(self, flag: int) -> bool:
        return bool(self.flags & flag)


def _ip_from_frame(buf: bytes, linktype: int) -> dpkt.ip.IP | None:
    try:
        if linktype == LINKTYPE_ETHERNET:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            # 802.1Q is unwrapped by dpkt; anything that is not IPv4 is ignored
            return ip if isinstance(ip, dpkt.ip.IP) else None
        if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4):
            return dpkt.ip.IP(buf)
        if linktype == LINKTYPE_LINUX_SLL:
            sll = dpkt.sll.SLL(buf)
            return sll.data if isinstance(sll.data, dpkt.ip.IP) else None
    except (dpkt.UnpackError, struct.error, ValueError):
        return None
    return None


def _inet4(b: bytes) -> str:
    return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"


def decode_bytes(ts: float, buf: bytes, linktype: int = LINKTYPE_ETHERNET) -> PacketInfo | None:
    """Decode one captured frame. Returns None for non-IPv4 frames or truncated packets."""
    ip = _ip_from_frame(buf, linktype)
    if ip is None:
        return None
    ts_us = round(ts * 1_000_000)
    src, dst = _inet4(ip.src), _inet4(ip.dst)
    if ip.p == dpkt.ip.IP_PROTO_TCP and isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        return PacketInfo(
            ts_us, src, dst, tcp.sport, tcp.dport, 6, len(tcp.data), tcp.off * 4, tcp.flags, tcp.win
        )
    if ip.p == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
        udp = ip.data
        return PacketInfo(ts_us, src, dst, udp.sport, udp.dport, 17, len(udp.data), 8, 0, -1)
    return PacketInfo(ts_us, src, dst, 0, 0, 0, 0, 0, 0, -1)


def decode_scapy(pkt: Any) -> PacketInfo | None:
    """Decode a scapy packet (live capture path) into the same record as :func:`decode_bytes`.

    The packet is serialised and handed to the byte decoder, so both paths agree by
    construction (scapy leaves length fields unset on packets it built itself).
    """
    from scapy.layers.inet import IP
    from scapy.layers.l2 import Ether

    if pkt.haslayer(Ether):
        linktype = LINKTYPE_ETHERNET
    elif pkt.haslayer(IP) and isinstance(pkt, IP):
        linktype = LINKTYPE_RAW
    else:
        return None
    return decode_bytes(float(pkt.time), bytes(pkt), linktype)
