#!/usr/bin/env python
"""Fetch one per-host PCAP out of a CSE-CIC-IDS2018 ``pcap.zip`` without downloading the archive.

The IDS2018 archives are 40-60 GB zip files containing one PCAP per captured host. The zip
central directory sits at the end of the file and records each entry's byte offset and
compressed size, so a single entry can be fetched with two HTTP range requests and
inflated locally. Nothing is executed from the download; the result is only ever parsed
by scapy/dpkt-style readers.

Usage:
    python scripts/fetch_pcap_entry.py --day Wednesday-14-02-2018 --list
    python scripts/fetch_pcap_entry.py --day Wednesday-14-02-2018 \
        --entry "pcap/UCAP172.31.69.25" --out data/pcaps/cseids2018/Wed-14-02-2018_UCAP172.31.69.25.pcap
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path

import httpx

BUCKET = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com"
PREFIX = "Original%20Network%20Traffic%20and%20Log%20data"
TAIL_BYTES = 4_000_000
CHUNK = 8 * 1024 * 1024


@dataclass(frozen=True)
class ZipEntry:
    name: str
    method: int
    csize: int
    usize: int
    offset: int


def _zip64_fields(extra: bytes, csize: int, usize: int, offset: int) -> tuple[int, int, int]:
    q = 0
    while q + 4 <= len(extra):
        tid, tsz = struct.unpack("<HH", extra[q : q + 4])
        data = extra[q + 4 : q + 4 + tsz]
        if tid == 1:
            vals = [struct.unpack("<Q", data[m : m + 8])[0] for m in range(0, len(data) - 7, 8)]
            it = iter(vals)
            if usize == 0xFFFFFFFF:
                usize = next(it)
            if csize == 0xFFFFFFFF:
                csize = next(it)
            if offset == 0xFFFFFFFF:
                offset = next(it)
        q += 4 + tsz
    return csize, usize, offset


def parse_central_directory(tail: bytes, total: int) -> list[ZipEntry]:
    """Parse zip (and zip64) central directory from the final bytes of an archive."""
    base = total - len(tail)
    i = tail.rfind(b"PK\x05\x06")
    if i < 0:
        raise ValueError("end-of-central-directory record not found in tail")
    _, _, _, _, ntot, _cdsize, cdoff, _ = struct.unpack("<IHHHHIIH", tail[i : i + 22])
    if cdoff == 0xFFFFFFFF or ntot == 0xFFFF:
        j = tail.rfind(b"PK\x06\x06")
        rec = struct.unpack("<IQHHIIQQQQ", tail[j : j + 56])
        ntot, cdoff = rec[6], rec[9]
    p = cdoff - base
    if p < 0:
        raise ValueError("central directory larger than fetched tail; increase TAIL_BYTES")
    entries: list[ZipEntry] = []
    for _ in range(ntot):
        h = struct.unpack("<IHHHHHHIIIHHHHHII", tail[p : p + 46])
        nlen, xlen, clen = h[10], h[11], h[12]
        name = tail[p + 46 : p + 46 + nlen].decode("latin1")
        extra = tail[p + 46 + nlen : p + 46 + nlen + xlen]
        csize, usize, offset = _zip64_fields(extra, h[8], h[9], h[16])
        entries.append(ZipEntry(name, h[4], csize, usize, offset))
        p += 46 + nlen + xlen + clen
    return entries


def archive_url(day: str) -> str:
    return f"{BUCKET}/{PREFIX}/{day}/pcap.zip"


def list_entries(client: httpx.Client, url: str) -> list[ZipEntry]:
    head = client.head(url)
    head.raise_for_status()
    total = int(head.headers["Content-Length"])
    r = client.get(url, headers={"Range": f"bytes={total - TAIL_BYTES}-"})
    r.raise_for_status()
    return parse_central_directory(r.content, total)


def fetch_entry(client: httpx.Client, url: str, entry: ZipEntry, out: Path) -> str:
    """Stream the entry's compressed bytes, inflate them and return the SHA-256 of the output."""
    # Local file header precedes the data: 30 bytes + name + extra. Fetch it first.
    r = client.get(url, headers={"Range": f"bytes={entry.offset}-{entry.offset + 29}"})
    r.raise_for_status()
    nlen, xlen = struct.unpack("<HH", r.content[26:30])
    start = entry.offset + 30 + nlen + xlen
    end = start + entry.csize - 1
    out.parent.mkdir(parents=True, exist_ok=True)
    sha = hashlib.sha256()
    inflater = zlib.decompressobj(-15) if entry.method == 8 else None
    done = 0
    with (
        out.open("wb") as fh,
        client.stream("GET", url, headers={"Range": f"bytes={start}-{end}"}) as resp,
    ):
        resp.raise_for_status()
        for chunk in resp.iter_bytes(CHUNK):
            data = inflater.decompress(chunk) if inflater else chunk
            fh.write(data)
            sha.update(data)
            done += len(chunk)
            print(
                f"\r{done / entry.csize:6.1%} of {entry.csize / 1e6:.0f} MB",
                end="",
                file=sys.stderr,
            )
        if inflater:
            data = inflater.flush()
            fh.write(data)
            sha.update(data)
    print(file=sys.stderr)
    return sha.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--day", required=True, help="e.g. Wednesday-14-02-2018")
    ap.add_argument("--list", action="store_true", help="list entries and exit")
    ap.add_argument("--entry", help="entry name inside the zip, e.g. pcap/UCAP172.31.69.25")
    ap.add_argument("--out", type=Path, help="output .pcap path")
    args = ap.parse_args()

    url = archive_url(args.day)
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        entries = list_entries(client, url)
        if args.list or not args.entry:
            for e in entries:
                if e.csize:
                    print(
                        f"{e.name:50s} compressed={e.csize / 1e6:9.1f} MB  pcap={e.usize / 1e6:9.1f} MB"
                    )
            return 0
        match = [e for e in entries if e.name == args.entry]
        if not match:
            print(f"entry {args.entry!r} not found", file=sys.stderr)
            return 2
        out = args.out or Path("data/pcaps/cseids2018") / f"{args.day}_{Path(args.entry).name}.pcap"
        digest = fetch_entry(client, url, match[0], out)
        (out.with_suffix(".sha256")).write_text(f"{digest}  {out.name}\n")
        print(f"wrote {out} ({out.stat().st_size / 1e6:.1f} MB) sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
