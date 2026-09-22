"""Extract transport payloads and create short-lived synthetic PCAPs.

Only payloads and their direction/order enter an archive.  The generated
Ethernet/IP/TCP or Ethernet/IP/UDP envelope is deterministic and is never
counted as retained data.
"""

from __future__ import annotations

import binascii
import socket
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path


class PcapError(RuntimeError):
    pass


@dataclass(frozen=True)
class Chunk:
    direction: int  # 0 client -> server, 1 server -> client
    data: bytes


def _run_tshark(pcap: Path, fields: list[str], display_filter: str) -> list[list[str]]:
    command = ["tshark", "-r", str(pcap), "-Y", display_filter, "-T", "fields"]
    for field in fields:
        command.extend(["-e", field])
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise PcapError(result.stderr.strip() or f"tshark failed for {pcap}")
    rows = []
    for line in result.stdout.splitlines():
        columns = line.split("\t")
        columns.extend([""] * (len(fields) - len(columns)))
        rows.append(columns[: len(fields)])
    return rows


def extract_tcp_chunks(pcap: Path, server_port: int) -> list[Chunk]:
    """Return de-duplicated TCP payload in observed order.

    Retransmitted prefixes are omitted.  Gaps are rejected because silently
    archiving an incomplete transcript would invalidate the sufficiency claim.
    """
    fields = ["tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.payload"]
    rows = _run_tshark(pcap, fields, f"tcp.port=={server_port} && tcp.len>0")
    next_seq: dict[tuple[int, int], int] = {}
    payload_streams: set[int] = set()
    chunks: list[Chunk] = []
    for stream_s, src_s, dst_s, seq_s, payload_hex in rows:
        if not payload_hex or not stream_s or not seq_s:
            continue
        try:
            stream = int(stream_s.split(",")[0])
            src = int(src_s.split(",")[0])
            dst = int(dst_s.split(",")[0])
            seq = int(seq_s.split(",")[0])
            data = binascii.unhexlify(payload_hex.replace(":", "").split(",")[0])
        except (ValueError, binascii.Error) as exc:
            raise PcapError(f"invalid TCP fields in {pcap}") from exc
        direction = 1 if src == server_port else 0 if dst == server_port else -1
        if direction < 0:
            continue
        payload_streams.add(stream)
        if len(payload_streams) > 1:
            raise PcapError(
                "capture contains more than one TCP flow with payload; select one session before compaction"
            )
        key = (stream, direction)
        expected = next_seq.get(key, seq)
        if seq > expected:
            raise PcapError(
                f"TCP gap in stream {stream}, direction {direction}: expected {expected}, got {seq}"
            )
        overlap = max(0, expected - seq)
        if overlap >= len(data):
            continue
        novel = data[overlap:]
        next_seq[key] = expected + len(novel)
        if chunks and chunks[-1].direction == direction:
            chunks[-1] = Chunk(direction, chunks[-1].data + novel)
        else:
            chunks.append(Chunk(direction, novel))
    if not chunks:
        raise PcapError(f"no TCP payload found in {pcap}")
    return chunks


def extract_udp_datagrams(pcap: Path, server_port: int) -> list[Chunk]:
    fields = ["udp.srcport", "udp.dstport", "udp.payload"]
    rows = _run_tshark(pcap, fields, f"udp.port=={server_port} && udp.length>8")
    datagrams = []
    for src_s, dst_s, payload_hex in rows:
        if not payload_hex:
            continue
        try:
            src, dst = int(src_s), int(dst_s)
            data = binascii.unhexlify(payload_hex.replace(":", "").split(",")[0])
        except (ValueError, binascii.Error) as exc:
            raise PcapError(f"invalid UDP fields in {pcap}") from exc
        direction = 1 if src == server_port else 0 if dst == server_port else -1
        if direction >= 0:
            datagrams.append(Chunk(direction, data))
    if not datagrams:
        raise PcapError(f"no UDP payload found in {pcap}")
    return datagrams


def extract_quic_cipher_suites(pcap: Path, server_port: int) -> set[int]:
    """Return TLS ServerHello ciphersuites exposed from public QUIC Initials."""
    rows = _run_tshark(
        pcap,
        ["tls.handshake.ciphersuite"],
        f"udp.port=={server_port} && tls.handshake.type==2",
    )
    suites = set()
    for (values,) in rows:
        for value in values.split(","):
            if not value:
                continue
            try:
                suites.add(int(value, 0))
            except ValueError as exc:
                raise PcapError(f"invalid QUIC TLS ciphersuite in {pcap}") from exc
    return suites


def _checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ethernet_ipv4(
    payload: bytes, protocol: int, source: bytes, destination: bytes, ident: int
) -> bytes:
    ethernet = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        ident & 0xFFFF,
        0x4000,
        64,
        protocol,
        0,
        source,
        destination,
    )
    header = header[:10] + struct.pack(">H", _checksum(header)) + header[12:]
    return ethernet + header + payload


def _tcp_segment(
    data: bytes, direction: int, server_port: int, sequence: int, ident: int
) -> bytes:
    client_ip, server_ip = socket.inet_aton("192.0.2.1"), socket.inet_aton("192.0.2.2")
    client_port = 49152
    if direction == 0:
        source, destination = client_ip, server_ip
        src_port, dst_port = client_port, server_port
    else:
        source, destination = server_ip, client_ip
        src_port, dst_port = server_port, client_port
    tcp = (
        struct.pack(
            ">HHIIBBHHH", src_port, dst_port, sequence, 1, 0x50, 0x18, 65535, 0, 0
        )
        + data
    )
    pseudo = source + destination + struct.pack(">BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack(">H", _checksum(pseudo + tcp)) + tcp[18:]
    return _ethernet_ipv4(tcp, 6, source, destination, ident)


def _udp_datagram(data: bytes, direction: int, server_port: int, ident: int) -> bytes:
    client_ip, server_ip = socket.inet_aton("192.0.2.1"), socket.inet_aton("192.0.2.2")
    client_port = 49152
    if direction == 0:
        source, destination = client_ip, server_ip
        src_port, dst_port = client_port, server_port
    else:
        source, destination = server_ip, client_ip
        src_port, dst_port = server_port, client_port
    udp = struct.pack(">HHHH", src_port, dst_port, 8 + len(data), 0) + data
    pseudo = source + destination + struct.pack(">BBH", 0, 17, len(udp))
    checksum = _checksum(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack(">H", checksum) + udp[8:]
    return _ethernet_ipv4(udp, 17, source, destination, ident)


def write_pcap(
    path: Path, chunks: list[Chunk], transport: str, server_port: int
) -> None:
    """Write classic little-endian PCAP (despite any .pcapng suffix)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 0x00040000, 1))
    tcp_sequences = [1, 1]
    timestamp = 1
    ident = 1
    for chunk in chunks:
        pieces = [chunk.data]
        if transport == "tcp":
            pieces = [chunk.data[i : i + 1400] for i in range(0, len(chunk.data), 1400)]
        for piece in pieces:
            if transport == "tcp":
                frame = _tcp_segment(
                    piece,
                    chunk.direction,
                    server_port,
                    tcp_sequences[chunk.direction],
                    ident,
                )
                tcp_sequences[chunk.direction] += len(piece)
            elif transport == "udp":
                if len(piece) > 65507:
                    raise PcapError("UDP datagram is too large for IPv4")
                frame = _udp_datagram(piece, chunk.direction, server_port, ident)
            else:
                raise ValueError(f"unknown transport {transport}")
            encoded.extend(struct.pack("<IIII", timestamp, 0, len(frame), len(frame)))
            encoded.extend(frame)
            timestamp += 1
            ident += 1
    path.write_bytes(encoded)
