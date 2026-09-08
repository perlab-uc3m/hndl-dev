"""Build and materialize explicit HN-DL archive-policy representations."""

from __future__ import annotations

import binascii
import json
import shutil
import socket
import struct
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterator, Sequence

from experiment import (
    ArtifactLayout,
    ManifestError,
    Protocol,
    RecoverySpec,
    RunManifest,
    sha256_file,
)
from decryptor.io.pcap_parser import run_tshark


ARCHIVE_FORMAT = "hndl-wire-archive-v1"
ARCHIVE_MAGIC = b"HNDLWA01"


class ArchivePolicy(str, Enum):
    """Retained representation used for a recovery experiment."""

    RAW = "raw"
    REASSEMBLED = "reassembled"
    COMPACT = "compact"

    @classmethod
    def parse(cls, value: str | ArchivePolicy) -> ArchivePolicy:
        if isinstance(value, cls):
            return value
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            raise ValueError(f"unsupported archive policy: {value}") from exc


@dataclass(frozen=True)
class WireEvent:
    """One direction-labelled TCP payload, UDP datagram, or protocol unit."""

    to_server: bool
    payload: bytes


@dataclass(frozen=True)
class ArchiveBuildResult:
    """Location and measured sizes of one generated policy archive."""

    root: Path
    policy: ArchivePolicy
    source_raw_bytes: int
    retained_bytes: int
    protocol_payload_bytes: int

    @property
    def retention_ratio(self) -> float:
        if self.source_raw_bytes == 0:
            return 0.0
        return self.retained_bytes / self.source_raw_bytes


def _encode_wire_events(events: Sequence[WireEvent]) -> bytes:
    encoded = bytearray(ARCHIVE_MAGIC)
    encoded.extend(struct.pack(">I", len(events)))
    for event in events:
        encoded.extend(
            struct.pack(">BI", 0 if event.to_server else 1, len(event.payload))
        )
        encoded.extend(event.payload)
    return bytes(encoded)


def _decode_wire_events(path: Path) -> list[WireEvent]:
    data = path.read_bytes()
    if len(data) < 12 or data[:8] != ARCHIVE_MAGIC:
        raise ManifestError(f"unsupported wire archive: {path}")
    count = struct.unpack_from(">I", data, 8)[0]
    offset = 12
    events = []
    for _ in range(count):
        if offset + 5 > len(data):
            raise ManifestError(f"truncated wire archive header: {path}")
        direction, length = struct.unpack_from(">BI", data, offset)
        offset += 5
        if direction not in (0, 1) or offset + length > len(data):
            raise ManifestError(f"invalid wire archive event: {path}")
        events.append(WireEvent(direction == 0, data[offset : offset + length]))
        offset += length
    if offset != len(data):
        raise ManifestError(f"trailing data in wire archive: {path}")
    return events


def _first_data_stream(pcap: Path, port: int) -> int:
    command = [
        "tshark",
        "-r",
        str(pcap),
        "-Y",
        f"tcp.port=={port} && tcp.len > 0",
        "-T",
        "fields",
        "-e",
        "tcp.stream",
    ]
    result = run_tshark(command, pcap)
    if result.returncode != 0:
        raise RuntimeError(result.stderr or f"cannot inspect {pcap}")
    for line in result.stdout.splitlines():
        value = line.strip()
        if value.isdigit():
            return int(value)
    raise RuntimeError(f"no TCP payload stream found in {pcap}")


def _tcp_events(pcap: Path, port: int) -> list[WireEvent]:
    stream = _first_data_stream(pcap, port)
    command = [
        "tshark",
        "-r",
        str(pcap),
        "-Y",
        f"tcp.stream=={stream} && tcp.len > 0",
        "-T",
        "fields",
        "-e",
        "tcp.seq",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "tcp.payload",
    ]
    result = run_tshark(command, pcap)
    if result.returncode != 0:
        raise RuntimeError(result.stderr or f"cannot reassemble {pcap}")
    events = []
    next_sequence = {True: None, False: None}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        sequence, source, destination, encoded = parts[:4]
        encoded = encoded.replace(":", "").replace(",", "")
        if not encoded:
            continue
        try:
            payload = binascii.unhexlify(encoded)
        except (binascii.Error, ValueError):
            continue
        to_server = destination == str(port)
        if not to_server and source != str(port):
            continue
        try:
            sequence_number = int(sequence)
        except ValueError:
            continue
        expected = next_sequence[to_server]
        if expected is not None:
            if sequence_number > expected:
                raise RuntimeError(
                    "TCP stream has a gap or out-of-order segment; "
                    "compact only a fully reassembled capture"
                )
            overlap = expected - sequence_number
            if overlap >= len(payload):
                continue
            if overlap > 0:
                payload = payload[overlap:]
                sequence_number += overlap
        next_sequence[to_server] = sequence_number + len(payload)
        events.append(WireEvent(to_server, payload))
    if not events:
        raise RuntimeError(f"no reassembled TCP payload found in {pcap}")
    return events


def _udp_events(pcap: Path, port: int) -> list[WireEvent]:
    command = [
        "tshark",
        "-r",
        str(pcap),
        "-Y",
        f"udp.port=={port} && udp.length > 8",
        "-T",
        "fields",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
        "-e",
        "udp.payload",
    ]
    result = run_tshark(command, pcap)
    if result.returncode != 0:
        raise RuntimeError(result.stderr or f"cannot extract datagrams from {pcap}")
    events = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        source, destination, encoded = parts[:3]
        encoded = encoded.replace(":", "").replace(",", "")
        try:
            payload = binascii.unhexlify(encoded)
        except (binascii.Error, ValueError):
            continue
        to_server = destination == str(port)
        if payload and (to_server or source == str(port)):
            events.append(WireEvent(to_server, payload))
    if not events:
        raise RuntimeError(f"no UDP payload found in {pcap}")
    return events


def _tls_record_events(
    events: Sequence[WireEvent],
    protocol: Protocol,
    mode: str | None,
    archive_index: int,
) -> list[WireEvent]:
    """Normalize TCP chunks into complete, direction-labelled TLS records."""
    buffers = {True: bytearray(), False: bytearray()}
    records = []
    for event in events:
        pending = buffers[event.to_server]
        pending.extend(event.payload)
        while len(pending) >= 5:
            content_type = pending[0]
            record_length = int.from_bytes(pending[3:5], "big")
            total = 5 + record_length
            if content_type not in range(20, 25) or pending[1] != 3:
                raise RuntimeError("TCP stream contains non-TLS data")
            if record_length > 18432:
                raise RuntimeError("TLS record exceeds the supported wire limit")
            if len(pending) < total:
                break
            records.append(WireEvent(event.to_server, bytes(pending[:total])))
            del pending[:total]
    if any(buffers.values()):
        raise RuntimeError("TLS stream ended inside a record")
    if not records:
        raise RuntimeError("no complete TLS records found")
    if protocol is Protocol.TLS12:
        # The controlled objective is the client request.  Server application
        # records are not inputs to RSA/EMS derivation or client-record
        # authentication; public content types make this pruning possible at
        # collection time.  Server handshake and CCS records remain.
        records = [
            record
            for record in records
            if record.to_server or record.payload[0] not in {21, 23}
        ]
    elif protocol is Protocol.TLS13 and mode == "0rtt" and archive_index == 1:
        # Early data is client-only and derives from the complete resumed
        # ClientHello.  No server flight is needed for this selected objective.
        records = [record for record in records if record.to_server]
    return records


def _quic_packet_events(events: Sequence[WireEvent]) -> list[WireEvent]:
    """Normalize UDP datagrams into QUIC packets when boundaries are public."""
    from decryptor.quic.derive_quic import _iter_coalesced_packets

    packets = []
    for event in events:
        for packet in _iter_coalesced_packets(event.payload):
            if len(packet) < 5:
                continue
            if packet[0] & 0x80 and int.from_bytes(packet[1:5], "big") != 1:
                continue
            long_header = bool(packet[0] & 0x80)
            if long_header:
                packet_type = (packet[0] >> 4) & 0x03
                # Keep both Initial directions, including any Retry.  The
                # decoder needs the server Handshake flight but not the client
                # Handshake flight to derive application secrets.  Client
                # 0-RTT, when present, belongs to the selected request side.
                if packet_type == 2 and event.to_server:
                    continue
            elif not event.to_server:
                # The controlled proof authenticates the client request, so a
                # server short-header application response is outside X.
                continue
            packets.append(WireEvent(event.to_server, bytes(packet)))
    if not packets:
        raise RuntimeError("no QUIC v1 packets found")
    return packets


def _ssh_stream_events(events: Sequence[WireEvent]) -> list[WireEvent]:
    """Retain direction-separated SSH streams; encrypted lengths prevent pruning."""
    client = b"".join(event.payload for event in events if event.to_server)
    server = b"".join(event.payload for event in events if not event.to_server)
    if not client.startswith(b"SSH-") or not server.startswith(b"SSH-"):
        raise RuntimeError("reassembled streams are not a complete SSH exchange")
    return [WireEvent(True, client), WireEvent(False, server)]


def _raw_archives(manifest: RunManifest) -> list[str]:
    archives = [
        path
        for path in manifest.recovery.archives
        if Path(path).suffix in {".pcap", ".pcapng"}
    ]
    if not archives:
        raise ManifestError("source manifest has no raw PCAP archive")
    return archives


def _write_policy_manifest(
    destination: Path,
    source: RunManifest,
    spec: RecoverySpec,
    policy: ArchivePolicy,
    artifact_paths: Sequence[Path],
    source_raw_bytes: int,
    protocol_payload_bytes: int,
    representation: str,
) -> None:
    layout = ArtifactLayout(destination)
    relative_artifacts = [
        str(path.resolve().relative_to(layout.root)) for path in artifact_paths
    ]
    retained_bytes = sum(layout.resolve(path).stat().st_size for path in spec.archives)
    data = {
        "schema": "hndl-run-manifest-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "experiment": dict(source.data["experiment"]),
        "recovery": spec.to_dict(),
        "archive_policy": {
            "schema": "hndl-archive-policy-v1",
            "policy": policy.value,
            "wire_format": (
                ARCHIVE_FORMAT if policy is not ArchivePolicy.RAW else "pcapng"
            ),
            "representation": representation,
            "source_manifest_sha256": sha256_file(source.path),
            "source_raw_bytes": source_raw_bytes,
            "retained_bytes": retained_bytes,
            "protocol_payload_bytes": protocol_payload_bytes,
            "retention_ratio": retained_bytes / source_raw_bytes,
            "ground_truth_included": False,
            "objective": "authenticated recovery of the controlled application marker",
        },
        "commands": {
            "build": [
                "python3",
                "hndl.py",
                "archive",
                str(source.path.parent),
                "--policy",
                policy.value,
            ]
        },
        "implementation_sha256": {
            "archive_policy.py": sha256_file(Path(__file__)),
            "decryptor/io/pcap_parser.py": sha256_file(
                Path(__file__).parent / "decryptor/io/pcap_parser.py"
            ),
        },
        "artifacts": {
            relative: {
                "bytes": layout.resolve(relative).stat().st_size,
                "sha256": sha256_file(layout.resolve(relative)),
            }
            for relative in relative_artifacts
        },
        "evidence_boundary": {
            "attack_inputs": [*spec.archives, spec.simulated_recovery],
            "excluded_from_attack_inputs": list(spec.ground_truth),
        },
    }
    layout.manifest.write_text(json.dumps(data, indent=2) + "\n")


def build_policy_archive(
    capture_dir: Path | str,
    output_root: Path | str,
    policy: ArchivePolicy | str,
) -> ArchiveBuildResult:
    """Build one standalone archive containing no comparison-only ground truth."""
    source = RunManifest.load(capture_dir)
    source.verify_recorded_artifacts()
    source_layout = ArtifactLayout(Path(capture_dir))
    selected = ArchivePolicy.parse(policy)
    destination = Path(output_root).resolve()
    if destination.exists():
        if not destination.is_dir() or any(destination.iterdir()):
            raise FileExistsError(f"archive destination is not empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    layout = ArtifactLayout(destination)
    (layout.root / "archive").mkdir()
    layout.keys_dir.mkdir()
    layout.derived_dir.mkdir()

    raw_names = _raw_archives(source)
    raw_paths = [source_layout.resolve(name) for name in raw_names]
    source_raw_bytes = sum(path.stat().st_size for path in raw_paths)
    artifact_paths = []
    archive_names = []
    protocol_payload_bytes = 0

    if selected is ArchivePolicy.RAW:
        for index, source_path in enumerate(raw_paths):
            relative = f"archive/raw-{index}-{source_path.name}"
            destination_path = layout.resolve(relative)
            shutil.copyfile(source_path, destination_path)
            artifact_paths.append(destination_path)
            archive_names.append(relative)
        protocol_payload_bytes = source_raw_bytes
        representation = "complete packet capture"
    else:
        for index, source_path in enumerate(raw_paths):
            if source.recovery.protocol is Protocol.QUIC:
                events = _udp_events(source_path, source.recovery.port)
                if selected is ArchivePolicy.COMPACT:
                    events = _quic_packet_events(events)
            else:
                events = _tcp_events(source_path, source.recovery.port)
                if selected is ArchivePolicy.COMPACT:
                    if source.recovery.protocol in {Protocol.TLS12, Protocol.TLS13}:
                        events = _tls_record_events(
                            events,
                            source.recovery.protocol,
                            (
                                source.recovery.mode.value
                                if source.recovery.mode
                                else None
                            ),
                            index,
                        )
                    else:
                        events = _ssh_stream_events(events)
            encoded = _encode_wire_events(events)
            relative = f"archive/{selected.value}-{index}.hndl"
            destination_path = layout.resolve(relative)
            destination_path.write_bytes(encoded)
            artifact_paths.append(destination_path)
            archive_names.append(relative)
            protocol_payload_bytes += sum(len(event.payload) for event in events)
        representation = (
            "ordered transport payloads without link/network headers or retransmissions"
            if selected is ArchivePolicy.REASSEMBLED
            else "protocol units visible at collection time"
        )

    recovery_destination = layout.resolve(source.recovery.simulated_recovery)
    recovery_destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(
        source_layout.resolve(source.recovery.simulated_recovery), recovery_destination
    )
    artifact_paths.append(recovery_destination)

    spec = RecoverySpec(
        source.recovery.protocol,
        source.recovery.mode,
        source.recovery.port,
        tuple(archive_names),
        source.recovery.simulated_recovery,
        source.recovery.ground_truth,
        source.recovery.derived,
    )
    spec._validate()
    _write_policy_manifest(
        destination,
        source,
        spec,
        selected,
        artifact_paths,
        source_raw_bytes,
        protocol_payload_bytes,
        representation,
    )
    return ArchiveBuildResult(
        destination,
        selected,
        source_raw_bytes,
        sum(layout.resolve(path).stat().st_size for path in spec.archives),
        protocol_payload_bytes,
    )


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4_header(
    source: bytes, destination: bytes, payload_length: int, protocol: int, identity: int
) -> bytes:
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20 + payload_length,
        identity & 0xFFFF,
        0x4000,
        64,
        protocol,
        0,
        source,
        destination,
    )
    checksum = _checksum(header)
    return header[:10] + struct.pack(">H", checksum) + header[12:]


def _ethernet(payload: bytes) -> bytes:
    return bytes.fromhex("0200000000020200000000010800") + payload


class _PcapWriter:
    def __init__(self, path: Path):
        self._handle = path.open("wb")
        self._handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self._counter = 0

    def write(self, packet: bytes) -> None:
        self._counter += 1
        seconds = 1 + self._counter // 1_000_000
        microseconds = self._counter % 1_000_000
        self._handle.write(
            struct.pack("<IIII", seconds, microseconds, len(packet), len(packet))
        )
        self._handle.write(packet)

    def close(self) -> None:
        self._handle.close()


def _tcp_packet(
    payload: bytes,
    to_server: bool,
    service_port: int,
    client_port: int,
    sequence: int,
    acknowledgement: int,
    flags: int,
    identity: int,
) -> bytes:
    client_ip = socket.inet_aton("127.0.0.1")
    server_ip = socket.inet_aton("127.0.0.2")
    source_ip, destination_ip = (
        (client_ip, server_ip) if to_server else (server_ip, client_ip)
    )
    source_port, destination_port = (
        (client_port, service_port) if to_server else (service_port, client_port)
    )
    header = struct.pack(
        ">HHIIBBHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        5 << 4,
        flags,
        65535,
        0,
        0,
    )
    pseudo = (
        source_ip
        + destination_ip
        + struct.pack(">BBH", 0, 6, len(header) + len(payload))
    )
    checksum = _checksum(pseudo + header + payload)
    header = header[:16] + struct.pack(">H", checksum) + header[18:]
    ip = _ipv4_header(
        source_ip, destination_ip, len(header) + len(payload), 6, identity
    )
    return _ethernet(ip + header + payload)


def _udp_packet(
    payload: bytes,
    to_server: bool,
    service_port: int,
    client_port: int,
    identity: int,
) -> bytes:
    client_ip = socket.inet_aton("127.0.0.1")
    server_ip = socket.inet_aton("127.0.0.2")
    source_ip, destination_ip = (
        (client_ip, server_ip) if to_server else (server_ip, client_ip)
    )
    source_port, destination_port = (
        (client_port, service_port) if to_server else (service_port, client_port)
    )
    udp = struct.pack(">HHHH", source_port, destination_port, 8 + len(payload), 0)
    ip = _ipv4_header(source_ip, destination_ip, len(udp) + len(payload), 17, identity)
    return _ethernet(ip + udp + payload)


def _write_tcp_pcap(path: Path, events: Sequence[WireEvent], port: int) -> None:
    writer = _PcapWriter(path)
    client_port = 55000 if port != 55000 else 55001
    client_sequence, server_sequence = 1000, 5000
    identity = 1
    try:
        writer.write(
            _tcp_packet(
                b"", True, port, client_port, client_sequence, 0, 0x02, identity
            )
        )
        client_sequence += 1
        identity += 1
        writer.write(
            _tcp_packet(
                b"",
                False,
                port,
                client_port,
                server_sequence,
                client_sequence,
                0x12,
                identity,
            )
        )
        server_sequence += 1
        identity += 1
        writer.write(
            _tcp_packet(
                b"",
                True,
                port,
                client_port,
                client_sequence,
                server_sequence,
                0x10,
                identity,
            )
        )
        identity += 1
        for event in events:
            for offset in range(0, len(event.payload), 1200):
                chunk = event.payload[offset : offset + 1200]
                sequence = client_sequence if event.to_server else server_sequence
                acknowledgement = (
                    server_sequence if event.to_server else client_sequence
                )
                writer.write(
                    _tcp_packet(
                        chunk,
                        event.to_server,
                        port,
                        client_port,
                        sequence,
                        acknowledgement,
                        0x18,
                        identity,
                    )
                )
                identity += 1
                if event.to_server:
                    client_sequence += len(chunk)
                else:
                    server_sequence += len(chunk)
    finally:
        writer.close()


def _write_udp_pcap(path: Path, events: Sequence[WireEvent], port: int) -> None:
    writer = _PcapWriter(path)
    client_port = 55000 if port != 55000 else 55001
    try:
        for identity, event in enumerate(events, 1):
            writer.write(
                _udp_packet(event.payload, event.to_server, port, client_port, identity)
            )
    finally:
        writer.close()


@contextmanager
def materialized_recovery_spec(
    capture_dir: Path | str, spec: RecoverySpec
) -> Iterator[RecoverySpec]:
    """Yield PCAP-backed inputs for a policy archive, removing adapters afterward."""
    root = Path(capture_dir).resolve()
    manifest = RunManifest.load(root)
    metadata = manifest.data.get("archive_policy")
    if not isinstance(metadata, dict):
        yield spec
        return
    try:
        policy = ArchivePolicy.parse(str(metadata.get("policy")))
    except ValueError as exc:
        raise ManifestError(str(exc)) from exc
    if policy is ArchivePolicy.RAW:
        yield spec
        return
    if metadata.get("wire_format") != ARCHIVE_FORMAT:
        raise ManifestError(
            f"unsupported archive wire format: {metadata.get('wire_format')}"
        )

    layout = ArtifactLayout(root)
    layout.derived_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".policy-input-", dir=layout.derived_dir
    ) as temporary:
        temporary_path = Path(temporary)
        materialized = []
        for index, relative in enumerate(spec.archives):
            events = _decode_wire_events(layout.resolve(relative))
            pcap = temporary_path / f"archive-{index}.pcap"
            if spec.protocol is Protocol.QUIC:
                _write_udp_pcap(pcap, events, spec.port)
            else:
                _write_tcp_pcap(pcap, events, spec.port)
            materialized.append(str(pcap.relative_to(layout.root)))
        yield RecoverySpec(
            spec.protocol,
            spec.mode,
            spec.port,
            tuple(materialized),
            spec.simulated_recovery,
            spec.ground_truth,
            spec.derived,
        )
