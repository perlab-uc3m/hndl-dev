"""Shared transport and TLS-record representations."""

from __future__ import annotations

from pathlib import Path

from ..binary import DecodeError, Reader, encode_blob, encode_uvarint
from ..pcap import Chunk, extract_tcp_chunks, extract_udp_datagrams, write_pcap


CONTENT_CODES = {20: 0, 21: 1, 22: 2, 23: 3, 24: 4}
CODE_CONTENTS = {value: key for key, value in CONTENT_CODES.items()}
VERSION_CODES = {b"\x03\x03": 0, b"\x03\x01": 1, b"\x03\x02": 2, b"\x03\x04": 3}
CODE_VERSIONS = {value: key for key, value in VERSION_CODES.items()}


OPAQUE_FRAGMENT = 0x40


def split_tls_records(chunks: list[Chunk]) -> list[tuple[int, int, bytes, bytes]]:
    """Reassemble TLS records while retaining their observed completion order."""
    pending = [bytearray(), bytearray()]
    records: list[tuple[int, int, bytes, bytes]] = []
    for chunk in chunks:
        buf = pending[chunk.direction]
        buf.extend(chunk.data)
        while len(buf) >= 5:
            record_len = int.from_bytes(buf[3:5], "big")
            if record_len > 18432:
                raise ValueError(f"invalid TLS record length {record_len}")
            if len(buf) < 5 + record_len:
                break
            records.append(
                (
                    chunk.direction,
                    buf[0],
                    bytes(buf[1:3]),
                    bytes(buf[5 : 5 + record_len]),
                )
            )
            del buf[: 5 + record_len]
    if pending[0] or pending[1]:
        raise ValueError("TCP stream ended in the middle of a TLS record")
    return records


def _encode_tls_records(chunks: list[Chunk]) -> tuple[bytes, bytes, dict]:
    records = split_tls_records(chunks)

    out = bytearray(encode_uvarint(len(records)))
    opaque = bytearray()
    protected = 0
    handshake = 0
    clear_protocol = 0
    encryption_active = [False, False]
    for direction, content_type, version, fragment in records:
        content_code = CONTENT_CODES.get(content_type, 7)
        version_code = VERSION_CODES.get(version, 7)
        # Application records are always opaque.  In TLS 1.2, ChangeCipherSpec
        # activates record protection independently in each direction, so the
        # following Finished/alert records are opaque too.  TLS 1.3 protected
        # records already use the application_data outer type.
        is_opaque = content_type == 23 or encryption_active[direction]
        out.append(
            (direction << 7)
            | (OPAQUE_FRAGMENT if is_opaque else 0)
            | (version_code << 3)
            | content_code
        )
        if content_code == 7:
            out.append(content_type)
        if version_code == 7:
            out.extend(version)
        if is_opaque:
            out.extend(encode_uvarint(len(fragment)))
            opaque.extend(fragment)
            protected += len(fragment)
        else:
            out.extend(encode_blob(fragment))
            clear_protocol += len(fragment)
        if content_type == 22:
            handshake += len(fragment)
        if content_type == 20:
            encryption_active[direction] = True
    return bytes(out), bytes(opaque), {
        "record_count": len(records),
        "record_header_bytes_removed": 5 * len(records),
        "protected_record_payload_bytes": protected,
        "opaque_bytes": protected,
        "clear_protocol_bytes": clear_protocol,
        "clear_handshake_payload_bytes": handshake,
        "transport_payload_bytes": sum(len(chunk.data) for chunk in chunks),
    }


def _decode_tls_records(layout: bytes, opaque_reader: Reader) -> list[Chunk]:
    reader = Reader(layout)
    count = reader.uvarint(10_000_000)
    records = []
    for _ in range(count):
        tag = reader.byte()
        direction = tag >> 7
        is_opaque = bool(tag & OPAQUE_FRAGMENT)
        version_code = (tag >> 3) & 0x07
        content_code = tag & 0x07
        content_type = (
            reader.byte() if content_code == 7 else CODE_CONTENTS.get(content_code)
        )
        version = (
            reader.take(2) if version_code == 7 else CODE_VERSIONS.get(version_code)
        )
        if content_type is None or version is None:
            raise DecodeError("invalid TLS record code")
        if is_opaque:
            fragment = opaque_reader.take(reader.uvarint(18432))
        else:
            fragment = reader.blob(18432)
        record = (
            bytes([content_type])
            + version
            + len(fragment).to_bytes(2, "big")
            + fragment
        )
        records.append(Chunk(direction, record))
    reader.finish()
    return records


def compact_tls_pcaps(
    pcaps: list[Path], server_port: int, trace_validator=None
) -> tuple[bytes, bytes, list[dict]]:
    out = bytearray(encode_uvarint(len(pcaps)))
    opaque = bytearray()
    measurements = []
    for index, pcap in enumerate(pcaps):
        chunks = extract_tcp_chunks(pcap, server_port)
        if trace_validator is not None:
            trace_validator(chunks, index)
        encoded, capture_opaque, stats = _encode_tls_records(chunks)
        out.extend(encode_blob(encoded))
        opaque.extend(capture_opaque)
        stats["raw_capture_bytes"] = pcap.stat().st_size
        stats["source_name"] = pcap.name
        measurements.append(stats)
    return bytes(out), bytes(opaque), measurements


def materialize_tls_pcaps(
    layout: bytes,
    opaque: bytes,
    output_dir: Path,
    names: list[str],
    server_port: int,
) -> None:
    reader = Reader(layout)
    opaque_reader = Reader(opaque)
    count = reader.uvarint(32)
    if count != len(names):
        raise DecodeError(
            f"archive contains {count} captures; mode requires {len(names)}"
        )
    for name in names:
        chunks = _decode_tls_records(reader.blob(), opaque_reader)
        write_pcap(output_dir / "pcap" / name, chunks, "tcp", server_port)
    reader.finish()
    opaque_reader.finish()


def compact_chunk_pcaps(
    pcaps: list[Path], server_port: int, transport: str, chunk_filter=None
) -> tuple[bytes, bytes, list[dict]]:
    out = bytearray(encode_uvarint(len(pcaps)))
    opaque = bytearray()
    measurements = []
    for pcap in pcaps:
        chunks = (
            extract_tcp_chunks(pcap, server_port)
            if transport == "tcp"
            else extract_udp_datagrams(pcap, server_port)
        )
        original_count = len(chunks)
        if chunk_filter is not None:
            chunks = [chunk for chunk in chunks if chunk_filter(chunk)]
            if not chunks:
                raise ValueError(f"no protocol packets retained from {pcap}")
        encoded = bytearray(encode_uvarint(len(chunks)))
        for chunk in chunks:
            encoded.append(chunk.direction)
            encoded.extend(encode_uvarint(len(chunk.data)))
            opaque.extend(chunk.data)
        out.extend(encode_blob(bytes(encoded)))
        measurements.append(
            {
                "source_name": pcap.name,
                "raw_capture_bytes": pcap.stat().st_size,
                "transport_payload_bytes": sum(len(chunk.data) for chunk in chunks),
                "opaque_bytes": sum(len(chunk.data) for chunk in chunks),
                "clear_protocol_bytes": 0,
                "unit_count": len(chunks),
                "discarded_non_protocol_units": original_count - len(chunks),
            }
        )
    return bytes(out), bytes(opaque), measurements


def materialize_chunk_pcaps(
    layout: bytes,
    opaque: bytes,
    output_dir: Path,
    names: list[str],
    server_port: int,
    transport: str,
) -> None:
    reader = Reader(layout)
    opaque_reader = Reader(opaque)
    count = reader.uvarint(32)
    if count != len(names):
        raise DecodeError(
            f"archive contains {count} captures; mode requires {len(names)}"
        )
    for name in names:
        capture_reader = Reader(reader.blob())
        chunk_count = capture_reader.uvarint(10_000_000)
        chunks = []
        for _ in range(chunk_count):
            direction = capture_reader.byte()
            if direction not in (0, 1):
                raise DecodeError("invalid direction")
            chunks.append(
                Chunk(direction, opaque_reader.take(capture_reader.uvarint()))
            )
        capture_reader.finish()
        write_pcap(output_dir / "pcap" / name, chunks, transport, server_port)
    reader.finish()
    opaque_reader.finish()


def resolve_pcaps(capture_dir: Path, names: list[str]) -> list[Path]:
    pcaps = [capture_dir / "pcap" / name for name in names]
    missing = [str(path) for path in pcaps if not path.is_file()]
    if missing:
        raise FileNotFoundError("missing capture file(s): " + ", ".join(missing))
    return pcaps


def clear_handshake_messages(chunks: list[Chunk]) -> list[tuple[int, bytes]]:
    """Return complete messages from cleartext TLS Handshake records."""
    buffers = [bytearray(), bytearray()]
    messages: list[tuple[int, bytes]] = []
    for direction, content_type, _, fragment in split_tls_records(chunks):
        if content_type != 22:
            continue
        buffer = buffers[direction]
        buffer.extend(fragment)
        while len(buffer) >= 4:
            length = int.from_bytes(buffer[1:4], "big")
            if length > 1 << 24:
                raise ValueError("invalid TLS handshake length")
            if len(buffer) < 4 + length:
                break
            messages.append((direction, bytes(buffer[: 4 + length])))
            del buffer[: 4 + length]
    return messages


def tls_hello_parameters(chunks: list[Chunk]) -> dict:
    """Extract profile-relevant parameters from clear Client/ServerHello."""
    client_hello = server_hello = None
    for _, message in clear_handshake_messages(chunks):
        if message[0] == 1 and client_hello is None:
            client_hello = message
        elif message[0] == 2 and server_hello is None:
            server_hello = message
    if client_hello is None:
        raise ValueError("profile validation could not find ClientHello")

    client_extensions = _hello_extensions(client_hello, server=False)
    result = {
        "client_extension_types": set(client_extensions),
        "resumption_offered": 41 in client_extensions,
        "early_data_offered": 42 in client_extensions,
    }
    client_key_share = client_extensions.get(51)
    if client_key_share and len(client_key_share) >= 4:
        result["client_key_share_group"] = int.from_bytes(
            client_key_share[2:4], "big"
        )
    if server_hello is not None:
        position = 4 + 2 + 32
        if position >= len(server_hello):
            raise ValueError("truncated ServerHello")
        session_id_length = server_hello[position]
        position += 1 + session_id_length
        if position + 2 > len(server_hello):
            raise ValueError("truncated ServerHello cipher suite")
        result["cipher_suite_id"] = int.from_bytes(
            server_hello[position : position + 2], "big"
        )
        server_extensions = _hello_extensions(server_hello, server=True)
        result["server_extension_types"] = set(server_extensions)
        result["extended_master_secret"] = 23 in server_extensions
        result["resumption_selected"] = 41 in server_extensions
        server_key_share = server_extensions.get(51)
        if server_key_share and len(server_key_share) >= 2:
            result["server_key_share_group"] = int.from_bytes(
                server_key_share[:2], "big"
            )
    return result


def _hello_extensions(message: bytes, server: bool) -> dict[int, bytes]:
    """Parse extension TLVs from a TLS 1.2/1.3 ClientHello or ServerHello."""
    position = 4 + 2 + 32
    if position >= len(message):
        raise ValueError("truncated Hello")
    session_id_length = message[position]
    position += 1 + session_id_length
    if server:
        position += 2 + 1  # cipher suite and compression method
    else:
        if position + 2 > len(message):
            raise ValueError("truncated ClientHello cipher suites")
        cipher_suites_length = int.from_bytes(message[position : position + 2], "big")
        position += 2 + cipher_suites_length
        if position >= len(message):
            raise ValueError("truncated ClientHello compression methods")
        compression_length = message[position]
        position += 1 + compression_length
    if position == len(message):
        return {}
    if position + 2 > len(message):
        raise ValueError("truncated Hello extensions")
    extensions_length = int.from_bytes(message[position : position + 2], "big")
    position += 2
    end = position + extensions_length
    if end > len(message):
        raise ValueError("Hello extension block exceeds message")
    extensions = {}
    while position + 4 <= end:
        extension_type = int.from_bytes(message[position : position + 2], "big")
        extension_length = int.from_bytes(message[position + 2 : position + 4], "big")
        position += 4
        if position + extension_length > end:
            raise ValueError("truncated Hello extension")
        extensions[extension_type] = message[position : position + extension_length]
        position += extension_length
    if position != end:
        raise ValueError("malformed Hello extensions")
    return extensions
