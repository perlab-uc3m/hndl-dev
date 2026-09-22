"""MinARX v1 container format.

Layout (network byte order)::

    magic[8] | version:u8 | profile:u8 | compression:u8 | flags:u8
    server_port:u16 | raw_capture_len:u32 | transport_payload_len:u32
    layout_stored_len:u32 | layout_plain_len:u32 | opaque_len:u32
    stored_protocol_layout | opaque_protected_bytes | sha256(all_previous)

The digest is a corruption boundary, not a MAC.  Authentication still comes
from the archived protocol records when the recovered key material is applied.
"""

from __future__ import annotations

import hashlib
import lzma
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

from .profiles import PROFILE_IDS, PROFILES_BY_ID, ProtocolProfile


MAGIC = b"MINARX\r\n"
VERSION = 1
HEADER = struct.Struct(">8sBBBBHIIIII")
DIGEST_SIZE = 32
MAX_ARCHIVE_PAYLOAD = 2 * 1024 * 1024 * 1024

COMPRESSION_NAMES = {0: "none", 1: "deflate", 2: "lzma"}


class FormatError(ValueError):
    pass


@dataclass(frozen=True)
class Container:
    profile: ProtocolProfile
    server_port: int
    raw_capture_bytes: int
    transport_payload_bytes: int
    layout: bytes
    opaque: bytes
    compression: str
    archive_bytes: int
    stored_layout_bytes: int


def _compress(layout: bytes, requested: str) -> tuple[int, bytes]:
    """Compress protocol layout only; opaque protected data is never passed here."""
    if requested == "none":
        return 0, layout
    if requested == "deflate":
        return 1, zlib.compress(layout, level=9)
    if requested == "lzma":
        return 2, lzma.compress(layout, preset=9 | lzma.PRESET_EXTREME)
    if requested == "auto":
        candidates = [
            (0, layout),
            (1, zlib.compress(layout, level=9)),
            (2, lzma.compress(layout, preset=9 | lzma.PRESET_EXTREME)),
        ]
        return min(candidates, key=lambda item: len(item[1]))
    raise ValueError(f"unknown compression: {requested}")


def write_container(
    path: Path,
    profile: ProtocolProfile,
    server_port: int,
    raw_capture_bytes: int,
    transport_payload_bytes: int,
    layout: bytes,
    opaque: bytes,
    compression: str = "auto",
) -> int:
    try:
        profile_id = PROFILE_IDS[profile.name]
    except KeyError as exc:
        raise ValueError(f"profile has no stable MinARX ID: {profile.name}") from exc
    if not 0 < server_port <= 65535:
        raise ValueError("server port is outside the uint16 range")
    if not (
        0
        <= len(opaque)
        <= transport_payload_bytes
        <= raw_capture_bytes
        <= MAX_ARCHIVE_PAYLOAD
    ):
        raise ValueError("archive byte counters are inconsistent")
    if len(layout) > MAX_ARCHIVE_PAYLOAD:
        raise ValueError("protocol layout exceeds the MinARX v1 limit")
    compression_id, stored_layout = _compress(layout, compression)
    header = HEADER.pack(
        MAGIC,
        VERSION,
        profile_id,
        compression_id,
        0,  # reserved v1 flags
        server_port,
        raw_capture_bytes,
        transport_payload_bytes,
        len(stored_layout),
        len(layout),
        len(opaque),
    )
    body = header + stored_layout + opaque
    encoded = body + hashlib.sha256(body).digest()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return len(encoded)


def read_container(path: Path, max_payload: int = MAX_ARCHIVE_PAYLOAD) -> Container:
    encoded = path.read_bytes()
    if len(encoded) < HEADER.size + DIGEST_SIZE:
        raise FormatError("archive is shorter than its fixed framing")
    body, digest = encoded[:-DIGEST_SIZE], encoded[-DIGEST_SIZE:]
    if not hashlib.sha256(body).digest() == digest:
        raise FormatError("archive SHA-256 mismatch")
    fields = HEADER.unpack(body[: HEADER.size])
    (
        magic,
        version,
        profile_id,
        compression_id,
        flags,
        server_port,
        raw_capture_bytes,
        transport_payload_bytes,
        layout_stored_len,
        layout_plain_len,
        opaque_len,
    ) = fields
    if magic != MAGIC:
        raise FormatError("not a MinARX archive")
    if version != VERSION:
        raise FormatError(f"unsupported MinARX version {version}")
    if profile_id not in PROFILES_BY_ID:
        raise FormatError("unknown protocol profile identifier")
    if compression_id not in COMPRESSION_NAMES:
        raise FormatError("unknown compression identifier")
    if flags:
        raise FormatError("unsupported MinARX flags")
    if not 0 < server_port <= 65535:
        raise FormatError("invalid server port")
    if not 0 <= opaque_len <= transport_payload_bytes <= raw_capture_bytes:
        raise FormatError("archive byte counters are inconsistent")
    if (
        raw_capture_bytes > max_payload
        or transport_payload_bytes > max_payload
        or layout_stored_len > max_payload
        or layout_plain_len > max_payload
        or opaque_len > max_payload
    ):
        raise FormatError(f"declared section exceeds {max_payload} bytes")
    expected = HEADER.size + layout_stored_len + opaque_len
    if expected != len(body):
        raise FormatError("archive lengths do not match file size")
    layout_start = HEADER.size
    stored_layout = body[layout_start : layout_start + layout_stored_len]
    opaque = body[layout_start + layout_stored_len :]
    try:
        if compression_id == 0:
            layout = stored_layout
        elif compression_id == 1:
            decoder = zlib.decompressobj()
            layout = decoder.decompress(stored_layout, layout_plain_len + 1)
            if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise FormatError("invalid or oversized DEFLATE layout")
        else:
            decoder = lzma.LZMADecompressor()
            layout = decoder.decompress(stored_layout, max_length=layout_plain_len + 1)
            if not decoder.eof or decoder.unused_data:
                raise FormatError("invalid or oversized LZMA layout")
    except (zlib.error, lzma.LZMAError) as exc:
        raise FormatError("invalid compressed payload") from exc
    if len(layout) != layout_plain_len:
        raise FormatError("decompressed layout length mismatch")
    if len(opaque) != opaque_len:
        raise FormatError("opaque section length mismatch")
    return Container(
        profile=PROFILES_BY_ID[profile_id],
        server_port=server_port,
        raw_capture_bytes=raw_capture_bytes,
        transport_payload_bytes=transport_payload_bytes,
        layout=layout,
        opaque=opaque,
        compression=COMPRESSION_NAMES[compression_id],
        archive_bytes=len(encoded),
        stored_layout_bytes=len(stored_layout),
    )
