"""SSH archive policy (RFC 4253).

The ordered directional TCP byte stream is retained.  SSH encrypts its packet
length, so an online collector cannot safely import post-KEX packet boundaries
before the future recovery output is available.  The stream is therefore kept
in the opaque region; only direction and length descriptors are compressible.
"""

from pathlib import Path

from ..binary import DecodeError, Reader
from ..pcap import Chunk, extract_tcp_chunks
from ..profiles import ProtocolProfile
from .common import compact_chunk_pcaps, materialize_chunk_pcaps, resolve_pcaps


PCAP_NAMES = ["ssh_session.pcapng"]
RECOVERY_FILES = ["simulated_quantum_output.json"]
RECOVERY_FILES_BY_MODE = {}
OPTIONAL_RECOVERY_FILES = []


def _name_list(reader: Reader) -> list[str]:
    try:
        value = reader.take(int.from_bytes(reader.take(4), "big")).decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("SSH KEXINIT contains a non-ASCII name-list") from exc
    return value.split(",") if value else []


def _first_kexinit(stream: bytes) -> list[list[str]]:
    banner_start = stream.find(b"SSH-")
    banner_end = stream.find(b"\n", banner_start)
    if banner_start < 0 or banner_end < 0:
        raise ValueError("SSH profile validation could not find identification")
    reader = Reader(stream[banner_end + 1 :])
    try:
        while reader.offset < len(reader.data):
            packet_length = int.from_bytes(reader.take(4), "big")
            if packet_length < 6 or packet_length > 35000:
                raise ValueError("invalid clear SSH packet length")
            packet = Reader(reader.take(packet_length))
            padding_length = packet.byte()
            if padding_length < 4 or padding_length >= packet_length:
                raise ValueError("invalid clear SSH padding length")
            payload = packet.take(packet_length - padding_length - 1)
            packet.take(padding_length)
            packet.finish()
            if payload and payload[0] == 20:  # SSH_MSG_KEXINIT
                fields = Reader(payload[1:])
                fields.take(16)  # cookie
                lists = [_name_list(fields) for _ in range(10)]
                fields.byte()  # first_kex_packet_follows
                fields.take(4)  # reserved
                fields.finish()
                return lists
    except DecodeError as exc:
        raise ValueError("truncated clear SSH KEXINIT") from exc
    raise ValueError("SSH profile validation could not find KEXINIT")


def _negotiate(client: list[str], server: list[str], kind: str) -> str:
    try:
        return next(name for name in client if name in server)
    except StopIteration as exc:
        raise ValueError(f"SSH peers have no common {kind}") from exc


def _validate_profile(chunks: list[Chunk], profile: ProtocolProfile) -> None:
    streams = [bytearray(), bytearray()]
    for chunk in chunks:
        streams[chunk.direction].extend(chunk.data)
    client, server = (_first_kexinit(bytes(stream)) for stream in streams)
    negotiated_kex = _negotiate(client[0], server[0], "key exchange")
    client_to_server = _negotiate(client[2], server[2], "client cipher")
    server_to_client = _negotiate(client[3], server[3], "server cipher")
    if negotiated_kex != profile.key_exchange:
        raise ValueError(
            f"trace KEX {negotiated_kex} does not match profile {profile.key_exchange}"
        )
    if {client_to_server, server_to_client} != {profile.cipher_suite}:
        raise ValueError(
            "trace SSH cipher negotiation does not match MinARX profile "
            f"{profile.cipher_suite}"
        )


def compact(capture_dir: Path, mode: str, port: int, profile: ProtocolProfile):
    if mode != "default":
        raise ValueError("SSH uses mode 'default'")
    pcaps = resolve_pcaps(capture_dir, PCAP_NAMES)
    _validate_profile(extract_tcp_chunks(pcaps[0], port), profile)
    layout, opaque, measurements = compact_chunk_pcaps(pcaps, port, "tcp")
    return (
        layout,
        opaque,
        {
            "policy": "ordered-directional-ciphertext-stream",
            "encrypted_packet_boundaries": "not-assumed",
            "future_recovery_input": "current decoder imports endpoint K/H/session_id and remains an explicit incomplete evidence boundary",
            "authenticated_passive_recovery": False,
            "profile_validation": "KEX and both directional ciphers checked from clear KEXINIT",
            "captures": measurements,
        },
    )


def materialize(
    layout: bytes, opaque: bytes, metadata: dict, output_dir: Path, port: int
):
    materialize_chunk_pcaps(layout, opaque, output_dir, PCAP_NAMES, port, "tcp")
