"""QUIC archive policy (RFC 9000 and RFC 9001).

UDP/IP framing is reconstructed, but each protected QUIC packet/datagram is
retained whole.  In particular, no authentication tag bytes are stripped:
RFC 9001 section 5.4.2 can sample those bytes for header protection.
"""

from pathlib import Path

from ..pcap import extract_quic_cipher_suites, extract_udp_datagrams
from ..profiles import ProtocolProfile
from .common import compact_chunk_pcaps, materialize_chunk_pcaps, resolve_pcaps


PCAP_NAMES = ["quic.pcapng"]
RECOVERY_FILES = ["simulated_quantum_output.json"]
RECOVERY_FILES_BY_MODE = {}
OPTIONAL_RECOVERY_FILES = ["sslkeylog.log"]


def compact(capture_dir: Path, mode: str, port: int, profile: ProtocolProfile):
    if mode != "default":
        raise ValueError("QUIC uses mode 'default'")
    pcaps = resolve_pcaps(capture_dir, PCAP_NAMES)
    versions = {
        int.from_bytes(chunk.data[1:5], "big")
        for chunk in extract_udp_datagrams(pcaps[0], port)
        if len(chunk.data) >= 5 and chunk.data[0] & 0x80
    }
    if profile.quic_version not in versions:
        raise ValueError(
            f"trace does not contain a QUIC v{profile.quic_version} long header"
        )
    cipher_suites = extract_quic_cipher_suites(pcaps[0], port)
    if profile.cipher_suite_id not in cipher_suites:
        observed = ", ".join(f"0x{value:04x}" for value in sorted(cipher_suites))
        raise ValueError(
            f"QUIC ServerHello does not select profile {profile.cipher_suite}; "
            f"observed {observed or 'no parseable ciphersuite'}"
        )
    layout, opaque, measurements = compact_chunk_pcaps(
        pcaps,
        port,
        "udp",
        # The local readiness probe is exactly one zero byte.  Retain all other
        # datagrams, including Version Negotiation packets whose fixed bit is 0.
        chunk_filter=lambda chunk: chunk.data != b"\x00",
    )
    return (
        layout,
        opaque,
        {
            "policy": "complete-quic-datagrams",
            "authentication_tags": "retained",
            "header_protection_samples": "retained",
            "future_recovery_input": "client X25519 private scalar; peer public share is reconstructed from Initial packets",
            "profile_validation": "QUIC version and public-Initial TLS ciphersuite checked",
            "captures": measurements,
        },
    )


def materialize(
    layout: bytes, opaque: bytes, metadata: dict, output_dir: Path, port: int
):
    materialize_chunk_pcaps(layout, opaque, output_dir, PCAP_NAMES, port, "udp")
