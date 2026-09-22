"""TLS 1.2 RSA archive policy (RFC 5246; EMS audit per RFC 7627).

TCP/IP framing and TLS record lengths are reconstructed.  Record contents are
retained because the EMS negotiation changes whether the pre-ClientKeyExchange
transcript is part of master-secret derivation.  Certificate dictionary coding
is deliberately left for a collection-wide layer rather than assumed free.
"""

from pathlib import Path

from ..profiles import ProtocolProfile
from .common import (
    compact_tls_pcaps,
    materialize_tls_pcaps,
    resolve_pcaps,
    tls_hello_parameters,
)


PCAP_NAMES = ["tls12_rsa.pcapng"]
RECOVERY_FILES = ["simulated_quantum_output.pem"]
RECOVERY_FILES_BY_MODE = {}
OPTIONAL_RECOVERY_FILES = ["sslkeylog.log"]


def compact(capture_dir: Path, mode: str, port: int, profile: ProtocolProfile):
    if mode != "rsa":
        raise ValueError("TLS 1.2 compaction currently supports rsa mode")

    def validate(chunks, _index):
        parameters = tls_hello_parameters(chunks)
        if parameters.get("cipher_suite_id") != profile.cipher_suite_id:
            raise ValueError(
                f"trace cipher suite 0x{parameters.get('cipher_suite_id', 0):04x} "
                f"does not match profile {profile.cipher_suite}"
            )
        if (
            parameters.get("extended_master_secret", False)
            != profile.extended_master_secret
        ):
            raise ValueError("trace EMS negotiation does not match MinARX profile")

    layout, opaque, measurements = compact_tls_pcaps(
        resolve_pcaps(capture_dir, PCAP_NAMES), port, validate
    )
    return (
        layout,
        opaque,
        {
            "policy": "tls-records",
            "future_recovery_input": "RSA private key corresponding to the archived certificate public key",
            "captures": measurements,
        },
    )


def materialize(
    layout: bytes, opaque: bytes, metadata: dict, output_dir: Path, port: int
):
    materialize_tls_pcaps(layout, opaque, output_dir, PCAP_NAMES, port)
