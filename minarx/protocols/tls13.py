"""TLS 1.3 full-handshake and resumption archive policies (RFC 8446).

The complete record fragments are retained.  An online collector cannot hash
the encrypted post-ServerHello transcript, so replacing it with a final digest
would be unsound.  HelloRetryRequest is rejected by the exercised-mode marker
rather than silently treated as an ordinary ServerHello transcript.
"""

from pathlib import Path

from ..profiles import ProtocolProfile
from .common import (
    compact_tls_pcaps,
    materialize_tls_pcaps,
    resolve_pcaps,
    tls_hello_parameters,
)


NAMES = {
    "1rtt": ["tls13_1rtt.pcapng"],
    "0rtt": ["tls13_0rtt_phase1_initial.pcapng", "tls13_0rtt_phase2_resumption.pcapng"],
    "external-psk": ["tls13_external_psk.pcapng"],
}
RECOVERY_FILES = ["simulated_quantum_output.json"]
RECOVERY_FILES_BY_MODE = {
    "external-psk": ["simulated_external_psk.json"],
}
OPTIONAL_RECOVERY_FILES = ["sslkeylog.log"]


def compact(
    capture_dir: Path, mode: str, port: int, profile: ProtocolProfile
):
    if mode not in NAMES:
        raise ValueError(
            "TLS 1.3 compaction mode must be 1rtt, 0rtt, or external-psk"
        )
    def validate(chunks, index):
        parameters = tls_hello_parameters(chunks)
        if parameters.get("cipher_suite_id") != profile.cipher_suite_id:
            raise ValueError(
                f"trace cipher suite 0x{parameters.get('cipher_suite_id', 0):04x} "
                f"does not match profile {profile.cipher_suite}"
            )
        expected_resumption = profile.resumption != "none" and (
            mode != "0rtt" or index == 1
        )
        if parameters.get("resumption_selected", False) != expected_resumption:
            raise ValueError("trace resumption selection does not match MinARX profile")
        expected_early_data = profile.early_data and mode == "0rtt" and index == 1
        if parameters.get("early_data_offered", False) != expected_early_data:
            raise ValueError("trace early-data offer does not match MinARX profile")
        expected_keyshare = mode == "1rtt" or (
            mode == "0rtt"
            and (index == 0 or profile.resumption == "ticket-psk-dhe")
        )
        observed_keyshare = parameters.get("server_key_share_group")
        if expected_keyshare and observed_keyshare != 0x001D:
            raise ValueError("trace does not select the profiled X25519 KeyShare")
        if not expected_keyshare and observed_keyshare is not None:
            raise ValueError("trace has a KeyShare but the MinARX profile is PSK-only")

    layout, opaque, measurements = compact_tls_pcaps(
        resolve_pcaps(capture_dir, NAMES[mode]), port, validate
    )
    return layout, opaque, {
        "policy": "tls-records-complete-transcript",
        "hello_retry_request": "outside-exercised-matrix",
        "future_recovery_input": "server X25519 private scalar; peer public share is reconstructed from the archive",
        "captures": measurements,
    }


def materialize(
    layout: bytes, opaque: bytes, metadata: dict, output_dir: Path, port: int
):
    mode = metadata["mode"]
    materialize_tls_pcaps(layout, opaque, output_dir, NAMES[mode], port)
