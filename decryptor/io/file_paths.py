#!/usr/bin/env python3
"""Capture directory path conventions."""

from pathlib import Path


class CapturePaths:
    """Centralized path management for capture directory structure."""

    def __init__(self, capture_dir: Path, pcap_name: str = "pcap/tls13_1rtt.pcapng"):
        self.capture_dir = Path(capture_dir)
        self.pcap = self.capture_dir / pcap_name

        self.keys_dir = self.capture_dir / "keys"
        self.server_ephemeral = self.keys_dir / "server_ephemeral.json"
        self.client_ephemeral = self.keys_dir / "client_ephemeral.json"
        self.openssl_keylog = self.keys_dir / "sslkeylog.log"

        self.derived_dir = self.capture_dir / "derived"
        self.client_hello_bin = self.derived_dir / "client_hello.bin"
        self.server_hello_bin = self.derived_dir / "server_hello.bin"
        self.th_hello_full_hex = self.derived_dir / "th_hello_full.hex"
        self.th_hello_body_hex = self.derived_dir / "th_hello_body.hex"
        self.th_finished_hex = self.derived_dir / "th_finished.hex"
        self.handshake_only_keylog = self.derived_dir / "handshake_only.keylog"
        self.nss_derived_keylog = self.derived_dir / "nss_derived.keylog"
        self.diagnostics_json = self.derived_dir / "diagnostics.json"
        self.key_schedule_trace_handshake = (
            self.derived_dir / "key_schedule_trace_handshake.json"
        )
        self.key_schedule_trace_full = self.derived_dir / "key_schedule_trace_full.json"
        self.transcript_hashes_json = self.derived_dir / "transcript_hashes.json"

    def ensure_derived_dir(self):
        """Create derived directory if it doesn't exist."""
        self.derived_dir.mkdir(parents=True, exist_ok=True)

    def pcap_exists(self) -> bool:
        """Check if PCAP file exists."""
        return self.pcap.exists()

    def openssl_keylog_exists(self) -> bool:
        """Check if OpenSSL keylog exists."""
        return self.openssl_keylog.exists()
