#!/usr/bin/env python3
"""Recover a TLS 1.3 pure external-PSK connection."""

from __future__ import annotations

import json
from pathlib import Path

from ..io import extract_psk_identity_from_client_hello, extract_tls_hello_pair
from .derive_resumption import derive_resumed_1rtt


def derive_external_psk(
    capture_dir: Path,
    pcap_name: str = "pcap/tls13_external_psk.pcapng",
    port: int = 44443,
    recovery_name: str = "keys/simulated_external_psk.json",
    ground_truth_name: str = "keys/sslkeylog.log",
    debug: bool = False,
) -> dict:
    """Use only the declared later-compromise PSK and passive wire trace."""
    root = Path(capture_dir)
    try:
        recovery = json.loads((root / recovery_name).read_text())
        identity = str(recovery["identity"]).encode()
        psk = bytes.fromhex(recovery["psk"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return {"success": False, "error": f"external PSK was withheld: {exc}"}
    if not psk:
        return {"success": False, "error": "external PSK was withheld"}
    client_hello, _ = extract_tls_hello_pair(root / pcap_name, port)
    if not client_hello:
        return {"success": False, "error": "external-PSK ClientHello is missing"}
    if extract_psk_identity_from_client_hello(client_hello) != identity:
        return {
            "success": False,
            "error": "compromised PSK identity does not match the wire identity",
        }
    result = derive_resumed_1rtt(
        root,
        psk,
        pcap_name=pcap_name,
        port=port,
        ground_truth_name=ground_truth_name,
        fresh_dh_required=False,
        output_name="nss_external_psk.keylog",
        debug=debug,
    )
    result.setdefault("validation", {})["external_psk_identity_matched"] = True
    return result
