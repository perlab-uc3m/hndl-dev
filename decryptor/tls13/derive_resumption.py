#!/usr/bin/env python3
"""Recover TLS 1.3 PSK-DHE child 1-RTT keys from explicit causal inputs."""

from __future__ import annotations

import binascii
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from experiment import require_tool

from ..core import (
    compute_shared_secret_from_priv_and_peer,
    derive_early_secrets,
    derive_psk_from_resumption_master,
    derive_resumption_master_secret,
    derive_tls13_keys_with_trace,
    nss_tls13_key_log_line,
    parse_tls13_handshake_secrets_from_keylog,
    print_secret_comparison,
)
from ..io import (
    extract_psk_identity_from_client_hello,
    extract_decrypted_handshake_from_tshark,
    extract_tls_hello_pair,
    load_simulated_recovery,
    parse_cipher_from_server_hello,
    parse_client_keyshare_pub_from_ch,
    parse_client_random_from_ch,
    parse_new_session_ticket,
    parse_server_keyshare_pub_from_sh,
    verify_tls_http_response,
    verify_tls_http_request,
)


def _recover_x25519_secret(ch: bytes, sh: bytes, recovery: dict) -> bytes:
    """Validate a simulated recovery result against the child wire shares."""
    if recovery["group"].lower() != "x25519":
        raise ValueError("only X25519 recovery is supported")
    client_public = parse_client_keyshare_pub_from_ch(ch)
    server_public = parse_server_keyshare_pub_from_sh(sh)
    if not client_public or not server_public:
        raise ValueError("PSK-DHE child is missing an X25519 KeyShare")

    private_hex = recovery["ephemeral_private"]
    private_key = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    recovered_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if recovered_public != bytes.fromhex(recovery["ephemeral_public_check"]):
        raise ValueError("recovered child private value fails its public check")

    if recovery["role"] == "server":
        own_public, peer_public = server_public, client_public
    else:
        own_public, peer_public = client_public, server_public
    if recovered_public != own_public:
        raise ValueError("recovered child value does not match its captured KeyShare")
    return compute_shared_secret_from_priv_and_peer(
        private_hex, peer_public.hex(), "x25519"
    )


def derive_resumed_1rtt(
    capture_dir: Path,
    psk: bytes,
    pcap_name: str = "pcap/tls13_0rtt_phase2_resumption.pcapng",
    port: int = 44443,
    recovery_name: str = "keys/simulated_quantum_output_phase2.json",
    ground_truth_name: str = "keys/sslkeylog.log",
    early_secret: bytes | None = None,
    fresh_dh_required: bool = True,
    output_name: str = "nss_phase2_1rtt.keylog",
    debug: bool = False,
) -> dict:
    """Recover a resumed TLS connection from its explicit causal inputs.

    ``psk`` is an explicit recovery input: either derived from a parent session
    or obtained through the external-PSK compromise model. For PSK-DHE,
    ``recovery_name`` represents a separate future recovery of the child's
    fresh DH private value. For pure PSK, the RFC zero input is used and a
    ServerHello KeyShare is rejected. Neither path reads an attack input from
    endpoint logs.
    """
    require_tool("tshark")
    root = Path(capture_dir)
    pcap = root / pcap_name
    if not pcap.is_file():
        return {"success": False, "error": f"PCAP not found: {pcap}"}
    if not psk:
        return {"success": False, "error": "required PSK was withheld"}

    try:
        ch, sh = extract_tls_hello_pair(pcap, port)
        if not ch or not sh:
            raise ValueError("could not extract child ClientHello/ServerHello")
        cipher_suite = parse_cipher_from_server_hello(sh)
        hash_name = "sha384" if cipher_suite == 0x1302 else "sha256"
        if fresh_dh_required:
            recovery = load_simulated_recovery(root, recovery_name)
            shared_secret = _recover_x25519_secret(ch, sh, recovery)
        else:
            if parse_server_keyshare_pub_from_sh(sh):
                raise ValueError("pure-PSK child unexpectedly negotiated a KeyShare")
            shared_secret = b"\x00" * hashlib.new(hash_name).digest_size
    except (OSError, TypeError, ValueError, binascii.Error) as exc:
        return {"success": False, "error": f"missing or invalid child input: {exc}"}

    hello_hash = hashlib.new(hash_name, ch + sh).digest()
    handshake, handshake_trace, _ = derive_tls13_keys_with_trace(
        shared_secret, hash_name, psk, hello_hash, None
    )
    derived_dir = root / "derived"
    derived_dir.mkdir(parents=True, exist_ok=True)
    client_random = parse_client_random_from_ch(ch)
    handshake_keylog = derived_dir / "phase2_handshake.keylog"
    with handshake_keylog.open("w") as handle:
        if early_secret is not None:
            handle.write(
                nss_tls13_key_log_line(
                    "CLIENT_EARLY_TRAFFIC_SECRET", client_random, early_secret
                )
            )
        for label, name in (
            ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", "client_handshake_traffic_secret"),
            ("SERVER_HANDSHAKE_TRAFFIC_SECRET", "server_handshake_traffic_secret"),
        ):
            handle.write(nss_tls13_key_log_line(label, client_random, handshake[name]))

    messages = extract_decrypted_handshake_from_tshark(
        pcap, handshake_keylog, debug=debug
    )
    transcript = bytearray(ch + sh)
    server_finished_transcript = None
    client_finished_transcript = None
    finished_count = 0
    for message in messages:
        if not message:
            continue
        transcript.extend(message)
        if message[0] == 20:
            finished_count += 1
            if finished_count == 1:
                server_finished_transcript = bytes(transcript)
            elif finished_count == 2:
                client_finished_transcript = bytes(transcript)
                break
    if server_finished_transcript is None:
        return {
            "success": False,
            "error": "child Finished could not be authenticated without both inputs",
        }

    finished_hash = hashlib.new(hash_name, server_finished_transcript).digest()
    derived, trace, derived_hex = derive_tls13_keys_with_trace(
        shared_secret, hash_name, psk, hello_hash, finished_hash
    )
    output_keylog = derived_dir / output_name
    with output_keylog.open("w") as handle:
        if early_secret is not None:
            handle.write(
                nss_tls13_key_log_line(
                    "CLIENT_EARLY_TRAFFIC_SECRET", client_random, early_secret
                )
            )
        for label, name in (
            ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", "client_handshake_traffic_secret"),
            ("SERVER_HANDSHAKE_TRAFFIC_SECRET", "server_handshake_traffic_secret"),
            ("CLIENT_TRAFFIC_SECRET_0", "client_application_traffic_secret"),
            ("SERVER_TRAFFIC_SECRET_0", "server_application_traffic_secret"),
        ):
            handle.write(nss_tls13_key_log_line(label, client_random, derived[name]))

    ground_truth = root / ground_truth_name
    ground_truth_available = ground_truth.is_file()
    if ground_truth_available:
        expected = parse_tls13_handshake_secrets_from_keylog(
            ground_truth, client_random
        )
        compared, total = print_secret_comparison(
            "TLS 1.3 resumed 1-RTT",
            expected,
            {
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET": derived_hex[
                    "client_handshake_traffic_secret"
                ],
                "SERVER_HANDSHAKE_TRAFFIC_SECRET": derived_hex[
                    "server_handshake_traffic_secret"
                ],
                "CLIENT_TRAFFIC_SECRET_0": derived_hex[
                    "client_application_traffic_secret"
                ],
                "SERVER_TRAFFIC_SECRET_0": derived_hex[
                    "server_application_traffic_secret"
                ],
            },
            verbose=debug,
        )
    else:
        compared, total = 0, 0

    response_authenticated = verify_tls_http_response(pcap, output_keylog, port, debug)
    resumption_master = None
    if client_finished_transcript is not None:
        client_finished_hash = hashlib.new(
            hash_name, client_finished_transcript
        ).digest()
        resumption_master = derive_resumption_master_secret(
            derived["master_secret"], client_finished_hash, hash_name
        )
        derived_hex["resumption_master_secret"] = resumption_master.hex()
    comparison_ok = not ground_truth_available or (compared == total == 4)
    success = comparison_ok and response_authenticated
    return {
        "success": success,
        "keylog_path": str(output_keylog),
        "secrets": derived_hex,
        "trace": trace,
        "handshake_trace": handshake_trace,
        "validation": {
            "ground_truth_available": ground_truth_available,
            "ground_truth_matches": compared,
            "ground_truth_expected": 4,
            "server_finished_authenticated": True,
            "client_finished_authenticated": client_finished_transcript is not None,
            "application_response_authenticated": response_authenticated,
            "psk_supplied": True,
            "fresh_dh_required": fresh_dh_required,
            "fresh_dh_supplied": fresh_dh_required,
        },
    }


def derive_grandchild_early(
    capture_dir: Path,
    child_result: dict,
    phase2_pcap_name: str = "pcap/tls13_0rtt_phase2_resumption.pcapng",
    phase3_pcap_name: str = "pcap/tls13_0rtt_phase3_grandchild.pcapng",
    port: int = 44443,
    ground_truth_name: str = "keys/sslkeylog.log",
    debug: bool = False,
) -> dict:
    """Derive grandchild early data through the captured child-ticket edge."""
    require_tool("tshark")
    root = Path(capture_dir)
    phase2_pcap = root / phase2_pcap_name
    phase3_pcap = root / phase3_pcap_name
    if not child_result.get("success"):
        return {"success": False, "error": "child 1-RTT recovery was withheld"}
    try:
        resumption_master = bytes.fromhex(
            child_result["secrets"]["resumption_master_secret"]
        )
        child_keylog = Path(child_result["keylog_path"])
    except (KeyError, TypeError, ValueError) as exc:
        return {"success": False, "error": f"child ticket state unavailable: {exc}"}
    if not phase2_pcap.is_file() or not phase3_pcap.is_file():
        return {"success": False, "error": "grandchild capture is missing"}

    child_messages = extract_decrypted_handshake_from_tshark(
        phase2_pcap, child_keylog, debug=debug
    )
    tickets = [
        parse_new_session_ticket(message)
        for message in child_messages
        if message and message[0] == 4
    ]
    grandchild_ch, _ = extract_tls_hello_pair(phase3_pcap, port)
    if not grandchild_ch:
        return {"success": False, "error": "grandchild ClientHello is missing"}
    identity = extract_psk_identity_from_client_hello(grandchild_ch)
    selected = next(
        (ticket for ticket in tickets if ticket["ticket"] == identity), None
    )
    if selected is None:
        return {
            "success": False,
            "error": "grandchild identity does not match a child-issued ticket",
        }

    cipher_suite = None
    _, phase3_sh = extract_tls_hello_pair(phase3_pcap, port)
    if phase3_sh:
        cipher_suite = parse_cipher_from_server_hello(phase3_sh)
    hash_name = "sha384" if cipher_suite == 0x1302 else "sha256"
    grandchild_psk = derive_psk_from_resumption_master(
        resumption_master, selected["ticket_nonce"], hash_name
    )
    early = derive_early_secrets(grandchild_psk, grandchild_ch, hash_name)
    client_random = parse_client_random_from_ch(grandchild_ch)
    keylog = root / "derived/nss_phase3_early.keylog"
    keylog.write_text(
        nss_tls13_key_log_line(
            "CLIENT_EARLY_TRAFFIC_SECRET",
            client_random,
            early["client_early_traffic_secret"],
        )
    )

    truth = root / ground_truth_name
    truth_available = truth.is_file()
    if truth_available:
        expected = parse_tls13_handshake_secrets_from_keylog(truth, client_random)
        compared, total = print_secret_comparison(
            "TLS 1.3 grandchild early data",
            expected,
            {"CLIENT_EARLY_TRAFFIC_SECRET": early["client_early_traffic_secret"].hex()},
            verbose=debug,
        )
    else:
        compared, total = 0, 0
    plaintext_authenticated = verify_tls_http_request(phase3_pcap, keylog, port, debug)
    comparison_ok = not truth_available or (compared == total == 1)
    return {
        "success": comparison_ok and plaintext_authenticated,
        "keylog_path": str(keylog),
        "secrets": {
            "RESUMPTION_PSK": grandchild_psk.hex(),
            "CLIENT_EARLY_TRAFFIC_SECRET": early["client_early_traffic_secret"].hex(),
        },
        "validation": {
            "ground_truth_available": truth_available,
            "ground_truth_matches": compared,
            "ground_truth_expected": 1,
            "ticket_identity_matched": True,
            "early_application_plaintext_recovered": plaintext_authenticated,
        },
    }
