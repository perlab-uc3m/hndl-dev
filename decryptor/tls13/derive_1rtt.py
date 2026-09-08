#!/usr/bin/env python3
"""TLS 1.3 1-RTT key derivation from captured handshakes."""

import binascii
import hashlib
from pathlib import Path

from experiment import require_tool
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from ..core import (
    derive_tls13_keys_with_trace,
    compute_shared_secret_from_priv_and_peer,
    nss_tls13_key_log_line,
    parse_tls13_handshake_secrets_from_keylog,
    print_secret_comparison,
    compute_th_finished,
)
from ..io import (
    RecoveryArtifacts,
    load_simulated_recovery,
    save_key_schedule_trace,
    extract_tls_hello_pair,
    parse_client_random_from_ch,
    parse_cipher_from_server_hello,
    parse_client_keyshare_pub_from_ch,
    parse_server_keyshare_pub_from_sh,
    extract_decrypted_handshake_from_tshark,
    verify_tls_http_request,
)


def _x25519_pub_from_priv(hexstr: str) -> bytes:
    pk = x25519.X25519PrivateKey.from_private_bytes(binascii.unhexlify(hexstr))
    return pk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


def _compute_th_finished(
    pcap_file: Path,
    keylog_file: Path,
    ch: bytes,
    sh: bytes,
    hash_algo: str,
    debug: bool,
) -> bytes:
    """Decrypt handshake and compute th_finished."""
    encrypted_msgs = extract_decrypted_handshake_from_tshark(
        pcap_file, keylog_file, debug=debug
    )
    if not encrypted_msgs:
        return None

    transcript = ch + sh
    for msg in encrypted_msgs:
        transcript += msg
        if msg[0] == 20:  # Stop after first Finished
            break

    return compute_th_finished(transcript, hash_algo)


def derive_1rtt(
    capture_dir: Path,
    pcap_name: str = "pcap/tls13_1rtt.pcapng",
    port: int = 44443,
    role: str = "server",
    curve: str = "x25519",
    hash_algo: str = "auto",
    debug: bool = False,
    recovery_name: str = "keys/simulated_quantum_output.json",
    ground_truth_name: str = "keys/sslkeylog.log",
) -> dict:
    """Derive TLS 1.3 1-RTT session keys from capture (RFC 8446)."""
    require_tool("tshark")

    paths = RecoveryArtifacts(capture_dir, pcap_name, ground_truth_name)
    if not paths.pcap_exists():
        return {"success": False, "error": f"PCAP not found: {paths.pcap}"}

    try:
        recovery = load_simulated_recovery(paths.capture_dir, recovery_name)
    except (OSError, ValueError) as exc:
        return {"success": False, "error": str(exc)}
    if recovery["group"].lower() != "x25519" or curve.lower() != "x25519":
        return {"success": False, "error": "Only X25519 recovery is supported"}

    # Extract CH/SH
    ch, sh = extract_tls_hello_pair(paths.pcap, port)
    if not ch or not sh:
        return {"success": False, "error": "Could not extract ClientHello/ServerHello"}

    # Detect hash from cipher suite
    tls_hash = hash_algo
    if tls_hash == "auto":
        try:
            cs = parse_cipher_from_server_hello(sh)
            tls_hash = "sha384" if cs == 0x1302 else "sha256"
        except Exception:
            tls_hash = "sha256"

    # Parse client random and keyshares
    client_random = parse_client_random_from_ch(ch)
    try:
        ch_pub = parse_client_keyshare_pub_from_ch(ch)
        sh_pub = parse_server_keyshare_pub_from_sh(sh)
        if not ch_pub or not sh_pub:
            raise ValueError("X25519 KeyShare missing from captured hello")
        private_hex = recovery["ephemeral_private"]
        recovered_public = _x25519_pub_from_priv(private_hex)
        declared_public = bytes.fromhex(recovery["ephemeral_public_check"])
        if recovered_public != declared_public:
            raise ValueError("recovered private value does not match its public check")
        if recovery["role"] == "server":
            own_public, peer_public = sh_pub, ch_pub
        else:
            own_public, peer_public = ch_pub, sh_pub
        if recovered_public != own_public:
            raise ValueError("recovered value does not match the captured KeyShare")
        Z = compute_shared_secret_from_priv_and_peer(
            private_hex, peer_public.hex(), curve
        )
    except (ValueError, TypeError, binascii.Error) as exc:
        return {"success": False, "error": f"Invalid recovery input: {exc}"}

    # Compute th_hello
    th_hello = hashlib.new(tls_hash, ch + sh).digest()

    # Derive handshake secrets
    derived_hs, trace_hs, derived_hs_hex = derive_tls13_keys_with_trace(
        Z, hash_name=tls_hash, th_hello=th_hello, th_finished=None
    )

    paths.ensure_derived_dir()

    # Write handshake-only keylog for decrypting rest of handshake
    tmp_keylog = paths.handshake_only_keylog
    with tmp_keylog.open("w") as f:
        f.write(
            nss_tls13_key_log_line(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                client_random,
                derived_hs["client_handshake_traffic_secret"],
            )
        )
        f.write(
            nss_tls13_key_log_line(
                "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                client_random,
                derived_hs["server_handshake_traffic_secret"],
            )
        )

    # Compute th_finished
    th_finished = _compute_th_finished(paths.pcap, tmp_keylog, ch, sh, tls_hash, debug)

    if not th_finished:
        # Handshake-only output
        with paths.nss_derived_keylog.open("w") as f:
            f.write(
                nss_tls13_key_log_line(
                    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                    client_random,
                    derived_hs["client_handshake_traffic_secret"],
                )
            )
            f.write(
                nss_tls13_key_log_line(
                    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                    client_random,
                    derived_hs["server_handshake_traffic_secret"],
                )
            )
        print(f"TLS 1.3 keys: PARTIAL (handshake only)")
        print(f"Output: {paths.nss_derived_keylog}")
        return {
            "success": False,
            "keylog_path": str(paths.nss_derived_keylog),
            "handshake_only": True,
        }

    # Derive full key schedule including application secrets
    derived, trace, derived_hex = derive_tls13_keys_with_trace(
        Z, hash_name=tls_hash, th_hello=th_hello, th_finished=th_finished
    )

    # Write full keylog
    with paths.nss_derived_keylog.open("w") as f:
        f.write(
            nss_tls13_key_log_line(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                client_random,
                derived["client_handshake_traffic_secret"],
            )
        )
        f.write(
            nss_tls13_key_log_line(
                "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                client_random,
                derived["server_handshake_traffic_secret"],
            )
        )
        f.write(
            nss_tls13_key_log_line(
                "CLIENT_TRAFFIC_SECRET_0",
                client_random,
                derived["client_application_traffic_secret"],
            )
        )
        f.write(
            nss_tls13_key_log_line(
                "SERVER_TRAFFIC_SECRET_0",
                client_random,
                derived["server_application_traffic_secret"],
            )
        )

    # Verification is deliberately last: endpoint key logs never supply an
    # attack input or intermediate value.
    keylog_truth = {}
    ground_truth_available = paths.openssl_keylog_exists()
    if ground_truth_available:
        keylog_truth = parse_tls13_handshake_secrets_from_keylog(
            paths.openssl_keylog, client_random
        )
    derived_map = {
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET": derived_hex[
            "client_handshake_traffic_secret"
        ],
        "SERVER_HANDSHAKE_TRAFFIC_SECRET": derived_hex[
            "server_handshake_traffic_secret"
        ],
        "CLIENT_TRAFFIC_SECRET_0": derived_hex["client_application_traffic_secret"],
        "SERVER_TRAFFIC_SECRET_0": derived_hex["server_application_traffic_secret"],
    }
    if ground_truth_available:
        ok, total = print_secret_comparison(
            "TLS 1.3", keylog_truth, derived_map, verbose=debug
        )
    else:
        ok, total = 0, 0
    plaintext_ok = verify_tls_http_request(
        paths.pcap, paths.nss_derived_keylog, port, debug
    )

    # Save trace
    save_key_schedule_trace(paths.derived_dir, trace, "key_schedule_trace.json", debug)

    status = (
        "ALL MATCH"
        if ground_truth_available and ok == total == 4
        else ("NOT PROVIDED" if not ground_truth_available else f"{ok}/{total} MATCH")
    )
    comparison = (
        f"{total} compared secrets" if ground_truth_available else "comparison omitted"
    )
    print(f"TLS 1.3 keys: {status} ({comparison})")
    print(f"TLS 1.3 plaintext: {'RECOVERED' if plaintext_ok else 'NOT VERIFIED'}")
    print(f"Output: {paths.nss_derived_keylog}")

    return {
        "success": (
            (not ground_truth_available or (ok == total and total == 4))
            and plaintext_ok
        ),
        "keylog_path": str(paths.nss_derived_keylog),
        "secrets": derived_hex,
        "validation": {
            "ground_truth_matches": ok,
            "ground_truth_expected": 4,
            "ground_truth_available": ground_truth_available,
            "application_plaintext_recovered": plaintext_ok,
        },
    }
