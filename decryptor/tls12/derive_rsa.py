#!/usr/bin/env python3
"""TLS 1.2 RSA key derivation from captured handshakes."""

import binascii
import hashlib
import json
from pathlib import Path

from experiment import require_tool

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from ..core.tls12_crypto import (
    derive_tls12_keys_with_trace,
    decrypt_premaster_secret_rsa,
)
from ..io import (
    get_tcp_stream_bytes,
    list_tcp_stream_indices,
    run_tshark,
    verify_tls_http_request,
)


def _tshark_field(pcap: Path, port: int, filter_expr: str, field: str) -> str:
    """Extract a single field from PCAP using tshark."""
    cmd = [
        "tshark",
        "-r",
        str(pcap),
        "-d",
        f"tcp.port=={port},tls",
        "-Y",
        filter_expr,
        "-T",
        "fields",
        "-e",
        field,
    ]
    result = run_tshark(cmd, pcap)
    if result.returncode != 0:
        return ""
    return result.stdout.strip().replace(":", "").replace("\n", "")


def _extract_random(pcap: Path, port: int, hs_type: int) -> bytes:
    """Extract client_random or server_random from handshake."""
    hex_str = _tshark_field(
        pcap, port, f"tls.handshake.type == {hs_type}", "tls.handshake.random"
    )
    if len(hex_str) >= 64:
        return binascii.unhexlify(hex_str[:64])
    return None


def _extract_encrypted_premaster(pcap: Path, port: int) -> bytes:
    """Extract encrypted premaster secret from ClientKeyExchange."""
    # Try direct field first
    hex_str = _tshark_field(
        pcap, port, "tls.handshake.type == 16", "tls.handshake.epms"
    )
    if hex_str:
        return binascii.unhexlify(hex_str)

    # Fallback: parse raw ClientKeyExchange
    raw_hex = _tshark_field(pcap, port, "tls.handshake.type == 16", "tls.handshake")
    if raw_hex:
        raw = binascii.unhexlify(raw_hex)
        if len(raw) > 6:
            epms_len = int.from_bytes(raw[4:6], "big")
            return raw[6 : 6 + epms_len]
    return None


def _check_extended_master_secret(pcap: Path, port: int) -> bool:
    """Check if EMS extension is negotiated (extension type 23)."""
    ext_str = _tshark_field(
        pcap, port, "tls.handshake.type == 2", "tls.handshake.extension.type"
    )
    return any(token == "23" for token in ext_str.replace(",", " ").split())


def _handshake_messages_from_stream(stream: bytes) -> list[bytes]:
    """Reassemble plaintext TLS handshake messages from one TCP byte stream."""
    messages = []
    pending = bytearray()
    offset = 0
    while offset + 5 <= len(stream):
        content_type = stream[offset]
        record_len = int.from_bytes(stream[offset + 3 : offset + 5], "big")
        end = offset + 5 + record_len
        if end > len(stream):
            break
        if content_type == 22:
            pending.extend(stream[offset + 5 : end])
            while len(pending) >= 4:
                msg_len = int.from_bytes(pending[1:4], "big")
                total = 4 + msg_len
                if len(pending) < total:
                    break
                messages.append(bytes(pending[:total]))
                del pending[:total]
        elif content_type == 20:
            # Subsequent handshake records are encrypted under TLS 1.2.
            break
        offset = end
    return messages


def _extract_handshake_for_session_hash(pcap: Path, port: int) -> bytes:
    """Extract handshake messages for EMS session hash computation."""
    for stream_index in list_tcp_stream_indices(pcap, port):
        try:
            side_a, side_b = get_tcp_stream_bytes(pcap, stream_index)
        except RuntimeError:
            continue
        msgs_a = _handshake_messages_from_stream(side_a)
        msgs_b = _handshake_messages_from_stream(side_b)
        if any(msg[0] == 1 for msg in msgs_a):
            client_msgs, server_msgs = msgs_a, msgs_b
        elif any(msg[0] == 1 for msg in msgs_b):
            client_msgs, server_msgs = msgs_b, msgs_a
        else:
            continue

        client_hello = next((msg for msg in client_msgs if msg[0] == 1), None)
        server_flight = []
        for msg in server_msgs:
            if msg[0] in (2, 11, 12, 13, 14):
                server_flight.append(msg)
            if msg[0] == 14:
                break
        client_flight = []
        for msg in client_msgs:
            if msg[0] in (11, 16) and msg is not client_hello:
                client_flight.append(msg)
            if msg[0] == 16:
                break
        if client_hello and server_flight and any(m[0] == 16 for m in client_flight):
            return b"".join([client_hello, *server_flight, *client_flight])
    return None


def _parse_openssl_keylog(keylog_path: Path) -> dict:
    """Parse OpenSSL keylog for CLIENT_RANDOM entries."""
    secrets = {}
    if not keylog_path.exists():
        return secrets
    for line in keylog_path.read_text().splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and parts[0] == "CLIENT_RANDOM":
            secrets[parts[1].lower()] = parts[2].lower()
    return secrets


def derive_rsa(
    capture_dir: Path,
    pcap_name: str = "pcap/tls12_rsa.pcapng",
    port: int = 44443,
    debug: bool = False,
    recovery_name: str = "keys/simulated_quantum_output.pem",
    ground_truth_name: str = "keys/sslkeylog.log",
) -> dict:
    """Derive TLS 1.2 RSA session keys from capture (RFC 5246, RFC 7627)."""
    require_tool("tshark")

    capture_path = Path(capture_dir)
    pcap = capture_path / pcap_name
    keys_dir = capture_path / "keys"
    derived_dir = capture_path / "derived"

    if not pcap.exists():
        return {"success": False, "error": f"PCAP not found: {pcap}"}

    key_path = capture_path / recovery_name
    if not key_path.exists():
        return {
            "success": False,
            "error": f"Simulated RSA recovery not found: {key_path}",
        }

    derived_dir.mkdir(parents=True, exist_ok=True)

    # Load RSA private key
    rsa_key = load_pem_private_key(key_path.read_bytes(), password=None)

    # Extract handshake data
    client_random = _extract_random(pcap, port, 1)
    server_random = _extract_random(pcap, port, 2)
    encrypted_pms = _extract_encrypted_premaster(pcap, port)

    if not client_random or not server_random or not encrypted_pms:
        return {"success": False, "error": "Could not extract handshake data"}

    # Decrypt premaster secret (HN-DL attack simulation)
    try:
        premaster = decrypt_premaster_secret_rsa(encrypted_pms, rsa_key)
    except Exception as e:
        return {"success": False, "error": f"RSA decryption failed: {e}"}

    # Check for Extended Master Secret
    use_ems = _check_extended_master_secret(pcap, port)
    session_hash = None
    if use_ems:
        hs_msgs = _extract_handshake_for_session_hash(pcap, port)
        if not hs_msgs:
            return {"success": False, "error": "Could not reconstruct EMS transcript"}
        session_hash = hashlib.sha256(hs_msgs).digest()

    # Derive master secret
    master_secret, trace = derive_tls12_keys_with_trace(
        premaster,
        client_random,
        server_random,
        session_hash=session_hash,
        extended_master_secret=use_ems,
    )

    # Verify against OpenSSL keylog
    keylog_path = capture_path / ground_truth_name
    openssl_secrets = _parse_openssl_keylog(keylog_path)
    client_random_hex = client_random.hex()

    match = False
    if client_random_hex in openssl_secrets:
        match = openssl_secrets[client_random_hex] == master_secret.hex()

    # Save outputs
    with (derived_dir / "tls12_trace.json").open("w") as f:
        json.dump(trace, f, indent=2)

    keylog_out = derived_dir / "nss_derived.keylog"
    with keylog_out.open("w") as f:
        f.write(f"CLIENT_RANDOM {client_random_hex} {master_secret.hex()}\n")

    plaintext_ok = verify_tls_http_request(pcap, keylog_out, port, debug)

    status = "MATCH" if match else "MISMATCH"
    print(f"TLS 1.2 RSA: {status}")
    print(f"TLS 1.2 plaintext: {'RECOVERED' if plaintext_ok else 'NOT VERIFIED'}")
    print(f"Output: {keylog_out}")

    return {
        "success": match and plaintext_ok,
        "keylog_path": str(keylog_out),
        "secrets": {"master_secret": master_secret.hex()},
        "validation": {
            "ground_truth_match": match,
            "application_plaintext_recovered": plaintext_ok,
            "extended_master_secret": use_ems,
        },
    }
