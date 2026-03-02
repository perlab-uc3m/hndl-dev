#!/usr/bin/env python3
"""TLS 1.2 RSA key derivation from captured handshakes."""

import binascii
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from ..core.tls12_crypto import (
    derive_tls12_keys_with_trace,
    decrypt_premaster_secret_rsa,
)


def _check_tool(name: str):
    if shutil.which(name) is None:
        sys.exit(f"Required tool '{name}' not found in PATH")


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
    result = subprocess.run(cmd, capture_output=True, text=True)
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
    return "23" in ext_str.split(",")


def _extract_handshake_for_session_hash(pcap: Path, port: int) -> bytes:
    """Extract handshake messages for EMS session hash computation."""
    cmd = [
        "tshark",
        "-r",
        str(pcap),
        "-d",
        f"tcp.port=={port},tls",
        "-Y",
        "tls.handshake",
        "-T",
        "fields",
        "-e",
        "tcp.payload",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None

    all_handshake = b""
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        try:
            payload = binascii.unhexlify(line.replace(":", ""))
        except (binascii.Error, ValueError):
            continue

        # Parse TLS records
        offset = 0
        while offset + 5 <= len(payload):
            content_type = payload[offset]
            record_len = int.from_bytes(payload[offset + 3 : offset + 5], "big")
            if offset + 5 + record_len > len(payload):
                break

            fragment = payload[offset + 5 : offset + 5 + record_len]

            if content_type == 22:  # Handshake
                hs_offset = 0
                while hs_offset + 4 <= len(fragment):
                    hs_type = fragment[hs_offset]
                    hs_len = int.from_bytes(
                        fragment[hs_offset + 1 : hs_offset + 4], "big"
                    )
                    if hs_offset + 4 + hs_len > len(fragment):
                        break

                    hs_msg = fragment[hs_offset : hs_offset + 4 + hs_len]
                    # Include: CH(1), SH(2), Cert(11), SKE(12), CertReq(13), SHD(14), CKE(16)
                    if hs_type in (1, 2, 11, 12, 13, 14, 16):
                        all_handshake += hs_msg
                    if hs_type == 16:  # Stop after ClientKeyExchange
                        return all_handshake
                    hs_offset += 4 + hs_len

            offset += 5 + record_len

    return all_handshake if all_handshake else None


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
) -> dict:
    """Derive TLS 1.2 RSA session keys from capture (RFC 5246, RFC 7627)."""
    _check_tool("tshark")

    capture_path = Path(capture_dir)
    pcap = capture_path / pcap_name
    keys_dir = capture_path / "keys"
    derived_dir = capture_path / "derived"

    if not pcap.exists():
        return {"success": False, "error": f"PCAP not found: {pcap}"}

    key_path = keys_dir / "key.pem"
    if not key_path.exists():
        return {"success": False, "error": f"RSA key not found: {key_path}"}

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
        if hs_msgs:
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
    keylog_path = keys_dir / "sslkeylog.log"
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

    status = "MATCH" if match else "MISMATCH"
    print(f"TLS 1.2 RSA: {status}")
    print(f"Output: {keylog_out}")

    return {
        "success": match,
        "keylog_path": str(keylog_out),
        "secrets": {"master_secret": master_secret.hex()},
    }
