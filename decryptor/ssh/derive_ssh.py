#!/usr/bin/env python3
"""SSH key derivation (RFC 4253) from instrumented key exchange logs."""

import binascii
import json
from pathlib import Path

from ..core.ssh_crypto import derive_ssh_keys_with_trace


def _load_keylog(keylog_file: Path) -> dict:
    """Load SSH keylog JSON."""
    if not keylog_file.exists():
        return {}
    with keylog_file.open() as f:
        return json.load(f)


def derive_ssh(capture_dir: Path, debug: bool = False) -> dict:
    """Derive SSH session keys from captured key material (RFC 4253 Section 7.2)."""
    capture_path = Path(capture_dir)
    keys_dir = capture_path / "keys"
    derived_dir = capture_path / "derived"
    derived_dir.mkdir(parents=True, exist_ok=True)

    keylog = _load_keylog(keys_dir / "ssh_keylog.json")
    if not keylog:
        return {"success": False, "error": "No SSH keylog found"}

    # Collect logged secrets from server/client
    logged = {}
    for source in [keylog.get("server", {}), keylog.get("client", {})]:
        for key in [
            "SHARED_SECRET_K",
            "EXCHANGE_HASH_H",
            "SESSION_ID",
            "IV_CLIENT_TO_SERVER",
            "IV_SERVER_TO_CLIENT",
            "ENC_KEY_CLIENT_TO_SERVER",
            "ENC_KEY_SERVER_TO_CLIENT",
            "MAC_KEY_CLIENT_TO_SERVER",
            "MAC_KEY_SERVER_TO_CLIENT",
        ]:
            if key in source and key not in logged:
                logged[key] = source[key]

    # Need K, H, session_id
    if not all(
        k in logged for k in ["SHARED_SECRET_K", "EXCHANGE_HASH_H", "SESSION_ID"]
    ):
        return {"success": False, "error": "Missing K, H, or session_id"}

    K = binascii.unhexlify(logged["SHARED_SECRET_K"])
    H = binascii.unhexlify(logged["EXCHANGE_HASH_H"])
    session_id = binascii.unhexlify(logged["SESSION_ID"])

    # Detect hash and key lengths from logged values
    hash_name = "sha512" if len(H) == 64 else "sha256"
    iv_len = len(binascii.unhexlify(logged.get("IV_CLIENT_TO_SERVER", "00" * 64)))
    key_len = len(binascii.unhexlify(logged.get("ENC_KEY_CLIENT_TO_SERVER", "00" * 64)))
    mac_len = len(binascii.unhexlify(logged.get("MAC_KEY_CLIENT_TO_SERVER", "00" * 64)))

    # Derive keys
    keys, trace = derive_ssh_keys_with_trace(
        K, H, session_id, hash_name, iv_len, key_len, mac_len
    )

    # Validate
    key_map = {
        "IV_CLIENT_TO_SERVER": "iv_c2s",
        "IV_SERVER_TO_CLIENT": "iv_s2c",
        "ENC_KEY_CLIENT_TO_SERVER": "enc_c2s",
        "ENC_KEY_SERVER_TO_CLIENT": "enc_s2c",
        "MAC_KEY_CLIENT_TO_SERVER": "mac_c2s",
        "MAC_KEY_SERVER_TO_CLIENT": "mac_s2c",
    }

    all_match = True
    for logged_name, derived_name in key_map.items():
        if logged_name in logged:
            logged_val = logged[logged_name].lower()
            derived_val = trace["derived"][derived_name].lower()
            if not (
                logged_val.startswith(derived_val[: len(logged_val)])
                or derived_val.startswith(logged_val)
            ):
                all_match = False

    # Save outputs
    output_file = derived_dir / "ssh_derived_keys.json"
    with output_file.open("w") as f:
        json.dump(
            {"derived": trace["derived"], "validation": {"all_match": all_match}},
            f,
            indent=2,
        )

    with (derived_dir / "key_schedule_trace.json").open("w") as f:
        json.dump(trace, f, indent=2)

    status = "ALL MATCH" if all_match else "MISMATCH"
    print(f"SSH keys: {status} ({len(key_map)} keys)")
    print(f"Output: {output_file}")

    return {
        "success": all_match,
        "keylog_path": str(output_file),
        "secrets": trace["derived"],
    }
