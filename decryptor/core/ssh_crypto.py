#!/usr/bin/env python3
"""SSH key derivation (RFC 4253) from captured ephemeral keys."""

import binascii
import hashlib


def derive_ssh_key(
    K: bytes,
    H: bytes,
    letter: str,
    session_id: bytes,
    length: int,
    hash_name: str = "sha256",
) -> bytes:
    """Derive a single SSH key per RFC 4253 Section 7.2.

    Key = HASH(K || H || letter || session_id), extended if needed.
    """
    hash_func = getattr(hashlib, hash_name)

    key = b""
    key_data = b""

    while len(key) < length:
        ctx = hash_func()
        ctx.update(K)
        ctx.update(H)
        if not key_data:
            ctx.update(letter.encode("ascii"))
            ctx.update(session_id)
        else:
            ctx.update(key_data)
        chunk = ctx.digest()
        key_data += chunk
        key += chunk

    return key[:length]


def derive_ssh_keys(
    shared_secret_K: bytes,
    exchange_hash_H: bytes,
    session_id: bytes,
    hash_name: str = "sha256",
    iv_len: int = 16,
    key_len: int = 32,
    mac_len: int = 32,
) -> dict:
    """Derive all six SSH session keys (IVs, encryption, MACs) per RFC 4253."""
    return {
        "iv_c2s": derive_ssh_key(
            shared_secret_K, exchange_hash_H, "A", session_id, iv_len, hash_name
        ),
        "iv_s2c": derive_ssh_key(
            shared_secret_K, exchange_hash_H, "B", session_id, iv_len, hash_name
        ),
        "enc_c2s": derive_ssh_key(
            shared_secret_K, exchange_hash_H, "C", session_id, key_len, hash_name
        ),
        "enc_s2c": derive_ssh_key(
            shared_secret_K, exchange_hash_H, "D", session_id, key_len, hash_name
        ),
        "mac_c2s": derive_ssh_key(
            shared_secret_K, exchange_hash_H, "E", session_id, mac_len, hash_name
        ),
        "mac_s2c": derive_ssh_key(
            shared_secret_K, exchange_hash_H, "F", session_id, mac_len, hash_name
        ),
    }


def derive_ssh_keys_with_trace(
    shared_secret_K: bytes,
    exchange_hash_H: bytes,
    session_id: bytes,
    hash_name: str = "sha256",
    iv_len: int = 16,
    key_len: int = 32,
    mac_len: int = 32,
) -> tuple[dict, dict]:
    """Derive SSH keys and return trace for debugging."""
    keys = derive_ssh_keys(
        shared_secret_K,
        exchange_hash_H,
        session_id,
        hash_name,
        iv_len,
        key_len,
        mac_len,
    )

    trace = {
        "inputs": {
            "hash": hash_name,
            "shared_secret_K": binascii.hexlify(shared_secret_K).decode(),
            "exchange_hash_H": binascii.hexlify(exchange_hash_H).decode(),
            "session_id": binascii.hexlify(session_id).decode(),
        },
        "derived": {k: binascii.hexlify(v).decode() for k, v in keys.items()},
    }
    return keys, trace


def compute_exchange_hash(
    V_C: bytes,
    V_S: bytes,
    I_C: bytes,
    I_S: bytes,
    K_S: bytes,
    e: bytes,
    f: bytes,
    K: bytes,
    hash_name: str = "sha256",
) -> bytes:
    """Compute SSH exchange hash H (RFC 4253)."""

    def ssh_string(data: bytes) -> bytes:
        return len(data).to_bytes(4, "big") + data

    def ssh_mpint(data: bytes) -> bytes:
        # Add leading 0x00 if high bit set
        if data and data[0] & 0x80:
            data = b"\x00" + data
        return ssh_string(data)

    ctx = getattr(hashlib, hash_name)()
    ctx.update(ssh_string(V_C))
    ctx.update(ssh_string(V_S))
    ctx.update(ssh_string(I_C))
    ctx.update(ssh_string(I_S))
    ctx.update(ssh_string(K_S))
    ctx.update(ssh_string(e))
    ctx.update(ssh_string(f))
    ctx.update(ssh_mpint(K))
    return ctx.digest()
