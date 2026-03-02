#!/usr/bin/env python3
"""TLS 1.2 PRF and master secret derivation (RFC 5246)."""

import hmac
import hashlib
from typing import Tuple


def _p_hash(hash_name: str, secret: bytes, seed: bytes, length: int) -> bytes:
    """P_hash expansion (RFC 5246 Section 5)."""
    result = b""
    a = seed

    while len(result) < length:
        a = hmac.new(secret, a, hash_name).digest()
        result += hmac.new(secret, a + seed, hash_name).digest()

    return result[:length]


def tls12_prf(
    secret: bytes, label: bytes, seed: bytes, length: int, hash_name: str = "sha256"
) -> bytes:
    """TLS 1.2 PRF: P_<hash>(secret, label + seed) (RFC 5246 Section 5)."""
    return _p_hash(hash_name, secret, label + seed, length)


def derive_master_secret(
    premaster_secret: bytes,
    client_random: bytes,
    server_random: bytes,
    hash_name: str = "sha256",
) -> bytes:
    """Derive 48-byte master secret (RFC 5246 Section 8.1)."""
    if len(client_random) != 32:
        raise ValueError(f"client_random must be 32 bytes, got {len(client_random)}")
    if len(server_random) != 32:
        raise ValueError(f"server_random must be 32 bytes, got {len(server_random)}")

    label = b"master secret"
    seed = client_random + server_random

    return tls12_prf(premaster_secret, label, seed, 48, hash_name)


def derive_extended_master_secret(
    premaster_secret: bytes, session_hash: bytes, hash_name: str = "sha256"
) -> bytes:
    """Derive master secret with Extended Master Secret (RFC 7627)."""
    label = b"extended master secret"
    return tls12_prf(premaster_secret, label, session_hash, 48, hash_name)


def derive_key_block(
    master_secret: bytes,
    client_random: bytes,
    server_random: bytes,
    key_block_length: int,
    hash_name: str = "sha256",
) -> bytes:
    """Derive key block from master secret (RFC 5246 Section 6.3).

    key_block = PRF(master_secret, "key expansion", server_random + client_random)
    """
    label = b"key expansion"
    # Seed order: server_random + client_random (note: reversed from master secret)
    seed = server_random + client_random

    return tls12_prf(master_secret, label, seed, key_block_length, hash_name)


def decrypt_premaster_secret_rsa(encrypted_pms: bytes, rsa_private_key) -> bytes:
    """Decrypt the RSA-encrypted premaster secret (PKCS#1 v1.5)."""
    from cryptography.hazmat.primitives.asymmetric import padding

    premaster_secret = rsa_private_key.decrypt(encrypted_pms, padding.PKCS1v15())

    if len(premaster_secret) != 48:
        raise ValueError(
            f"Decrypted premaster secret should be 48 bytes, got {len(premaster_secret)}"
        )

    return premaster_secret


def derive_tls12_keys_with_trace(
    premaster_secret: bytes,
    client_random: bytes,
    server_random: bytes,
    session_hash: bytes = None,
    extended_master_secret: bool = False,
    hash_name: str = "sha256",
) -> Tuple[bytes, dict]:
    """Derive TLS 1.2 master secret and return (master_secret, trace_dict)."""
    if extended_master_secret:
        if session_hash is None:
            raise ValueError("session_hash required for extended master secret")
        master_secret = derive_extended_master_secret(
            premaster_secret, session_hash, hash_name
        )
        label = "extended master secret"
        seed_hex = session_hash.hex()
    else:
        master_secret = derive_master_secret(
            premaster_secret, client_random, server_random, hash_name
        )
        label = "master secret"
        seed_hex = f"{client_random.hex()} + {server_random.hex()}"

    trace = {
        "premaster_secret_len": len(premaster_secret),
        "premaster_secret_hex": premaster_secret.hex(),
        "client_random_hex": client_random.hex(),
        "server_random_hex": server_random.hex(),
        "extended_master_secret": extended_master_secret,
        "session_hash_hex": session_hash.hex() if session_hash else None,
        "master_secret_hex": master_secret.hex(),
        "hash_algorithm": hash_name,
        "prf_label": label,
        "prf_seed": seed_hex,
    }

    return master_secret, trace
