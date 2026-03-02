#!/usr/bin/env python3
"""TLS 1.3 transcript hash computation."""

import hashlib


def sha_hex(data: bytes, hash_name: str) -> str:
    """Compute SHA hash and return as hex string."""
    h = hashlib.new(hash_name)
    h.update(data)
    return h.hexdigest()


def compute_th_hello(
    client_hello: bytes,
    server_hello: bytes,
    hash_name: str,
    include_headers: bool = True,
) -> str:
    """Compute th_hello = Hash(ClientHello || ServerHello)."""
    if include_headers:
        return sha_hex(client_hello + server_hello, hash_name)
    else:
        ch_body = client_hello[4:] if len(client_hello) >= 4 else client_hello
        sh_body = server_hello[4:] if len(server_hello) >= 4 else server_hello
        return sha_hex(ch_body + sh_body, hash_name)


def compute_th_finished(transcript: bytes, hash_name: str) -> bytes:
    """Compute th_finished = Hash(full handshake transcript up to server Finished)."""
    if hash_name == "sha256":
        return hashlib.sha256(transcript).digest()
    elif hash_name == "sha384":
        return hashlib.sha384(transcript).digest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {hash_name}")
