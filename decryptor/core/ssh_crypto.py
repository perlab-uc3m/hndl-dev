#!/usr/bin/env python3
"""SSH key derivation (RFC 4253) from captured ephemeral keys."""

import binascii
import hmac
import hashlib

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305


SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_KEX_ECDH_INIT = 30
SSH_MSG_KEX_ECDH_REPLY = 31
SSH_MSG_CHANNEL_DATA = 94


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


def encode_ssh_mpint(value: bytes) -> bytes:
    """Encode a non-negative big-endian integer as an SSH ``mpint``."""
    value = value.lstrip(b"\x00")
    if value and value[0] & 0x80:
        value = b"\x00" + value
    return len(value).to_bytes(4, "big") + value


def recover_curve25519_shared_secret(private_value: bytes, peer_public: bytes) -> bytes:
    """Compute the raw X25519 output represented by a recovered private value."""
    if len(private_value) != 32 or len(peer_public) != 32:
        raise ValueError("Curve25519 private and public values must be 32 bytes")
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_value)
    public_key = x25519.X25519PublicKey.from_public_bytes(peer_public)
    return private_key.exchange(public_key)


def curve25519_public_from_private(private_value: bytes) -> bytes:
    """Return the raw public value for an X25519 private value."""
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_value)
    return private_key.public_key().public_bytes_raw()


def read_ssh_string(data: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Read one SSH string and return ``(value, next_offset)``."""
    if offset + 4 > len(data):
        raise ValueError("Truncated SSH string length")
    length = int.from_bytes(data[offset : offset + 4], "big")
    start = offset + 4
    end = start + length
    if end > len(data):
        raise ValueError("Truncated SSH string value")
    return data[start:end], end


def parse_ssh_transport_stream(stream: bytes) -> dict:
    """Parse an SSH identification and plaintext packets through NEWKEYS."""
    banner_start = stream.find(b"SSH-")
    if banner_start < 0:
        raise ValueError("SSH identification string not found")
    banner_end = stream.find(b"\n", banner_start)
    if banner_end < 0:
        raise ValueError("Truncated SSH identification string")
    version = stream[banner_start:banner_end].rstrip(b"\r")
    offset = banner_end + 1
    packets = []

    while offset + 5 <= len(stream):
        packet_length = int.from_bytes(stream[offset : offset + 4], "big")
        packet_end = offset + 4 + packet_length
        if packet_length < 6 or packet_end > len(stream):
            break
        padding_length = stream[offset + 4]
        payload_end = packet_end - padding_length
        if padding_length < 4 or payload_end <= offset + 5:
            raise ValueError("Invalid plaintext SSH packet padding")
        payload = stream[offset + 5 : payload_end]
        packets.append(payload)
        offset = packet_end
        if payload[0] == SSH_MSG_NEWKEYS:
            break

    if not packets or packets[-1][0] != SSH_MSG_NEWKEYS:
        raise ValueError("SSH stream did not contain plaintext NEWKEYS")
    return {"version": version, "packets": packets, "encrypted": stream[offset:]}


def parse_kexinit_name_lists(payload: bytes) -> list[list[str]]:
    """Return the ten algorithm name-lists from an SSH_MSG_KEXINIT payload."""
    if len(payload) < 17 or payload[0] != SSH_MSG_KEXINIT:
        raise ValueError("Not an SSH_MSG_KEXINIT payload")
    offset = 17  # message number plus 16-byte cookie
    lists = []
    for _ in range(10):
        encoded, offset = read_ssh_string(payload, offset)
        lists.append(encoded.decode("ascii").split(",") if encoded else [])
    return lists


def negotiate_name(client_names: list[str], server_names: list[str]) -> str:
    """Apply SSH's client-preference algorithm selection rule."""
    server_set = set(server_names)
    for name in client_names:
        if name in server_set:
            return name
    raise ValueError("No common SSH algorithm")


def extract_initial_kex(client_stream: bytes, server_stream: bytes) -> dict:
    """Extract all public inputs to a Curve25519 initial exchange hash."""
    client = parse_ssh_transport_stream(client_stream)
    server = parse_ssh_transport_stream(server_stream)

    exchange = extract_kex_exchange(client["packets"], server["packets"])
    I_C = exchange["I_C"]
    I_S = exchange["I_S"]

    client_lists = parse_kexinit_name_lists(I_C)
    server_lists = parse_kexinit_name_lists(I_S)
    negotiated = {
        "kex": negotiate_name(client_lists[0], server_lists[0]),
        "host_key": negotiate_name(client_lists[1], server_lists[1]),
        "cipher_c2s": negotiate_name(client_lists[2], server_lists[2]),
        "cipher_s2c": negotiate_name(client_lists[3], server_lists[3]),
    }
    strict_kex = (
        "kex-strict-c-v00@openssh.com" in client_lists[0]
        and "kex-strict-s-v00@openssh.com" in server_lists[0]
    )
    return {
        "V_C": client["version"],
        "V_S": server["version"],
        **exchange,
        "negotiated": negotiated,
        "strict_kex": strict_kex,
        "encrypted_c2s": client["encrypted"],
        "encrypted_s2c": server["encrypted"],
        "plaintext_packets_c2s": len(client["packets"]),
        "plaintext_packets_s2c": len(server["packets"]),
    }


def extract_kex_exchange(
    client_packets: list[bytes], server_packets: list[bytes]
) -> dict:
    """Extract the transcript fields for one Curve25519 key exchange."""

    def packet(message_type: int, packets: list[bytes]) -> bytes:
        for payload in packets:
            if payload and payload[0] == message_type:
                return payload
        raise ValueError(f"Missing SSH message {message_type}")

    I_C = packet(SSH_MSG_KEXINIT, client_packets)
    I_S = packet(SSH_MSG_KEXINIT, server_packets)
    init = packet(SSH_MSG_KEX_ECDH_INIT, client_packets)
    reply = packet(SSH_MSG_KEX_ECDH_REPLY, server_packets)

    Q_C, init_end = read_ssh_string(init, 1)
    if init_end != len(init):
        raise ValueError("Unexpected data after SSH_MSG_KEX_ECDH_INIT")
    K_S, offset = read_ssh_string(reply, 1)
    Q_S, offset = read_ssh_string(reply, offset)
    signature, offset = read_ssh_string(reply, offset)
    if offset != len(reply):
        raise ValueError("Unexpected data after SSH_MSG_KEX_ECDH_REPLY")

    return {
        "I_C": I_C,
        "I_S": I_S,
        "K_S": K_S,
        "Q_C": Q_C,
        "Q_S": Q_S,
        "signature": signature,
    }


def _chacha20_xor(key: bytes, sequence_number: int, counter: int, data: bytes) -> bytes:
    """Apply OpenSSH's original ChaCha20 64-bit-counter/64-bit-nonce stream."""
    nonce = counter.to_bytes(8, "little") + sequence_number.to_bytes(8, "big")
    encryptor = Cipher(algorithms.ChaCha20(key, nonce), mode=None).encryptor()
    return encryptor.update(data)


def decrypt_chachapoly_packet(data: bytes, key: bytes, sequence_number: int) -> dict:
    """Authenticate and decrypt one chacha20-poly1305@openssh.com packet."""
    if len(key) < 64:
        raise ValueError("OpenSSH ChaCha20-Poly1305 requires a 64-byte key")
    if len(data) < 4 + 16:
        raise ValueError("Truncated encrypted SSH packet")
    main_key, header_key = key[:32], key[32:64]
    clear_length = _chacha20_xor(header_key, sequence_number, 0, data[:4])
    packet_length = int.from_bytes(clear_length, "big")
    total_length = 4 + packet_length + 16
    if packet_length < 6 or total_length > len(data):
        raise ValueError("Invalid or truncated encrypted SSH packet length")

    authenticated_ciphertext = data[: 4 + packet_length]
    tag = data[4 + packet_length : total_length]
    poly_key = _chacha20_xor(main_key, sequence_number, 0, bytes(32))
    expected_tag = Poly1305.generate_tag(poly_key, authenticated_ciphertext)
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("SSH packet Poly1305 authentication failed")

    body = _chacha20_xor(
        main_key, sequence_number, 1, data[4 : 4 + packet_length]
    )
    padding_length = body[0]
    if padding_length < 4 or padding_length + 1 >= len(body):
        raise ValueError("Invalid decrypted SSH padding")
    payload = body[1 : len(body) - padding_length]
    return {
        "payload": payload,
        "packet_length": packet_length,
        "consumed": total_length,
        "sequence_number": sequence_number,
    }


def decrypt_chachapoly_stream(data: bytes, key: bytes, first_sequence: int) -> list[dict]:
    """Authenticate and decrypt all complete OpenSSH ChaCha20-Poly1305 packets."""
    packets = []
    offset = 0
    sequence_number = first_sequence
    while offset < len(data):
        packet = decrypt_chachapoly_packet(data[offset:], key, sequence_number)
        packets.append(packet)
        offset += packet["consumed"]
        sequence_number = (sequence_number + 1) & 0xFFFFFFFF
    return packets


def decrypt_chachapoly_epoch(data: bytes, key: bytes, first_sequence: int) -> dict:
    """Decrypt through the next NEWKEYS boundary or the end of a direction.

    The NEWKEYS packet itself is protected by the old key. Its successor is
    protected by the newly derived key. The returned sequence number is the
    ordinary next value; callers reset it to zero when strict KEX applies.
    """
    packets = []
    offset = 0
    sequence_number = first_sequence
    while offset < len(data):
        packet = decrypt_chachapoly_packet(data[offset:], key, sequence_number)
        packets.append(packet)
        offset += packet["consumed"]
        sequence_number = (sequence_number + 1) & 0xFFFFFFFF
        if packet["payload"] and packet["payload"][0] == SSH_MSG_NEWKEYS:
            return {
                "packets": packets,
                "remaining": data[offset:],
                "next_sequence": sequence_number,
                "newkeys": True,
            }
    return {
        "packets": packets,
        "remaining": b"",
        "next_sequence": sequence_number,
        "newkeys": False,
    }


def channel_data(payload: bytes) -> bytes | None:
    """Extract the data string from SSH_MSG_CHANNEL_DATA, if applicable."""
    if not payload or payload[0] != SSH_MSG_CHANNEL_DATA or len(payload) < 5:
        return None
    value, offset = read_ssh_string(payload, 5)  # type + recipient channel
    if offset != len(payload):
        raise ValueError("Unexpected bytes after SSH_MSG_CHANNEL_DATA")
    return value


def verify_ed25519_kex_signature(host_key_blob: bytes, signature_blob: bytes, H: bytes):
    """Verify an ``ssh-ed25519`` server signature over the exchange hash."""
    host_algorithm, offset = read_ssh_string(host_key_blob)
    public_value, offset = read_ssh_string(host_key_blob, offset)
    if offset != len(host_key_blob) or host_algorithm != b"ssh-ed25519":
        raise ValueError("Expected an ssh-ed25519 host key blob")
    signature_algorithm, offset = read_ssh_string(signature_blob)
    signature, offset = read_ssh_string(signature_blob, offset)
    if offset != len(signature_blob) or signature_algorithm != b"ssh-ed25519":
        raise ValueError("Expected an ssh-ed25519 signature blob")
    ed25519.Ed25519PublicKey.from_public_bytes(public_value).verify(signature, H)
