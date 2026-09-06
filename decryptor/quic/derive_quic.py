#!/usr/bin/env python3
"""QUIC key derivation (RFC 9001).

QUIC mandates TLS 1.3 internally, so the key schedule is identical
to TLS 1.3 1-RTT. The difference is that CH/SH are carried in QUIC
CRYPTO frames (UDP) rather than TLS records (TCP). We decrypt QUIC
Initial packets in Python because tshark cannot export raw CRYPTO
frame bytes.
"""

import binascii
import hashlib
import hmac
import shutil
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes
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
    CapturePaths,
    load_simulated_recovery,
    save_key_schedule_trace,
    parse_client_random_from_ch,
    parse_cipher_from_server_hello,
    parse_client_keyshare_pub_from_ch,
    parse_server_keyshare_pub_from_sh,
    verify_quic_stream_data,
    run_tshark,
)


# ---------------------------------------------------------------------------
# QUIC Initial packet decryption  (RFC 9001 §5)
# ---------------------------------------------------------------------------

# QUIC v1 Initial salt (RFC 9001 §5.2)
_QUIC_V1_INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def _hkdf_expand_label(
    secret: bytes, label: bytes, context: bytes, length: int
) -> bytes:
    """TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1)."""
    full_label = b"tls13 " + label
    hkdf_label = (
        length.to_bytes(2, "big")
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=hkdf_label).derive(
        secret
    )


def _quic_initial_keys(dcid: bytes, is_server: bool):
    """Derive QUIC Initial encryption keys from DCID (RFC 9001 §5.2).

    Returns (key, iv, hp_key).
    """
    initial_secret = hmac.new(_QUIC_V1_INITIAL_SALT, dcid, hashlib.sha256).digest()

    label = b"server in" if is_server else b"client in"
    secret = _hkdf_expand_label(initial_secret, label, b"", 32)

    key = _hkdf_expand_label(secret, b"quic key", b"", 16)
    iv = _hkdf_expand_label(secret, b"quic iv", b"", 12)
    hp = _hkdf_expand_label(secret, b"quic hp", b"", 16)
    return key, iv, hp


def _decode_varint(data: bytes):
    """Decode a QUIC variable-length integer. Returns (value, bytes_consumed)."""
    if not data:
        raise ValueError("truncated QUIC variable-length integer")
    first = data[0]
    prefix = first >> 6
    length = 1 << prefix
    if len(data) < length:
        raise ValueError("truncated QUIC variable-length integer")
    val = first & 0x3F
    for i in range(1, length):
        val = (val << 8) | data[i]
    return val, length


def _decrypt_quic_initial(
    raw: bytes, dcid_for_keys: bytes, is_server: bool, debug: bool = False
):
    """Decrypt a single QUIC Initial packet and return its plaintext frames.

    *raw* is the raw bytes of a single QUIC Long-Header Initial packet
    (starting at the first byte of the QUIC header).
    *dcid_for_keys* is the DCID used to derive the Initial keys
    (the original client DCID, or the Retry SCID).
    """
    if len(raw) < 7:
        return None
    first_byte = raw[0]
    if not (first_byte & 0x80):  # must be Long Header
        return None
    pkt_type = (first_byte >> 4) & 0x03
    if pkt_type != 0:  # must be Initial (0)
        return None

    offset = 1
    version = int.from_bytes(raw[offset : offset + 4], "big")
    if version != 1:
        return None
    offset += 4
    dcid_len = raw[offset]
    offset += 1
    # dcid_bytes = raw[offset:offset+dcid_len]
    offset += dcid_len
    scid_len = raw[offset]
    offset += 1
    offset += scid_len

    # Token (variable-length)
    try:
        token_len, consumed = _decode_varint(raw[offset:])
    except ValueError:
        return None
    offset += consumed + token_len

    # Payload length (variable-length)
    try:
        pkt_payload_len, consumed = _decode_varint(raw[offset:])
    except ValueError:
        return None
    offset += consumed

    # offset now points to the (protected) packet number
    pn_offset = offset

    # Derive keys
    key, iv, hp_key = _quic_initial_keys(dcid_for_keys, is_server)

    # Header protection: sample is 4 bytes after pn_offset
    sample_offset = pn_offset + 4
    if sample_offset + 16 > len(raw):
        return None
    sample = raw[sample_offset : sample_offset + 16]

    cipher_ecb = Cipher(algorithms.AES(hp_key), modes.ECB())
    enc = cipher_ecb.encryptor()
    mask = enc.update(sample) + enc.finalize()

    # Unmask first byte (long header → mask & 0x0f)
    first_byte ^= mask[0] & 0x0F
    pn_length = (first_byte & 0x03) + 1

    # Unmask packet number
    pn_bytes = bytearray(raw[pn_offset : pn_offset + pn_length])
    for i in range(pn_length):
        pn_bytes[i] ^= mask[1 + i]
    pn = int.from_bytes(pn_bytes, "big")

    # Build nonce  (IV XOR packet_number, right-aligned)
    nonce = bytearray(iv)
    for i in range(pn_length):
        nonce[-(1 + i)] ^= pn_bytes[-(1 + i)]

    # Authenticated data = unmasked header (first_byte + rest up to pn)
    ad = bytes([first_byte]) + raw[1:pn_offset] + bytes(pn_bytes)

    # Ciphertext = bytes after pn, total pkt_payload_len - pn_length
    ct_start = pn_offset + pn_length
    ct_len = pkt_payload_len - pn_length
    ciphertext = raw[ct_start : ct_start + ct_len]

    try:
        plaintext = AESGCM(key).decrypt(bytes(nonce), ciphertext, ad)
    except Exception as e:
        if debug:
            print(f"[dbg] QUIC Initial decrypt failed: {e}")
        return None

    if debug:
        print(f"[dbg] Decrypted QUIC Initial ({len(plaintext)} bytes plaintext)")
    return plaintext


def _parse_crypto_frames(plaintext: bytes):
    """Parse CRYPTO frames from decrypted QUIC payload.

    Returns list of (offset, data) tuples from CRYPTO frames.
    Other frame types (PADDING, ACK, etc.) are skipped.
    """
    crypto_data = []
    i = 0
    while i < len(plaintext):
        try:
            frame_type_val, consumed = _decode_varint(plaintext[i:])
        except ValueError:
            break
        i += consumed
        if frame_type_val == 0x00:
            # PADDING — single zero byte, already consumed
            continue
        elif frame_type_val == 0x06:
            # CRYPTO frame: offset(var) + length(var) + data
            try:
                crypto_offset, c = _decode_varint(plaintext[i:])
            except ValueError:
                break
            i += c
            try:
                crypto_len, c = _decode_varint(plaintext[i:])
            except ValueError:
                break
            i += c
            if i + crypto_len > len(plaintext):
                break
            crypto_data.append((crypto_offset, plaintext[i : i + crypto_len]))
            i += crypto_len
        elif frame_type_val == 0x02 or frame_type_val == 0x03:
            # ACK frame — skip (complex, but we just need to get past it)
            # largest_ack(var) + ack_delay(var) + ack_range_count(var) ...
            _, c = _decode_varint(plaintext[i:])  # largest_ack
            i += c
            _, c = _decode_varint(plaintext[i:])  # ack_delay
            i += c
            range_count, c = _decode_varint(plaintext[i:])
            i += c
            _, c = _decode_varint(plaintext[i:])  # first_ack_range
            i += c
            for _ in range(range_count):
                _, c = _decode_varint(plaintext[i:])  # gap
                i += c
                _, c = _decode_varint(plaintext[i:])  # ack_range
                i += c
        elif frame_type_val == 0x1C:
            # CONNECTION_CLOSE: error_code(var)+frame_type(var)+reason_len(var)+reason
            _, c = _decode_varint(plaintext[i:])
            i += c
            _, c = _decode_varint(plaintext[i:])
            i += c
            reason_len, c = _decode_varint(plaintext[i:])
            i += c
            i += reason_len
        else:
            # Unknown frame — stop parsing to avoid corruption
            break
    return crypto_data


def _parse_handshake_from_crypto(data: bytes):
    """Parse a single TLS handshake message from raw CRYPTO frame payload.

    CRYPTO frame payload begins directly with a TLS Handshake message:
      handshake_type(1) + length(3) + body
    (No TLS record layer header.)
    """
    if len(data) < 4:
        return None
    hs_type = data[0]
    hs_len = (data[1] << 16) | (data[2] << 8) | data[3]
    total = 4 + hs_len
    if len(data) < total:
        return None
    return data[:total]


def _reassemble_crypto_prefix(segments: dict[int, bytes]) -> bytes:
    """Return the contiguous CRYPTO stream prefix beginning at offset zero."""
    out = bytearray()
    for offset in sorted(segments):
        data = segments[offset]
        if offset > len(out):
            break
        overlap = len(out) - offset
        if overlap < len(data):
            out.extend(data[overlap:])
    return bytes(out)


def _iter_coalesced_packets(datagram: bytes):
    """Yield individual QUIC packets from a potentially coalesced datagram."""
    offset = 0
    while offset < len(datagram):
        if offset >= len(datagram):
            break
        first = datagram[offset]
        if first & 0x80:  # Long Header
            # Need to find the packet length to split coalesced packets
            pos = offset + 1
            if pos + 4 > len(datagram):
                yield datagram[offset:]
                break
            pos += 4  # version
            if pos >= len(datagram):
                yield datagram[offset:]
                break
            dcid_len = datagram[pos]
            pos += 1
            pos += dcid_len
            if pos >= len(datagram):
                yield datagram[offset:]
                break
            scid_len = datagram[pos]
            pos += 1
            pos += scid_len

            pkt_type = (first >> 4) & 0x03
            if pkt_type == 0:  # Initial — has token field
                if pos >= len(datagram):
                    yield datagram[offset:]
                    break
                try:
                    token_len, c = _decode_varint(datagram[pos:])
                except ValueError:
                    yield datagram[offset:]
                    break
                pos += c + token_len
            elif pkt_type == 3:  # Retry — no length, rest is the packet
                yield datagram[offset:]
                break

            if pos >= len(datagram):
                yield datagram[offset:]
                break
            try:
                pkt_payload_len, c = _decode_varint(datagram[pos:])
            except ValueError:
                yield datagram[offset:]
                break
            pos += c
            total_len = pos - offset + pkt_payload_len
            yield datagram[offset : offset + total_len]
            offset += total_len
        else:  # Short Header — rest of datagram is one packet
            yield datagram[offset:]
            break


def _extract_quic_crypto_data(pcap: Path, port: int, debug: bool = False):
    """Extract ClientHello and ServerHello from QUIC CRYPTO frames."""
    cmd = [
        "tshark",
        "-r",
        str(pcap),
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "udp.payload",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
    ]
    if debug:
        print(f"[dbg] Running: {' '.join(cmd)}")
    p = run_tshark(cmd, pcap)
    if p.returncode != 0:
        if debug:
            print(f"[dbg] tshark error: {p.stderr}")
        return None, None

    ch = sh = None
    client_crypto: dict[int, bytes] = {}
    server_crypto: dict[int, bytes] = {}
    # Track the DCID used for Initial key derivation.
    # After a Retry the DCID changes and Initial keys are re-derived.
    initial_dcid = None  # the DCID from the *latest* client Initial
    retry_scid = None

    for line in p.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        # fno = parts[0]
        payload_hex = parts[1].replace(":", "")
        src_port = parts[2]
        dst_port = parts[3]
        if not payload_hex:
            continue
        try:
            datagram = binascii.unhexlify(payload_hex)
        except Exception:
            continue

        is_to_server = dst_port == str(port)

        for pkt in _iter_coalesced_packets(datagram):
            if len(pkt) < 6:
                continue
            first = pkt[0]
            if not (first & 0x80):
                continue  # Short header → skip
            if int.from_bytes(pkt[1:5], "big") != 1:
                continue

            pkt_type = (first >> 4) & 0x03

            if pkt_type == 3:
                # Retry packet — extract SCID for new Initial keys
                pos = 5  # skip first_byte(1) + version(4)
                dcid_len = pkt[pos]
                pos += 1
                pos += dcid_len
                scid_len = pkt[pos]
                pos += 1
                retry_scid = pkt[pos : pos + scid_len]
                if debug:
                    print(f"[dbg] Retry SCID: {retry_scid.hex()}")
                continue

            if pkt_type != 0:  # not Initial
                continue

            # Parse Initial header to get DCID
            pos = 5  # first_byte(1) + version(4)
            dcid_len = pkt[pos]
            pos += 1
            dcid = pkt[pos : pos + dcid_len]

            if is_to_server:
                # Client Initial → record DCID for key derivation
                initial_dcid = dcid
                if debug:
                    print(f"[dbg] Client Initial DCID: {dcid.hex()}")

            # Use the current DCID for key derivation
            keys_dcid = initial_dcid if initial_dcid else dcid
            is_server_pkt = not is_to_server

            plaintext = _decrypt_quic_initial(pkt, keys_dcid, is_server_pkt, debug)
            if plaintext is None:
                continue

            # Extract CRYPTO frames
            target = client_crypto if is_to_server else server_crypto
            try:
                crypto_frames = _parse_crypto_frames(plaintext)
            except ValueError:
                continue
            for crypto_offset, crypto_bytes in crypto_frames:
                target.setdefault(crypto_offset, crypto_bytes)

            if ch is None:
                msg = _parse_handshake_from_crypto(
                    _reassemble_crypto_prefix(client_crypto)
                )
                if msg is not None and msg[0] == 1:
                    ch = msg
                    if debug:
                        print(f"[dbg] Extracted ClientHello: {len(ch)} bytes")
            if sh is None:
                msg = _parse_handshake_from_crypto(
                    _reassemble_crypto_prefix(server_crypto)
                )
                if msg is not None and msg[0] == 2:
                    sh = msg
                    if debug:
                        print(f"[dbg] Extracted ServerHello: {len(sh)} bytes")
            if ch and sh:
                return ch, sh

    return ch, sh


def _quic_traffic_keys(traffic_secret: bytes, cipher_suite: int):
    """Derive QUIC packet-protection keys from a traffic secret.

    Returns (key, iv, hp_key, aead_class).
    """
    if cipher_suite == 0x1302:  # TLS_AES_256_GCM_SHA384
        key_len, hash_algo = 32, hashes.SHA384()
    elif cipher_suite == 0x1303:  # TLS_CHACHA20_POLY1305_SHA256
        key_len, hash_algo = 32, hashes.SHA256()
    else:  # TLS_AES_128_GCM_SHA256 (0x1301) or default
        key_len, hash_algo = 16, hashes.SHA256()

    def _expand(secret, label, length):
        full_label = b"tls13 " + label
        info = (
            length.to_bytes(2, "big")
            + bytes([len(full_label)])
            + full_label
            + b"\x00"  # empty context
        )
        return HKDFExpand(algorithm=hash_algo, length=length, info=info).derive(secret)

    key = _expand(traffic_secret, b"quic key", key_len)
    iv = _expand(traffic_secret, b"quic iv", 12)
    hp = _expand(traffic_secret, b"quic hp", key_len)
    return key, iv, hp


def _decrypt_quic_handshake_pkt(
    raw: bytes, key: bytes, iv: bytes, hp_key: bytes, debug: bool = False
):
    """Decrypt a single QUIC Handshake packet. Returns decrypted payload."""
    if len(raw) < 7:
        return None
    first_byte = raw[0]
    if not (first_byte & 0x80):  # must be Long Header
        return None
    pkt_type = (first_byte >> 4) & 0x03
    if pkt_type != 2:  # must be Handshake (2)
        return None

    offset = 1
    if int.from_bytes(raw[offset : offset + 4], "big") != 1:
        return None
    offset += 4  # version
    dcid_len = raw[offset]
    offset += 1
    offset += dcid_len
    scid_len = raw[offset]
    offset += 1
    offset += scid_len

    # Payload length (variable-length integer) — no token in Handshake
    try:
        pkt_payload_len, consumed = _decode_varint(raw[offset:])
    except ValueError:
        return None
    offset += consumed

    pn_offset = offset

    # Header protection
    sample_offset = pn_offset + 4
    if sample_offset + 16 > len(raw):
        return None
    sample = raw[sample_offset : sample_offset + 16]

    # Use AES-ECB for HP regardless of cipher suite key size
    # (HP key is always the same size as the AEAD key)
    if len(hp_key) == 32:
        cipher_ecb = Cipher(algorithms.AES(hp_key), modes.ECB())
    else:
        cipher_ecb = Cipher(algorithms.AES(hp_key), modes.ECB())
    enc = cipher_ecb.encryptor()
    mask = enc.update(sample) + enc.finalize()

    first_byte ^= mask[0] & 0x0F
    pn_length = (first_byte & 0x03) + 1

    pn_bytes = bytearray(raw[pn_offset : pn_offset + pn_length])
    for i in range(pn_length):
        pn_bytes[i] ^= mask[1 + i]

    nonce = bytearray(iv)
    for i in range(pn_length):
        nonce[-(1 + i)] ^= pn_bytes[-(1 + i)]

    ad = bytes([first_byte]) + raw[1:pn_offset] + bytes(pn_bytes)

    ct_start = pn_offset + pn_length
    ct_len = pkt_payload_len - pn_length
    ciphertext = raw[ct_start : ct_start + ct_len]

    try:
        plaintext = AESGCM(key).decrypt(bytes(nonce), ciphertext, ad)
    except Exception as e:
        if debug:
            print(f"[dbg] QUIC Handshake decrypt failed: {e}")
        return None
    return plaintext


def _extract_quic_decrypted_handshake(
    pcap_file: Path,
    server_hs_secret: bytes,
    cipher_suite: int,
    port: int,
    debug: bool = False,
):
    """Decrypt server QUIC Handshake packets and extract TLS messages."""
    key, iv, hp_key = _quic_traffic_keys(server_hs_secret, cipher_suite)

    if debug:
        print(f"[dbg] Server HS key: {key.hex()}")
        print(f"[dbg] Server HS iv: {iv.hex()}")

    cmd = [
        "tshark",
        "-r",
        str(pcap_file),
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "udp.payload",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
    ]
    p = run_tshark(cmd, pcap_file)
    if p.returncode != 0:
        return []

    # Collect CRYPTO frame data from server Handshake packets
    # crypto_data: dict mapping offset → bytes
    crypto_segments = {}

    for line in p.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        payload_hex = parts[1].replace(":", "")
        src_port = parts[2]
        dst_port = parts[3]
        if not payload_hex:
            continue
        is_from_server = src_port == str(port)
        if not is_from_server:
            continue
        try:
            datagram = binascii.unhexlify(payload_hex)
        except Exception:
            continue

        for pkt in _iter_coalesced_packets(datagram):
            if len(pkt) < 6:
                continue
            first = pkt[0]
            if not (first & 0x80):
                continue
            pkt_type = (first >> 4) & 0x03
            if pkt_type != 2:  # Handshake
                continue

            plaintext = _decrypt_quic_handshake_pkt(pkt, key, iv, hp_key, debug)
            if plaintext is None:
                continue

            if debug:
                print(
                    f"[dbg] Decrypted QUIC Handshake pkt " f"({len(plaintext)} bytes)"
                )

            try:
                crypto_frames = _parse_crypto_frames(plaintext)
            except ValueError:
                continue
            for crypto_offset, crypto_bytes in crypto_frames:
                crypto_segments[crypto_offset] = crypto_bytes

    if not crypto_segments:
        if debug:
            print("[dbg] No CRYPTO frames found in server Handshake packets")
        return []

    # Reassemble CRYPTO stream in offset order
    reassembled = bytearray()
    for off in sorted(crypto_segments.keys()):
        data = crypto_segments[off]
        end = off + len(data)
        if off <= len(reassembled):
            # overlap or contiguous
            if end > len(reassembled):
                reassembled.extend(data[len(reassembled) - off :])
        else:
            # gap — fill with zeros (shouldn't happen in normal flow)
            reassembled.extend(b"\x00" * (off - len(reassembled)))
            reassembled.extend(data)

    # Parse TLS handshake messages from reassembled CRYPTO data
    messages = []
    pos = 0
    while pos + 4 <= len(reassembled):
        hs_type = reassembled[pos]
        hs_len = (
            (reassembled[pos + 1] << 16)
            | (reassembled[pos + 2] << 8)
            | reassembled[pos + 3]
        )
        total = 4 + hs_len
        if pos + total > len(reassembled):
            break
        messages.append(bytes(reassembled[pos : pos + total]))
        pos += total

    if debug and messages:
        type_names = {
            4: "NewSessionTicket",
            8: "EncryptedExtensions",
            11: "Certificate",
            15: "CertificateVerify",
            20: "Finished",
        }
        print(f"[dbg] Extracted {len(messages)} server HS messages:")
        for msg in messages:
            name = type_names.get(msg[0], f"Type{msg[0]}")
            print(f"[dbg]   {name} ({msg[0]}): {len(msg)} bytes")

    return messages


# ---------------------------------------------------------------------------
# Main derivation entry point
# ---------------------------------------------------------------------------


def derive_quic(
    capture_dir: Path,
    pcap_name: str = "pcap/quic.pcapng",
    port: int = 44443,
    role: str = "client",
    curve: str = "x25519",
    hash_algo: str = "auto",
    debug: bool = False,
) -> dict:
    """Derive QUIC session keys from capture (RFC 9001, TLS 1.3 key schedule)."""
    if shutil.which("tshark") is None:
        return {"success": False, "error": "tshark not found in PATH"}

    paths = CapturePaths(capture_dir, pcap_name)
    if not paths.pcap_exists():
        return {"success": False, "error": f"PCAP not found: {paths.pcap}"}

    try:
        recovery = load_simulated_recovery(paths.capture_dir)
    except (OSError, ValueError) as exc:
        return {"success": False, "error": str(exc)}
    if recovery["group"].lower() != "x25519" or curve.lower() != "x25519":
        return {"success": False, "error": "Only X25519 recovery is supported"}

    # Extract CH/SH from QUIC CRYPTO frames
    ch, sh = _extract_quic_crypto_data(paths.pcap, port, debug)
    if not ch or not sh:
        return {
            "success": False,
            "error": "Could not extract ClientHello/ServerHello from QUIC PCAP",
        }

    if debug:
        print(f"[dbg] ClientHello: {len(ch)} bytes, ServerHello: {len(sh)} bytes")

    # Detect hash from cipher suite
    tls_hash = hash_algo
    if tls_hash == "auto":
        try:
            cs = parse_cipher_from_server_hello(sh)
            tls_hash = "sha384" if cs == 0x1302 else "sha256"
            if debug:
                print(f"[dbg] Cipher suite: 0x{cs:04x} -> {tls_hash}")
        except Exception:
            tls_hash = "sha256"

    # Parse client random and keyshares from CH/SH
    client_random = parse_client_random_from_ch(ch)
    try:
        ch_pub = parse_client_keyshare_pub_from_ch(ch)
        sh_pub = parse_server_keyshare_pub_from_sh(sh)
        if not ch_pub or not sh_pub:
            raise ValueError("X25519 KeyShare missing from captured hello")
        private_hex = recovery["ephemeral_private"]
        private_key = x25519.X25519PrivateKey.from_private_bytes(
            bytes.fromhex(private_hex)
        )
        recovered_public = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        if recovered_public != bytes.fromhex(recovery["ephemeral_public_check"]):
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

    if debug:
        print(f"[dbg] Shared secret Z: {binascii.hexlify(Z).decode()}")

    # Compute th_hello = Hash(CH || SH)
    th_hello = hashlib.new(tls_hash, ch + sh).digest()

    # Derive handshake secrets
    derived_hs, trace_hs, derived_hs_hex = derive_tls13_keys_with_trace(
        Z, hash_name=tls_hash, th_hello=th_hello, th_finished=None
    )

    paths.ensure_derived_dir()

    # Detect cipher suite for Handshake-level decryption
    try:
        cs = parse_cipher_from_server_hello(sh)
    except Exception:
        cs = 0x1301  # default
    if cs == 0x1303:
        return {
            "success": False,
            "error": "Native QUIC handshake decryption does not support ChaCha20 header protection",
        }

    # Decrypt server Handshake packets to get remaining TLS messages
    encrypted_msgs = _extract_quic_decrypted_handshake(
        paths.pcap,
        derived_hs["server_handshake_traffic_secret"],
        cs,
        port,
        debug,
    )
    th_finished = None
    if encrypted_msgs:
        transcript = ch + sh
        for msg in encrypted_msgs:
            transcript += msg
            if len(msg) >= 1 and msg[0] == 20:  # Finished
                break
        th_finished = compute_th_finished(transcript, tls_hash)

    if not th_finished:
        # Partial output (handshake secrets only)
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
        print("QUIC keys: PARTIAL (handshake only)")
        print(f"Output: {paths.nss_derived_keylog}")

        # Still compare handshake secrets, but partial reconstruction is not
        # an end-to-end success.
        keylog_truth = {}
        if paths.openssl_keylog_exists():
            keylog_truth = parse_tls13_handshake_secrets_from_keylog(
                paths.openssl_keylog, client_random
            )
        derived_map = {
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET": derived_hs_hex[
                "client_handshake_traffic_secret"
            ],
            "SERVER_HANDSHAKE_TRAFFIC_SECRET": derived_hs_hex[
                "server_handshake_traffic_secret"
            ],
        }
        ok, total = print_secret_comparison(
            "QUIC (handshake)", keylog_truth, derived_map, verbose=debug
        )

        return {
            "success": False,
            "keylog_path": str(paths.nss_derived_keylog),
            "handshake_only": True,
            "validation": {
                "ground_truth_matches": ok,
                "ground_truth_expected": 2,
                "application_plaintext_recovered": False,
            },
        }

    # Derive full key schedule including application secrets
    derived, trace, derived_hex = derive_tls13_keys_with_trace(
        Z, hash_name=tls_hash, th_hello=th_hello, th_finished=th_finished
    )

    # Write full keylog (NSS format)
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
    if paths.openssl_keylog_exists():
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
    ok, total = print_secret_comparison(
        "QUIC", keylog_truth, derived_map, verbose=debug
    )
    plaintext_ok = verify_quic_stream_data(
        paths.pcap, paths.nss_derived_keylog, port, debug
    )

    # Save trace
    save_key_schedule_trace(paths.derived_dir, trace, "key_schedule_trace.json", debug)

    status = "ALL MATCH" if ok == total else f"{ok}/{total} MATCH"
    print(f"QUIC keys: {status} ({total} secrets)")
    print(f"QUIC plaintext: {'RECOVERED' if plaintext_ok else 'NOT VERIFIED'}")
    print(f"Output: {paths.nss_derived_keylog}")

    return {
        "success": ok == total and total == 4 and plaintext_ok,
        "keylog_path": str(paths.nss_derived_keylog),
        "secrets": derived_hex,
        "validation": {
            "ground_truth_matches": ok,
            "ground_truth_expected": 4,
            "application_plaintext_recovered": plaintext_ok,
        },
    }
