#!/usr/bin/env python3
"""
TLS 1.3 key schedule (RFC 8446 Section 7.1).

    PSK (or 0)
      |
      v
    HKDF-Extract = early_secret
      |                             |
      v                             v
    Derive-Secret("c e traffic")  Derive-Secret("derived", "")
    = CLIENT_EARLY_TRAFFIC_SECRET   |
                                    v
                              HKDF-Extract(., DHE) = handshake_secret
                                    |
              +---------------------+---------------------+
              v                     v                     v
    Derive-Secret               Derive-Secret       Derive-Secret("derived","")
    ("c hs traffic", CH||SH)    ("s hs traffic")          |
                                                          v
                                                    HKDF-Extract(., 0)
                                                    = master_secret
                                                          |
              +-------------------------------------------+
              v                                           v
    Derive-Secret                                 Derive-Secret
    ("c ap traffic", CH..SF)                      ("s ap traffic", CH..SF)
    = CLIENT_TRAFFIC_SECRET_0                     = SERVER_TRAFFIC_SECRET_0
"""

import binascii
import hashlib
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.backends import default_backend


def hkdf_expand_label(
    secret: bytes, label: str, context: bytes, length: int, hash_alg=hashes.SHA256()
):
    """HKDF-Expand-Label (RFC 8446 Section 7.1)."""
    prefix = b"tls13 "
    full_label = prefix + label.encode("utf-8")
    length_bytes = length.to_bytes(2, "big")
    label_len = len(full_label).to_bytes(1, "big")
    context_len = len(context).to_bytes(1, "big")
    hkdf_label = length_bytes + label_len + full_label + context_len + context
    hkdf_expand = HKDFExpand(
        algorithm=hash_alg, length=length, info=hkdf_label, backend=default_backend()
    )
    return hkdf_expand.derive(secret)


def hkdf_extract(salt: bytes, ikm: bytes, hash_name="sha256"):
    """HKDF-Extract (RFC 5869): PRK = HMAC-Hash(salt, IKM)."""
    if salt is None or len(salt) == 0:
        salt = b"\x00" * hashlib.new(hash_name).digest_size
    return hmac.new(salt, ikm, getattr(hashlib, hash_name)).digest()


def get_hash_algo(name):
    """Convert hash name string to cryptography hash algorithm object."""
    if name.lower() in ("sha256", "sha-256"):
        return hashes.SHA256()
    if name.lower() in ("sha384", "sha-384"):
        return hashes.SHA384()
    raise ValueError("unsupported hash")


def derive_tls13_keys_from_z(
    Z: bytes,
    hash_name="sha256",
    psk: bytes = None,
    th_hello: bytes = None,
    th_finished: bytes = None,
):
    """Derive TLS 1.3 traffic secrets from ECDHE shared secret Z.

    Implements the 1-RTT key schedule (RFC 8446 Section 7.1).
    Requires th_hello = Hash(CH || SH). If th_finished is provided,
    also derives application traffic secrets.
    """
    hash_len = hashlib.new(hash_name).digest_size
    zero_salt = b"\x00" * hash_len

    if psk is None or len(psk) == 0:
        psk = zero_salt
    early_secret = hkdf_extract(b"", psk, hash_name)

    empty_hash = hashlib.new(hash_name, b"").digest()
    derived = hkdf_expand_label(
        early_secret, "derived", empty_hash, hash_len, hash_alg=get_hash_algo(hash_name)
    )
    handshake_secret = hkdf_extract(derived, Z, hash_name)

    if th_hello is None:
        raise ValueError("th_hello is required: Hash(ClientHello || ServerHello)")

    client_hs = hkdf_expand_label(
        handshake_secret,
        "c hs traffic",
        th_hello,
        hash_len,
        hash_alg=get_hash_algo(hash_name),
    )
    server_hs = hkdf_expand_label(
        handshake_secret,
        "s hs traffic",
        th_hello,
        hash_len,
        hash_alg=get_hash_algo(hash_name),
    )

    derived2 = hkdf_expand_label(
        handshake_secret,
        "derived",
        empty_hash,
        hash_len,
        hash_alg=get_hash_algo(hash_name),
    )
    master_secret = hkdf_extract(derived2, b"\x00" * hash_len, hash_name)

    out = {
        "client_handshake_traffic_secret": client_hs,
        "server_handshake_traffic_secret": server_hs,
        "handshake_secret": handshake_secret,
        "master_secret": master_secret,
    }

    if th_finished is not None:
        client_app = hkdf_expand_label(
            master_secret,
            "c ap traffic",
            th_finished,
            hash_len,
            hash_alg=get_hash_algo(hash_name),
        )
        server_app = hkdf_expand_label(
            master_secret,
            "s ap traffic",
            th_finished,
            hash_len,
            hash_alg=get_hash_algo(hash_name),
        )
        out.update(
            {
                "client_application_traffic_secret": client_app,
                "server_application_traffic_secret": server_app,
            }
        )

    return out


def derive_tls13_keys_with_trace(
    Z: bytes,
    hash_name: str = "sha256",
    psk: bytes | None = None,
    th_hello: bytes | None = None,
    th_finished: bytes | None = None,
):
    """Like derive_tls13_keys_from_z but also returns trace dict with intermediate secrets."""
    if th_hello is None:
        raise ValueError("th_hello is required")

    hlen = hashlib.new(hash_name).digest_size
    zero_salt = b"\x00" * hlen

    if psk is None or len(psk) == 0:
        psk = zero_salt
    early_secret = hkdf_extract(b"", psk, hash_name)

    empty_hash = hashlib.new(hash_name, b"").digest()
    derived1 = hkdf_expand_label(
        early_secret, "derived", empty_hash, hlen, hash_alg=get_hash_algo(hash_name)
    )
    handshake_secret = hkdf_extract(derived1, Z, hash_name)

    client_hs = hkdf_expand_label(
        handshake_secret,
        "c hs traffic",
        th_hello,
        hlen,
        hash_alg=get_hash_algo(hash_name),
    )
    server_hs = hkdf_expand_label(
        handshake_secret,
        "s hs traffic",
        th_hello,
        hlen,
        hash_alg=get_hash_algo(hash_name),
    )

    derived2 = hkdf_expand_label(
        handshake_secret, "derived", empty_hash, hlen, hash_alg=get_hash_algo(hash_name)
    )
    master_secret = hkdf_extract(derived2, b"\x00" * hlen, hash_name)

    derived = {
        "client_handshake_traffic_secret": client_hs,
        "server_handshake_traffic_secret": server_hs,
        "handshake_secret": handshake_secret,
        "master_secret": master_secret,
    }

    if th_finished is not None:
        client_app = hkdf_expand_label(
            master_secret,
            "c ap traffic",
            th_finished,
            hlen,
            hash_alg=get_hash_algo(hash_name),
        )
        server_app = hkdf_expand_label(
            master_secret,
            "s ap traffic",
            th_finished,
            hlen,
            hash_alg=get_hash_algo(hash_name),
        )
        derived.update(
            {
                "client_application_traffic_secret": client_app,
                "server_application_traffic_secret": server_app,
            }
        )

    trace = {
        "inputs": {
            "hash": hash_name,
            "Z_hex": binascii.hexlify(Z).decode(),
            "psk_hex": (
                binascii.hexlify(psk).decode()
                if (psk is not None and len(psk) > 0)
                else ""
            ),
            "th_hello_hex": binascii.hexlify(th_hello).decode() if th_hello else None,
            "th_finished_hex": (
                binascii.hexlify(th_finished).decode() if th_finished else None
            ),
        },
        "early_secret": binascii.hexlify(early_secret).decode(),
        "derived_secret_1": binascii.hexlify(derived1).decode(),
        "handshake_secret": binascii.hexlify(handshake_secret).decode(),
        "client_handshake_traffic_secret": binascii.hexlify(client_hs).decode(),
        "server_handshake_traffic_secret": binascii.hexlify(server_hs).decode(),
        "derived_secret_2": binascii.hexlify(derived2).decode(),
        "master_secret": binascii.hexlify(master_secret).decode(),
    }
    if th_finished is not None:
        trace.update(
            {
                "client_application_traffic_secret": binascii.hexlify(
                    derived.get("client_application_traffic_secret", b"")
                ).decode(),
                "server_application_traffic_secret": binascii.hexlify(
                    derived.get("server_application_traffic_secret", b"")
                ).decode(),
            }
        )

    derived_hex = {
        k: (binascii.hexlify(v).decode() if isinstance(v, (bytes, bytearray)) else v)
        for k, v in derived.items()
    }
    return derived, trace, derived_hex


def compute_shared_secret_from_priv_and_peer(
    priv_hex: str, peer_pub_hex: str, curve: str
):
    """Compute ECDHE shared secret Z from a private key and peer public key."""
    priv = binascii.unhexlify(priv_hex)
    peer = binascii.unhexlify(peer_pub_hex)
    if curve.lower() == "x25519":
        priv_key = x25519.X25519PrivateKey.from_private_bytes(priv)
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer)
        z = priv_key.exchange(peer_pub)
        return z
    elif curve.lower() in ("p256", "secp256r1", "secp256r1"):
        private_value = int.from_bytes(priv, "big")
        private_numbers = ec.derive_private_key(
            private_value, ec.SECP256R1(), default_backend()
        )
        peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer)
        z = private_numbers.exchange(ec.ECDH(), peer_pub)
        return z
    else:
        raise ValueError("unsupported curve")


# =============================================================================
# 0-RTT / PSK Resumption Key Derivation (RFC 8446 Section 4.6.1)
# =============================================================================


def derive_resumption_master_secret(
    master_secret: bytes, th_client_finished: bytes, hash_name: str = "sha256"
) -> bytes:
    """Derive resumption_master_secret (RFC 8446 Section 7.1).

    resumption_master = Derive-Secret(master, "res master", Hash(CH..CF))
    """
    hash_len = hashlib.new(hash_name).digest_size
    return hkdf_expand_label(
        master_secret,
        "res master",
        th_client_finished,
        hash_len,
        hash_alg=get_hash_algo(hash_name),
    )


def derive_psk_from_resumption_master(
    resumption_master: bytes, ticket_nonce: bytes, hash_name: str = "sha256"
) -> bytes:
    """Derive PSK from resumption_master_secret and ticket nonce (RFC 8446 Section 4.6.1).

    PSK = HKDF-Expand-Label(resumption_master, "resumption", ticket_nonce, Hash.length)
    """
    hash_len = hashlib.new(hash_name).digest_size
    return hkdf_expand_label(
        resumption_master,
        "resumption",
        ticket_nonce,
        hash_len,
        hash_alg=get_hash_algo(hash_name),
    )


def derive_early_secrets(
    psk: bytes, client_hello: bytes, hash_name: str = "sha256"
) -> dict:
    """Derive 0-RTT early traffic secrets from PSK and ClientHello (RFC 8446 Section 7.1).

    early_secret = HKDF-Extract(0, PSK)
    CLIENT_EARLY_TRAFFIC_SECRET = Derive-Secret(early_secret, "c e traffic", Hash(CH))
    """
    hash_len = hashlib.new(hash_name).digest_size

    early_secret = hkdf_extract(b"", psk, hash_name)
    ch_hash = hashlib.new(hash_name, client_hello).digest()

    client_early = hkdf_expand_label(
        early_secret,
        "c e traffic",
        ch_hash,
        hash_len,
        hash_alg=get_hash_algo(hash_name),
    )

    early_exporter = hkdf_expand_label(
        early_secret,
        "e exp master",
        ch_hash,
        hash_len,
        hash_alg=get_hash_algo(hash_name),
    )

    return {
        "early_secret": early_secret,
        "client_early_traffic_secret": client_early,
        "early_exporter_secret": early_exporter,
    }
