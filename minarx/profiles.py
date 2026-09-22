"""Explicit protocol profiles used for MinARX accounting and tests.

Profiles distinguish parameters that can change the sufficient archive:
transcript rules, key-establishment mode, cipher/hash selection, resumption,
early data, and protocol-specific packet protection. They are deliberately
more precise than a label such as merely "TLS 1.3".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ProtocolProfile:
    name: str
    category: str
    protocol: str
    mode: str
    cipher_suite: str
    cipher_suite_id: int | None
    key_exchange: str
    hash_name: str
    resumption: str = "none"
    early_data: bool = False
    extended_master_secret: bool | None = None
    quic_version: int | None = None
    notes: str = ""

    def to_metadata(self) -> dict:
        return asdict(self)


def _profile(
    name: str,
    category: str,
    protocol: str,
    mode: str,
    cipher_suite: str,
    cipher_suite_id: int | None,
    key_exchange: str,
    hash_name: str,
    **kwargs,
) -> ProtocolProfile:
    return ProtocolProfile(
        name=name,
        category=category,
        protocol=protocol,
        mode=mode,
        cipher_suite=cipher_suite,
        cipher_suite_id=cipher_suite_id,
        key_exchange=key_exchange,
        hash_name=hash_name,
        **kwargs,
    )


PROFILES = {
    profile.name: profile
    for profile in (
        _profile(
            "tls12-rsa-aes128-sha-noems",
            "TLS 1.2 RSA / no EMS",
            "tls12",
            "rsa",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            0x002F,
            "rsa-key-transport",
            "sha256",
            extended_master_secret=False,
        ),
        _profile(
            "tls12-rsa-aes128-sha-ems",
            "TLS 1.2 RSA / EMS",
            "tls12",
            "rsa",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            0x002F,
            "rsa-key-transport",
            "sha256",
            extended_master_secret=True,
        ),
        _profile(
            "tls12-rsa-aes128gcm-ems",
            "TLS 1.2 RSA / EMS",
            "tls12",
            "rsa",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            0x009C,
            "rsa-key-transport",
            "sha256",
            extended_master_secret=True,
        ),
        _profile(
            "tls13-full-aes128gcm",
            "TLS 1.3 full handshake",
            "tls13",
            "1rtt",
            "TLS_AES_128_GCM_SHA256",
            0x1301,
            "x25519",
            "sha256",
        ),
        _profile(
            "tls13-full-aes256gcm",
            "TLS 1.3 full handshake",
            "tls13",
            "1rtt",
            "TLS_AES_256_GCM_SHA384",
            0x1302,
            "x25519",
            "sha384",
        ),
        _profile(
            "tls13-full-chacha20",
            "TLS 1.3 full handshake",
            "tls13",
            "1rtt",
            "TLS_CHACHA20_POLY1305_SHA256",
            0x1303,
            "x25519",
            "sha256",
        ),
        _profile(
            "tls13-ticket-0rtt-aes128gcm",
            "TLS 1.3 resumption / 0-RTT",
            "tls13",
            "0rtt",
            "TLS_AES_128_GCM_SHA256",
            0x1301,
            "resumption-psk+x25519",
            "sha256",
            resumption="ticket-psk-dhe",
            early_data=True,
        ),
        _profile(
            "quic-v1-aes128gcm",
            "QUIC v1",
            "quic",
            "default",
            "TLS_AES_128_GCM_SHA256",
            0x1301,
            "x25519",
            "sha256",
            quic_version=1,
        ),
        _profile(
            "quic-v1-aes256gcm",
            "QUIC v1",
            "quic",
            "default",
            "TLS_AES_256_GCM_SHA384",
            0x1302,
            "x25519",
            "sha384",
            quic_version=1,
        ),
        _profile(
            "quic-v1-chacha20",
            "QUIC v1",
            "quic",
            "default",
            "TLS_CHACHA20_POLY1305_SHA256",
            0x1303,
            "x25519",
            "sha256",
            quic_version=1,
        ),
        _profile(
            "ssh-curve25519-chacha20",
            "SSH initial/rekey stream",
            "ssh",
            "default",
            "chacha20-poly1305@openssh.com",
            None,
            "curve25519-sha256",
            "sha256",
        ),
        _profile(
            "ssh-curve25519-aes128gcm",
            "SSH initial/rekey stream",
            "ssh",
            "default",
            "aes128-gcm@openssh.com",
            None,
            "curve25519-sha256",
            "sha256",
        ),
        _profile(
            "tls13-ticket-0rtt-aes256gcm",
            "TLS 1.3 ticket resumption / 0-RTT (PSK-DHE)",
            "tls13",
            "0rtt",
            "TLS_AES_256_GCM_SHA384",
            0x1302,
            "resumption-psk+x25519",
            "sha384",
            resumption="ticket-psk-dhe",
            early_data=True,
        ),
        _profile(
            "tls13-ticket-0rtt-psk-only-aes256gcm",
            "TLS 1.3 ticket resumption / 0-RTT (PSK-only)",
            "tls13",
            "0rtt",
            "TLS_AES_256_GCM_SHA384",
            0x1302,
            "bootstrap-x25519;resumption-psk-only",
            "sha384",
            resumption="ticket-psk-only",
            early_data=True,
        ),
        _profile(
            "tls13-external-psk-aes256gcm",
            "TLS 1.3 external PSK (no DHE)",
            "tls13",
            "external-psk",
            "TLS_AES_256_GCM_SHA384",
            0x1302,
            "external-psk-only",
            "sha384",
            resumption="external-psk",
        ),
        _profile(
            "tls13-external-psk-chacha20",
            "TLS 1.3 external PSK (no DHE)",
            "tls13",
            "external-psk",
            "TLS_CHACHA20_POLY1305_SHA256",
            0x1303,
            "external-psk-only",
            "sha256",
            resumption="external-psk",
        ),
    )
}

# These IDs are part of the MinARX v1 wire format.  Append new profiles; never
# reorder existing entries after archives have been published.
PROFILE_NAMES = (
    "tls12-rsa-aes128-sha-noems",
    "tls12-rsa-aes128-sha-ems",
    "tls12-rsa-aes128gcm-ems",
    "tls13-full-aes128gcm",
    "tls13-full-aes256gcm",
    "tls13-full-chacha20",
    "tls13-ticket-0rtt-aes128gcm",
    "quic-v1-aes128gcm",
    "quic-v1-aes256gcm",
    "quic-v1-chacha20",
    "ssh-curve25519-chacha20",
    "ssh-curve25519-aes128gcm",
    "tls13-ticket-0rtt-aes256gcm",
    "tls13-ticket-0rtt-psk-only-aes256gcm",
    "tls13-external-psk-aes256gcm",
    "tls13-external-psk-chacha20",
)
PROFILE_IDS = {name: index for index, name in enumerate(PROFILE_NAMES, start=1)}
PROFILES_BY_ID = {PROFILE_IDS[name]: PROFILES[name] for name in PROFILE_NAMES}


DEFAULT_PROFILE = {
    ("tls12", "rsa"): "tls12-rsa-aes128-sha-ems",
    ("tls13", "1rtt"): "tls13-full-aes128gcm",
    ("tls13", "0rtt"): "tls13-ticket-0rtt-aes128gcm",
    ("tls13", "external-psk"): "tls13-external-psk-aes256gcm",
    ("quic", "default"): "quic-v1-aes128gcm",
    ("ssh", "default"): "ssh-curve25519-chacha20",
}


def resolve_profile(
    protocol: str, mode: str, profile: str | ProtocolProfile | None
) -> ProtocolProfile:
    if profile is None:
        try:
            return PROFILES[DEFAULT_PROFILE[(protocol, mode)]]
        except KeyError as exc:
            raise ValueError(
                f"no default MinARX profile for {protocol}/{mode}"
            ) from exc
    if isinstance(profile, str):
        try:
            selected = PROFILES[profile]
        except KeyError as exc:
            raise ValueError(f"unknown MinARX profile: {profile}") from exc
    else:
        selected = profile
    if selected.protocol != protocol or selected.mode != mode:
        raise ValueError(
            f"profile {selected.name} is for {selected.protocol}/{selected.mode}, "
            f"not {protocol}/{mode}"
        )
    return selected


def profiles_by_category() -> dict[str, list[ProtocolProfile]]:
    categories: dict[str, list[ProtocolProfile]] = {}
    for profile in PROFILES.values():
        categories.setdefault(profile.category, []).append(profile)
    return categories
