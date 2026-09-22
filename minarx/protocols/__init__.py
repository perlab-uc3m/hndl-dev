"""Protocol-specific MinARX policies."""

from . import quic, ssh, tls12, tls13

CODECS = {
    "tls12": tls12,
    "tls13": tls13,
    "quic": quic,
    "ssh": ssh,
}

__all__ = ["CODECS"]
