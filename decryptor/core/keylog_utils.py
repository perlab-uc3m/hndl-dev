#!/usr/bin/env python3
"""NSS/Wireshark keylog format utilities."""

import binascii
from pathlib import Path


def nss_key_log_line(label: str, secret: bytes):
    """Format a legacy NSS keylog line: LABEL <secret-hex>."""
    return f"{label} {binascii.hexlify(secret).decode()}\n"


def nss_tls13_key_log_line(label: str, client_random: bytes, secret: bytes):
    """Format a TLS 1.3 NSS keylog line: LABEL <client_random> <secret>."""
    return f"{label} {binascii.hexlify(client_random).decode()} {binascii.hexlify(secret).decode()}\n"


def parse_tls13_handshake_secrets_from_keylog(
    keylog_path: Path, client_random: bytes
) -> dict[str, str]:
    """Parse TLS 1.3 secrets from an NSS keylog, filtered by client_random."""
    out: dict[str, str] = {}
    if not keylog_path.exists() or client_random is None:
        return out
    cr_hex = binascii.hexlify(client_random).decode()
    try:
        for line in keylog_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 3:
                continue
            label, cr, secret = parts
            if cr.lower() != cr_hex:
                continue
            if label in (
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                "CLIENT_TRAFFIC_SECRET_0",
                "SERVER_TRAFFIC_SECRET_0",
                "EXPORTER_SECRET",
                "CLIENT_EARLY_TRAFFIC_SECRET",
            ):
                out[label] = secret.lower()
    except Exception:
        return {}
    return out


def _fmt_hex_prefix(h: str | bytes | None, n: int = 16) -> str:
    """Format hex string/bytes as prefix for display."""
    if h is None:
        return "-"
    if isinstance(h, (bytes, bytearray)):
        h = binascii.hexlify(h).decode()
    h = h.lower()
    return h[:n] + ("..." if len(h) > n else "")


def print_secret_comparison(
    title: str, truth: dict[str, str], derived: dict[str, str], verbose: bool = False
):
    """Print comparison of truth vs derived secrets."""
    # A missing reference must never make validation pass vacuously.  Only the
    # secrets the attack claims to derive are required; unrelated reference
    # labels (for example EXPORTER_SECRET) are ignored.
    labels = sorted(derived.keys())
    if not labels:
        return 0, 0
    ok = 0
    total = 0
    for lab in labels:
        t = truth.get(lab)
        d = derived.get(lab)
        total += 1
        if t and d:
            if t.lower() == d.lower():
                ok += 1
                if verbose:
                    print(f"  {lab}: OK")
            elif verbose:
                print(f"  {lab}: MISMATCH")
        elif verbose:
            if t and not d:
                print(f"  {lab}: not derived")
            elif d and not t:
                print(f"  {lab}: no reference")
    return ok, total
