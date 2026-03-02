#!/usr/bin/env python3
"""Unified capture entrypoint for TLS 1.2, TLS 1.3, QUIC, and SSH."""

import argparse
import sys
from pathlib import Path

from .common import ensure_exec, check_tool, now_ts

# TLS 1.3 implementations
from .tls13.capture_1rtt import capture_1rtt as tls13_capture_1rtt
from .tls13.capture_0rtt import capture_0rtt as tls13_capture_0rtt

# TLS 1.2 implementations
from .tls12.capture_rsa import capture_tls12_rsa

# SSH implementation
from .ssh.capture_ssh import capture_ssh

# QUIC implementation
from .quic.capture_quic import capture_quic


def main():
    repo_root = Path(__file__).resolve().parent.parent

    ap = argparse.ArgumentParser(
        description="Unified TLS/SSH/QUIC capture tool",
    )

    ap.add_argument(
        "--version",
        choices=["tls12", "tls13", "ssh", "quic"],
        default="tls13",
        help="Protocol version to capture (default: tls13)",
    )
    ap.add_argument(
        "--mode",
        help="Capture mode. tls13: {1rtt,0rtt}. tls12: {rsa}. ssh: ignored.",
        default=None,
    )
    ap.add_argument(
        "--openssl",
        default=str(repo_root / "openssl/.local/bin/openssl"),
        help="Path to OpenSSL binary (default: ./openssl/.local/bin/openssl)",
    )
    ap.add_argument(
        "--openssh-dir",
        default=str(repo_root / "openssh/.local"),
        help="Path to OpenSSH install directory (default: ./openssh/.local)",
    )
    ap.add_argument("--iface", default="lo", help="Capture interface (default: lo)")
    ap.add_argument("--port", type=int, default=44443, help="TCP port (default: 44443)")
    ap.add_argument(
        "--group",
        default="X25519",
        help="TLS group for TLS 1.3 -groups option (default: X25519)",
    )
    ap.add_argument(
        "--data-root",
        default=str(repo_root / "data"),
        help="Root data directory (default: ./data)",
    )
    ap.add_argument(
        "--label",
        default=None,
        help="Custom folder label suffix (default: auto-generated)",
    )
    ap.add_argument("--verbose", action="store_true", help="Print detailed progress")

    args = ap.parse_args()

    check_tool("tshark")

    # Prepare capture directory label
    if args.label is None:
        if args.version == "ssh":
            label = "ssh-capture"
        elif args.version == "quic":
            label = "quic-capture"
        elif args.version == "tls13":
            args.mode = args.mode or "1rtt"
            label = f"tls13-{args.mode}-capture"
        else:
            args.mode = args.mode or "rsa"
            label = f"tls12-{args.mode}-capture"
    else:
        label = args.label

    capture_root = Path(args.data_root) / f"{now_ts()}-{label}"

    # Dispatch
    result = None
    if args.version == "ssh":
        openssh_dir = Path(args.openssh_dir)
        sshd = openssh_dir / "sbin/sshd"
        ssh_bin = openssh_dir / "bin/ssh"
        ssh_keygen = openssh_dir / "bin/ssh-keygen"
        for bin_path, name in [
            (sshd, "sshd"),
            (ssh_bin, "ssh"),
            (ssh_keygen, "ssh-keygen"),
        ]:
            ensure_exec(bin_path, name)
        result = capture_ssh(
            sshd, ssh_bin, ssh_keygen, args.iface, args.port, capture_root, args.verbose
        )
    elif args.version == "tls13":
        openssl = Path(args.openssl)
        ensure_exec(openssl, "openssl")
        if args.mode not in ("1rtt", "0rtt"):
            sys.exit("For tls13, --mode must be one of: 1rtt, 0rtt")
        if args.mode == "1rtt":
            result = tls13_capture_1rtt(
                openssl, args.iface, args.port, args.group, capture_root, args.verbose
            )
        else:
            result = tls13_capture_0rtt(
                openssl, args.iface, args.port, args.group, capture_root, args.verbose
            )
    elif args.version == "quic":
        openssl = Path(args.openssl)
        ensure_exec(openssl, "openssl")
        result = capture_quic(
            openssl, args.iface, args.port, args.group, capture_root, args.verbose
        )
    else:  # tls12
        openssl = Path(args.openssl)
        ensure_exec(openssl, "openssl")
        if args.mode != "rsa":
            sys.exit("For tls12, only --mode rsa is supported")
        result = capture_tls12_rsa(
            openssl, args.iface, args.port, capture_root, args.verbose
        )

    if args.verbose:
        print(f"\n[+] Capture result: {result}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)
