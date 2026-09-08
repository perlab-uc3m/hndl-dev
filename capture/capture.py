#!/usr/bin/env python3
"""Typed capture dispatch for TLS 1.2, TLS 1.3, QUIC, and SSH."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from experiment import CaptureResult, ExperimentConfig, Protocol

from .common import CaptureLifecycle, check_tool, ensure_exec, now_ts
from .quic.capture_quic import capture_quic
from .ssh.capture_ssh import capture_ssh
from .tls12.capture_rsa import capture_tls12_rsa
from .tls13.capture_0rtt import capture_0rtt as tls13_capture_0rtt
from .tls13.capture_1rtt import capture_1rtt as tls13_capture_1rtt
from .tls13.capture_external_psk import capture_external_psk


def _capture_configured(config: ExperimentConfig, capture_root: Path) -> None:
    if config.protocol is Protocol.SSH:
        sshd = config.openssh_dir / "sbin/sshd"
        ssh = config.openssh_dir / "bin/ssh"
        ssh_keygen = config.openssh_dir / "bin/ssh-keygen"
        for binary, name in ((sshd, "sshd"), (ssh, "ssh"), (ssh_keygen, "ssh-keygen")):
            ensure_exec(binary, name)
        capture_ssh(
            sshd,
            ssh,
            ssh_keygen,
            config.interface,
            config.port,
            capture_root,
            config.verbose,
            config.ssh_rekey_limit,
            config.ssh_payload_bytes,
        )
    else:
        ensure_exec(config.openssl, "openssl")
        if config.protocol is Protocol.TLS13:
            arguments = (
                config.openssl,
                config.interface,
                config.port,
                config.group,
                capture_root,
                config.verbose,
            )
            if config.mode.value == "0rtt":
                tls13_capture_0rtt(
                    *arguments,
                    config.tls13_resumption_kex,
                    config.tls13_grandchild,
                )
            elif config.mode.value == "external-psk":
                capture_external_psk(*arguments)
            else:
                tls13_capture_1rtt(*arguments)
        elif config.protocol is Protocol.QUIC:
            capture_quic(
                config.openssl,
                config.interface,
                config.port,
                config.group,
                capture_root,
                config.verbose,
            )
        else:
            capture_tls12_rsa(
                config.openssl,
                config.interface,
                config.port,
                capture_root,
                config.verbose,
            )


def capture_protocol(config: ExperimentConfig) -> CaptureResult:
    """Run one configured capture and return its exact artifacts."""
    check_tool("tshark")
    check_tool("dumpcap")
    capture_root = config.data_root / f"{now_ts()}-{config.capture_label}"
    with CaptureLifecycle():
        _capture_configured(config, capture_root)

    result = CaptureResult.from_manifest(capture_root)
    if config.verbose:
        print(f"\n[+] Capture result: {result}")
    return result


def _parser(repo_root: Path) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version",
        choices=[protocol.value for protocol in Protocol],
        default=Protocol.TLS13.value,
        help="protocol to capture (default: tls13)",
    )
    parser.add_argument("--mode", help="tls13: 1rtt|0rtt|external-psk; tls12: rsa")
    parser.add_argument(
        "--openssl",
        default=str(repo_root / "openssl/.local/bin/openssl"),
        help="OpenSSL binary (default: ./openssl/.local/bin/openssl)",
    )
    parser.add_argument(
        "--openssh-dir",
        default=str(repo_root / "openssh/.local"),
        help="OpenSSH installation (default: ./openssh/.local)",
    )
    parser.add_argument("--iface", default="lo", help="capture interface")
    parser.add_argument("--port", type=int, help="loopback service port")
    parser.add_argument("--group", default="X25519", help="TLS key-exchange group")
    parser.add_argument(
        "--data-root",
        default=str(repo_root / "data"),
        help="root data directory (default: ./data)",
    )
    parser.add_argument("--label", help="custom capture-directory suffix")
    parser.add_argument("--ssh-rekey-limit", help="OpenSSH RekeyLimit, e.g. 64K")
    parser.add_argument(
        "--ssh-payload-bytes",
        type=int,
        default=0,
        help="zero bytes to send before the SSH recovery marker",
    )
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--tls13-resumption-kex",
        choices=("psk-dhe", "psk-only"),
        default="psk-dhe",
    )
    parser.add_argument("--tls13-grandchild", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parent.parent
    parser = _parser(repo_root)
    args = parser.parse_args(argv)
    try:
        config = ExperimentConfig.create(
            args.version,
            args.mode,
            args.port,
            interface=args.iface,
            group=args.group,
            data_root=args.data_root,
            label=args.label,
            openssl=args.openssl,
            openssh_dir=args.openssh_dir,
            verbose=args.verbose,
            ssh_rekey_limit=args.ssh_rekey_limit,
            ssh_payload_bytes=args.ssh_payload_bytes,
            tls13_resumption_kex=args.tls13_resumption_kex,
            tls13_grandchild=args.tls13_grandchild,
        )
        capture_protocol(config)
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Capture failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)
