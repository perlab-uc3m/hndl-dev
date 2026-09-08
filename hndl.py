#!/usr/bin/env python3
"""Capture traffic and reproduce HN-DL session-key recovery."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from archive_policy import ArchivePolicy, build_policy_archive
from capture.capture import capture_protocol
from decryptor.derive import recover_protocol
from experiment import CaptureResult, ExperimentConfig, Protocol, RecoveryResult


REPO_ROOT = Path(__file__).resolve().parent


def run_capture(config: ExperimentConfig) -> CaptureResult:
    """Capture exactly one configured experiment in this process."""
    print(f"\n[HARVEST] Capturing {config.protocol.value.upper()} traffic...")
    return capture_protocol(config)


def run_decryption(
    capture_dir: Path,
    protocol: str | None = None,
    mode: str | None = None,
    port: int | None = None,
    debug: bool = False,
) -> RecoveryResult:
    """Recover one capture, taking omitted parameters from its manifest."""
    print("\n[DECRYPT] Deriving session keys...")
    return recover_protocol(capture_dir, protocol, mode, debug, port)


def _print_summary(capture: CaptureResult, recovery: RecoveryResult) -> None:
    print(f"\n{'=' * 60}")
    print(f"HN-DL Pipeline: {'SUCCESS' if recovery.success else 'FAILED'}")
    print("=" * 60)
    print(f"Capture: {capture.root}")
    if recovery.success:
        for artifact in recovery.derived_artifacts:
            if artifact.is_file() and artifact.stat().st_size:
                print(f"Derived: {artifact}")
        for archive in capture.archives:
            if archive.is_file() and archive.stat().st_size:
                print(f"Archive: {archive}")
    elif recovery.error:
        print(f"Error:   {recovery.error}")


def _legacy_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--protocol", "-p", choices=[protocol.value for protocol in Protocol]
    )
    parser.add_argument(
        "--mode", "-m", help="tls13: 1rtt|0rtt|external-psk; tls12: rsa"
    )
    parser.add_argument("--port", type=int)
    parser.add_argument(
        "--data-root",
        default=str(REPO_ROOT / "data"),
        help="capture output directory (default: ./data)",
    )
    parser.add_argument("--iface", default="lo", help="capture interface")
    parser.add_argument("--group", default="X25519")
    parser.add_argument(
        "--openssl", default=str(REPO_ROOT / "openssl/.local/bin/openssl")
    )
    parser.add_argument("--openssh-dir", default=str(REPO_ROOT / "openssh/.local"))
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--debug", "-d", action="store_true")
    parser.add_argument("--capture-only", action="store_true")
    parser.add_argument("--decrypt-only", metavar="DIR")
    parser.add_argument("--ssh-rekey-limit", help="SSH RekeyLimit, e.g. 64K")
    parser.add_argument("--ssh-payload-bytes", type=int, default=0)
    parser.add_argument(
        "--tls13-resumption-kex",
        choices=("psk-dhe", "psk-only"),
        default="psk-dhe",
        help="TLS 1.3 0-RTT child key exchange (default: psk-dhe)",
    )
    parser.add_argument(
        "--tls13-grandchild",
        action="store_true",
        help="capture a third connection using a ticket issued by the child",
    )
    return parser


def _recover_command(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="hndl recover", description="Recover a capture"
    )
    parser.add_argument("capture_dir", type=Path)
    parser.add_argument("--debug", "-d", action="store_true")
    args = parser.parse_args(argv)
    recovery = run_decryption(args.capture_dir.resolve(), debug=args.debug)
    if recovery.success:
        print(f"Recovery: SUCCESS ({recovery.capture_root})")
        return 0
    print(f"Recovery: FAILED ({recovery.error})", file=sys.stderr)
    return 1


def _archive_command(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="hndl archive",
        description="Build standalone raw, reassembled, or compact archives",
    )
    parser.add_argument("capture_dir", type=Path)
    parser.add_argument(
        "--policy",
        choices=[policy.value for policy in ArchivePolicy] + ["all"],
        default="all",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        help="parent directory for policy archives (default: beside the capture)",
    )
    args = parser.parse_args(argv)
    capture = args.capture_dir.resolve()
    output_root = (
        args.output_root.resolve()
        if args.output_root
        else capture.parent / "policy-archives"
    )
    policies = (
        list(ArchivePolicy)
        if args.policy == "all"
        else [ArchivePolicy.parse(args.policy)]
    )
    for policy in policies:
        destination = output_root / f"{capture.name}-{policy.value}"
        result = build_policy_archive(capture, destination, policy)
        print(
            f"{policy.value:11} {result.retained_bytes:10d} bytes "
            f"({result.retention_ratio:.4f} of raw): {result.root}"
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(argv if argv is not None else sys.argv[1:])
    if arguments[:1] == ["recover"]:
        return _recover_command(arguments[1:])
    if arguments[:1] == ["archive"]:
        try:
            return _archive_command(arguments[1:])
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"Archive construction failed: {exc}", file=sys.stderr)
            return 1

    args = _legacy_parser().parse_args(arguments)
    if args.decrypt_only:
        recovery = run_decryption(
            Path(args.decrypt_only).resolve(),
            args.protocol,
            args.mode,
            args.port,
            args.debug,
        )
        if not recovery.success and recovery.error:
            print(f"Recovery failed: {recovery.error}", file=sys.stderr)
        return 0 if recovery.success else 1

    try:
        config = ExperimentConfig.create(
            args.protocol or Protocol.TLS13,
            args.mode,
            args.port,
            interface=args.iface,
            group=args.group,
            data_root=args.data_root,
            openssl=args.openssl,
            openssh_dir=args.openssh_dir,
            verbose=args.verbose,
            ssh_rekey_limit=args.ssh_rekey_limit,
            ssh_payload_bytes=args.ssh_payload_bytes,
            tls13_resumption_kex=args.tls13_resumption_kex,
            tls13_grandchild=args.tls13_grandchild,
        )
        capture = run_capture(config)
        if args.capture_only:
            print(f"\nCapture saved: {capture.root}")
            print(f"To recover: python3 hndl.py recover {capture.root}")
            return 0
        recovery = run_decryption(capture.root, debug=args.debug)
        _print_summary(capture, recovery)
        return 0 if recovery.success else 1
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"HN-DL failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
