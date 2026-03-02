#!/usr/bin/env python3
"""HN-DL Attack: Capture traffic, derive session keys."""

import argparse
import subprocess
import sys
import os
from pathlib import Path


def find_latest_capture(data_dir: Path, protocol: str, mode: str = None) -> Path:
    """Find the most recent capture directory."""
    if protocol == "ssh":
        pattern = "*-ssh-capture"
    elif protocol == "tls13":
        pattern = f"*-tls13-{mode}-capture" if mode else "*-tls13-*-capture"
    elif protocol == "tls12":
        pattern = f"*-tls12-{mode}-capture" if mode else "*-tls12-*-capture"
    elif protocol == "quic":
        pattern = "*-quic-capture"
    else:
        pattern = f"*-{protocol}-capture"

    captures = sorted(data_dir.glob(pattern), reverse=True)
    return captures[0] if captures else None


def run_capture(protocol: str, mode: str, port: int, verbose: bool) -> Path:
    """Run capture phase."""
    print(f"\n[HARVEST] Capturing {protocol.upper()} traffic...")

    cmd = [sys.executable, "-m", "capture.capture", "--version", protocol]
    if mode:
        cmd.extend(["--mode", mode])
    if port:
        cmd.extend(["--port", str(port)])
    if verbose:
        cmd.append("--verbose")

    result = subprocess.run(cmd)
    if result.returncode != 0:
        sys.exit(1)

    capture_dir = find_latest_capture(Path("data"), protocol, mode)
    if not capture_dir:
        print("Error: Could not find capture directory")
        sys.exit(1)

    return capture_dir


def run_decryption(capture_dir: Path, protocol: str, mode: str, debug: bool) -> bool:
    """Run key derivation phase."""
    print(f"\n[DECRYPT] Deriving session keys...")

    cmd = [
        sys.executable,
        "-W",
        "ignore::RuntimeWarning",
        "-m",
        "decryptor.derive",
        "--capture-dir",
        str(capture_dir),
        "--protocol",
        protocol,
    ]

    if mode:
        cmd.extend(["--mode", mode])
    if debug:
        cmd.append("--debug")

    result = subprocess.run(cmd)
    return result.returncode == 0


def get_keylog_path(capture_dir: Path, protocol: str, mode: str) -> Path:
    """Get the expected keylog path for the given protocol/mode."""
    if protocol == "ssh":
        return capture_dir / "derived/ssh_derived_keys.json"
    elif protocol == "tls13" and mode == "0rtt":
        return capture_dir / "derived/nss_0rtt.keylog"
    else:
        return capture_dir / "derived/nss_derived.keylog"


def main():
    parser = argparse.ArgumentParser(description="HN-DL Attack Simulation")
    parser.add_argument(
        "--protocol", "-p", choices=["ssh", "tls13", "tls12", "quic"], default="tls13"
    )
    parser.add_argument("--mode", "-m", help="tls13: 1rtt|0rtt, tls12: rsa")
    parser.add_argument("--port", type=int)
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--debug", "-d", action="store_true")
    parser.add_argument("--capture-only", action="store_true")
    parser.add_argument("--decrypt-only", metavar="DIR")
    args = parser.parse_args()

    # Defaults
    if args.protocol == "ssh" and args.port is None:
        args.port = 22222
    elif args.port is None:
        args.port = 44443
    if args.protocol == "tls13" and args.mode is None:
        args.mode = "1rtt"
    if args.protocol == "tls12" and args.mode is None:
        args.mode = "rsa"
    # QUIC has no mode (always 1-RTT TLS 1.3 internally)

    os.chdir(Path(__file__).parent)

    # Decrypt-only mode
    if args.decrypt_only:
        capture_dir = Path(args.decrypt_only)
        if not capture_dir.exists():
            sys.exit(f"Error: {capture_dir} not found")
        success = run_decryption(capture_dir, args.protocol, args.mode, args.debug)
        sys.exit(0 if success else 1)

    # Capture
    capture_dir = run_capture(args.protocol, args.mode, args.port, args.verbose)

    if args.capture_only:
        print(f"\nCapture saved: {capture_dir}")
        print(
            f"To decrypt: python3 hndl.py -p {args.protocol} --decrypt-only {capture_dir}"
        )
        sys.exit(0)

    # Decrypt
    success = run_decryption(capture_dir, args.protocol, args.mode, args.debug)

    # Summary
    print(f"\n{'=' * 60}")
    print(f"HN-DL Pipeline: {'SUCCESS' if success else 'FAILED'}")
    print(f"{'=' * 60}")
    print(f"Capture: {capture_dir}")
    if success:
        keylog = get_keylog_path(capture_dir, args.protocol, args.mode)
        print(f"Keylog:  {keylog}")
        print(f"PCAP:    {capture_dir}/pcap/")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
