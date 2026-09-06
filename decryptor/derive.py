#!/usr/bin/env python3
"""Unified key derivation entrypoint for HN-DL attack simulation."""

import argparse
import sys
from pathlib import Path


def derive(
    capture_dir: str, protocol: str, mode: str = None, debug: bool = False
) -> dict:
    """Dispatch key derivation to protocol-specific handler."""
    capture_path = Path(capture_dir)
    if not capture_path.exists():
        return {
            "success": False,
            "error": f"Capture directory not found: {capture_dir}",
        }

    if protocol == "tls13":
        if mode == "0rtt":
            from .tls13.derive_0rtt import derive_0rtt

            return derive_0rtt(capture_path, debug=debug)
        else:
            from .tls13.derive_1rtt import derive_1rtt

            return derive_1rtt(capture_path, debug=debug)

    elif protocol == "tls12":
        from .tls12.derive_rsa import derive_rsa

        return derive_rsa(capture_path, debug=debug)

    elif protocol == "ssh":
        from .ssh.derive_ssh import derive_ssh

        return derive_ssh(capture_path, debug=debug)

    elif protocol == "quic":
        from .quic.derive_quic import derive_quic

        return derive_quic(capture_path, debug=debug)

    else:
        return {"success": False, "error": f"Unknown protocol: {protocol}"}


def main():
    parser = argparse.ArgumentParser(
        description="Key derivation from captures (HN-DL attack)"
    )
    parser.add_argument("--capture-dir", required=True, help="Capture directory path")
    parser.add_argument(
        "--protocol", choices=["tls13", "tls12", "ssh", "quic"], default="tls13"
    )
    parser.add_argument("--mode", help="tls13: 1rtt|0rtt, tls12: rsa")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    # Defaults
    if args.protocol == "tls13" and not args.mode:
        args.mode = "1rtt"
    if args.protocol == "tls12" and not args.mode:
        args.mode = "rsa"

    result = derive(args.capture_dir, args.protocol, args.mode, args.debug)
    if not result.get("success") and result.get("error"):
        print(f"Recovery failed: {result['error']}", file=sys.stderr)
    sys.exit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
