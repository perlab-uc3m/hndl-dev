#!/usr/bin/env python3
"""Create, inspect, or expand a protocol-aware minimal archive."""

import argparse
import json
from pathlib import Path

from .archive import ArchiveError, compact_capture, inspect_archive, materialize_archive
from .profiles import PROFILES, profiles_by_category


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Protocol-aware MinARX archives"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    compact = subparsers.add_parser("compact", help="compact a capture directory")
    compact.add_argument("--capture-dir", required=True, type=Path)
    compact.add_argument("--output", required=True, type=Path)
    compact.add_argument(
        "--protocol", required=True, choices=["tls12", "tls13", "quic", "ssh"]
    )
    compact.add_argument("--mode")
    compact.add_argument("--profile", choices=sorted(PROFILES))
    compact.add_argument("--port", type=int)
    compact.add_argument(
        "--compression", choices=["auto", "none", "deflate", "lzma"], default="auto"
    )

    inspect = subparsers.add_parser(
        "inspect", help="verify and print archive accounting"
    )
    inspect.add_argument("archive", type=Path)

    expand = subparsers.add_parser(
        "expand", help="create a temporary decoder-compatible capture"
    )
    expand.add_argument("archive", type=Path)
    expand.add_argument("--output-dir", required=True, type=Path)

    subparsers.add_parser("profiles", help="list parameterized protocol profiles")

    args = parser.parse_args()
    try:
        if args.command == "compact":
            result = compact_capture(
                args.capture_dir,
                args.output,
                args.protocol,
                args.mode,
                args.port,
                profile=args.profile,
                compression=args.compression,
            )
        elif args.command == "inspect":
            result = inspect_archive(args.archive)
        elif args.command == "expand":
            result = materialize_archive(args.archive, args.output_dir)
        else:
            result = {
                category: [profile.to_metadata() for profile in profiles]
                for category, profiles in profiles_by_category().items()
            }
    except ArchiveError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
