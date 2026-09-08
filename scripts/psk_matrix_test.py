#!/usr/bin/env python3
"""Capture and validate the four TLS 1.3 PSK causality cases."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from capture.capture import capture_protocol
from experiment import ExperimentConfig
from scripts.psk_causality_test import run_causality_test


@dataclass(frozen=True)
class Outcome:
    scenario: str
    capture: str | None
    passed: bool
    assertions: dict[str, bool]
    error: str | None = None


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _preflight() -> None:
    for tool in ("dumpcap", "tshark"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"missing tool: {tool}")
    openssl = REPO_ROOT / "openssl/.local/bin/openssl"
    if not openssl.is_file() or not os.access(openssl, os.X_OK):
        raise RuntimeError(f"missing instrumented OpenSSL: {openssl}")
    probe = subprocess.run(["dumpcap", "-D"], capture_output=True, text=True)
    if probe.returncode:
        raise RuntimeError(probe.stderr.strip() or "dumpcap cannot list interfaces")


def _configs(output_root: Path, verbose: bool) -> list[tuple[str, ExperimentConfig]]:
    common = {
        "data_root": output_root,
        "openssl": REPO_ROOT / "openssl/.local/bin/openssl",
        "verbose": verbose,
    }
    return [
        (
            "parent-to-pure-psk-child",
            ExperimentConfig.create(
                "tls13",
                "0rtt",
                _available_port(),
                tls13_resumption_kex="psk-only",
                **common,
            ),
        ),
        (
            "parent-to-psk-dhe-child-and-grandchild",
            ExperimentConfig.create(
                "tls13",
                "0rtt",
                _available_port(),
                tls13_grandchild=True,
                **common,
            ),
        ),
        (
            "independent-external-psk",
            ExperimentConfig.create(
                "tls13", "external-psk", _available_port(), **common
            ),
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    try:
        _preflight()
    except RuntimeError as exc:
        print(f"Preflight failed: {exc}", file=sys.stderr)
        return 2

    temporary = args.output_root is None
    output_root = (
        Path(tempfile.mkdtemp(prefix="hndl-psk-matrix-"))
        if temporary
        else args.output_root.resolve()
    )
    output_root.mkdir(parents=True, exist_ok=True)
    print(f"Artifacts: {output_root}")
    outcomes = []
    for scenario, config in _configs(output_root, args.verbose):
        try:
            capture = capture_protocol(config)
            evidence = run_causality_test(capture.root, args.verbose)
            outcomes.append(
                Outcome(
                    scenario,
                    str(capture.root),
                    bool(evidence["passed"]),
                    dict(evidence["assertions"]),
                )
            )
        except (OSError, RuntimeError, ValueError) as exc:
            outcomes.append(Outcome(scenario, None, False, {}, str(exc)))

    result = {
        "schema": "hndl-tls13-psk-matrix-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "outcomes": [asdict(outcome) for outcome in outcomes],
        "passed": all(outcome.passed for outcome in outcomes),
    }
    result_path = output_root / "psk_matrix_results.json"
    result_path.write_text(json.dumps(result, indent=2) + "\n")
    for outcome in outcomes:
        print(f"{'PASS' if outcome.passed else 'FAIL'}  {outcome.scenario}")
        if outcome.error:
            print(f"  {outcome.error}")

    if temporary and result["passed"] and not args.keep:
        shutil.rmtree(output_root)
        print("All PSK cases passed; temporary artifacts removed.")
    else:
        print(f"Evidence: {result_path}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
