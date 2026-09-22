#!/usr/bin/env python3
"""Build MinARX archives and require authenticated recovery for paper rows."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from decryptor.derive import derive_compacted
from experiment import RunManifest, sha256_file
from minarx import ArchiveError, compact_capture
from minarx.profiles import PROFILES


@dataclass(frozen=True)
class MinArxOutcome:
    capture: str
    category: str
    profile: str
    source_manifest_sha256: str
    minarx_sha256: str
    raw_capture_bytes: int
    transport_payload_bytes: int
    opaque_bytes: int
    capture_envelope_bytes: int
    clear_protocol_bytes: int
    protocol_layout_bytes: int
    protocol_projection_saving_bytes: int
    fixed_container_bytes: int
    layout_entropy_saving_bytes: int
    minarx_bytes: int
    total_saved_bytes: int
    recovery_success: bool
    plaintext_authenticated: bool
    reference_keylog_absent: bool
    error: str | None = None

    @property
    def passed(self) -> bool:
        return (
            self.recovery_success
            and self.plaintext_authenticated
            and self.reference_keylog_absent
            and self.total_saved_bytes
            == self.raw_capture_bytes - self.minarx_bytes
        )


def _plaintext_authenticated(result: dict) -> bool:
    validation = result.get("validation", {})
    return bool(
        result.get("expected_plaintext_recovered")
        or validation.get("application_plaintext_recovered")
        or validation.get("early_application_plaintext_recovered")
        or validation.get("application_response_authenticated")
    )


def _profile_candidates(protocol: str, mode: str) -> list[str]:
    return [
        name
        for name, profile in PROFILES.items()
        if profile.protocol == protocol and profile.mode == mode
    ]


def _select_profile(
    capture: Path,
    protocol: str,
    mode: str,
    port: int,
    requested: str | None,
) -> str:
    if requested:
        return requested
    matches = []
    failures = []
    with tempfile.TemporaryDirectory(prefix="minarx-profile-") as directory:
        root = Path(directory)
        for candidate in _profile_candidates(protocol, mode):
            try:
                compact_capture(
                    capture,
                    root / f"{candidate}.minarx",
                    protocol,
                    mode,
                    port,
                    profile=candidate,
                    compression="none",
                )
                matches.append(candidate)
            except ArchiveError as exc:
                failures.append(f"{candidate}: {exc}")
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise ArchiveError(
            "no MinARX profile matches the trace; " + "; ".join(failures)
        )
    raise ArchiveError(
        "trace matches multiple profiles; pass --profile CAPTURE=PROFILE: "
        + ", ".join(matches)
    )


def _run(
    capture: Path,
    output_root: Path,
    requested_profile: str | None,
) -> MinArxOutcome:
    source = RunManifest.load(capture)
    source.verify_recorded_artifacts()
    protocol = source.recovery.protocol.value
    mode = source.recovery.mode.value if source.recovery.mode else "default"
    port = source.recovery.port
    profile = _select_profile(
        capture, protocol, mode, port, requested_profile
    )
    archive = output_root / f"{capture.name}-{profile}.minarx"
    try:
        stats = compact_capture(
            capture,
            archive,
            protocol,
            mode,
            port,
            profile=profile,
            compression="auto",
        )
        derived = output_root / "derived" / capture.name
        recovery = derive_compacted(
            str(archive),
            str(capture),
            protocol=protocol,
            mode=mode,
            output_dir=str(derived),
        )
        reference_absent = not any(
            path.name in {"sslkeylog.log", "client_keylog.log", "ssh_ground_truth.json"}
            for path in derived.rglob("*")
            if path.is_file()
        )
        return MinArxOutcome(
            capture.name,
            stats["category"],
            profile,
            sha256_file(source.path),
            sha256_file(archive),
            stats["raw_capture_bytes"],
            stats["transport_payload_bytes"],
            stats["opaque_bytes"],
            stats["capture_envelope_bytes"],
            stats["clear_protocol_bytes"],
            stats["protocol_layout_bytes"],
            stats["protocol_projection_saving_bytes"],
            stats["fixed_container_bytes"],
            stats["layout_entropy_saving_bytes"],
            stats["archive_bytes"],
            stats["bytes_saved_vs_raw"],
            bool(recovery.get("success")),
            _plaintext_authenticated(recovery),
            reference_absent,
            recovery.get("error"),
        )
    except (OSError, RuntimeError, ValueError) as exc:
        selected = PROFILES[profile]
        return MinArxOutcome(
            capture.name,
            selected.category,
            profile,
            sha256_file(source.path),
            sha256_file(archive) if archive.is_file() else "",
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            False,
            False,
            False,
            str(exc),
        )


def _write_results(output_root: Path, outcomes: list[MinArxOutcome]) -> None:
    repo_root = Path(__file__).resolve().parent.parent
    rows = [asdict(item) | {"passed": item.passed} for item in outcomes]
    payload = {
        "schema": "hndl-minarx-paper-experiment-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "opaque_bytes_entropy_coded": False,
        "fixed_container_bytes": 66,
        "success_criterion": (
            "future recovery authenticates application plaintext without a "
            "reference key log"
        ),
        "implementation_sha256": {
            relative: sha256_file(repo_root / relative)
            for relative in (
                "archive_policy.py",
                "minarx/archive.py",
                "minarx/format.py",
                "minarx/pcap.py",
                "minarx/profiles.py",
                "minarx/protocols/common.py",
                "minarx/protocols/tls12.py",
                "minarx/protocols/tls13.py",
                "minarx/protocols/quic.py",
                "minarx/protocols/ssh.py",
                "decryptor/derive.py",
                "scripts/minarx_experiment.py",
            )
        },
        "outcomes": rows,
    }
    (output_root / "minarx_results.json").write_text(
        json.dumps(payload, indent=2) + "\n"
    )
    with (output_root / "minarx_results.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _profile_overrides(values: list[str]) -> dict[str, str]:
    result = {}
    for value in values:
        capture, separator, profile = value.partition("=")
        if not separator or profile not in PROFILES:
            raise ValueError("--profile must be CAPTURE=PROFILE with a known profile")
        result[str(Path(capture).resolve())] = profile
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", nargs="+", type=Path)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--profile",
        action="append",
        default=[],
        metavar="CAPTURE=PROFILE",
        help="override automatic profile selection for one capture",
    )
    args = parser.parse_args()
    output_root = args.output_root.resolve()
    if output_root.exists() and any(output_root.iterdir()):
        parser.error(f"output directory is not empty: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)
    try:
        overrides = _profile_overrides(args.profile)
        outcomes = [
            _run(
                capture.resolve(),
                output_root,
                overrides.get(str(capture.resolve())),
            )
            for capture in args.captures
        ]
    except (OSError, RuntimeError, ValueError) as exc:
        if not any(output_root.iterdir()):
            output_root.rmdir()
        parser.error(str(exc))
    _write_results(output_root, outcomes)
    for item in outcomes:
        status = "PASS" if item.passed else "FAIL"
        print(
            f"{status} {item.category}: raw={item.raw_capture_bytes} "
            f"opaque={item.opaque_bytes} minarx={item.minarx_bytes} "
            f"saved={item.total_saved_bytes}"
        )
        if item.error:
            print(f"  {item.error}")
    print(f"Results: {output_root}")
    return 0 if all(item.passed for item in outcomes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
