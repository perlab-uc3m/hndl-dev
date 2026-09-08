#!/usr/bin/env python3
"""Build and prove every archive policy for one or more retained captures."""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from archive_policy import (
    ArchivePolicy,
    WireEvent,
    _decode_wire_events,
    _encode_wire_events,
    build_policy_archive,
)
from decryptor.derive import recover_protocol
from experiment import ArtifactLayout, Mode, Protocol, RunManifest, sha256_file


@dataclass
class PolicyOutcome:
    capture: str
    protocol: str
    mode: str | None
    policy: str
    source_raw_bytes: int
    retained_bytes: int
    protocol_payload_bytes: int
    retention_ratio: float
    recovery_success: bool
    plaintext_authenticated: bool
    ground_truth_absent: bool
    tamper_rejected: bool
    authenticated_tamper_rejected: bool
    missing_recovery_rejected: bool
    transient_inputs_removed: bool
    error: str | None = None

    @property
    def passed(self) -> bool:
        return all(
            (
                self.recovery_success,
                self.plaintext_authenticated,
                self.ground_truth_absent,
                self.tamper_rejected,
                self.authenticated_tamper_rejected,
                self.missing_recovery_rejected,
                self.transient_inputs_removed,
            )
        )


def _negative_controls(root: Path) -> tuple[bool, bool]:
    manifest = RunManifest.load(root)
    layout = ArtifactLayout(root)
    archive = layout.resolve(manifest.recovery.archives[0])
    original = archive.read_bytes()
    if not original:
        raise RuntimeError(f"cannot tamper with empty archive: {archive}")
    changed = bytearray(original)
    changed[-1] ^= 1
    archive.write_bytes(changed)
    try:
        tamper_rejected = not recover_protocol(root).success
    finally:
        archive.write_bytes(original)

    recovery = layout.resolve(manifest.recovery.simulated_recovery)
    withheld = recovery.with_name(recovery.name + ".withheld")
    recovery.rename(withheld)
    try:
        missing_recovery_rejected = not recover_protocol(root).success
    finally:
        withheld.rename(recovery)
    return tamper_rejected, missing_recovery_rejected


def _authenticated_tamper_rejected(root: Path) -> bool:
    """Bypass the file hash and require protocol authentication to reject a bit."""
    manifest = RunManifest.load(root)
    layout = ArtifactLayout(root)
    if manifest.data["archive_policy"]["policy"] != ArchivePolicy.COMPACT.value:
        return True

    archive_index = (
        1
        if manifest.recovery.protocol is Protocol.TLS13
        and manifest.recovery.mode is Mode.ZERO_RTT
        else 0
    )
    relative = manifest.recovery.archives[archive_index]
    archive = layout.resolve(relative)
    events = _decode_wire_events(archive)

    if manifest.recovery.protocol is Protocol.TLS12:
        candidates = [
            index
            for index, event in enumerate(events)
            if event.to_server and event.payload[:1] == b"\x17"
        ]
        selected = candidates[-1]
        byte_index = len(events[selected].payload) - 17
    elif manifest.recovery.protocol is Protocol.TLS13:
        if manifest.recovery.mode is Mode.EXTERNAL_PSK:
            candidates = [
                index
                for index, event in enumerate(events)
                if not event.to_server
                and event.payload[:1] == b"\x17"
                and len(event.payload) > 24
            ]
            selected = max(candidates, key=lambda index: len(events[index].payload))
        else:
            candidates = [
                index
                for index, event in enumerate(events)
                if event.to_server
                and event.payload[:1] == b"\x17"
                and len(event.payload) > 24
            ]
            selected = (
                candidates[0]
                if manifest.recovery.mode is Mode.ZERO_RTT
                else candidates[-1]
            )
        byte_index = len(events[selected].payload) - 17
    elif manifest.recovery.protocol is Protocol.QUIC:
        candidates = [
            index
            for index, event in enumerate(events)
            if event.to_server and not event.payload[0] & 0x80
        ]
        selected = candidates[0]
        byte_index = len(events[selected].payload) - 17
    else:
        candidates = [
            index for index, event in enumerate(events) if not event.to_server
        ]
        selected = candidates[0]
        byte_index = len(events[selected].payload) // 2

    original_archive = archive.read_bytes()
    original_manifest = layout.manifest.read_text()
    changed_payload = bytearray(events[selected].payload)
    changed_payload[byte_index] ^= 1
    events[selected] = WireEvent(events[selected].to_server, bytes(changed_payload))
    archive.write_bytes(_encode_wire_events(events))
    data = json.loads(original_manifest)
    data["artifacts"][relative] = {
        "bytes": archive.stat().st_size,
        "sha256": sha256_file(archive),
    }
    layout.manifest.write_text(json.dumps(data, indent=2) + "\n")
    try:
        return not recover_protocol(root).success
    finally:
        archive.write_bytes(original_archive)
        layout.manifest.write_text(original_manifest)


def _run(capture: Path, output_root: Path, policy: ArchivePolicy) -> PolicyOutcome:
    source = RunManifest.load(capture)
    destination = output_root / f"{capture.name}-{policy.value}"
    try:
        built = build_policy_archive(capture, destination, policy)
        generated = RunManifest.load(destination)
        layout = ArtifactLayout(destination)
        ground_truth_absent = all(
            not layout.resolve(relative).exists()
            for relative in generated.recovery.ground_truth
        )
        recovery = recover_protocol(destination)
        tamper_rejected, missing_recovery_rejected = _negative_controls(destination)
        authenticated_tamper_rejected = _authenticated_tamper_rejected(destination)
        transient_inputs_removed = not any(layout.derived_dir.glob(".policy-input-*"))
        return PolicyOutcome(
            capture.name,
            source.recovery.protocol.value,
            source.recovery.mode.value if source.recovery.mode else None,
            policy.value,
            built.source_raw_bytes,
            built.retained_bytes,
            built.protocol_payload_bytes,
            built.retention_ratio,
            recovery.success,
            recovery.plaintext_authenticated,
            ground_truth_absent,
            tamper_rejected,
            authenticated_tamper_rejected,
            missing_recovery_rejected,
            transient_inputs_removed,
            recovery.error,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return PolicyOutcome(
            capture.name,
            source.recovery.protocol.value,
            source.recovery.mode.value if source.recovery.mode else None,
            policy.value,
            0,
            0,
            0,
            0.0,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            str(exc),
        )


def _write_results(output_root: Path, outcomes: list[PolicyOutcome]) -> None:
    rows = [asdict(outcome) | {"passed": outcome.passed} for outcome in outcomes]
    (output_root / "archive_policy_results.json").write_text(
        json.dumps(
            {
                "schema": "hndl-archive-policy-results-v1",
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "outcomes": rows,
            },
            indent=2,
        )
        + "\n"
    )
    with (output_root / "archive_policy_results.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", type=Path, nargs="+")
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    temporary = args.output_root is None
    output_root = (
        Path(tempfile.mkdtemp(prefix="hndl-archive-policies-"))
        if temporary
        else args.output_root.resolve()
    )
    output_root.mkdir(parents=True, exist_ok=True)
    print(f"Artifacts: {output_root}")

    outcomes = [
        _run(capture.resolve(), output_root, policy)
        for capture in args.captures
        for policy in ArchivePolicy
    ]
    _write_results(output_root, outcomes)
    for outcome in outcomes:
        status = "PASS" if outcome.passed else "FAIL"
        print(
            f"{outcome.protocol:5} {(outcome.mode or '-'):4} "
            f"{outcome.policy:11} {status} "
            f"{outcome.retained_bytes:9d}/{outcome.source_raw_bytes:9d} bytes "
            f"({outcome.retention_ratio:.4f})"
        )
        if outcome.error:
            print(f"  {outcome.error}")

    passed = all(outcome.passed for outcome in outcomes)
    if temporary and passed and not args.keep:
        shutil.rmtree(output_root)
        print("All policies passed; temporary artifacts removed.")
    else:
        print(f"Artifacts retained at: {output_root}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
