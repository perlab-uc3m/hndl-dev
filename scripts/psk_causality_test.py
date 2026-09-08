#!/usr/bin/env python3
"""Prove the parent-PSK/fresh-DH boundary on a TLS 1.3 0-RTT capture."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from decryptor.tls13.derive_0rtt import derive_0rtt
from decryptor.tls13.derive_external_psk import derive_external_psk
from decryptor.tls13.derive_resumption import (
    derive_grandchild_early,
    derive_resumed_1rtt,
)
from decryptor.io import extract_tls_hello_pair, parse_server_keyshare_pub_from_sh
from experiment import ArtifactLayout, Mode, Protocol, RunManifest, sha256_file


def _derive_early(root: Path, manifest: RunManifest, debug: bool = False) -> dict:
    spec = manifest.recovery
    return derive_0rtt(
        root,
        pcap_phase1=spec.archives[0],
        pcap_phase2=spec.archives[1],
        port=spec.port,
        debug=debug,
        recovery_name=spec.simulated_recovery,
        ground_truth_name=spec.ground_truth[0],
    )


def _derive_child(
    root: Path,
    manifest: RunManifest,
    psk: bytes,
    early_secret: bytes,
    fresh_dh_required: bool,
    debug: bool = False,
) -> dict:
    spec = manifest.recovery
    return derive_resumed_1rtt(
        root,
        psk,
        pcap_name=spec.archives[1],
        port=spec.port,
        ground_truth_name=spec.ground_truth[0],
        early_secret=early_secret,
        fresh_dh_required=fresh_dh_required,
        debug=debug,
    )


def _withheld(path: Path, operation):
    temporary = path.with_name(path.name + ".withheld")
    path.rename(temporary)
    try:
        return operation()
    finally:
        temporary.rename(path)


def _run_external_psk(root: Path, manifest: RunManifest, debug: bool = False) -> dict:
    spec = manifest.recovery
    layout = ArtifactLayout(root)

    def derive() -> dict:
        return derive_external_psk(
            root,
            pcap_name=spec.archives[0],
            port=spec.port,
            recovery_name=spec.simulated_recovery,
            ground_truth_name=spec.ground_truth[0],
            debug=debug,
        )

    baseline = derive()
    recovery_path = layout.resolve(spec.simulated_recovery)
    recovery_original = recovery_path.read_text()
    recovery = json.loads(recovery_original)
    psk_hex = recovery["psk"]
    withheld = _withheld(recovery_path, derive)

    wrong = dict(recovery)
    changed_psk = bytearray.fromhex(psk_hex)
    changed_psk[0] ^= 1
    wrong["psk"] = changed_psk.hex()
    recovery_path.write_text(json.dumps(wrong, indent=2) + "\n")
    try:
        wrong_psk = derive()
    finally:
        recovery_path.write_text(recovery_original)

    truth_paths = [layout.resolve(spec.ground_truth[0])]
    external_truth = layout.keys_dir / "external_psk_ground_truth.json"
    if external_truth.is_file():
        truth_paths.append(external_truth)
    moved_truth = [
        (path, path.with_name(path.name + ".withheld")) for path in truth_paths
    ]
    for path, temporary in moved_truth:
        path.rename(temporary)
    try:
        no_truth = derive()
    finally:
        for path, temporary in reversed(moved_truth):
            temporary.rename(path)

    _, server_hello = extract_tls_hello_pair(
        layout.resolve(spec.archives[0]), spec.port
    )
    manifest_text = layout.manifest.read_text()
    assertions = {
        "external_psk_1rtt_authenticated": bool(baseline.get("success")),
        "withheld_external_psk_rejected": not bool(withheld.get("success")),
        "unrelated_psk_rejected": not bool(wrong_psk.get("success")),
        "ground_truth_absent_external_psk_authenticated": bool(no_truth.get("success")),
        "pure_psk_has_no_server_keyshare": bool(server_hello)
        and parse_server_keyshare_pub_from_sh(server_hello) is None,
        "manifest_command_redacts_psk": psk_hex not in manifest_text,
    }
    result = {
        "schema": "hndl-tls13-psk-causality-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "capture": str(root),
        "inputs": {
            relative: sha256_file(layout.resolve(relative))
            for relative in (*spec.archives, spec.simulated_recovery)
        },
        "causal_model": {
            "resumption_key_exchange": "external-psk-only",
            "external_1rtt": [
                "independently provisioned external PSK",
                "matching ClientHello identity",
                "connection transcript",
            ],
            "captured_parent_required": False,
        },
        "assertions": assertions,
        "passed": all(assertions.values()),
    }
    output = layout.derived_dir / "psk_causality_results.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    result["output"] = str(output)
    return result


def run_causality_test(root: Path, debug: bool = False) -> dict:
    root = root.resolve()
    manifest = RunManifest.load(root)
    manifest.verify_recorded_artifacts()
    spec = manifest.recovery
    if spec.protocol is Protocol.TLS13 and spec.mode is Mode.EXTERNAL_PSK:
        return _run_external_psk(root, manifest, debug)
    if spec.protocol is not Protocol.TLS13 or spec.mode is not Mode.ZERO_RTT:
        raise ValueError("PSK causality test requires a TLS 1.3 0-RTT capture")

    layout = ArtifactLayout(root)
    resumption_kex = manifest.data["experiment"].get(
        "resumption_key_exchange", "psk-dhe"
    )
    fresh_dh_required = resumption_kex == "psk-dhe"
    child_recovery = layout.keys_dir / "simulated_quantum_output_phase2.json"
    if fresh_dh_required and not child_recovery.is_file():
        raise ValueError(
            "capture predates the phase-2 recovery artifact; create a fresh 0-RTT capture"
        )

    early = _derive_early(root, manifest, debug)
    if not early.get("success"):
        raise RuntimeError(f"baseline early-data recovery failed: {early.get('error')}")
    psk = bytes.fromhex(early["secrets"]["RESUMPTION_PSK"])
    early_secret = bytes.fromhex(early["secrets"]["CLIENT_EARLY_TRAFFIC_SECRET"])
    child = _derive_child(root, manifest, psk, early_secret, fresh_dh_required, debug)
    grandchild_captured = bool(
        manifest.data["experiment"].get("grandchild_captured", False)
    )
    grandchild = (
        derive_grandchild_early(root, child, port=spec.port, debug=debug)
        if grandchild_captured
        else None
    )

    no_parent = _withheld(
        layout.resolve(spec.simulated_recovery),
        lambda: _derive_early(root, manifest, debug),
    )

    def without_child_dh() -> tuple[dict, dict]:
        return (
            _derive_early(root, manifest, debug),
            _derive_child(root, manifest, psk, early_secret, fresh_dh_required, debug),
        )

    if fresh_dh_required:
        early_without_child_dh, child_without_dh = _withheld(
            child_recovery, without_child_dh
        )
    else:
        early_without_child_dh, child_without_dh = without_child_dh()
    wrong_psk = bytearray(psk)
    wrong_psk[0] ^= 1
    child_with_wrong_psk = _derive_child(
        root,
        manifest,
        bytes(wrong_psk),
        early_secret,
        fresh_dh_required,
        debug,
    )

    truth_paths = [
        layout.resolve(relative)
        for relative in spec.ground_truth
        if layout.resolve(relative).is_file()
    ]
    truth_paths.extend(
        path
        for path in (
            layout.keys_dir / "openssl_ephemeral_ground_truth.json",
            layout.keys_dir / "openssl_ephemeral_phase2_ground_truth.json",
        )
        if path.is_file()
    )
    withheld_truth = [
        (path, path.with_name(path.name + ".withheld")) for path in truth_paths
    ]
    for path, temporary in withheld_truth:
        path.rename(temporary)
    try:
        early_without_truth = _derive_early(root, manifest, debug)
        child_without_truth = _derive_child(
            root, manifest, psk, early_secret, fresh_dh_required, debug
        )
        grandchild_without_truth = (
            derive_grandchild_early(
                root, child_without_truth, port=spec.port, debug=debug
            )
            if grandchild_captured
            else None
        )
    finally:
        for path, temporary in reversed(withheld_truth):
            temporary.rename(path)

    assertions = {
        "baseline_early_data_authenticated": bool(early.get("success")),
        "baseline_child_1rtt_authenticated": bool(child.get("success")),
        "withheld_parent_recovery_rejected_early_data": not bool(
            no_parent.get("success")
        ),
        "early_data_recovers_without_child_dh": bool(
            early_without_child_dh.get("success")
        )
        and early_without_child_dh.get("secrets", {}).get("CLIENT_EARLY_TRAFFIC_SECRET")
        == early["secrets"]["CLIENT_EARLY_TRAFFIC_SECRET"],
        "child_fresh_dh_requirement_enforced": (
            not bool(child_without_dh.get("success"))
            if fresh_dh_required
            else bool(child_without_dh.get("success")) and not child_recovery.exists()
        ),
        "wrong_parent_psk_rejected_child_1rtt": not bool(
            child_with_wrong_psk.get("success")
        ),
        "ground_truth_absent_early_data_authenticated": bool(
            early_without_truth.get("success")
        ),
        "ground_truth_absent_child_1rtt_authenticated": bool(
            child_without_truth.get("success")
        ),
    }
    if grandchild_captured:
        blocked_child = child_without_dh if fresh_dh_required else child_with_wrong_psk
        grandchild_with_blocked_child = derive_grandchild_early(
            root, blocked_child, port=spec.port, debug=debug
        )
        assertions.update(
            {
                "grandchild_early_data_authenticated": bool(
                    grandchild and grandchild.get("success")
                ),
                "grandchild_rejected_without_child_ticket_state": not bool(
                    grandchild_with_blocked_child.get("success")
                ),
                "ground_truth_absent_grandchild_authenticated": bool(
                    grandchild_without_truth and grandchild_without_truth.get("success")
                ),
            }
        )
    result = {
        "schema": "hndl-tls13-psk-causality-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "capture": str(root),
        "inputs": {
            relative: sha256_file(layout.resolve(relative))
            for relative in (*spec.archives, spec.simulated_recovery)
        }
        | (
            {str(child_recovery.relative_to(root)): sha256_file(child_recovery)}
            if child_recovery.is_file()
            else {}
        )
        | (
            {
                "pcap/tls13_0rtt_phase3_grandchild.pcapng": sha256_file(
                    layout.archive_dir / "tls13_0rtt_phase3_grandchild.pcapng"
                )
            }
            if grandchild_captured
            else {}
        ),
        "causal_model": {
            "resumption_key_exchange": resumption_kex,
            "early_data": ["parent-derived PSK", "resumed ClientHello"],
            "child_1rtt": [
                "parent-derived PSK",
                *(["fresh child X25519 recovery"] if fresh_dh_required else []),
                "child transcript",
            ],
            "grandchild_early_data": (
                [
                    "authenticated child connection",
                    "child resumption master secret",
                    "matching child-issued ticket",
                    "grandchild ClientHello",
                ]
                if grandchild_captured
                else None
            ),
        },
        "assertions": assertions,
        "passed": all(assertions.values()),
    }
    output = layout.derived_dir / "psk_causality_results.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    result["output"] = str(output)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--debug", "-d", action="store_true")
    args = parser.parse_args()
    try:
        result = run_causality_test(args.capture, args.debug)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"PSK causality test failed: {exc}", file=sys.stderr)
        return 1
    for name, passed in result["assertions"].items():
        print(f"{'PASS' if passed else 'FAIL'}  {name}")
    print(f"Evidence: {result['output']}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
