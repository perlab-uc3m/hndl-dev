#!/usr/bin/env python3
"""Manifest-driven key recovery from an HN-DL capture."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from experiment import (
    ExperimentConfig,
    ManifestError,
    Mode,
    Protocol,
    RecoveryResult,
    RecoverySpec,
    RunManifest,
    recovery_spec,
    sha256_file,
)


def resolve_recovery_spec(
    capture_dir: Path | str,
    protocol: str | Protocol | None = None,
    mode: str | Mode | None = None,
    port: int | None = None,
) -> RecoverySpec:
    """Load recovery inputs from the manifest, checking optional assertions."""
    capture_path = Path(capture_dir).resolve()
    if not (capture_path / "manifest.json").is_file():
        if protocol is None:
            raise ManifestError(
                f"capture manifest not found: {capture_path / 'manifest.json'}"
            )
        config = ExperimentConfig.create(protocol, mode, port)
        return recovery_spec(config.protocol, config.mode, config.port)

    manifest = RunManifest.load(capture_path)
    manifest.verify_recorded_artifacts()
    manifest_spec = manifest.recovery

    if protocol is not None and Protocol.parse(protocol) is not manifest_spec.protocol:
        raise ManifestError(
            f"requested protocol {Protocol.parse(protocol).value} does not match "
            f"manifest protocol {manifest_spec.protocol.value}"
        )
    if mode is not None and Mode.parse(mode) is not manifest_spec.mode:
        requested = Mode.parse(mode)
        raise ManifestError(
            f"requested mode {requested.value if requested else None} does not match "
            f"manifest mode {manifest_spec.mode.value if manifest_spec.mode else None}"
        )
    if port is not None and port != manifest_spec.port:
        raise ManifestError(
            f"requested port {port} does not match manifest port {manifest_spec.port}"
        )
    return manifest_spec


def _derive_mapping(capture_path: Path, spec: RecoverySpec, debug: bool) -> dict:
    if spec.protocol is Protocol.TLS13:
        if spec.mode is Mode.ZERO_RTT:
            from .tls13.derive_0rtt import derive_0rtt

            return derive_0rtt(
                capture_path,
                pcap_phase1=spec.archives[0],
                pcap_phase2=spec.archives[1],
                port=spec.port,
                debug=debug,
                recovery_name=spec.simulated_recovery,
                ground_truth_name=spec.ground_truth[0],
            )
        from .tls13.derive_1rtt import derive_1rtt

        return derive_1rtt(
            capture_path,
            pcap_name=spec.archives[0],
            port=spec.port,
            debug=debug,
            recovery_name=spec.simulated_recovery,
            ground_truth_name=spec.ground_truth[0],
        )

    if spec.protocol is Protocol.TLS12:
        from .tls12.derive_rsa import derive_rsa

        return derive_rsa(
            capture_path,
            pcap_name=spec.archives[0],
            port=spec.port,
            debug=debug,
            recovery_name=spec.simulated_recovery,
            ground_truth_name=spec.ground_truth[0],
        )

    if spec.protocol is Protocol.SSH:
        from .ssh.derive_ssh import derive_ssh

        return derive_ssh(
            capture_path,
            debug=debug,
            recovery_name=spec.simulated_recovery,
            ground_truth_name=spec.ground_truth[0],
        )

    from .quic.derive_quic import derive_quic

    return derive_quic(
        capture_path,
        pcap_name=spec.archives[0],
        port=spec.port,
        debug=debug,
        recovery_name=spec.simulated_recovery,
        ground_truth_name=spec.ground_truth[0],
    )


def _record_provenance(capture_path: Path, spec: RecoverySpec, result: dict) -> Path:
    """Bind derived output to the exact archive, oracle, manifest, and code."""
    from experiment import ArtifactLayout

    layout = ArtifactLayout(capture_path)
    decryptor_root = Path(__file__).parent
    implementations = [Path(__file__), decryptor_root / "io/pcap_parser.py"]
    if spec.protocol is Protocol.TLS12:
        implementations.extend(
            [
                decryptor_root / "tls12/derive_rsa.py",
                decryptor_root / "core/tls12_crypto.py",
            ]
        )
    elif spec.protocol is Protocol.TLS13:
        implementations.extend(
            [
                decryptor_root
                / (
                    "tls13/derive_0rtt.py"
                    if spec.mode is Mode.ZERO_RTT
                    else "tls13/derive_1rtt.py"
                ),
                decryptor_root / "core/tls13_crypto.py",
            ]
        )
    elif spec.protocol is Protocol.QUIC:
        implementations.extend(
            [
                decryptor_root / "quic/derive_quic.py",
                decryptor_root / "core/tls13_crypto.py",
            ]
        )
    else:
        implementations.extend(
            [
                decryptor_root / "ssh/derive_ssh.py",
                decryptor_root / "ssh/oracle.py",
                decryptor_root / "core/ssh_crypto.py",
            ]
        )

    def hashes(paths: tuple[str, ...]) -> dict[str, str]:
        return {
            relative: sha256_file(layout.resolve(relative))
            for relative in paths
            if layout.resolve(relative).is_file()
        }

    provenance = {
        "schema": "hndl-recovery-provenance-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "protocol": spec.protocol.value,
        "mode": spec.mode.value if spec.mode else None,
        "port": spec.port,
        "source_manifest_sha256": (
            sha256_file(layout.manifest) if layout.manifest.is_file() else None
        ),
        "attack_input_sha256": hashes((*spec.archives, spec.simulated_recovery)),
        "comparison_only_sha256": hashes(spec.ground_truth),
        "implementation_sha256": {
            str(path.relative_to(Path(__file__).parents[1])): sha256_file(path)
            for path in implementations
        },
        "success": bool(result.get("success")),
        "plaintext_authenticated": RecoveryResult.from_mapping(
            capture_path, spec, result
        ).plaintext_authenticated,
    }
    output = layout.derived_dir / "recovery_provenance.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(provenance, indent=2) + "\n")
    return output


def recover_protocol(
    capture_dir: Path | str,
    protocol: str | Protocol | None = None,
    mode: str | Mode | None = None,
    debug: bool = False,
    port: int | None = None,
) -> RecoveryResult:
    """Recover a capture using its manifest and return a typed result."""
    capture_path = Path(capture_dir).resolve()
    if not capture_path.is_dir():
        return RecoveryResult(
            False,
            capture_path,
            (),
            False,
            f"capture directory not found: {capture_path}",
        )
    try:
        spec = resolve_recovery_spec(capture_path, protocol, mode, port)
        result = _derive_mapping(capture_path, spec, debug)
        if result.get("success"):
            _record_provenance(capture_path, spec, result)
        return RecoveryResult.from_mapping(capture_path, spec, result)
    except (OSError, RuntimeError, ValueError) as exc:
        return RecoveryResult(False, capture_path, (), False, str(exc))


def derive(
    capture_dir: str,
    protocol: str | Protocol | None = None,
    mode: str | Mode | None = None,
    debug: bool = False,
    port: int | None = None,
) -> dict:
    """Compatibility API returning the protocol-specific result mapping."""
    result = recover_protocol(capture_dir, protocol, mode, debug, port)
    if result.details:
        return dict(result.details)
    return {"success": False, "error": result.error}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-dir", required=True, help="capture directory")
    parser.add_argument(
        "--protocol",
        choices=[protocol.value for protocol in Protocol],
        help="optional assertion; normally read from manifest",
    )
    parser.add_argument(
        "--mode", help="optional assertion; normally read from manifest"
    )
    parser.add_argument(
        "--port", type=int, help="optional assertion; normally read from manifest"
    )
    parser.add_argument("--debug", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    result = recover_protocol(
        args.capture_dir,
        args.protocol,
        args.mode,
        args.debug,
        args.port,
    )
    if not result.success and result.error:
        print(f"Recovery failed: {result.error}", file=sys.stderr)
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
