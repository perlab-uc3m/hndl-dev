"""High-level MinARX creation, inspection, and materialization."""

from __future__ import annotations

import json
from pathlib import Path

from .format import FormatError, read_container, write_container
from .pcap import PcapError
from .profiles import ProtocolProfile, resolve_profile
from .protocols import CODECS


class ArchiveError(RuntimeError):
    pass


DEFAULT_MODES = {"tls12": "rsa", "tls13": "1rtt", "quic": "default", "ssh": "default"}
DEFAULT_PORTS = {"tls12": 44443, "tls13": 44443, "quic": 44443, "ssh": 22222}


def compact_capture(
    capture_dir: Path,
    output: Path,
    protocol: str,
    mode: str | None = None,
    port: int | None = None,
    profile: str | ProtocolProfile | None = None,
    compression: str = "auto",
) -> dict:
    capture_dir, output = Path(capture_dir), Path(output)
    if protocol not in CODECS:
        raise ArchiveError(f"unsupported protocol: {protocol}")
    mode = mode or DEFAULT_MODES[protocol]
    port = port or DEFAULT_PORTS[protocol]
    try:
        selected_profile = resolve_profile(protocol, mode, profile)
        layout, opaque, protocol_metadata = CODECS[protocol].compact(
            capture_dir, mode, port, selected_profile
        )
    except (FileNotFoundError, ValueError, PcapError) as exc:
        raise ArchiveError(str(exc)) from exc
    raw_bytes = sum(item["raw_capture_bytes"] for item in protocol_metadata["captures"])
    transport_bytes = sum(
        item["transport_payload_bytes"] for item in protocol_metadata["captures"]
    )
    opaque_bytes = sum(item["opaque_bytes"] for item in protocol_metadata["captures"])
    if opaque_bytes != len(opaque):
        raise ArchiveError("protocol codec opaque-byte accounting mismatch")
    archive_bytes = write_container(
        output,
        selected_profile,
        port,
        raw_bytes,
        transport_bytes,
        layout,
        opaque,
        compression,
    )
    container = read_container(output)
    fixed_container_bytes = archive_bytes - opaque_bytes - container.stored_layout_bytes
    capture_envelope_bytes = raw_bytes - transport_bytes
    clear_protocol_bytes = transport_bytes - opaque_bytes
    protocol_projection_saving = clear_protocol_bytes - len(layout)
    stored_structural_bytes = archive_bytes - opaque_bytes
    precompression_structural_bytes = stored_structural_bytes + (
        len(layout) - container.stored_layout_bytes
    )
    structural_baseline_bytes = raw_bytes - opaque_bytes
    return {
        "archive": str(output),
        "protocol": protocol,
        "mode": mode,
        "raw_capture_bytes": raw_bytes,
        "transport_payload_bytes": transport_bytes,
        "profile": selected_profile.to_metadata(),
        "category": selected_profile.category,
        "protocol_layout_bytes": len(layout),
        "stored_layout_bytes": container.stored_layout_bytes,
        "opaque_bytes": opaque_bytes,
        "archive_bytes": archive_bytes,
        "bytes_saved_vs_raw": raw_bytes - archive_bytes,
        "fraction_saved_vs_raw": (
            (raw_bytes - archive_bytes) / raw_bytes if raw_bytes else 0.0
        ),
        "recovery_inputs_counted": False,
        "opaque_bytes_entropy_coded": False,
        "fixed_container_bytes": fixed_container_bytes,
        "capture_envelope_bytes": capture_envelope_bytes,
        "clear_protocol_bytes": clear_protocol_bytes,
        "protocol_projection_saving_bytes": protocol_projection_saving,
        **protocol_metadata,
        "structural_baseline_bytes": structural_baseline_bytes,
        "structural_bytes_before_entropy_coding": precompression_structural_bytes,
        "structural_bytes_after_entropy_coding": stored_structural_bytes,
        "deterministic_pruning_bytes": structural_baseline_bytes
        - precompression_structural_bytes,
        "net_saving_before_layout_compression_bytes": raw_bytes
        - (opaque_bytes + fixed_container_bytes + len(layout)),
        "layout_entropy_saving_bytes": len(layout) - container.stored_layout_bytes,
        "total_structural_saving_bytes": structural_baseline_bytes
        - stored_structural_bytes,
    }


def inspect_archive(path: Path) -> dict:
    try:
        container = read_container(Path(path))
    except (OSError, FormatError) as exc:
        raise ArchiveError(str(exc)) from exc
    opaque_bytes = len(container.opaque)
    structural_baseline = container.raw_capture_bytes - opaque_bytes
    structural_before = (
        container.archive_bytes
        - opaque_bytes
        + len(container.layout)
        - container.stored_layout_bytes
    )
    structural_after = container.archive_bytes - opaque_bytes
    fixed_container_bytes = (
        container.archive_bytes - opaque_bytes - container.stored_layout_bytes
    )
    capture_envelope_bytes = (
        container.raw_capture_bytes - container.transport_payload_bytes
    )
    clear_protocol_bytes = container.transport_payload_bytes - opaque_bytes
    return {
        "format": "MinARX",
        "format_version": 1,
        "protocol": container.profile.protocol,
        "mode": container.profile.mode,
        "server_port": container.server_port,
        "raw_capture_bytes": container.raw_capture_bytes,
        "transport_payload_bytes": container.transport_payload_bytes,
        "profile": container.profile.to_metadata(),
        "category": container.profile.category,
        "future_recovery_outputs_included": False,
        "recovery_inputs_counted": False,
        "opaque_bytes_entropy_coded": False,
        "archive_bytes": container.archive_bytes,
        "protocol_layout_bytes": len(container.layout),
        "stored_layout_bytes": container.stored_layout_bytes,
        "opaque_bytes": opaque_bytes,
        "fixed_container_bytes": fixed_container_bytes,
        "capture_envelope_bytes": capture_envelope_bytes,
        "clear_protocol_bytes": clear_protocol_bytes,
        "protocol_projection_saving_bytes": clear_protocol_bytes
        - len(container.layout),
        "structural_baseline_bytes": structural_baseline,
        "structural_bytes_before_entropy_coding": structural_before,
        "structural_bytes_after_entropy_coding": structural_after,
        "deterministic_pruning_bytes": structural_baseline - structural_before,
        "net_saving_before_layout_compression_bytes": container.raw_capture_bytes
        - (opaque_bytes + fixed_container_bytes + len(container.layout)),
        "layout_entropy_saving_bytes": len(container.layout)
        - container.stored_layout_bytes,
        "total_structural_saving_bytes": structural_baseline - structural_after,
        "compression": container.compression,
    }


def materialize_archive(path: Path, output_dir: Path) -> dict:
    try:
        container = read_container(Path(path))
        codec = CODECS[container.profile.protocol]
        port = container.server_port
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        codec.materialize(
            container.layout,
            container.opaque,
            {
                "mode": container.profile.mode,
                "profile": container.profile.to_metadata(),
            },
            output_dir,
            port,
        )
    except (OSError, KeyError, ValueError, FormatError, PcapError) as exc:
        raise ArchiveError(str(exc)) from exc
    manifest = inspect_archive(path)
    (output_dir / "archive_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return manifest
