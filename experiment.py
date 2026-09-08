"""Typed experiment configuration, artifacts, manifests, and results."""

from __future__ import annotations

import hashlib
import json
import shutil
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping


MANIFEST_SCHEMAS = {"hndl-run-manifest-v1", "hndl-ssh-run-manifest-v1"}
SSH_REKEY_LIMIT_RE = re.compile(
    r"^(?:default|none|[1-9][0-9]*(?:[KMG])?)"
    r"(?:[ \t]+(?:none|[1-9][0-9]*(?:[smhdw])?))?$",
    re.IGNORECASE,
)


class HNDLError(RuntimeError):
    """Base class for user-facing HN-DL failures."""


class ConfigurationError(HNDLError):
    """Raised when an experiment configuration is unsupported or incomplete."""


class ManifestError(HNDLError):
    """Raised when capture metadata is absent, malformed, or unsafe."""


def normalize_ssh_rekey_limit(value: str | None) -> str | None:
    """Validate the OpenSSH ``RekeyLimit`` data/time syntax."""
    if value is None:
        return None
    normalized = str(value).strip()
    if not SSH_REKEY_LIMIT_RE.fullmatch(normalized):
        raise ConfigurationError(
            "invalid SSH RekeyLimit; use default, none, or a size such as "
            "64K with an optional time such as 1h"
        )
    return normalized


def require_tool(name: str) -> None:
    """Require an external executable without terminating library callers."""
    if shutil.which(name) is None:
        raise ConfigurationError(f"required tool '{name}' not found in PATH")


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of one artifact without loading it at once."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Protocol(str, Enum):
    TLS12 = "tls12"
    TLS13 = "tls13"
    QUIC = "quic"
    SSH = "ssh"

    @classmethod
    def parse(cls, value: str | Protocol) -> Protocol:
        if isinstance(value, cls):
            return value
        normalized = value.strip().lower().replace(" ", "")
        aliases = {
            "tls1.2": cls.TLS12,
            "tls12": cls.TLS12,
            "tls1.3": cls.TLS13,
            "tls13": cls.TLS13,
            "quic": cls.QUIC,
            "quicv1withtls1.3": cls.QUIC,
            "ssh": cls.SSH,
            "ssh-2": cls.SSH,
        }
        try:
            return aliases[normalized]
        except KeyError as exc:
            raise ConfigurationError(f"unsupported protocol: {value}") from exc


class Mode(str, Enum):
    RSA = "rsa"
    ONE_RTT = "1rtt"
    ZERO_RTT = "0rtt"
    EXTERNAL_PSK = "external-psk"

    @classmethod
    def parse(cls, value: str | Mode | None) -> Mode | None:
        if value is None or isinstance(value, cls):
            return value
        normalized = value.strip().lower().replace(" ", "")
        aliases = {
            "rsa": cls.RSA,
            "rsakeytransport": cls.RSA,
            "1rtt": cls.ONE_RTT,
            "full1-rtthandshake": cls.ONE_RTT,
            "0rtt": cls.ZERO_RTT,
            "0-rttresumption": cls.ZERO_RTT,
            "external-psk": cls.EXTERNAL_PSK,
            "externalpsk": cls.EXTERNAL_PSK,
        }
        try:
            return aliases[normalized]
        except KeyError as exc:
            raise ConfigurationError(f"unsupported mode: {value}") from exc


@dataclass
class ArtifactLayout:
    """Protocol-neutral paths rooted at one capture directory."""

    root: Path

    def __post_init__(self) -> None:
        self.root = Path(self.root).resolve()

    @property
    def manifest(self) -> Path:
        return self.root / "manifest.json"

    @property
    def archive_dir(self) -> Path:
        # ``pcap`` remains the on-disk name for compatibility with v1 captures.
        return self.root / "pcap"

    @property
    def keys_dir(self) -> Path:
        return self.root / "keys"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    @property
    def derived_dir(self) -> Path:
        return self.root / "derived"

    def create_capture_dirs(self) -> None:
        for directory in (self.archive_dir, self.keys_dir, self.logs_dir):
            directory.mkdir(parents=True, exist_ok=True)

    def resolve(self, relative_path: str) -> Path:
        path = Path(relative_path)
        if path.is_absolute() or ".." in path.parts:
            raise ManifestError(f"artifact path must be relative: {relative_path}")
        resolved = (self.root / path).resolve()
        if not resolved.is_relative_to(self.root):
            raise ManifestError(f"artifact path escapes capture root: {relative_path}")
        return resolved


@dataclass(frozen=True)
class ExperimentConfig:
    protocol: Protocol
    mode: Mode | None
    port: int
    interface: str = "lo"
    group: str = "X25519"
    data_root: Path = Path("data")
    label: str | None = None
    openssl: Path = Path("openssl/.local/bin/openssl")
    openssh_dir: Path = Path("openssh/.local")
    verbose: bool = False
    ssh_rekey_limit: str | None = None
    ssh_payload_bytes: int = 0
    tls13_resumption_kex: str = "psk-dhe"
    tls13_grandchild: bool = False

    @classmethod
    def create(
        cls,
        protocol: str | Protocol,
        mode: str | Mode | None = None,
        port: int | None = None,
        **kwargs: Any,
    ) -> ExperimentConfig:
        parsed_protocol = Protocol.parse(protocol)
        parsed_mode = Mode.parse(mode)
        if parsed_mode is None:
            if parsed_protocol is Protocol.TLS12:
                parsed_mode = Mode.RSA
            elif parsed_protocol is Protocol.TLS13:
                parsed_mode = Mode.ONE_RTT
        if parsed_protocol is Protocol.TLS12 and parsed_mode is not Mode.RSA:
            raise ConfigurationError("TLS 1.2 supports only RSA mode")
        if parsed_protocol is Protocol.TLS13 and parsed_mode not in {
            Mode.ONE_RTT,
            Mode.ZERO_RTT,
            Mode.EXTERNAL_PSK,
        }:
            raise ConfigurationError("TLS 1.3 mode must be 1rtt, 0rtt, or external-psk")
        if parsed_protocol in {Protocol.QUIC, Protocol.SSH} and parsed_mode is not None:
            raise ConfigurationError(f"{parsed_protocol.value} does not accept a mode")
        selected_port = (
            port
            if port is not None
            else (22222 if parsed_protocol is Protocol.SSH else 44443)
        )
        if not 1 <= selected_port <= 65535:
            raise ConfigurationError("port must be between 1 and 65535")
        if parsed_protocol is Protocol.SSH and selected_port == 65535:
            raise ConfigurationError("SSH requires the following port for its relay")
        payload_bytes = int(kwargs.get("ssh_payload_bytes", 0))
        if payload_bytes < 0:
            raise ConfigurationError("SSH payload size cannot be negative")
        rekey_limit = normalize_ssh_rekey_limit(kwargs.get("ssh_rekey_limit"))
        if parsed_protocol is not Protocol.SSH and (payload_bytes or rekey_limit):
            raise ConfigurationError(
                "SSH payload and RekeyLimit options require the SSH protocol"
            )
        group = str(kwargs.get("group", "X25519"))
        if (
            parsed_protocol in {Protocol.TLS13, Protocol.QUIC}
            and group.lower() != "x25519"
        ):
            raise ConfigurationError("recovery currently supports only X25519")
        resumption_kex = str(kwargs.get("tls13_resumption_kex", "psk-dhe")).lower()
        if resumption_kex not in {"psk-dhe", "psk-only"}:
            raise ConfigurationError(
                "TLS 1.3 resumption key exchange must be psk-dhe or psk-only"
            )
        if resumption_kex != "psk-dhe" and not (
            parsed_protocol is Protocol.TLS13 and parsed_mode is Mode.ZERO_RTT
        ):
            raise ConfigurationError(
                "psk-only is supported only for the TLS 1.3 0-RTT experiment"
            )
        grandchild = bool(kwargs.get("tls13_grandchild", False))
        if grandchild and not (
            parsed_protocol is Protocol.TLS13 and parsed_mode is Mode.ZERO_RTT
        ):
            raise ConfigurationError(
                "grandchild capture is supported only for TLS 1.3 0-RTT"
            )
        kwargs["protocol"] = parsed_protocol
        kwargs["mode"] = parsed_mode
        kwargs["port"] = selected_port
        kwargs["group"] = group
        kwargs["ssh_payload_bytes"] = payload_bytes
        kwargs["ssh_rekey_limit"] = rekey_limit
        kwargs["tls13_resumption_kex"] = resumption_kex
        kwargs["tls13_grandchild"] = grandchild
        kwargs["data_root"] = Path(kwargs.get("data_root", "data")).resolve()
        kwargs["openssl"] = Path(
            kwargs.get("openssl", "openssl/.local/bin/openssl")
        ).resolve()
        kwargs["openssh_dir"] = Path(
            kwargs.get("openssh_dir", "openssh/.local")
        ).resolve()
        return cls(**kwargs)

    @property
    def capture_label(self) -> str:
        if self.label:
            return self.label
        if self.protocol is Protocol.SSH:
            return "ssh-capture"
        if self.protocol is Protocol.QUIC:
            return "quic-capture"
        return f"{self.protocol.value}-{self.mode.value}-capture"


@dataclass(frozen=True)
class RecoverySpec:
    """All inputs needed to recover one capture, as declared by its manifest."""

    protocol: Protocol
    mode: Mode | None
    port: int
    archives: tuple[str, ...]
    simulated_recovery: str
    ground_truth: tuple[str, ...]
    derived: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol.value,
            "mode": self.mode.value if self.mode else None,
            "port": self.port,
            "archives": list(self.archives),
            "simulated_recovery": self.simulated_recovery,
            "ground_truth": list(self.ground_truth),
            "derived": list(self.derived),
        }

    @classmethod
    def from_manifest(cls, manifest: Mapping[str, Any]) -> RecoverySpec:
        recovery = manifest.get("recovery")
        if recovery is not None:
            if not isinstance(recovery, Mapping):
                raise ManifestError("manifest recovery field must be an object")
            for field_name in ("archives", "ground_truth", "derived"):
                value = recovery.get(field_name)
                if not isinstance(value, list) or not all(
                    isinstance(item, str) for item in value
                ):
                    raise ManifestError(
                        f"recovery.{field_name} must be a list of paths"
                    )
            if not isinstance(recovery.get("simulated_recovery"), str):
                raise ManifestError("recovery.simulated_recovery must be a path")
            try:
                protocol = Protocol.parse(str(recovery["protocol"]))
                mode = Mode.parse(recovery.get("mode"))
                port = int(recovery["port"])
                archives = tuple(str(item) for item in recovery["archives"])
                simulated = str(recovery["simulated_recovery"])
                ground_truth = tuple(str(item) for item in recovery["ground_truth"])
                derived = tuple(str(item) for item in recovery["derived"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ManifestError(f"invalid recovery metadata: {exc}") from exc
            spec = cls(
                protocol,
                mode,
                port,
                archives,
                simulated,
                ground_truth,
                derived,
            )
            spec._validate()
            return spec
        return cls._infer_v1(manifest)

    @classmethod
    def _infer_v1(cls, manifest: Mapping[str, Any]) -> RecoverySpec:
        experiment = manifest.get("experiment")
        if not isinstance(experiment, Mapping):
            raise ManifestError("manifest experiment field must be an object")
        try:
            protocol = Protocol.parse(str(experiment["protocol"]))
            mode = Mode.parse(experiment.get("mode"))
            port = int(experiment.get("public_port", experiment.get("port")))
        except (KeyError, TypeError, ValueError) as exc:
            raise ManifestError(f"cannot infer recovery metadata: {exc}") from exc
        defaults = recovery_spec(protocol, mode, port)
        defaults._validate()
        return defaults

    def _validate(self) -> None:
        normalized = ExperimentConfig.create(self.protocol, self.mode, self.port)
        if normalized.mode is not self.mode:
            raise ManifestError("recovery metadata must declare the protocol mode")
        if not self.archives:
            raise ManifestError("recovery metadata has no archive")
        if not self.simulated_recovery:
            raise ManifestError("recovery metadata has no simulated-recovery input")
        if not self.ground_truth:
            raise ManifestError("recovery metadata has no comparison-only input")
        if not self.derived:
            raise ManifestError("recovery metadata has no derived output")
        if self.protocol is Protocol.TLS13 and self.mode is Mode.ZERO_RTT:
            if len(self.archives) != 2:
                raise ManifestError("TLS 1.3 0-RTT recovery requires two archives")
        layout = ArtifactLayout(Path.cwd())
        for relative in (
            *self.archives,
            self.simulated_recovery,
            *self.ground_truth,
            *self.derived,
        ):
            layout.resolve(relative)


def recovery_spec(
    protocol: str | Protocol, mode: str | Mode | None, port: int
) -> RecoverySpec:
    """Return the canonical artifact contract for a supported experiment."""
    protocol = Protocol.parse(protocol)
    mode = Mode.parse(mode)
    if protocol is Protocol.TLS12:
        return RecoverySpec(
            protocol,
            Mode.RSA,
            port,
            ("pcap/tls12_rsa.pcapng",),
            "keys/simulated_quantum_output.pem",
            ("keys/sslkeylog.log",),
            (
                "derived/nss_derived.keylog",
                "derived/recovery_provenance.json",
            ),
        )
    if protocol is Protocol.TLS13 and mode is Mode.ZERO_RTT:
        return RecoverySpec(
            protocol,
            mode,
            port,
            (
                "pcap/tls13_0rtt_phase1_initial.pcapng",
                "pcap/tls13_0rtt_phase2_resumption.pcapng",
            ),
            "keys/simulated_quantum_output.json",
            ("keys/sslkeylog.log",),
            ("derived/nss_0rtt.keylog", "derived/recovery_provenance.json"),
        )
    if protocol is Protocol.TLS13 and mode is Mode.EXTERNAL_PSK:
        return RecoverySpec(
            protocol,
            mode,
            port,
            ("pcap/tls13_external_psk.pcapng",),
            "keys/simulated_external_psk.json",
            ("keys/sslkeylog.log",),
            (
                "derived/nss_external_psk.keylog",
                "derived/recovery_provenance.json",
            ),
        )
    if protocol is Protocol.TLS13:
        return RecoverySpec(
            protocol,
            Mode.ONE_RTT,
            port,
            ("pcap/tls13_1rtt.pcapng",),
            "keys/simulated_quantum_output.json",
            ("keys/sslkeylog.log",),
            (
                "derived/nss_derived.keylog",
                "derived/recovery_provenance.json",
            ),
        )
    if protocol is Protocol.QUIC:
        return RecoverySpec(
            protocol,
            None,
            port,
            ("pcap/quic.pcapng",),
            "keys/simulated_quantum_output.json",
            ("keys/sslkeylog.log", "keys/client_keylog.log"),
            (
                "derived/nss_derived.keylog",
                "derived/recovery_provenance.json",
            ),
        )
    return RecoverySpec(
        Protocol.SSH,
        None,
        port,
        (
            "pcap/ssh_session.pcapng",
            "pcap/ssh_client_to_server.bin",
            "pcap/ssh_server_to_client.bin",
        ),
        "keys/simulated_quantum_output.json",
        ("keys/ssh_ground_truth.json",),
        (
            "derived/ssh_derived_keys.json",
            "derived/key_schedule_trace.json",
            "derived/recovery_provenance.json",
        ),
    )


@dataclass(frozen=True)
class RunManifest:
    path: Path
    data: Mapping[str, Any]
    recovery: RecoverySpec

    @classmethod
    def load(cls, capture_dir: Path | str) -> RunManifest:
        layout = ArtifactLayout(Path(capture_dir))
        try:
            data = json.loads(layout.manifest.read_text())
        except FileNotFoundError as exc:
            raise ManifestError(f"manifest not found: {layout.manifest}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise ManifestError(
                f"cannot read manifest {layout.manifest}: {exc}"
            ) from exc
        if not isinstance(data, Mapping):
            raise ManifestError("manifest root must be an object")
        if data.get("schema") not in MANIFEST_SCHEMAS:
            raise ManifestError(f"unsupported manifest schema: {data.get('schema')}")
        for field_name in ("experiment", "artifacts", "evidence_boundary"):
            if not isinstance(data.get(field_name), Mapping):
                raise ManifestError(f"manifest {field_name} field must be an object")
        boundary = data["evidence_boundary"]
        for field_name in ("attack_inputs", "excluded_from_attack_inputs"):
            if not isinstance(boundary.get(field_name), list):
                raise ManifestError(f"evidence_boundary.{field_name} must be a list")
        recovery = RecoverySpec.from_manifest(data)
        for relative in (
            *recovery.archives,
            recovery.simulated_recovery,
            *recovery.ground_truth,
            *recovery.derived,
        ):
            layout.resolve(relative)
        return cls(layout.manifest, data, recovery)

    def verify_recorded_artifacts(self) -> None:
        """Verify every artifact size and digest recorded at capture time."""
        layout = ArtifactLayout(self.path.parent)
        for relative, metadata in self.data["artifacts"].items():
            if not isinstance(relative, str) or not isinstance(metadata, Mapping):
                raise ManifestError(
                    "manifest artifact entries must map paths to objects"
                )
            artifact = layout.resolve(relative)
            if not artifact.is_file():
                raise ManifestError(f"recorded artifact is missing: {relative}")
            try:
                expected_size = int(metadata["bytes"])
                expected_hash = str(metadata["sha256"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ManifestError(
                    f"invalid metadata for artifact: {relative}"
                ) from exc
            if artifact.stat().st_size != expected_size:
                raise ManifestError(f"recorded artifact size changed: {relative}")
            if sha256_file(artifact) != expected_hash:
                raise ManifestError(f"recorded artifact hash changed: {relative}")


@dataclass(frozen=True)
class CaptureResult:
    root: Path
    manifest: Path
    archives: tuple[Path, ...]
    simulated_recovery: Path
    ground_truth: tuple[Path, ...]

    @classmethod
    def from_manifest(cls, capture_dir: Path | str) -> CaptureResult:
        layout = ArtifactLayout(Path(capture_dir))
        manifest = RunManifest.load(layout.root)
        manifest.verify_recorded_artifacts()
        spec = manifest.recovery
        return cls(
            layout.root,
            manifest.path,
            tuple(layout.resolve(path) for path in spec.archives),
            layout.resolve(spec.simulated_recovery),
            tuple(layout.resolve(path) for path in spec.ground_truth),
        )


@dataclass(frozen=True)
class RecoveryResult:
    success: bool
    capture_root: Path
    derived_artifacts: tuple[Path, ...]
    plaintext_authenticated: bool
    error: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_mapping(
        cls,
        capture_dir: Path | str,
        spec: RecoverySpec,
        result: Mapping[str, Any],
    ) -> RecoveryResult:
        layout = ArtifactLayout(Path(capture_dir))
        validation = result.get("validation", {})
        plaintext = bool(
            result.get("expected_plaintext_recovered")
            or validation.get("application_plaintext_recovered")
            or validation.get("early_application_plaintext_recovered")
            or validation.get("application_response_authenticated")
        )
        return cls(
            bool(result.get("success")),
            layout.root,
            tuple(layout.resolve(path) for path in spec.derived),
            plaintext,
            str(result["error"]) if result.get("error") else None,
            result,
        )
