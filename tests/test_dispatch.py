import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from capture.capture import capture_protocol
from decryptor.derive import recover_protocol, resolve_recovery_spec
from experiment import ExperimentConfig, ManifestError, recovery_spec


def write_capture_contract(root: Path, port: int = 45123) -> None:
    spec = recovery_spec("tls13", "1rtt", port)
    root.mkdir(parents=True)
    for relative in (*spec.archives, spec.simulated_recovery, *spec.ground_truth):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"test evidence")
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "hndl-run-manifest-v1",
                "experiment": {
                    "protocol": "TLS 1.3",
                    "mode": "full 1-RTT handshake",
                    "port": port,
                },
                "recovery": spec.to_dict(),
                "artifacts": {},
                "evidence_boundary": {
                    "attack_inputs": list(spec.archives) + [spec.simulated_recovery],
                    "excluded_from_attack_inputs": list(spec.ground_truth),
                },
            }
        )
    )


class DispatchTests(unittest.TestCase):
    def test_capture_returns_its_exact_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            data_root = Path(directory)
            config = ExperimentConfig.create(
                "tls13",
                "1rtt",
                45123,
                data_root=data_root,
                openssl="/bin/true",
            )

            def fake_capture(_openssl, _iface, port, _group, root, _verbose):
                write_capture_contract(root, port)

            with (
                patch("capture.capture.check_tool"),
                patch("capture.capture.ensure_exec"),
                patch("capture.capture.now_ts", return_value="exact"),
                patch("capture.capture.tls13_capture_1rtt", fake_capture),
            ):
                result = capture_protocol(config)
            self.assertEqual(
                result.root,
                (data_root / "exact-tls13-1rtt-capture").resolve(),
            )

    def test_recovery_uses_manifest_port_and_records_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "capture"
            write_capture_contract(root, 45123)
            raw = {
                "success": True,
                "validation": {"application_plaintext_recovered": True},
            }
            with patch("decryptor.derive._derive_mapping", return_value=raw) as derive:
                result = recover_protocol(root)
            self.assertTrue(result.success)
            self.assertTrue(result.plaintext_authenticated)
            self.assertEqual(derive.call_args.args[1].port, 45123)
            self.assertTrue((root / "derived/recovery_provenance.json").is_file())

    def test_conflicting_override_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "capture"
            write_capture_contract(root, 45123)
            with self.assertRaises(ManifestError):
                resolve_recovery_spec(root, port=44443)

    def test_existing_invalid_manifest_never_uses_legacy_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "capture"
            root.mkdir()
            (root / "manifest.json").write_text("{}")
            with self.assertRaises(ManifestError):
                resolve_recovery_spec(root, "tls13", "1rtt", 45123)


if __name__ == "__main__":
    unittest.main()
