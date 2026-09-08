import json
import tempfile
import unittest
from pathlib import Path

from experiment import (
    ArtifactLayout,
    ConfigurationError,
    ExperimentConfig,
    ManifestError,
    Mode,
    Protocol,
    RunManifest,
    normalize_ssh_rekey_limit,
    recovery_spec,
    sha256_file,
)


def manifest_data(protocol="tls13", mode="1rtt", port=45123):
    spec = recovery_spec(protocol, mode, port)
    return {
        "schema": "hndl-run-manifest-v1",
        "experiment": {"protocol": protocol, "mode": mode, "port": port},
        "recovery": spec.to_dict(),
        "artifacts": {},
        "evidence_boundary": {
            "attack_inputs": list(spec.archives) + [spec.simulated_recovery],
            "excluded_from_attack_inputs": list(spec.ground_truth),
        },
    }


class ExperimentConfigTests(unittest.TestCase):
    def test_protocol_specific_defaults(self):
        tls = ExperimentConfig.create("tls13")
        ssh = ExperimentConfig.create("ssh")
        self.assertEqual((tls.mode, tls.port), (Mode.ONE_RTT, 44443))
        self.assertEqual((ssh.mode, ssh.port), (None, 22222))

    def test_invalid_combinations_fail_before_capture(self):
        with self.assertRaises(ConfigurationError):
            ExperimentConfig.create("tls12", "0rtt")
        with self.assertRaises(ConfigurationError):
            ExperimentConfig.create("quic", tls13_resumption_kex="psk-only")
        with self.assertRaises(ConfigurationError):
            ExperimentConfig.create("tls13", "1rtt", tls13_grandchild=True)
        with self.assertRaises(ConfigurationError):
            ExperimentConfig.create("tls13", ssh_rekey_limit="64K")
        with self.assertRaises(ConfigurationError):
            ExperimentConfig.create("ssh", ssh_rekey_limit="64K\nLogLevel QUIET")

    def test_ssh_rekey_limit_validation(self):
        self.assertEqual(normalize_ssh_rekey_limit("64K 1h"), "64K 1h")
        self.assertEqual(normalize_ssh_rekey_limit(" none "), "none")

    def test_tls13_psk_modes(self):
        pure = ExperimentConfig.create("tls13", "0rtt", tls13_resumption_kex="psk-only")
        external = ExperimentConfig.create("tls13", "external-psk")
        self.assertEqual(pure.tls13_resumption_kex, "psk-only")
        self.assertEqual(external.mode, Mode.EXTERNAL_PSK)
        spec = recovery_spec("tls13", "external-psk", 44443)
        self.assertEqual(spec.simulated_recovery, "keys/simulated_external_psk.json")
        with self.assertRaises(ConfigurationError):
            ExperimentConfig.create("quic", "1rtt")
        with self.assertRaises(ConfigurationError):
            ExperimentConfig.create("ssh", port=65535)


class ManifestTests(unittest.TestCase):
    def test_normalized_recovery_contract_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manifest.json").write_text(json.dumps(manifest_data()))
            spec = RunManifest.load(root).recovery
            self.assertEqual(spec.protocol, Protocol.TLS13)
            self.assertEqual(spec.mode, Mode.ONE_RTT)
            self.assertEqual(spec.port, 45123)

    def test_old_manifest_is_inferred(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_manifest = manifest_data()
            del old_manifest["recovery"]
            old_manifest["experiment"] = {
                "protocol": "SSH-2",
                "public_port": 23001,
            }
            (root / "manifest.json").write_text(json.dumps(old_manifest))
            spec = RunManifest.load(root).recovery
            self.assertEqual(spec.protocol, Protocol.SSH)
            self.assertEqual(spec.port, 23001)

    def test_unsafe_artifact_path_is_rejected(self):
        data = manifest_data()
        data["recovery"]["archives"] = ["../outside.pcap"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manifest.json").write_text(json.dumps(data))
            with self.assertRaises(ManifestError):
                RunManifest.load(root)

    def test_recorded_artifact_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "pcap/capture.pcapng"
            artifact.parent.mkdir()
            artifact.write_bytes(b"original")
            data = manifest_data()
            data["artifacts"] = {
                "pcap/capture.pcapng": {
                    "bytes": len(b"original"),
                    "sha256": sha256_file(artifact),
                }
            }
            (root / "manifest.json").write_text(json.dumps(data))
            manifest = RunManifest.load(root)
            manifest.verify_recorded_artifacts()
            artifact.write_bytes(b"changed")
            with self.assertRaises(ManifestError):
                manifest.verify_recorded_artifacts()

    def test_artifact_layout_is_protocol_neutral(self):
        with tempfile.TemporaryDirectory() as directory:
            layout = ArtifactLayout(Path(directory))
            layout.create_capture_dirs()
            self.assertTrue(layout.archive_dir.is_dir())
            self.assertTrue(layout.keys_dir.is_dir())
            self.assertTrue(layout.logs_dir.is_dir())


if __name__ == "__main__":
    unittest.main()
