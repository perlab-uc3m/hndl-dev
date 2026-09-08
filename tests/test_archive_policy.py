import json
import tempfile
import unittest
from pathlib import Path

from archive_policy import (
    ARCHIVE_MAGIC,
    ArchivePolicy,
    WireEvent,
    _decode_wire_events,
    _encode_wire_events,
    _tls_record_events,
    _write_tcp_pcap,
    build_policy_archive,
)
from decryptor.derive import recover_protocol
from experiment import Protocol, recovery_spec, sha256_file


def _source_capture(root: Path) -> None:
    spec = recovery_spec("tls13", "1rtt", 45123)
    pcap = root / spec.archives[0]
    recovery = root / spec.simulated_recovery
    truth = root / spec.ground_truth[0]
    for path, content in (
        (pcap, b"pcap evidence"),
        (recovery, b"simulated future result"),
        (truth, b"comparison only"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    artifacts = {}
    for path in (pcap, recovery, truth):
        relative = str(path.relative_to(root))
        artifacts[relative] = {
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "hndl-run-manifest-v1",
                "experiment": {
                    "protocol": "TLS 1.3",
                    "mode": "full 1-RTT handshake",
                    "port": 45123,
                },
                "recovery": spec.to_dict(),
                "artifacts": artifacts,
                "evidence_boundary": {
                    "attack_inputs": [*spec.archives, spec.simulated_recovery],
                    "excluded_from_attack_inputs": list(spec.ground_truth),
                },
            }
        )
    )


class WireArchiveTests(unittest.TestCase):
    def test_wire_event_round_trip(self):
        events = [WireEvent(True, b"client"), WireEvent(False, b"server")]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.hndl"
            encoded = _encode_wire_events(events)
            self.assertTrue(encoded.startswith(ARCHIVE_MAGIC))
            path.write_bytes(encoded)
            self.assertEqual(_decode_wire_events(path), events)

    def test_trailing_or_truncated_data_is_rejected(self):
        events = [WireEvent(True, b"payload")]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.hndl"
            encoded = _encode_wire_events(events)
            path.write_bytes(encoded[:-1])
            with self.assertRaises(RuntimeError):
                _decode_wire_events(path)
            path.write_bytes(encoded + b"extra")
            with self.assertRaises(RuntimeError):
                _decode_wire_events(path)

    def test_synthetic_pcap_has_no_retained_role(self):
        events = [WireEvent(True, b"request"), WireEvent(False, b"response")]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "adapter.pcap"
            _write_tcp_pcap(path, events, 45123)
            self.assertGreater(
                path.stat().st_size, sum(map(len, (b"request", b"response")))
            )
            self.assertEqual(path.read_bytes()[:4], bytes.fromhex("d4c3b2a1"))

    def test_tls12_compact_policy_drops_only_server_application_records(self):
        def record(content_type: int, body: bytes) -> bytes:
            return bytes([content_type, 3, 3]) + len(body).to_bytes(2, "big") + body

        client_handshake = record(22, b"client hello")
        server_handshake = record(22, b"server hello")
        client_application = record(23, b"request")
        server_application = record(23, b"response")
        compact = _tls_record_events(
            [
                WireEvent(True, client_handshake + client_application),
                WireEvent(False, server_handshake + server_application),
            ],
            protocol=Protocol.TLS12,
            mode="rsa",
            archive_index=0,
        )
        self.assertEqual(
            compact,
            [
                WireEvent(True, client_handshake),
                WireEvent(True, client_application),
                WireEvent(False, server_handshake),
            ],
        )


class ArchiveEvidenceBoundaryTests(unittest.TestCase):
    def test_raw_archive_excludes_ground_truth_and_records_sizes(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            destination = base / "raw"
            _source_capture(source)
            result = build_policy_archive(source, destination, ArchivePolicy.RAW)
            manifest = json.loads((destination / "manifest.json").read_text())
            self.assertEqual(result.retained_bytes, len(b"pcap evidence"))
            self.assertEqual(manifest["archive_policy"]["policy"], "raw")
            self.assertFalse(manifest["archive_policy"]["ground_truth_included"])
            self.assertFalse((destination / "keys/sslkeylog.log").exists())
            self.assertTrue(
                (destination / "keys/simulated_quantum_output.json").is_file()
            )

    def test_tampered_or_missing_attack_input_fails_before_derivation(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            destination = base / "raw"
            _source_capture(source)
            build_policy_archive(source, destination, ArchivePolicy.RAW)
            archive = next((destination / "archive").iterdir())
            original = archive.read_bytes()
            archive.write_bytes(original + b"tampered")
            result = recover_protocol(destination)
            self.assertFalse(result.success)
            self.assertIn("changed", result.error)

            archive.write_bytes(original)
            recovery = destination / "keys/simulated_quantum_output.json"
            recovery.unlink()
            result = recover_protocol(destination)
            self.assertFalse(result.success)
            self.assertIn("missing", result.error)


if __name__ == "__main__":
    unittest.main()
