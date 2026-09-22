import importlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from decryptor.core import compute_shared_secret_from_priv_and_peer
from decryptor.derive import derive_compacted
from decryptor.io import (
    parse_client_keyshare_pub_from_ch,
    parse_server_keyshare_pub_from_sh,
)
from decryptor.io import extract_tls_hello_pair
from minarx import ArchiveError, compact_capture, inspect_archive, materialize_archive
from minarx.format import read_container
from minarx.pcap import Chunk, extract_tcp_chunks, extract_udp_datagrams, write_pcap
from minarx.profiles import PROFILES


def _record(content_type: int, fragment: bytes) -> bytes:
    return bytes([content_type]) + b"\x03\x03" + len(fragment).to_bytes(2, "big") + fragment


def _handshake(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + len(body).to_bytes(3, "big") + body


def _extension(extension_type: int, data: bytes = b"") -> bytes:
    return extension_type.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


def _tls13_hellos(
    client_public: bytes,
    server_public: bytes,
    cipher_suite: int = 0x1301,
    resumed: bool = False,
    early_data: bool = False,
    key_share: bool = True,
) -> tuple[bytes, bytes]:
    client_extensions = b""
    if key_share:
        client_share = (
            b"\x00\x1d" + len(client_public).to_bytes(2, "big") + client_public
        )
        client_extensions += _extension(
            51, len(client_share).to_bytes(2, "big") + client_share
        )
    if early_data:
        client_extensions += _extension(42)
    if resumed:
        # The validator only needs negotiation markers; the decoder still sees
        # the exact bytes and will validate a real PSK structure.
        client_extensions += _extension(41, b"\x00\x00\x00\x00")
    client_body = (
        b"\x03\x03"
        + b"C" * 32
        + b"\x00"
        + b"\x00\x02"
        + cipher_suite.to_bytes(2, "big")
        + b"\x01\x00"
        + len(client_extensions).to_bytes(2, "big")
        + client_extensions
    )
    server_extensions = b""
    if key_share:
        server_share = (
            b"\x00\x1d" + len(server_public).to_bytes(2, "big") + server_public
        )
        server_extensions += _extension(51, server_share)
    if resumed:
        server_extensions += _extension(41, b"\x00\x00")
    server_body = (
        b"\x03\x03"
        + b"S" * 32
        + b"\x00"
        + cipher_suite.to_bytes(2, "big")
        + b"\x00"
        + len(server_extensions).to_bytes(2, "big")
        + server_extensions
    )
    return _handshake(1, client_body), _handshake(2, server_body)


def _tls12_hellos(cipher_suite: int, ems: bool) -> tuple[bytes, bytes]:
    extensions = _extension(23) if ems else b""
    client_body = (
        b"\x03\x03"
        + b"C" * 32
        + b"\x00"
        + b"\x00\x02"
        + cipher_suite.to_bytes(2, "big")
        + b"\x01\x00"
        + (len(extensions).to_bytes(2, "big") + extensions if extensions else b"")
    )
    server_body = (
        b"\x03\x03"
        + b"S" * 32
        + b"\x00"
        + cipher_suite.to_bytes(2, "big")
        + b"\x00"
        + (len(extensions).to_bytes(2, "big") + extensions if extensions else b"")
    )
    return _handshake(1, client_body), _handshake(2, server_body)


def _public_bytes(private: x25519.X25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _ssh_packet(payload: bytes) -> bytes:
    padding_length = 4
    while (4 + 1 + len(payload) + padding_length) % 8:
        padding_length += 1
    packet_length = 1 + len(payload) + padding_length
    return (
        packet_length.to_bytes(4, "big")
        + bytes([padding_length])
        + payload
        + b"P" * padding_length
    )


def _ssh_kexinit(cipher: str, client: bool) -> bytes:
    alternatives = "aes128-gcm@openssh.com,chacha20-poly1305@openssh.com"
    ciphers = f"{cipher},{alternatives}" if client else alternatives
    name_lists = (
        "curve25519-sha256",
        "ssh-ed25519",
        ciphers,
        ciphers,
        "hmac-sha2-256",
        "hmac-sha2-256",
        "none",
        "none",
        "",
        "",
    )
    payload = bytearray(b"\x14" + (b"C" if client else b"S") * 16)
    for value in name_lists:
        encoded = value.encode("ascii")
        payload.extend(len(encoded).to_bytes(4, "big") + encoded)
    payload.extend(b"\x00\x00\x00\x00\x00")
    return _ssh_packet(bytes(payload))


def _ssh_chunks(
    cipher: str,
    client_tail: bytes = b"A" * 4096,
    server_tail: bytes = b"B" * 512,
) -> list[Chunk]:
    return [
        Chunk(0, b"SSH-2.0-test-client\r\n" + _ssh_kexinit(cipher, True) + client_tail),
        Chunk(1, b"SSH-2.0-test-server\r\n" + _ssh_kexinit(cipher, False) + server_tail),
    ]


def _tls13_chunks(
    cipher_suite: int = 0x1301,
    resumed: bool = False,
    early_data: bool = False,
    opaque_size: int = 2048,
    key_share: bool = True,
) -> list[Chunk]:
    client_private = x25519.X25519PrivateKey.generate()
    server_private = x25519.X25519PrivateKey.generate()
    client_hello, server_hello = _tls13_hellos(
        _public_bytes(client_private),
        _public_bytes(server_private),
        cipher_suite,
        resumed,
        early_data,
        key_share,
    )
    return [
        Chunk(0, _record(22, client_hello) + _record(23, b"A" * opaque_size)),
        Chunk(1, _record(22, server_hello) + _record(23, b"B" * opaque_size)),
    ]


class MinArxTests(unittest.TestCase):
    def _capture(self, root: Path, filename: str, chunks: list[Chunk], transport: str, port: int) -> Path:
        capture = root / "capture"
        (capture / "pcap").mkdir(parents=True, exist_ok=True)
        write_pcap(capture / "pcap" / filename, chunks, transport, port)
        return capture

    def _profile_capture(self, root: Path, profile_name: str) -> tuple[Path, int]:
        profile = PROFILES[profile_name]
        port = 22222 if profile.protocol == "ssh" else 44443
        capture = root / profile_name
        (capture / "pcap").mkdir(parents=True)
        if profile.protocol == "tls12":
            client_hello, server_hello = _tls12_hellos(
                profile.cipher_suite_id, bool(profile.extended_master_secret)
            )
            write_pcap(
                capture / "pcap" / "tls12_rsa.pcapng",
                [
                    Chunk(0, _record(22, client_hello) + _record(23, b"A" * 2048)),
                    Chunk(1, _record(22, server_hello) + _record(23, b"B" * 2048)),
                ],
                "tcp",
                port,
            )
        elif profile.protocol == "tls13" and profile.mode == "1rtt":
            write_pcap(
                capture / "pcap" / "tls13_1rtt.pcapng",
                _tls13_chunks(profile.cipher_suite_id),
                "tcp",
                port,
            )
        elif profile.protocol == "tls13" and profile.mode == "0rtt":
            write_pcap(
                capture / "pcap" / "tls13_0rtt_phase1_initial.pcapng",
                _tls13_chunks(profile.cipher_suite_id),
                "tcp",
                port,
            )
            write_pcap(
                capture / "pcap" / "tls13_0rtt_phase2_resumption.pcapng",
                _tls13_chunks(
                    profile.cipher_suite_id,
                    resumed=True,
                    early_data=True,
                    key_share=profile.resumption == "ticket-psk-dhe",
                ),
                "tcp",
                port,
            )
        elif profile.protocol == "tls13":
            write_pcap(
                capture / "pcap" / "tls13_external_psk.pcapng",
                _tls13_chunks(
                    profile.cipher_suite_id, resumed=True, key_share=False
                ),
                "tcp",
                port,
            )
        elif profile.protocol == "quic":
            write_pcap(
                capture / "pcap" / "quic.pcapng",
                [
                    Chunk(0, b"\xc0\x00\x00\x00\x01" + os.urandom(1195)),
                    Chunk(1, b"\x40" + os.urandom(499)),
                ],
                "udp",
                port,
            )
        else:
            write_pcap(
                capture / "pcap" / "ssh_session.pcapng",
                _ssh_chunks(
                    profile.cipher_suite,
                    os.urandom(4096),
                    os.urandom(512),
                ),
                "tcp",
                port,
            )
        return capture, port

    def test_profile_matrix_round_trips_and_accounts_every_category(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seen_categories = set()
            for profile_name, profile in PROFILES.items():
                with self.subTest(profile=profile_name):
                    capture, port = self._profile_capture(root, profile_name)
                    archive = root / f"{profile_name}.minarx"
                    with patch(
                        "minarx.protocols.quic.extract_quic_cipher_suites",
                        return_value={profile.cipher_suite_id},
                    ):
                        stats = compact_capture(
                            capture,
                            archive,
                            profile.protocol,
                            profile.mode,
                            port,
                            profile=profile_name,
                        )
                    expanded = root / f"expanded-{profile_name}"
                    manifest = materialize_archive(archive, expanded)
                    self.assertEqual(manifest["profile"]["name"], profile_name)
                    self.assertEqual(stats["category"], profile.category)
                    self.assertFalse(stats["opaque_bytes_entropy_coded"])
                    self.assertEqual(
                        stats["archive_bytes"],
                        stats["opaque_bytes"] + stats["structural_bytes_after_entropy_coding"],
                    )
                    self.assertEqual(
                        stats["total_structural_saving_bytes"],
                        stats["structural_baseline_bytes"]
                        - stats["structural_bytes_after_entropy_coding"],
                    )
                    self.assertEqual(
                        stats["total_structural_saving_bytes"],
                        stats["deterministic_pruning_bytes"]
                        + stats["layout_entropy_saving_bytes"],
                    )
                    for source in stats["captures"]:
                        source_path = capture / "pcap" / source["source_name"]
                        output_path = expanded / "pcap" / source["source_name"]
                        extractor = extract_udp_datagrams if profile.protocol == "quic" else extract_tcp_chunks
                        self.assertEqual(extractor(source_path, port), extractor(output_path, port))
                    seen_categories.add(profile.category)
            self.assertEqual(seen_categories, {profile.category for profile in PROFILES.values()})

    def test_tls13_archive_reconstructs_keyshare_and_shared_secret(self):
        client_private = x25519.X25519PrivateKey.generate()
        server_private = x25519.X25519PrivateKey.generate()
        client_hello, server_hello = _tls13_hellos(
            _public_bytes(client_private), _public_bytes(server_private)
        )
        chunks = [
            Chunk(0, _record(22, client_hello) + _record(23, os.urandom(4096))),
            Chunk(1, _record(22, server_hello) + _record(23, os.urandom(4096))),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = self._capture(root, "tls13_1rtt.pcapng", chunks, "tcp", 44443)
            archive = root / "trace.minarx"
            stats = compact_capture(capture, archive, "tls13", "1rtt", 44443)
            expanded = root / "expanded"
            materialize_archive(archive, expanded)
            parsed_client, parsed_server = extract_tls_hello_pair(
                expanded / "pcap" / "tls13_1rtt.pcapng", 44443
            )
            self.assertEqual(parse_client_keyshare_pub_from_ch(parsed_client), _public_bytes(client_private))
            self.assertEqual(parse_server_keyshare_pub_from_sh(parsed_server), _public_bytes(server_private))
            recovered = compute_shared_secret_from_priv_and_peer(
                client_private.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                ).hex(),
                parse_server_keyshare_pub_from_sh(parsed_server).hex(),
                "x25519",
            )
            self.assertEqual(recovered, client_private.exchange(server_private.public_key()))
            self.assertLess(stats["archive_bytes"], stats["raw_capture_bytes"])

    def test_opaque_payload_entropy_cannot_change_size_accounting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archives = []
            manifests = []
            payloads = [b"A" * 8192, os.urandom(8192)]
            for index, payload in enumerate(payloads):
                chunks = _ssh_chunks(
                    "chacha20-poly1305@openssh.com", payload, b"B" * 512
                )
                capture = self._capture(
                    root / str(index),
                    "ssh_session.pcapng",
                    chunks,
                    "tcp",
                    22222,
                )
                archive = root / f"entropy-{index}.minarx"
                compact_capture(capture, archive, "ssh", "default", 22222)
                archives.append(read_container(archive))
                manifests.append(inspect_archive(archive))
            self.assertIn(payloads[0], archives[0].opaque)
            self.assertIn(payloads[1], archives[1].opaque)
            for key in (
                "raw_capture_bytes",
                "opaque_bytes",
                "archive_bytes",
                "structural_baseline_bytes",
                "structural_bytes_before_entropy_coding",
                "structural_bytes_after_entropy_coding",
                "total_structural_saving_bytes",
            ):
                self.assertEqual(manifests[0][key], manifests[1][key], key)
            self.assertFalse(manifests[0]["opaque_bytes_entropy_coded"])

    def test_entropy_coding_is_confined_to_protocol_layout(self):
        client_hello, server_hello = _tls12_hellos(0x002F, True)
        clear_certificate = _handshake(11, b"C" * 4096)
        chunks = [
            Chunk(0, _record(22, client_hello)),
            Chunk(1, _record(22, server_hello + clear_certificate) + _record(23, os.urandom(2048))),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = self._capture(root, "tls12_rsa.pcapng", chunks, "tcp", 44443)
            plain_path, auto_path = root / "plain.minarx", root / "auto.minarx"
            plain = compact_capture(capture, plain_path, "tls12", compression="none")
            auto = compact_capture(capture, auto_path, "tls12", compression="auto")
            plain_container, auto_container = read_container(plain_path), read_container(auto_path)
            self.assertEqual(plain_container.opaque, auto_container.opaque)
            self.assertEqual(plain_container.layout, auto_container.layout)
            self.assertEqual(
                plain["archive_bytes"] - auto["archive_bytes"],
                plain["stored_layout_bytes"] - auto["stored_layout_bytes"],
            )
            self.assertGreater(auto["layout_entropy_saving_bytes"], 0)

            for compression in ("none", "deflate", "lzma", "auto"):
                with self.subTest(compression=compression):
                    path = root / f"{compression}.minarx"
                    compact_capture(
                        capture, path, "tls12", compression=compression
                    )
                    container = read_container(path)
                    expected = (
                        compression
                        if compression != "auto"
                        else auto_container.compression
                    )
                    self.assertEqual(container.compression, expected)
                    self.assertEqual(container.opaque, plain_container.opaque)
                    self.assertEqual(container.layout, plain_container.layout)

    def test_profile_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture, _ = self._profile_capture(root, "tls13-full-aes128gcm")
            with self.assertRaisesRegex(ArchiveError, "does not match profile"):
                compact_capture(
                    capture,
                    root / "wrong.minarx",
                    "tls13",
                    "1rtt",
                    profile="tls13-full-aes256gcm",
                )

            quic_capture, quic_port = self._profile_capture(
                root, "quic-v1-aes128gcm"
            )
            with patch(
                "minarx.protocols.quic.extract_quic_cipher_suites",
                return_value={0x1301},
            ), self.assertRaisesRegex(ArchiveError, "does not select profile"):
                compact_capture(
                    quic_capture,
                    root / "wrong-quic.minarx",
                    "quic",
                    "default",
                    quic_port,
                    profile="quic-v1-aes256gcm",
                )

    def test_checksum_rejects_modified_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = self._capture(
                root,
                "ssh_session.pcapng",
                _ssh_chunks("chacha20-poly1305@openssh.com", b"", b""),
                "tcp",
                22222,
            )
            archive = root / "ssh.minarx"
            compact_capture(capture, archive, "ssh", "default", 22222)
            damaged = bytearray(archive.read_bytes())
            damaged[-33] ^= 1
            archive.write_bytes(damaged)
            with self.assertRaises(ArchiveError):
                inspect_archive(archive)

    def test_compacted_derivation_uses_separate_recovery_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = self._capture(
                root,
                "tls13_1rtt.pcapng",
                _tls13_chunks(opaque_size=64),
                "tcp",
                44443,
            )
            archive = root / "trace.minarx"
            compact_capture(capture, archive, "tls13", "1rtt", 44443)
            recovery = root / "recovery"
            recovery.mkdir()
            (recovery / "simulated_quantum_output.json").write_text(
                json.dumps({"priv": "11" * 32})
            )

            def fake_derive(
                capture_dir, protocol=None, mode=None, debug=False
            ):
                materialized = Path(capture_dir)
                self.assertTrue((materialized / "pcap" / "tls13_1rtt.pcapng").is_file())
                self.assertTrue(
                    (materialized / "keys" / "simulated_quantum_output.json").is_file()
                )
                self.assertFalse((materialized / "keys" / "sslkeylog.log").exists())
                (materialized / "derived").mkdir()
                (materialized / "derived" / "proof.txt").write_text("derived")
                return {"success": True}

            output = root / "output"
            derive_module = importlib.import_module("decryptor.derive")
            with patch.object(derive_module, "derive", side_effect=fake_derive):
                result = derive_compacted(str(archive), str(recovery), output_dir=str(output))
            self.assertTrue(result["success"])
            self.assertTrue(result["compacted_input"])
            self.assertEqual((output / "proof.txt").read_text(), "derived")


if __name__ == "__main__":
    unittest.main()
