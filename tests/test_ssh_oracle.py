import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519

from decryptor.ssh.oracle import SimulatedQuantumOracle


class SshOracleBoundaryTests(unittest.TestCase):
    def test_release_requires_matching_public_value_and_is_one_time(self):
        private = bytes.fromhex("11" * 32)
        public = (
            x25519.X25519PrivateKey.from_private_bytes(private)
            .public_key()
            .public_bytes_raw()
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oracle.json"
            path.write_text(
                json.dumps(
                    {
                        "algorithm": "curve25519-sha256",
                        "recovered_side": "client",
                        "recoveries": [
                            {
                                "ephemeral_private": private.hex(),
                                "ephemeral_public": public.hex(),
                            }
                        ],
                    }
                )
            )
            oracle = SimulatedQuantumOracle(path)
            try:
                self.assertEqual(oracle.recover(public, 0, 0), private)
                with self.assertRaisesRegex(ValueError, "no unreleased scalar"):
                    oracle.recover(public, 1, 1)
            finally:
                oracle.close()


if __name__ == "__main__":
    unittest.main()
