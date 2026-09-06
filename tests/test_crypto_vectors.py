import unittest

from decryptor.core.tls13_crypto import compute_shared_secret_from_priv_and_peer
from decryptor.quic.derive_quic import _quic_initial_keys


class PublishedVectorTests(unittest.TestCase):
    def test_rfc7748_x25519_shared_secret(self):
        alice_private = (
            "77076d0a7318a57d3c16c17251b26645" "df4c2f87ebc0992ab177fba51db92c2a"
        )
        bob_public = (
            "de9edb7d7b7dc1b4d35b61c2ece43537" "3f8343c85b78674dadfc7e146f882b4f"
        )
        expected = "4a5d9d5ba4ce2de1728e3bf480350f25" "e07e21c947d19e3376f09b3c1e161742"
        shared = compute_shared_secret_from_priv_and_peer(
            alice_private, bob_public, "x25519"
        )
        self.assertEqual(shared.hex(), expected)

    def test_rfc9001_quic_v1_initial_keys(self):
        destination_connection_id = bytes.fromhex("8394c8f03e515708")
        client_key, client_iv, client_hp = _quic_initial_keys(
            destination_connection_id, is_server=False
        )
        server_key, server_iv, server_hp = _quic_initial_keys(
            destination_connection_id, is_server=True
        )
        self.assertEqual(client_key.hex(), "1f369613dd76d5467730efcbe3b1a22d")
        self.assertEqual(client_iv.hex(), "fa044b2f42a3fd3b46fb255c")
        self.assertEqual(client_hp.hex(), "9f50449e04a0e810283a1e9933adedd2")
        self.assertEqual(server_key.hex(), "cf3a5331653c364c88f0f379b6067e37")
        self.assertEqual(server_iv.hex(), "0ac1493ca1905853b0bba03e")
        self.assertEqual(server_hp.hex(), "c206b8d9b9f0f37644430b490eeaa314")


if __name__ == "__main__":
    unittest.main()
