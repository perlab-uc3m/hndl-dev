"""Cryptographic primitives for TLS 1.2, TLS 1.3, and SSH key derivation."""

from .tls13_crypto import (
    hkdf_expand_label,
    hkdf_extract,
    get_hash_algo,
    derive_tls13_keys_from_z,
    derive_tls13_keys_with_trace,
    compute_shared_secret_from_priv_and_peer,
    derive_resumption_master_secret,
    derive_psk_from_resumption_master,
    derive_early_secrets,
)
from .transcript_hash import (
    sha_hex,
    compute_th_hello,
    compute_th_finished,
)
from .keylog_utils import (
    nss_key_log_line,
    nss_tls13_key_log_line,
    parse_tls13_handshake_secrets_from_keylog,
    print_secret_comparison,
)
from .ssh_crypto import (
    derive_ssh_key,
    derive_ssh_keys,
    derive_ssh_keys_with_trace,
    compute_exchange_hash,
)

__all__ = [
    # tls13_crypto
    "hkdf_expand_label",
    "hkdf_extract",
    "get_hash_algo",
    "derive_tls13_keys_from_z",
    "derive_tls13_keys_with_trace",
    "compute_shared_secret_from_priv_and_peer",
    "derive_resumption_master_secret",
    "derive_psk_from_resumption_master",
    "derive_early_secrets",
    # transcript_hash
    "sha_hex",
    "compute_th_hello",
    "compute_th_finished",
    # keylog_utils
    "nss_key_log_line",
    "nss_tls13_key_log_line",
    "parse_tls13_handshake_secrets_from_keylog",
    "print_secret_comparison",
    # ssh_crypto
    "derive_ssh_key",
    "derive_ssh_keys",
    "derive_ssh_keys_with_trace",
    "compute_exchange_hash",
]
