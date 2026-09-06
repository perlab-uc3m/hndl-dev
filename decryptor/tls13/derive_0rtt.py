#!/usr/bin/env python3
"""TLS 1.3 0-RTT key derivation from two-phase capture (initial + resumption)."""

import binascii
import hashlib
from pathlib import Path

from experiment import require_tool
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from ..core import (
    derive_tls13_keys_with_trace,
    compute_shared_secret_from_priv_and_peer,
    nss_tls13_key_log_line,
    parse_tls13_handshake_secrets_from_keylog,
    print_secret_comparison,
    derive_resumption_master_secret,
    derive_psk_from_resumption_master,
    derive_early_secrets,
)
from ..io import (
    RecoveryArtifacts,
    load_simulated_recovery,
    extract_tls_hello_pair,
    parse_client_random_from_ch,
    parse_cipher_from_server_hello,
    parse_client_keyshare_pub_from_ch,
    parse_server_keyshare_pub_from_sh,
    extract_decrypted_handshake_from_tshark,
    parse_new_session_ticket,
    verify_tls_http_request,
)


def _extract_psk_ticket_from_ch(ch: bytes) -> bytes:
    """Extract PSK ticket identity from ClientHello."""
    pos = 4 + 2 + 32  # Skip handshake header + version + random
    if pos >= len(ch):
        return None

    sess_id_len = ch[pos]
    pos += 1 + sess_id_len
    if pos + 2 > len(ch):
        return None

    cipher_suites_len = int.from_bytes(ch[pos : pos + 2], "big")
    pos += 2 + cipher_suites_len
    if pos >= len(ch):
        return None

    comp_len = ch[pos]
    pos += 1 + comp_len
    if pos + 2 > len(ch):
        return None

    ext_len = int.from_bytes(ch[pos : pos + 2], "big")
    pos += 2
    end = pos + ext_len

    while pos + 4 <= end:
        ext_type = int.from_bytes(ch[pos : pos + 2], "big")
        ext_len_val = int.from_bytes(ch[pos + 2 : pos + 4], "big")
        if ext_type == 41:  # PSK extension
            psk_data = ch[pos + 4 : pos + 4 + ext_len_val]
            if len(psk_data) >= 4:
                id_len = int.from_bytes(psk_data[2:4], "big")
                if len(psk_data) >= 4 + id_len:
                    return psk_data[4 : 4 + id_len]
        pos += 4 + ext_len_val

    return None


def derive_0rtt(
    capture_dir: Path,
    pcap_phase1: str = "pcap/tls13_0rtt_phase1_initial.pcapng",
    pcap_phase2: str = "pcap/tls13_0rtt_phase2_resumption.pcapng",
    port: int = 44443,
    role: str = "server",
    curve: str = "x25519",
    hash_algo: str = "auto",
    debug: bool = False,
    recovery_name: str = "keys/simulated_quantum_output.json",
    ground_truth_name: str = "keys/sslkeylog.log",
) -> dict:
    """Derive 0-RTT CLIENT_EARLY_TRAFFIC_SECRET from two-phase capture (RFC 8446)."""
    require_tool("tshark")

    capture_path = Path(capture_dir)
    pcap1 = capture_path / pcap_phase1
    pcap2 = capture_path / pcap_phase2

    if not pcap1.exists() or not pcap2.exists():
        return {"success": False, "error": f"Missing PCAPs: {pcap1} or {pcap2}"}

    paths = RecoveryArtifacts(capture_path, keylog_name=ground_truth_name)
    paths.ensure_derived_dir()

    # ========== PHASE 1: Derive PSK from initial handshake ==========

    try:
        recovery = load_simulated_recovery(capture_path, recovery_name)
    except (OSError, ValueError) as exc:
        return {"success": False, "error": str(exc)}
    if recovery["group"].lower() != "x25519" or curve.lower() != "x25519":
        return {"success": False, "error": "Only X25519 recovery is supported"}

    ch1, sh1 = extract_tls_hello_pair(pcap1, port)
    if not ch1 or not sh1:
        return {"success": False, "error": "Could not extract CH/SH from phase 1"}

    try:
        ch_pub = parse_client_keyshare_pub_from_ch(ch1)
        sh_pub = parse_server_keyshare_pub_from_sh(sh1)
        if not ch_pub or not sh_pub:
            raise ValueError("X25519 KeyShare missing from captured hello")
        private_hex = recovery["ephemeral_private"]
        private_key = x25519.X25519PrivateKey.from_private_bytes(
            bytes.fromhex(private_hex)
        )
        recovered_public = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        if recovered_public != bytes.fromhex(recovery["ephemeral_public_check"]):
            raise ValueError("recovered private value does not match its public check")
        if recovery["role"] == "server":
            own_public, peer_public = sh_pub, ch_pub
        else:
            own_public, peer_public = ch_pub, sh_pub
        if recovered_public != own_public:
            raise ValueError("recovered value does not match the captured KeyShare")
        Z = compute_shared_secret_from_priv_and_peer(
            private_hex, peer_public.hex(), curve
        )
    except (ValueError, TypeError, binascii.Error) as exc:
        return {"success": False, "error": f"Invalid recovery input: {exc}"}

    tls_hash = hash_algo
    if tls_hash == "auto":
        cs = parse_cipher_from_server_hello(sh1)
        tls_hash = "sha384" if cs == 0x1302 else "sha256"

    th_hello = hashlib.new(tls_hash, ch1 + sh1).digest()
    client_random1 = parse_client_random_from_ch(ch1)

    # Derive phase 1 handshake secrets
    _, trace1, _ = derive_tls13_keys_with_trace(Z, tls_hash, None, th_hello, None)

    client_hs = binascii.unhexlify(trace1["client_handshake_traffic_secret"])
    server_hs = binascii.unhexlify(trace1["server_handshake_traffic_secret"])

    # Write phase 1 keylog
    keylog1 = paths.derived_dir / "phase1_handshake.keylog"
    with keylog1.open("w") as f:
        f.write(
            nss_tls13_key_log_line(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_random1, client_hs
            )
        )
        f.write(
            nss_tls13_key_log_line(
                "SERVER_HANDSHAKE_TRAFFIC_SECRET", client_random1, server_hs
            )
        )

    # Decrypt phase 1 handshake
    encrypted_msgs = extract_decrypted_handshake_from_tshark(
        pcap1, keylog1, debug=debug
    )
    if not encrypted_msgs:
        return {"success": False, "error": "Failed to decrypt phase 1 handshake"}

    # Build transcripts: one up to Server Finished, one including Client Finished
    transcript_sf = ch1 + sh1
    client_finished = None
    finished_count = 0

    for msg in encrypted_msgs:
        msg_type = msg[0] if msg else None
        if msg_type in (8, 11, 15, 20):  # EE, Cert, CertVerify, Finished
            if msg_type == 20:
                finished_count += 1
                if finished_count == 1:
                    transcript_sf += msg  # Server Finished
                else:
                    client_finished = msg  # Client Finished
            else:
                transcript_sf += msg

    if not client_finished:
        return {"success": False, "error": "Could not find Client Finished"}

    th_server_finished = hashlib.new(tls_hash, transcript_sf).digest()
    th_client_finished = hashlib.new(tls_hash, transcript_sf + client_finished).digest()

    # Derive application secrets and master_secret
    _, trace_full, _ = derive_tls13_keys_with_trace(
        Z, tls_hash, None, th_hello, th_server_finished
    )
    master_secret = binascii.unhexlify(trace_full["master_secret"])

    # Write full phase 1 keylog
    client_app = binascii.unhexlify(trace_full["client_application_traffic_secret"])
    server_app = binascii.unhexlify(trace_full["server_application_traffic_secret"])

    keylog1_full = paths.derived_dir / "phase1_full.keylog"
    with keylog1_full.open("w") as f:
        f.write(
            nss_tls13_key_log_line(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_random1, client_hs
            )
        )
        f.write(
            nss_tls13_key_log_line(
                "SERVER_HANDSHAKE_TRAFFIC_SECRET", client_random1, server_hs
            )
        )
        f.write(
            nss_tls13_key_log_line(
                "CLIENT_TRAFFIC_SECRET_0", client_random1, client_app
            )
        )
        f.write(
            nss_tls13_key_log_line(
                "SERVER_TRAFFIC_SECRET_0", client_random1, server_app
            )
        )

    # Derive resumption_master_secret (uses th_client_finished!)
    resumption_master = derive_resumption_master_secret(
        master_secret, th_client_finished, tls_hash
    )

    # Extract NewSessionTickets
    all_msgs = extract_decrypted_handshake_from_tshark(pcap1, keylog1_full, debug=debug)
    nst_list = []
    for msg in all_msgs:
        if msg and msg[0] == 4:  # NewSessionTicket
            parsed = parse_new_session_ticket(msg)
            nst_list.append(parsed)

    if not nst_list:
        return {"success": False, "error": "No NewSessionTicket found"}

    # ========== PHASE 2: Derive CLIENT_EARLY_TRAFFIC_SECRET ==========

    ch2, _ = extract_tls_hello_pair(pcap2, port)
    if not ch2:
        return {"success": False, "error": "Could not extract ClientHello from phase 2"}

    # Match ticket identity
    ticket_identity = _extract_psk_ticket_from_ch(ch2)
    if not ticket_identity:
        return {
            "success": False,
            "error": "Could not extract PSK ticket from ClientHello2",
        }

    matched_nst = None
    for nst in nst_list:
        if nst["ticket"] == ticket_identity:
            matched_nst = nst
            break

    if not matched_nst:
        return {
            "success": False,
            "error": "Ticket identity not found in NewSessionTickets",
        }

    # Derive PSK
    psk = derive_psk_from_resumption_master(
        resumption_master, matched_nst["ticket_nonce"], tls_hash
    )

    # Derive early secrets
    early = derive_early_secrets(psk, ch2, tls_hash)
    client_early = early["client_early_traffic_secret"]
    client_early_hex = binascii.hexlify(client_early).decode()

    # Write 0-RTT keylog
    client_random2 = parse_client_random_from_ch(ch2)
    keylog_0rtt = paths.derived_dir / "nss_0rtt.keylog"
    with keylog_0rtt.open("w") as f:
        f.write(
            nss_tls13_key_log_line(
                "CLIENT_EARLY_TRAFFIC_SECRET", client_random2, client_early
            )
        )

    # Verify against OpenSSL keylog
    ok, total = 0, 1
    if paths.openssl_keylog_exists():
        keylog_truth = parse_tls13_handshake_secrets_from_keylog(
            paths.openssl_keylog, client_random2
        )
        if keylog_truth.get("CLIENT_EARLY_TRAFFIC_SECRET"):
            ok, total = print_secret_comparison(
                "0-RTT",
                keylog_truth,
                {"CLIENT_EARLY_TRAFFIC_SECRET": client_early_hex},
                verbose=debug,
            )

    plaintext_ok = verify_tls_http_request(pcap2, keylog_0rtt, port, debug)

    status = "ALL MATCH" if ok == total else f"{ok}/{total} MATCH"
    print(f"TLS 1.3 0-RTT keys: {status} ({total} secret)")
    print(f"TLS 1.3 0-RTT plaintext: {'RECOVERED' if plaintext_ok else 'NOT VERIFIED'}")
    print(f"Output: {keylog_0rtt}")

    return {
        "success": ok == total and total == 1 and plaintext_ok,
        "keylog_path": str(keylog_0rtt),
        "secrets": {"CLIENT_EARLY_TRAFFIC_SECRET": client_early_hex},
        "validation": {
            "ground_truth_matches": ok,
            "ground_truth_expected": 1,
            "early_application_plaintext_recovered": plaintext_ok,
        },
    }
