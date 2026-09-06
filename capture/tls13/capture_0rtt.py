#!/usr/bin/env python3
"""TLS 1.3 0-RTT (early data) capture."""

import json
import os
import subprocess
import threading
import time
from pathlib import Path

from ..common import (
    reader_thread,
    persist_recovery_material,
    write_run_manifest,
    terminate,
    generate_cert_key,
    start_tshark,
    stop_tshark,
)


def capture_0rtt(
    openssl: Path,
    iface: str,
    port: int,
    group: str,
    capture_root: Path,
    verbose: bool = False,
):
    """Capture a TLS 1.3 0-RTT session (initial handshake + resumption with early data)."""
    pcap_dir = capture_root / "pcap"
    logs_dir = capture_root / "logs"
    keys_dir = capture_root / "keys"
    for d in (pcap_dir, logs_dir, keys_dir):
        d.mkdir(parents=True, exist_ok=True)

    keylog_file = keys_dir / "sslkeylog.log"
    cert_pem = keys_dir / "cert.pem"
    key_pem = keys_dir / "key.pem"
    session_file = keys_dir / "session_0rtt.pem"
    early_data_file = keys_dir / "early_data_request.txt"
    pcap_file_phase1 = pcap_dir / "tls13_0rtt_phase1_initial.pcapng"
    pcap_file_phase2 = pcap_dir / "tls13_0rtt_phase2_resumption.pcapng"
    server_ephem_json = keys_dir / "server_ephemeral.json"
    client_ephem_json = keys_dir / "client_ephemeral.json"
    combined_ephem_txt = keys_dir / "ephemeral_combined.txt"

    if verbose:
        print(f"[+] Output dir: {capture_root}")
        print("[+] Mode: 0-RTT (two-phase capture)")

    # Generate cert/key
    base_env = generate_cert_key(openssl, cert_pem, key_pem, keys_dir, verbose)

    # Prepare early data request
    early_data_file.write_text("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")

    # ========== PHASE 1: Initial handshake to get session ticket ==========
    if verbose:
        print("\n[PHASE 1] Initial handshake to obtain session ticket")

    # Start tshark for phase 1
    tshark1, tshark1_threads = start_tshark(
        pcap_file_phase1, iface, port, logs_dir / "phase1", verbose
    )

    # Start one server for both connections. TLS 1.3 tickets are protected by
    # server-side ticket keys; restarting s_server between issuance and use
    # would make the second connection a full handshake instead of a genuine
    # resumption in the default configuration.
    server_cmd = [
        str(openssl),
        "s_server",
        "-accept",
        str(port),
        "-cert",
        str(cert_pem),
        "-key",
        str(key_pem),
        "-tls1_3",
        "-groups",
        group,
        "-early_data",
        # Controlled loopback experiment: accept the first use of the saved
        # ticket deterministically. This is not a deployment recommendation;
        # production anti-replay policy is outside this reconstruction test.
        "-no_anti_replay",
        "-www",
        "-keylogfile",
        str(keylog_file),
    ]
    if verbose:
        print(f"[+] Starting server (phase 1): {' '.join(server_cmd)}")

    server1_stdout = logs_dir / "phase1_server_stdout.log"
    server1_stderr = logs_dir / "phase1_server_stderr.log"
    server1 = subprocess.Popen(
        server_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=False,
        preexec_fn=os.setsid,
        env=base_env,
    )

    # Reader threads for phase 1
    eph_store_phase1 = {
        "server": {"priv": None, "pub": None},
        "client": {"priv": None, "pub": None},
    }
    server1_accept_event = threading.Event()
    t_srv1_out = threading.Thread(
        target=reader_thread,
        args=(
            server1.stdout,
            server1_stdout,
            "server",
            eph_store_phase1,
            server1_accept_event,
        ),
    )
    t_srv1_err = threading.Thread(
        target=reader_thread,
        args=(
            server1.stderr,
            server1_stderr,
            "server",
            eph_store_phase1,
            server1_accept_event,
        ),
    )
    t_srv1_out.daemon = True
    t_srv1_err.daemon = True
    t_srv1_out.start()
    t_srv1_err.start()

    # Wait for server ready
    if verbose:
        print("[+] Waiting for server to be ready...")
    for _ in range(50):
        if server1.poll() is not None:
            stop_tshark(tshark1, tshark1_threads)
            raise RuntimeError("server exited before phase 1 became ready")
        if server1_accept_event.is_set():
            break
        time.sleep(0.1)
    if not server1_accept_event.is_set():
        terminate(server1, "server")
        stop_tshark(tshark1, tshark1_threads)
        raise RuntimeError("server did not report readiness for phase 1")

    # Start client to get session ticket
    # Use -ign_eof to auto-close after handshake completes
    client1_cmd = [
        str(openssl),
        "s_client",
        "-connect",
        f"127.0.0.1:{port}",
        "-tls1_3",
        "-groups",
        group,
        "-servername",
        "localhost",
        "-sess_out",
        str(session_file),
        "-keylogfile",
        str(keylog_file),
        "-ign_eof",  # Close after first EOF on stdin
        "-quiet",
    ]
    if verbose:
        print(f"[+] Starting client (phase 1): {' '.join(client1_cmd)}")

    client1_stdout = logs_dir / "phase1_client_stdout.log"
    client1_stderr = logs_dir / "phase1_client_stderr.log"
    client1 = subprocess.Popen(
        client1_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=False,
        preexec_fn=os.setsid,
        env=base_env,
    )
    t_cli1_out = threading.Thread(
        target=reader_thread,
        args=(client1.stdout, client1_stdout, "client", eph_store_phase1),
    )
    t_cli1_err = threading.Thread(
        target=reader_thread,
        args=(client1.stderr, client1_stderr, "client", eph_store_phase1),
    )
    t_cli1_out.daemon = True
    t_cli1_err.daemon = True
    t_cli1_out.start()
    t_cli1_err.start()

    # Keep the client alive long enough to receive the post-handshake
    # NewSessionTicket.  In quiet mode OpenSSL implicitly ignores stdin EOF, so
    # poll for the session file and then terminate the client deliberately.
    try:
        if verbose:
            print("[+] Waiting for the post-handshake session ticket")
        client1.stdin.close()
    except Exception as e:
        if verbose:
            print(f"[!] Error closing client stdin: {e}")

    for _ in range(80):
        if session_file.exists() and session_file.stat().st_size > 0:
            break
        if client1.poll() is not None:
            break
        time.sleep(0.1)
    terminate(client1, "client1")
    t_cli1_out.join(timeout=1)
    t_cli1_err.join(timeout=1)

    # Preserve phase-1 server keys before the persistent server handles the
    # second connection and the reader records the next key pair.
    server_phase1 = dict(eph_store_phase1["server"])

    # Stop tshark (phase 1)
    stop_tshark(tshark1, tshark1_threads)

    if verbose:
        print(f"[+] Phase 1 complete. Session ticket saved: {session_file}")

    # Verify session file exists
    if not session_file.exists() or session_file.stat().st_size == 0:
        terminate(server1, "server")
        raise RuntimeError(f"session ticket was not saved: {session_file}")

    # Wait between phases
    if verbose:
        print("[+] Waiting 1 second before phase 2...")
    time.sleep(1)

    # ========== PHASE 2: 0-RTT resumption with early data ==========
    if verbose:
        print("\n[PHASE 2] 0-RTT resumption with early data")

    # Start tshark for phase 2
    tshark2, tshark2_threads = start_tshark(
        pcap_file_phase2, iface, port, logs_dir / "phase2", verbose
    )

    # The server and its ticket-encryption state remain alive from phase 1.
    eph_store_phase2 = {
        "server": {"priv": None, "pub": None},
        "client": {"priv": None, "pub": None},
    }
    if server1.poll() is not None:
        stop_tshark(tshark2, tshark2_threads)
        raise RuntimeError("server exited before the resumption phase")

    # Start client with 0-RTT early data
    client2_cmd = [
        str(openssl),
        "s_client",
        "-connect",
        f"127.0.0.1:{port}",
        "-tls1_3",
        "-groups",
        group,
        "-servername",
        "localhost",
        "-sess_in",
        str(session_file),
        "-early_data",
        str(early_data_file),
        "-keylogfile",
        str(keylog_file),
        # Keep the connection alive so the diagnostic summary is emitted and
        # can prove that this was a resumed handshake with accepted early data.
        "-ign_eof",
    ]
    if verbose:
        print(f"[+] Starting client (phase 2) with early data: {' '.join(client2_cmd)}")

    client2_stdout = logs_dir / "phase2_client_stdout.log"
    client2_stderr = logs_dir / "phase2_client_stderr.log"
    client2 = subprocess.Popen(
        client2_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=False,
        preexec_fn=os.setsid,
        env=base_env,
    )
    t_cli2_out = threading.Thread(
        target=reader_thread,
        args=(client2.stdout, client2_stdout, "client", eph_store_phase2),
    )
    t_cli2_err = threading.Thread(
        target=reader_thread,
        args=(client2.stderr, client2_stderr, "client", eph_store_phase2),
    )
    t_cli2_out.daemon = True
    t_cli2_err.daemon = True
    t_cli2_out.start()
    t_cli2_err.start()

    # Close stdin (early data already sent via -early_data file)
    try:
        client2.stdin.close()
    except Exception:
        pass

    # Wait for client to exit
    try:
        client2.wait(timeout=8)
    except subprocess.TimeoutExpired:
        if verbose:
            print("[!] Client (phase 2) timeout; terminating")
        terminate(client2, "client2")

    t_cli2_out.join(timeout=1)
    t_cli2_err.join(timeout=1)

    phase2_summary = (
        client2_stdout.read_text(errors="replace") if client2_stdout.exists() else ""
    )
    if "Reused, TLSv1.3" not in phase2_summary:
        terminate(server1, "server")
        stop_tshark(tshark2, tshark2_threads)
        raise RuntimeError("phase 2 did not resume the saved TLS 1.3 session")
    if "Early data was accepted" not in phase2_summary:
        terminate(server1, "server")
        stop_tshark(tshark2, tshark2_threads)
        raise RuntimeError("phase 2 resumed, but the server rejected early data")

    # Stop the persistent server after both connections.
    time.sleep(0.5)
    terminate(server1, "server")
    t_srv1_out.join(timeout=1)
    t_srv1_err.join(timeout=1)

    # The persistent server reader now contains the latest (phase-2) pair.
    eph_store_phase2["server"] = dict(eph_store_phase1["server"])
    eph_store_phase1["server"] = server_phase1

    # Stop tshark (phase 2)
    stop_tshark(tshark2, tshark2_threads)

    # Persist ephemeral keys for BOTH phases
    # Phase 1 keys (for breaking initial handshake)
    server_ephem_phase1_json = keys_dir / "server_ephemeral_phase1.json"
    client_ephem_phase1_json = keys_dir / "client_ephemeral_phase1.json"
    with server_ephem_phase1_json.open("w") as f:
        json.dump(eph_store_phase1["server"], f, indent=2)
    with client_ephem_phase1_json.open("w") as f:
        json.dump(eph_store_phase1["client"], f, indent=2)

    # Phase 2 keys (for completeness, though not needed for 0-RTT decryption)
    server_ephem_phase2_json = keys_dir / "server_ephemeral_phase2.json"
    client_ephem_phase2_json = keys_dir / "client_ephemeral_phase2.json"
    with server_ephem_phase2_json.open("w") as f:
        json.dump(eph_store_phase2["server"], f, indent=2)
    with client_ephem_phase2_json.open("w") as f:
        json.dump(eph_store_phase2["client"], f, indent=2)

    # For backward compatibility, use Phase 1 keys as the main ephemeral keys
    with server_ephem_json.open("w") as f:
        json.dump(eph_store_phase1["server"], f, indent=2)
    with client_ephem_json.open("w") as f:
        json.dump(eph_store_phase1["client"], f, indent=2)
    with combined_ephem_txt.open("w") as f:
        f.write("# Phase 1 (initial handshake) ephemeral keys\n")
        for who in ("server", "client"):
            f.write(
                f"PHASE1_{who.upper()}_EPHEMERAL_PRIV={eph_store_phase1[who].get('priv')}\n"
            )
            f.write(
                f"PHASE1_{who.upper()}_EPHEMERAL_PUB={eph_store_phase1[who].get('pub')}\n"
            )
        f.write("\n# Phase 2 (0-RTT resumption) ephemeral keys\n")
        for who in ("server", "client"):
            f.write(
                f"PHASE2_{who.upper()}_EPHEMERAL_PRIV={eph_store_phase2[who].get('priv')}\n"
            )
            f.write(
                f"PHASE2_{who.upper()}_EPHEMERAL_PUB={eph_store_phase2[who].get('pub')}\n"
            )
    recovery_file, ephemeral_truth_file = persist_recovery_material(
        keys_dir, eph_store_phase1, "server"
    )
    repo_root = Path(__file__).resolve().parents[2]
    manifest_file = write_run_manifest(
        capture_root,
        experiment={
            "protocol": "TLS 1.3",
            "mode": "0-RTT resumption",
            "group": group,
            "network": f"{iface} capture",
            "port": port,
            "resumption_confirmed": True,
            "early_data_accepted": True,
            "phase1_pcap_available": (
                pcap_file_phase1.exists() and pcap_file_phase1.stat().st_size > 0
            ),
            "phase2_pcap_available": (
                pcap_file_phase2.exists() and pcap_file_phase2.stat().st_size > 0
            ),
        },
        commands={
            "server": server_cmd,
            "initial_client": client1_cmd,
            "resumption_client": client2_cmd,
        },
        binaries=[openssl],
        implementation_paths=[
            Path(__file__).resolve(),
            repo_root / "capture/common.py",
            repo_root / "decryptor/tls13/derive_0rtt.py",
            repo_root / "decryptor/io/pcap_parser.py",
            repo_root / "patches/openssl-3.6.0-tls13-debug.patch",
        ],
        artifact_paths=[
            pcap_file_phase1,
            pcap_file_phase2,
            keylog_file,
            recovery_file,
            ephemeral_truth_file,
            session_file,
            early_data_file,
            cert_pem,
            key_pem,
            server1_stdout,
            server1_stderr,
            client1_stdout,
            client1_stderr,
            client2_stdout,
            client2_stderr,
        ],
        attack_inputs=[
            "pcap/tls13_0rtt_phase1_initial.pcapng",
            "pcap/tls13_0rtt_phase2_resumption.pcapng",
            "keys/simulated_quantum_output.json",
        ],
        excluded_from_attack_inputs=[
            "keys/sslkeylog.log",
            "keys/openssl_ephemeral_ground_truth.json",
            "keys/session_0rtt.pem",
            "keys/key.pem",
            "process logs",
        ],
    )

    # Report
    print("\nCapture complete (0-RTT two-phase).")
    print(f"- PCAP (phase 1 - initial): {pcap_file_phase1}")
    print(f"- PCAP (phase 2 - 0-RTT):   {pcap_file_phase2}")
    print(f"- Key log: {keylog_file}")
    print(f"- Session ticket: {session_file}")
    print(f"- Ephemeral (server): {server_ephem_json}")
    print(f"- Ephemeral (client): {client_ephem_json}")
    print(f"- Simulated recovery: {recovery_file}")
    print(f"- Comparison-only ephemeral state: {ephemeral_truth_file}")
    print(f"- Reproduction manifest: {manifest_file}")
    print(f"- Logs: {logs_dir}")

    return {
        "mode": "0rtt",
        "pcap_phase1": str(pcap_file_phase1),
        "pcap_phase2": str(pcap_file_phase2),
        "keylog": str(keylog_file),
        "session_ticket": str(session_file),
        "server_ephemeral": str(server_ephem_json),
        "client_ephemeral": str(client_ephem_json),
        "simulated_recovery": str(recovery_file),
        "ephemeral_ground_truth": str(ephemeral_truth_file),
        "manifest": str(manifest_file),
        "logs": str(logs_dir),
    }
