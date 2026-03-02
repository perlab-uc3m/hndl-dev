#!/usr/bin/env python3
"""TLS 1.3 0-RTT (early data) capture."""

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from ..common import (
    reader_thread,
    terminate,
    tcp_port_open,
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

    # Start server with -early_data flag
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
        args=(server1.stdout, server1_stdout, "server", eph_store_phase1),
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
            sys.exit("Server (phase 1) exited prematurely")
        if server1_accept_event.is_set() or tcp_port_open("127.0.0.1", port):
            break
        time.sleep(0.1)

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

    # Just close stdin to trigger handshake completion
    try:
        if verbose:
            print("[+] Closing stdin to complete handshake")
        time.sleep(1)  # Let handshake complete
        client1.stdin.close()
    except Exception as e:
        if verbose:
            print(f"[!] Error closing client stdin: {e}")

    # Wait for client to exit
    try:
        client1.wait(timeout=8)
    except subprocess.TimeoutExpired:
        if verbose:
            print("[!] Client (phase 1) timeout; terminating")
        terminate(client1, "client1")

    # Stop server (phase 1)
    time.sleep(0.5)
    terminate(server1, "server1")

    # Stop tshark (phase 1)
    stop_tshark(tshark1, tshark1_threads)

    if verbose:
        print(f"[+] Phase 1 complete. Session ticket saved: {session_file}")

    # Verify session file exists
    if not session_file.exists():
        sys.exit(f"[!] Session file not created: {session_file}")

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

    # Start server again (same -early_data flag)
    if verbose:
        print(f"[+] Starting server (phase 2): {' '.join(server_cmd)}")

    server2_stdout = logs_dir / "phase2_server_stdout.log"
    server2_stderr = logs_dir / "phase2_server_stderr.log"
    server2 = subprocess.Popen(
        server_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=False,
        preexec_fn=os.setsid,
        env=base_env,
    )

    # Reader threads for phase 2
    eph_store_phase2 = {
        "server": {"priv": None, "pub": None},
        "client": {"priv": None, "pub": None},
    }
    server2_accept_event = threading.Event()
    t_srv2_out = threading.Thread(
        target=reader_thread,
        args=(server2.stdout, server2_stdout, "server", eph_store_phase2),
    )
    t_srv2_err = threading.Thread(
        target=reader_thread,
        args=(
            server2.stderr,
            server2_stderr,
            "server",
            eph_store_phase2,
            server2_accept_event,
        ),
    )
    t_srv2_out.daemon = True
    t_srv2_err.daemon = True
    t_srv2_out.start()
    t_srv2_err.start()

    # Wait for server ready
    if verbose:
        print("[+] Waiting for server to be ready...")
    for _ in range(50):
        if server2.poll() is not None:
            sys.exit("Server (phase 2) exited prematurely")
        if server2_accept_event.is_set() or tcp_port_open("127.0.0.1", port):
            break
        time.sleep(0.1)

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
        "-quiet",
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

    # Stop server (phase 2)
    time.sleep(0.5)
    terminate(server2, "server2")

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

    # Report
    print("\nCapture complete (0-RTT two-phase).")
    print(f"- PCAP (phase 1 - initial): {pcap_file_phase1}")
    print(f"- PCAP (phase 2 - 0-RTT):   {pcap_file_phase2}")
    print(f"- Key log: {keylog_file}")
    print(f"- Session ticket: {session_file}")
    print(f"- Ephemeral (server): {server_ephem_json}")
    print(f"- Ephemeral (client): {client_ephem_json}")
    print(f"- Logs: {logs_dir}")

    return {
        "mode": "0rtt",
        "pcap_phase1": str(pcap_file_phase1),
        "pcap_phase2": str(pcap_file_phase2),
        "keylog": str(keylog_file),
        "session_ticket": str(session_file),
        "server_ephemeral": str(server_ephem_json),
        "client_ephemeral": str(client_ephem_json),
        "logs": str(logs_dir),
    }
