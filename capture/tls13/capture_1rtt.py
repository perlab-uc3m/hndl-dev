#!/usr/bin/env python3
"""TLS 1.3 1-RTT (full ECDHE handshake) capture."""

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


def capture_1rtt(
    openssl: Path,
    iface: str,
    port: int,
    group: str,
    capture_root: Path,
    verbose: bool = False,
):
    """Capture a TLS 1.3 1-RTT session (full ECDHE handshake)."""
    pcap_dir = capture_root / "pcap"
    logs_dir = capture_root / "logs"
    keys_dir = capture_root / "keys"
    for d in (pcap_dir, logs_dir, keys_dir):
        d.mkdir(parents=True, exist_ok=True)

    keylog_file = keys_dir / "sslkeylog.log"
    cert_pem = keys_dir / "cert.pem"
    key_pem = keys_dir / "key.pem"
    pcap_file = pcap_dir / "tls13_1rtt.pcapng"
    server_stdout = logs_dir / "server_stdout.log"
    server_stderr = logs_dir / "server_stderr.log"
    client_stdout = logs_dir / "client_stdout.log"
    client_stderr = logs_dir / "client_stderr.log"
    server_ephem_json = keys_dir / "server_ephemeral.json"
    client_ephem_json = keys_dir / "client_ephemeral.json"
    combined_ephem_txt = keys_dir / "ephemeral_combined.txt"

    if verbose:
        print(f"[+] Output dir: {capture_root}")

    # Generate cert/key
    base_env = generate_cert_key(openssl, cert_pem, key_pem, keys_dir, verbose)

    # Start tshark
    tshark, tshark_threads = start_tshark(pcap_file, iface, port, logs_dir, verbose)

    # Start server
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
        "-www",
        "-keylogfile",
        str(keylog_file),
    ]
    if verbose:
        print(f"[+] Starting server: {' '.join(server_cmd)}")
    server = subprocess.Popen(
        server_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=False,
        preexec_fn=os.setsid,
        env=base_env,
    )

    # Reader threads
    eph_store = {
        "server": {"priv": None, "pub": None},
        "client": {"priv": None, "pub": None},
    }
    server_accept_event = threading.Event()
    t_srv_out = threading.Thread(
        target=reader_thread, args=(server.stdout, server_stdout, "server", eph_store)
    )
    t_srv_err = threading.Thread(
        target=reader_thread,
        args=(server.stderr, server_stderr, "server", eph_store, server_accept_event),
    )
    t_srv_out.daemon = True
    t_srv_err.daemon = True
    t_srv_out.start()
    t_srv_err.start()

    # Wait for server ready
    if verbose:
        print("[+] Waiting for server to be ready...")
    for _ in range(50):
        if server.poll() is not None:
            sys.exit("Server exited prematurely")
        if server_accept_event.is_set() or tcp_port_open("127.0.0.1", port):
            break
        time.sleep(0.1)

    # Start client
    client_cmd = [
        str(openssl),
        "s_client",
        "-connect",
        f"127.0.0.1:{port}",
        "-tls1_3",
        "-groups",
        group,
        "-servername",
        "localhost",
        "-keylogfile",
        str(keylog_file),
        "-quiet",
    ]
    if verbose:
        print(f"[+] Starting client: {' '.join(client_cmd)}")
    client = subprocess.Popen(
        client_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=False,
        preexec_fn=os.setsid,
        env=base_env,
    )
    t_cli_out = threading.Thread(
        target=reader_thread, args=(client.stdout, client_stdout, "client", eph_store)
    )
    t_cli_err = threading.Thread(
        target=reader_thread, args=(client.stderr, client_stderr, "client", eph_store)
    )
    t_cli_out.daemon = True
    t_cli_err.daemon = True
    t_cli_out.start()
    t_cli_err.start()

    # Send HTTP GET
    try:
        if verbose:
            print("[+] Sending HTTP GET from client")
        http_req = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
        client.stdin.write(http_req)
        client.stdin.flush()
        client.stdin.close()
    except Exception:
        pass

    # Wait for client exit
    try:
        client.wait(timeout=8)
    except subprocess.TimeoutExpired:
        if verbose:
            print("[!] Client timeout; terminating")
        terminate(client, "client")

    # Stop server
    time.sleep(0.5)
    terminate(server, "server")

    # Stop tshark
    stop_tshark(tshark, tshark_threads)

    # Persist ephemeral keys
    with server_ephem_json.open("w") as f:
        json.dump(eph_store["server"], f, indent=2)
    with client_ephem_json.open("w") as f:
        json.dump(eph_store["client"], f, indent=2)
    with combined_ephem_txt.open("w") as f:
        for who in ("server", "client"):
            f.write(f"{who.upper()}_DEMO_EPHEMERAL_PRIV={eph_store[who].get('priv')}\n")
            f.write(f"{who.upper()}_DEMO_EPHEMERAL_PUB={eph_store[who].get('pub')}\n")

    # Report
    print("Capture complete (1-RTT).")
    print(f"- PCAP: {pcap_file}")
    print(f"- Key log: {keylog_file}")
    print(f"- Ephemeral (server): {server_ephem_json}")
    print(f"- Ephemeral (client): {client_ephem_json}")
    print(f"- Logs: {logs_dir}")

    try:
        size = pcap_file.stat().st_size
        if size == 0:
            print("[!] Warning: PCAP file is empty.")
    except Exception:
        pass

    return {
        "mode": "1rtt",
        "pcap": str(pcap_file),
        "keylog": str(keylog_file),
        "server_ephemeral": str(server_ephem_json),
        "client_ephemeral": str(client_ephem_json),
        "logs": str(logs_dir),
    }
