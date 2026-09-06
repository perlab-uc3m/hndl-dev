#!/usr/bin/env python3
"""TLS 1.3 1-RTT (full ECDHE handshake) capture."""

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
        target=reader_thread,
        args=(server.stdout, server_stdout, "server", eph_store, server_accept_event),
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
            stop_tshark(tshark, tshark_threads)
            raise RuntimeError("TLS 1.3 server exited before becoming ready")
        if server_accept_event.is_set():
            break
        time.sleep(0.1)
    if not server_accept_event.is_set():
        terminate(server, "server")
        stop_tshark(tshark, tshark_threads)
        raise RuntimeError("TLS 1.3 server did not report readiness")

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
    t_cli_out.join(timeout=1)
    t_cli_err.join(timeout=1)
    if client.poll() not in (0, None):
        terminate(server, "server")
        t_srv_out.join(timeout=1)
        t_srv_err.join(timeout=1)
        stop_tshark(tshark, tshark_threads)
        raise RuntimeError(f"TLS 1.3 client failed with exit status {client.poll()}")

    # Stop server
    time.sleep(0.5)
    terminate(server, "server")
    t_srv_out.join(timeout=1)
    t_srv_err.join(timeout=1)

    # Stop tshark
    stop_tshark(tshark, tshark_threads)

    response = client_stdout.read_bytes() if client_stdout.exists() else b""
    if b"HTTP/" not in response:
        raise RuntimeError("TLS 1.3 client did not receive the test HTTP response")

    # Persist ephemeral keys
    with server_ephem_json.open("w") as f:
        json.dump(eph_store["server"], f, indent=2)
    with client_ephem_json.open("w") as f:
        json.dump(eph_store["client"], f, indent=2)
    with combined_ephem_txt.open("w") as f:
        for who in ("server", "client"):
            f.write(f"{who.upper()}_DEMO_EPHEMERAL_PRIV={eph_store[who].get('priv')}\n")
            f.write(f"{who.upper()}_DEMO_EPHEMERAL_PUB={eph_store[who].get('pub')}\n")
    recovery_file, ephemeral_truth_file = persist_recovery_material(
        keys_dir, eph_store, "server"
    )
    repo_root = Path(__file__).resolve().parents[2]
    manifest_file = write_run_manifest(
        capture_root,
        experiment={
            "protocol": "TLS 1.3",
            "mode": "full 1-RTT handshake",
            "group": group,
            "network": f"{iface} capture",
            "port": port,
            "pcap_available": pcap_file.exists() and pcap_file.stat().st_size > 0,
        },
        commands={"server": server_cmd, "client": client_cmd},
        binaries=[openssl],
        implementation_paths=[
            Path(__file__).resolve(),
            repo_root / "capture/common.py",
            repo_root / "decryptor/tls13/derive_1rtt.py",
            repo_root / "decryptor/io/pcap_parser.py",
            repo_root / "patches/openssl-3.6.0-tls13-debug.patch",
        ],
        artifact_paths=[
            pcap_file,
            keylog_file,
            recovery_file,
            ephemeral_truth_file,
            cert_pem,
            key_pem,
            server_stdout,
            server_stderr,
            client_stdout,
            client_stderr,
        ],
        attack_inputs=[
            "pcap/tls13_1rtt.pcapng",
            "keys/simulated_quantum_output.json",
        ],
        excluded_from_attack_inputs=[
            "keys/sslkeylog.log",
            "keys/openssl_ephemeral_ground_truth.json",
            "keys/key.pem",
            "process logs",
        ],
    )

    # Report
    print("Capture complete (1-RTT).")
    print(f"- PCAP: {pcap_file}")
    print(f"- Key log: {keylog_file}")
    print(f"- Ephemeral (server): {server_ephem_json}")
    print(f"- Ephemeral (client): {client_ephem_json}")
    print(f"- Simulated recovery: {recovery_file}")
    print(f"- Comparison-only ephemeral state: {ephemeral_truth_file}")
    print(f"- Reproduction manifest: {manifest_file}")
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
        "simulated_recovery": str(recovery_file),
        "ephemeral_ground_truth": str(ephemeral_truth_file),
        "manifest": str(manifest_file),
        "logs": str(logs_dir),
    }
