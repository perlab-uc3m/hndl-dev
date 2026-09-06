#!/usr/bin/env python3
"""QUIC capture using patched OpenSSL 3.6 quic_server + s_client."""

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from experiment import ArtifactLayout, ConfigurationError, recovery_spec

from ..common import (
    reader_thread,
    persist_recovery_material,
    write_run_manifest,
    terminate,
    generate_cert_key,
    start_capture,
    stop_capture,
    start_process,
)


def _start_udp_capture(
    pcap_file: Path, iface: str, port: int, logs_dir: Path, verbose: bool = False
):
    """Start the shared direct-dumpcap capture path with a UDP filter."""
    return start_capture(pcap_file, iface, port, logs_dir, verbose, transport="udp")


def capture_quic(
    openssl: Path,
    iface: str,
    port: int,
    group: str,
    capture_root: Path,
    verbose: bool = False,
    response_size: int = 256,
):
    """Capture a QUIC session (quic_server + openssl s_client -quic)."""
    if response_size <= 0:
        raise ValueError("response_size must be positive")
    # Locate quic_server binary relative to the openssl binary
    quic_server_bin = openssl.parent / "quic_server"
    if not quic_server_bin.exists():
        raise ConfigurationError(
            f"quic_server not found at {quic_server_bin}.\n"
            "Build it with: bash scripts/build_quic_server.sh"
        )

    layout = ArtifactLayout(capture_root)
    layout.create_capture_dirs()
    pcap_dir, logs_dir, keys_dir = (
        layout.archive_dir,
        layout.logs_dir,
        layout.keys_dir,
    )

    keylog_file = keys_dir / "sslkeylog.log"
    cert_pem = keys_dir / "cert.pem"
    key_pem = keys_dir / "key.pem"
    pcap_file = pcap_dir / "quic.pcapng"
    server_stdout = logs_dir / "server_stdout.log"
    server_stderr = logs_dir / "server_stderr.log"
    client_stdout = logs_dir / "client_stdout.log"
    client_stderr = logs_dir / "client_stderr.log"
    server_ephem_json = keys_dir / "server_ephemeral.json"
    client_ephem_json = keys_dir / "client_ephemeral.json"
    combined_ephem_txt = keys_dir / "ephemeral_combined.txt"
    client_keylog = keys_dir / "client_keylog.log"

    if verbose:
        print(f"[+] Output dir: {capture_root}")

    # Generate cert/key
    base_env = generate_cert_key(openssl, cert_pem, key_pem, keys_dir, verbose)
    # Ensure QUIC server & client export ephemeral keys
    base_env["DEMO_PRINT_EPHEMERAL"] = "1"

    # Start UDP packet capture.
    capture, capture_threads = _start_udp_capture(
        pcap_file, iface, port, logs_dir, verbose
    )

    # Start QUIC server (one-shot mode)
    server_cmd = [
        str(quic_server_bin),
        "-p",
        str(port),
        "-c",
        str(cert_pem),
        "-K",
        str(key_pem),
        "-k",
        str(keylog_file),
        "-g",
        group,
        "-n",
        str(response_size),
        "-1",  # one-shot: exit after one connection
    ]
    if verbose:
        print(f"[+] Starting QUIC server: {' '.join(server_cmd)}")
    server = start_process(
        server_cmd,
        "QUIC server",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=False,
        preexec_fn=os.setsid,
        env=base_env,
    )

    # Reader threads for server output (capture ephemeral keys from stderr)
    eph_store = {
        "server": {"priv": None, "pub": None},
        "client": {"priv": None, "pub": None},
    }
    server_accept_event = threading.Event()
    t_srv_out = threading.Thread(
        target=reader_thread,
        args=(server.stdout, server_stdout, "server", eph_store),
    )
    t_srv_err = threading.Thread(
        target=reader_thread,
        args=(
            server.stderr,
            server_stderr,
            "server",
            eph_store,
            server_accept_event,
        ),
    )
    t_srv_out.daemon = True
    t_srv_err.daemon = True
    t_srv_out.start()
    t_srv_err.start()

    # Wait for server to be ready (look for ACCEPT event or just wait)
    if verbose:
        print("[+] Waiting for QUIC server to be ready...")
    for _ in range(30):
        if server.poll() is not None:
            stop_capture(capture, capture_threads)
            raise RuntimeError("QUIC server exited before becoming ready")
        if server_accept_event.is_set():
            break
        time.sleep(0.1)
    if not server_accept_event.is_set():
        terminate(server, "quic_server")
        stop_capture(capture, capture_threads)
        raise RuntimeError("QUIC server did not report readiness")
    # Extra wait for UDP socket to be ready
    time.sleep(0.3)

    # Start QUIC client
    # OPENSSL_CONF must be set to avoid missing openssl.cnf errors
    client_cmd = [
        str(openssl),
        "s_client",
        "-quic",
        "-alpn",
        "ossltest",
        "-connect",
        f"127.0.0.1:{port}",
        "-groups",
        group,
        "-keylogfile",
        str(client_keylog),
        "-quiet",
    ]
    if verbose:
        print(f"[+] Starting QUIC client: {' '.join(client_cmd)}")
    client = start_process(
        client_cmd,
        "QUIC client",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=False,
        preexec_fn=os.setsid,
        env=base_env,
    )
    t_cli_out = threading.Thread(
        target=reader_thread,
        args=(client.stdout, client_stdout, "client", eph_store),
    )
    t_cli_err = threading.Thread(
        target=reader_thread,
        args=(client.stderr, client_stderr, "client", eph_store),
    )
    t_cli_out.daemon = True
    t_cli_err.daemon = True
    t_cli_out.start()
    t_cli_err.start()

    # Send HTTP GET request
    try:
        if verbose:
            print("[+] Sending HTTP GET from QUIC client")
        http_req = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
        client.stdin.write(http_req)
        client.stdin.flush()
        client.stdin.close()
    except (BrokenPipeError, OSError, ValueError):
        pass

    # Wait for client to exit
    try:
        client.wait(timeout=10)
    except subprocess.TimeoutExpired:
        if verbose:
            print("[!] QUIC client timeout; terminating")
        terminate(client, "quic_client")
    t_cli_out.join(timeout=1)
    t_cli_err.join(timeout=1)
    if client.poll() not in (0, None):
        terminate(server, "quic_server")
        t_srv_out.join(timeout=1)
        t_srv_err.join(timeout=1)
        stop_capture(capture, capture_threads)
        raise RuntimeError(f"QUIC client failed with exit status {client.poll()}")

    # Wait for server to exit (one-shot mode)
    time.sleep(0.5)
    terminate(server, "quic_server")
    t_srv_out.join(timeout=1)
    t_srv_err.join(timeout=1)

    # Finalize the packet capture.
    stop_capture(capture, capture_threads)

    response = client_stdout.read_bytes() if client_stdout.exists() else b""
    if b"A" * min(32, response_size) not in response:
        raise RuntimeError("QUIC client did not receive the known test response")

    # Merge keylogs (server + client)
    if client_keylog.exists():
        with keylog_file.open("a") as dst:
            for line in client_keylog.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    dst.write(line + "\n")

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
        keys_dir, eph_store, "client"
    )
    repo_root = Path(__file__).resolve().parents[2]
    manifest_file = write_run_manifest(
        capture_root,
        experiment={
            "protocol": "QUIC v1 with TLS 1.3",
            "mode": "full 1-RTT handshake",
            "group": group,
            "response_bytes": response_size,
            "network": f"{iface} capture",
            "port": port,
            "pcap_available": pcap_file.exists() and pcap_file.stat().st_size > 0,
        },
        commands={"server": server_cmd, "client": client_cmd},
        binaries=[openssl, quic_server_bin],
        implementation_paths=[
            Path(__file__).resolve(),
            repo_root / "capture/common.py",
            repo_root / "decryptor/quic/derive_quic.py",
            repo_root / "decryptor/io/pcap_parser.py",
            repo_root / "patches/openssl-3.6.0-tls13-debug.patch",
            repo_root / "patches/openssl-3.6.0-quic-server.patch",
        ],
        artifact_paths=[
            pcap_file,
            keylog_file,
            client_keylog,
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
            "pcap/quic.pcapng",
            "keys/simulated_quantum_output.json",
        ],
        excluded_from_attack_inputs=[
            "keys/sslkeylog.log and keys/client_keylog.log",
            "keys/openssl_ephemeral_ground_truth.json",
            "keys/key.pem",
            "process logs",
        ],
        recovery=recovery_spec("quic", None, port),
    )

    # Report
    print("Capture complete (QUIC).")
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
    except OSError:
        pass

    return {
        "mode": "quic",
        "pcap": str(pcap_file),
        "keylog": str(keylog_file),
        "server_ephemeral": str(server_ephem_json),
        "client_ephemeral": str(client_ephem_json),
        "simulated_recovery": str(recovery_file),
        "ephemeral_ground_truth": str(ephemeral_truth_file),
        "manifest": str(manifest_file),
        "logs": str(logs_dir),
    }
