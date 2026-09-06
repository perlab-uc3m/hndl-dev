#!/usr/bin/env python3
"""TLS 1.2 RSA key-transport capture using OpenSSL and dumpcap."""

import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

from experiment import ArtifactLayout, recovery_spec

from ..common import (
    reader_thread,
    write_run_manifest,
    terminate,
    generate_cert_key,
    start_capture,
    stop_capture,
    start_process,
)


def capture_tls12_rsa(
    openssl: Path, iface: str, port: int, capture_root: Path, verbose: bool = False
):
    """Capture a TLS 1.2 RSA key-transport session."""
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
    pcap_file = pcap_dir / "tls12_rsa.pcapng"
    server_stdout = logs_dir / "server_stdout.log"
    server_stderr = logs_dir / "server_stderr.log"
    client_stdout = logs_dir / "client_stdout.log"
    client_stderr = logs_dir / "client_stderr.log"

    if verbose:
        print(f"[+] Output dir: {capture_root}")

    # Generate a throwaway RSA cert/key
    base_env = generate_cert_key(openssl, cert_pem, key_pem, keys_dir, verbose)

    # Start packet capture.
    capture, capture_threads = start_capture(pcap_file, iface, port, logs_dir, verbose)

    # Force TLS 1.2 RSA key transport (AES128-SHA)
    cipher_str = "AES128-SHA"

    # Start server (TLS 1.2 RSA)
    server_cmd = [
        str(openssl),
        "s_server",
        "-accept",
        str(port),
        "-cert",
        str(cert_pem),
        "-key",
        str(key_pem),
        "-tls1_2",
        "-cipher",
        cipher_str,
        "-www",
        "-keylogfile",
        str(keylog_file),
    ]
    if verbose:
        print(f"[+] Starting TLS 1.2 RSA server: {' '.join(server_cmd)}")
    server = start_process(
        server_cmd,
        "TLS 1.2 server",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=False,
        preexec_fn=os.setsid,
        env=base_env,
    )

    # Reader threads for logging
    eph_store = {"server": {}, "client": {}}  # No ephemeral keys in RSA mode
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
            stop_capture(capture, capture_threads)
            raise RuntimeError("TLS 1.2 server exited before becoming ready")
        if server_accept_event.is_set():
            break
        time.sleep(0.1)
    if not server_accept_event.is_set():
        terminate(server, "server")
        stop_capture(capture, capture_threads)
        raise RuntimeError("TLS 1.2 server did not report readiness")

    # Start client (TLS 1.2 RSA)
    client_cmd = [
        str(openssl),
        "s_client",
        "-connect",
        f"127.0.0.1:{port}",
        "-tls1_2",
        "-cipher",
        cipher_str,
        "-servername",
        "localhost",
        "-keylogfile",
        str(keylog_file),
        "-quiet",
    ]
    if verbose:
        print(f"[+] Starting TLS 1.2 RSA client: {' '.join(client_cmd)}")
    client = start_process(
        client_cmd,
        "TLS 1.2 client",
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
    except (BrokenPipeError, OSError, ValueError):
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
        stop_capture(capture, capture_threads)
        raise RuntimeError(f"TLS 1.2 client failed with exit status {client.poll()}")

    # Stop server
    time.sleep(0.5)
    terminate(server, "server")
    t_srv_out.join(timeout=1)
    t_srv_err.join(timeout=1)

    # Finalize the packet capture.
    stop_capture(capture, capture_threads)

    response = client_stdout.read_bytes() if client_stdout.exists() else b""
    if b"HTTP/" not in response:
        raise RuntimeError("TLS 1.2 client did not receive the test HTTP response")

    # This copy represents the long-term RSA private key recovered by the
    # simulated future attacker.  The original key.pem remains endpoint state.
    recovery_key = keys_dir / "simulated_quantum_output.pem"
    shutil.copyfile(key_pem, recovery_key)
    recovery_key.chmod(0o600)
    repo_root = Path(__file__).resolve().parents[2]
    manifest_file = write_run_manifest(
        capture_root,
        experiment={
            "protocol": "TLS 1.2",
            "mode": "RSA key transport",
            "cipher": cipher_str,
            "network": f"{iface} capture",
            "port": port,
            "pcap_available": pcap_file.exists() and pcap_file.stat().st_size > 0,
        },
        commands={"server": server_cmd, "client": client_cmd},
        binaries=[openssl],
        implementation_paths=[
            Path(__file__).resolve(),
            repo_root / "capture/common.py",
            repo_root / "decryptor/tls12/derive_rsa.py",
            repo_root / "decryptor/io/pcap_parser.py",
        ],
        artifact_paths=[
            pcap_file,
            keylog_file,
            recovery_key,
            cert_pem,
            key_pem,
            server_stdout,
            server_stderr,
            client_stdout,
            client_stderr,
        ],
        attack_inputs=[
            "pcap/tls12_rsa.pcapng",
            "keys/simulated_quantum_output.pem",
        ],
        excluded_from_attack_inputs=[
            "keys/sslkeylog.log",
            "keys/key.pem",
            "process logs",
        ],
        recovery=recovery_spec("tls12", "rsa", port),
    )

    # Report
    print("Capture complete (TLS 1.2 RSA).")
    print(f"- PCAP: {pcap_file}")
    print(f"- Key log: {keylog_file}")
    print(f"- Simulated RSA recovery: {recovery_key}")
    print(f"- Reproduction manifest: {manifest_file}")
    print(f"- Logs: {logs_dir}")

    return {
        "version": "tls1.2",
        "mode": "rsa",
        "pcap": str(pcap_file),
        "keylog": str(keylog_file),
        "simulated_recovery": str(recovery_key),
        "manifest": str(manifest_file),
        "logs": str(logs_dir),
    }
