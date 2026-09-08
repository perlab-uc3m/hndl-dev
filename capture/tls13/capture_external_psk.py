#!/usr/bin/env python3
"""Capture a TLS 1.3 connection authenticated by an external pure PSK."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import threading
import time
from pathlib import Path

from experiment import ArtifactLayout, recovery_spec

from ..common import (
    reader_thread,
    start_capture,
    start_process,
    stop_capture,
    terminate,
    write_run_manifest,
)


def _redact_psk(command: list[str]) -> list[str]:
    redacted = list(command)
    if "-psk" in redacted:
        redacted[redacted.index("-psk") + 1] = "<redacted>"
    return redacted


def capture_external_psk(
    openssl: Path,
    iface: str,
    port: int,
    group: str,
    capture_root: Path,
    verbose: bool = False,
):
    """Capture an external-PSK 1-RTT session with no fresh DH contribution."""
    del group
    layout = ArtifactLayout(capture_root)
    layout.create_capture_dirs()
    pcap = layout.archive_dir / "tls13_external_psk.pcapng"
    keylog = layout.keys_dir / "sslkeylog.log"
    recovery_file = layout.keys_dir / "simulated_external_psk.json"
    truth_file = layout.keys_dir / "external_psk_ground_truth.json"
    server_stdout = layout.logs_dir / "server_stdout.log"
    server_stderr = layout.logs_dir / "server_stderr.log"
    client_stdout = layout.logs_dir / "client_stdout.log"
    client_stderr = layout.logs_dir / "client_stderr.log"

    identity = "hndl-external-psk"
    psk = secrets.token_bytes(32)
    psk_hex = psk.hex()
    base_env = os.environ.copy()
    capture, capture_threads = start_capture(
        pcap, iface, port, layout.logs_dir, verbose
    )
    server_cmd = [
        str(openssl),
        "s_server",
        "-accept",
        str(port),
        "-tls1_3",
        "-nocert",
        "-psk_identity",
        identity,
        "-psk",
        psk_hex,
        "-allow_no_dhe_kex",
        "-prefer_no_dhe_kex",
        "-www",
        "-keylogfile",
        str(keylog),
    ]
    if verbose:
        print("[+] Starting TLS 1.3 external-PSK server (PSK redacted)")
    server = start_process(
        server_cmd,
        "TLS 1.3 external-PSK server",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=False,
        preexec_fn=os.setsid,
        env=base_env,
    )
    endpoint_state = {
        "server": {"priv": None, "pub": None},
        "client": {"priv": None, "pub": None},
    }
    ready = threading.Event()
    server_threads = (
        threading.Thread(
            target=reader_thread,
            args=(server.stdout, server_stdout, "server", endpoint_state, ready),
            daemon=True,
        ),
        threading.Thread(
            target=reader_thread,
            args=(server.stderr, server_stderr, "server", endpoint_state, ready),
            daemon=True,
        ),
    )
    for thread in server_threads:
        thread.start()
    for _ in range(50):
        if server.poll() is not None:
            stop_capture(capture, capture_threads)
            raise RuntimeError("external-PSK server exited before becoming ready")
        if ready.is_set():
            break
        time.sleep(0.1)
    if not ready.is_set():
        terminate(server, "server")
        stop_capture(capture, capture_threads)
        raise RuntimeError("external-PSK server did not report readiness")

    client_cmd = [
        str(openssl),
        "s_client",
        "-connect",
        f"127.0.0.1:{port}",
        "-tls1_3",
        "-psk_identity",
        identity,
        "-psk",
        psk_hex,
        "-allow_no_dhe_kex",
        "-prefer_no_dhe_kex",
        "-keylogfile",
        str(keylog),
        "-quiet",
    ]
    client = start_process(
        client_cmd,
        "TLS 1.3 external-PSK client",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=False,
        preexec_fn=os.setsid,
        env=base_env,
    )
    client_threads = (
        threading.Thread(
            target=reader_thread,
            args=(client.stdout, client_stdout, "client", endpoint_state),
            daemon=True,
        ),
        threading.Thread(
            target=reader_thread,
            args=(client.stderr, client_stderr, "client", endpoint_state),
            daemon=True,
        ),
    )
    for thread in client_threads:
        thread.start()
    try:
        client.stdin.write(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        client.stdin.flush()
        client.stdin.close()
    except (BrokenPipeError, OSError, ValueError):
        pass
    try:
        client.wait(timeout=8)
    except subprocess.TimeoutExpired:
        terminate(client, "client")
    for thread in client_threads:
        thread.join(timeout=1)
    if client.poll() not in (0, None):
        terminate(server, "server")
        stop_capture(capture, capture_threads)
        raise RuntimeError(f"external-PSK client failed: {client.poll()}")
    time.sleep(0.5)
    terminate(server, "server")
    for thread in server_threads:
        thread.join(timeout=1)
    stop_capture(capture, capture_threads)
    if b"HTTP/" not in client_stdout.read_bytes():
        raise RuntimeError("external-PSK client did not receive the HTTP response")

    recovery_file.write_text(
        json.dumps(
            {
                "model": "simulated later compromise of an external PSK",
                "identity": identity,
                "psk": psk_hex,
            },
            indent=2,
        )
        + "\n"
    )
    truth_file.write_text(
        json.dumps({"identity": identity, "psk": psk_hex}, indent=2) + "\n"
    )
    repo_root = Path(__file__).resolve().parents[2]
    manifest = write_run_manifest(
        capture_root,
        experiment={
            "protocol": "TLS 1.3",
            "mode": "external PSK",
            "resumption_key_exchange": "external-psk-only",
            "port": port,
            "network": f"{iface} capture",
        },
        commands={
            "server": _redact_psk(server_cmd),
            "client": _redact_psk(client_cmd),
        },
        binaries=[openssl],
        implementation_paths=[
            Path(__file__).resolve(),
            repo_root / "capture/common.py",
            repo_root / "decryptor/tls13/derive_external_psk.py",
            repo_root / "decryptor/tls13/derive_resumption.py",
            repo_root / "decryptor/io/pcap_parser.py",
        ],
        artifact_paths=[
            pcap,
            keylog,
            recovery_file,
            truth_file,
            server_stdout,
            server_stderr,
            client_stdout,
            client_stderr,
        ],
        attack_inputs=[
            "pcap/tls13_external_psk.pcapng",
            "keys/simulated_external_psk.json",
        ],
        excluded_from_attack_inputs=[
            "keys/sslkeylog.log",
            "keys/external_psk_ground_truth.json",
            "process logs",
        ],
        recovery=recovery_spec("tls13", "external-psk", port),
    )
    print("Capture complete (TLS 1.3 external PSK).")
    print(f"- PCAP: {pcap}")
    print(f"- Simulated later compromise: {recovery_file}")
    print(f"- Reproduction manifest: {manifest}")
    return {
        "mode": "external-psk",
        "pcap": str(pcap),
        "simulated_recovery": str(recovery_file),
        "manifest": str(manifest),
    }
