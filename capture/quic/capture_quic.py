#!/usr/bin/env python3
"""QUIC capture using patched OpenSSL 3.6 quic_server + s_client."""

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
    generate_cert_key,
    stop_tshark,
    tshark_reader_thread,
    find_or_write_openssl_conf,
)


def _udp_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    """Best-effort UDP port probe (no reliable method for QUIC)."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(b"\x00", (host, port))
            # If no ICMP unreachable within timeout, assume port is open
            try:
                s.recvfrom(1)
            except socket.timeout:
                return True  # No response = likely listening
            return True
        except Exception:
            return False


def _start_tshark_udp(
    pcap_file: Path, iface: str, port: int, logs_dir: Path, verbose: bool = False
):
    """Start tshark on a UDP port."""
    tshark_cmd = [
        "tshark",
        "-i",
        iface,
        "-f",
        f"udp port {port}",
        "-w",
        str(pcap_file),
    ]
    if verbose:
        print(f"[+] Starting capture: {' '.join(tshark_cmd)}")
    tshark_ready = threading.Event()
    tshark_out_log = logs_dir / "tshark_stdout.log"
    tshark_err_log = logs_dir / "tshark_stderr.log"

    try:
        tshark = subprocess.Popen(
            tshark_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )
    except Exception as e:
        sys.exit(f"Failed to start tshark: {e}")

    t_out = threading.Thread(
        target=tshark_reader_thread,
        args=(tshark.stdout, tshark_out_log, None, verbose),
    )
    t_err = threading.Thread(
        target=tshark_reader_thread,
        args=(tshark.stderr, tshark_err_log, tshark_ready, verbose),
    )
    t_out.daemon = True
    t_err.daemon = True
    t_out.start()
    t_err.start()

    if verbose:
        print("[+] Waiting for tshark to be ready...")
    for _ in range(30):
        if tshark.poll() is not None:
            err = (
                tshark_err_log.read_text(errors="replace")
                if tshark_err_log.exists()
                else ""
            )
            out = (
                tshark_out_log.read_text(errors="replace")
                if tshark_out_log.exists()
                else ""
            )
            sys.exit(
                f"tshark exited before capture started.\nstdout:\n{out}\nstderr:\n{err}"
            )
        if tshark_ready.is_set():
            break
        time.sleep(0.1)
    time.sleep(0.2)

    return tshark, (t_out, t_err)


def capture_quic(
    openssl: Path,
    iface: str,
    port: int,
    group: str,
    capture_root: Path,
    verbose: bool = False,
):
    """Capture a QUIC session (quic_server + openssl s_client -quic)."""
    # Locate quic_server binary relative to the openssl binary
    quic_server_bin = openssl.parent / "quic_server"
    if not quic_server_bin.exists():
        sys.exit(
            f"quic_server not found at {quic_server_bin}.\n"
            "Build it with: bash scripts/build_quic_server.sh"
        )

    pcap_dir = capture_root / "pcap"
    logs_dir = capture_root / "logs"
    keys_dir = capture_root / "keys"
    for d in (pcap_dir, logs_dir, keys_dir):
        d.mkdir(parents=True, exist_ok=True)

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

    # Start tshark (UDP capture)
    tshark, tshark_threads = _start_tshark_udp(
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
        "-1",  # one-shot: exit after one connection
    ]
    if verbose:
        print(f"[+] Starting QUIC server: {' '.join(server_cmd)}")
    server = subprocess.Popen(
        server_cmd,
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
            sys.exit("QUIC server exited prematurely")
        if server_accept_event.is_set():
            break
        time.sleep(0.1)
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
    except Exception:
        pass

    # Wait for client to exit
    try:
        client.wait(timeout=10)
    except subprocess.TimeoutExpired:
        if verbose:
            print("[!] QUIC client timeout; terminating")
        terminate(client, "quic_client")

    # Wait for server to exit (one-shot mode)
    time.sleep(0.5)
    terminate(server, "quic_server")

    # Stop tshark
    stop_tshark(tshark, tshark_threads)

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

    # Report
    print("Capture complete (QUIC).")
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
        "mode": "quic",
        "pcap": str(pcap_file),
        "keylog": str(keylog_file),
        "server_ephemeral": str(server_ephem_json),
        "client_ephemeral": str(client_ephem_json),
        "logs": str(logs_dir),
    }
