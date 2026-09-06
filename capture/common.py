#!/usr/bin/env python3
"""Shared helpers for traffic capture (tshark, process lifecycle, cert generation)."""

import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

EPHEM_RE_PRIV = re.compile(r"DEMO_EPHEMERAL_PRIV=\s*([0-9a-fA-F]+)")
EPHEM_RE_PUB = re.compile(r"DEMO_EPHEMERAL_PUB=\s*([0-9a-fA-F]+)")


def now_ts():
    """Generate timestamp for directory names."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")


def ensure_exec(path: Path, name: str):
    """Ensure file exists and is executable."""
    if not path.exists():
        sys.exit(f"Missing {name}: {path}")
    if not os.access(path, os.X_OK):
        sys.exit(f"Not executable {name}: {path}")


def check_tool(name: str):
    """Check if tool is available in PATH."""
    if shutil.which(name) is None:
        sys.exit(f"Required tool '{name}' not found in PATH")


def tcp_port_open(host: str, port: int, timeout=0.2) -> bool:
    """Check if TCP port is open."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return True
        except Exception:
            return False


def reader_thread(
    pipe,
    logfile: Path,
    label: str,
    eph_store: dict,
    accept_event: threading.Event = None,
):
    """Read process output, persist to log, extract ephemeral keys."""
    logfile.parent.mkdir(parents=True, exist_ok=True)
    with logfile.open("wb") as f:
        for raw in iter(pipe.readline, b""):
            f.write(raw)
            try:
                line = raw.decode(errors="replace").rstrip()
            except Exception:
                line = ""
            if accept_event and "ACCEPT" in line:
                accept_event.set()
            m1 = EPHEM_RE_PRIV.search(line)
            if m1:
                eph_store[label]["priv"] = m1.group(1).lower()
            m2 = EPHEM_RE_PUB.search(line)
            if m2:
                eph_store[label]["pub"] = m2.group(1).lower()


def terminate(proc: subprocess.Popen, name: str, grace=2.0):
    """Gracefully terminate a process."""
    if proc is None:
        return
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
    except Exception:
        pass
    t0 = time.time()
    while time.time() - t0 < grace:
        if proc.poll() is not None:
            return
        time.sleep(0.1)
    try:
        proc.kill()
    except Exception:
        pass


def tshark_reader_thread(
    pipe,
    logfile: Path,
    ready_event: threading.Event | None = None,
    verbose: bool = False,
):
    """Read tshark output, persist logs, and detect readiness."""
    logfile.parent.mkdir(parents=True, exist_ok=True)
    saw_ready = False
    with logfile.open("wb") as f:
        for raw in iter(pipe.readline, b""):
            f.write(raw)
            line = raw.decode(errors="replace").rstrip()
            if verbose:
                try:
                    print(f"[tshark] {line}")
                except Exception:
                    pass
            if not saw_ready and ("Capturing on" in line or 'File: "' in line):
                saw_ready = True
                if ready_event:
                    ready_event.set()


def find_or_write_openssl_conf(keys_dir: Path, verbose=False) -> Path:
    """Return a usable openssl.cnf path (system or generated)."""
    candidates = [Path("/etc/ssl/openssl.cnf"), Path("/etc/openssl/openssl.cnf")]
    for c in candidates:
        if c.exists():
            if verbose:
                print(f"[+] Using system OpenSSL config: {c}")
            return c
    cfg = keys_dir / "minimal_openssl.cnf"
    if verbose:
        print(f"[+] Writing minimal OpenSSL config: {cfg}")
    cfg.write_text(
        "[ req ]\n"
        "distinguished_name = dn\n"
        "prompt = no\n"
        "x509_extensions = v3_req\n"
        "\n"
        "[ dn ]\n"
        "CN = localhost\n"
        "\n"
        "[ v3_req ]\n"
        "basicConstraints = CA:false\n"
        "keyUsage = digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth, clientAuth\n"
    )
    return cfg


def start_tshark(
    pcap_file: Path, iface: str, port: int, logs_dir: Path, verbose: bool = False
):
    """Start tshark capture and return (process, ready_event)."""
    tshark_cmd = ["tshark", "-i", iface, "-f", f"tcp port {port}", "-w", str(pcap_file)]
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
        target=tshark_reader_thread, args=(tshark.stdout, tshark_out_log, None, verbose)
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
            msg = (
                "tshark exited before capture started.\n"
                f"stdout:\n{out}\n\nstderr:\n{err}"
            )
            raise RuntimeError(msg)
        if tshark_ready.is_set():
            break
        time.sleep(0.1)
    time.sleep(0.2)

    if tshark.poll() is not None:
        for t in (t_out, t_err):
            t.join(timeout=1)
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
        raise RuntimeError(
            "tshark exited before capture started.\n"
            f"stdout:\n{out}\n\nstderr:\n{err}"
        )

    return tshark, (t_out, t_err)


def stop_tshark(tshark: subprocess.Popen, threads: tuple):
    """Stop tshark and join reader threads."""
    try:
        os.killpg(os.getpgid(tshark.pid), signal.SIGINT)
    except Exception:
        pass
    try:
        tshark.wait(timeout=5)
    except subprocess.TimeoutExpired:
        terminate(tshark, "tshark")
    for t in threads:
        try:
            t.join(timeout=1)
        except Exception:
            pass


def generate_cert_key(
    openssl: Path, cert_pem: Path, key_pem: Path, keys_dir: Path, verbose: bool = False
):
    """Generate self-signed certificate and key."""
    openssl_conf = find_or_write_openssl_conf(keys_dir, verbose=verbose)
    base_env = os.environ.copy()
    base_env["OPENSSL_CONF"] = str(openssl_conf)

    gen_cmd = [
        str(openssl),
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key_pem),
        "-out",
        str(cert_pem),
        "-subj",
        "/CN=localhost",
        "-days",
        "1",
        "-config",
        str(openssl_conf),
    ]
    if verbose:
        print("[+] Generating throwaway cert/key...")
        print("[cmd]", " ".join(gen_cmd))
    try:
        r = subprocess.run(gen_cmd, check=True, capture_output=True, env=base_env)
        if verbose and r.stdout:
            sys.stdout.write(r.stdout.decode(errors="replace"))
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or b"").decode(errors="replace")
        sys.exit(f"openssl req failed:\n{stderr}")

    return base_env
