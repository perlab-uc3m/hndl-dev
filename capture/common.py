#!/usr/bin/env python3
"""Shared helpers for traffic capture (tshark, process lifecycle, cert generation)."""

import json
import hashlib
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

EPHEM_RE_PRIV = re.compile(r"DEMO_EPHEMERAL_PRIV=\s*([0-9a-fA-F]+)")
EPHEM_RE_PUB = re.compile(r"DEMO_EPHEMERAL_PUB=\s*([0-9a-fA-F]+)")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _version_output(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        return (result.stdout + result.stderr).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return f"unavailable: {exc}"


def write_run_manifest(
    capture_root: Path,
    experiment: dict,
    commands: dict[str, list[str]],
    binaries: list[Path],
    implementation_paths: list[Path],
    artifact_paths: list[Path],
    attack_inputs: list[str],
    excluded_from_attack_inputs: list[str],
) -> Path:
    """Write reproducibility metadata without exposing endpoint secret values."""
    repo_root = Path(__file__).resolve().parents[1]
    openssl_binary = next(
        (path for path in binaries if path.name == "openssl" and path.exists()), None
    )
    git_commit = _version_output(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"]
    ).splitlines()[0]
    git_dirty = bool(
        _version_output(["git", "-C", str(repo_root), "status", "--porcelain"])
    )
    manifest = {
        "schema": "hndl-run-manifest-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "experiment": experiment,
        "commands": commands,
        "software": {
            "python": sys.version,
            "platform": platform.platform(),
            "uname": list(platform.uname()),
            "openssl_version": (
                _version_output([str(openssl_binary), "version"])
                if openssl_binary
                else "not used"
            ),
            "tshark_version": _version_output(["tshark", "--version"]),
            "dumpcap_version": _version_output(["dumpcap", "--version"]),
            "repository_commit": git_commit,
            "repository_dirty": git_dirty,
        },
        "binary_sha256": {
            str(path): _sha256(path) for path in binaries if path.exists()
        },
        "implementation_sha256": {
            str(path.resolve().relative_to(repo_root)): _sha256(path)
            for path in implementation_paths
            if path.exists()
        },
        "artifacts": {
            str(path.resolve().relative_to(capture_root.resolve())): {
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
            for path in artifact_paths
            if path.exists()
        },
        "evidence_boundary": {
            "attack_inputs": attack_inputs,
            "excluded_from_attack_inputs": excluded_from_attack_inputs,
        },
    }
    manifest_path = capture_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest_path


def persist_recovery_material(
    keys_dir: Path, endpoint_state: dict, recovered_role: str = "server"
) -> tuple[Path, Path]:
    """Separate simulated attacker output from comparison-only endpoint state."""
    recovered = endpoint_state.get(recovered_role, {})
    private_value = recovered.get("priv")
    public_value = recovered.get("pub")
    if not private_value or not public_value:
        raise RuntimeError(
            f"instrumented {recovered_role} did not export a complete ephemeral key"
        )

    oracle_path = keys_dir / "simulated_quantum_output.json"
    truth_path = keys_dir / "openssl_ephemeral_ground_truth.json"
    oracle_path.write_text(
        json.dumps(
            {
                "model": "simulated asymmetric recovery",
                "role": recovered_role,
                "group": "X25519",
                "ephemeral_private": private_value,
                "ephemeral_public_check": public_value,
            },
            indent=2,
        )
        + "\n"
    )
    truth_path.write_text(json.dumps(endpoint_state, indent=2) + "\n")
    return oracle_path, truth_path


def now_ts():
    """Generate timestamp for directory names."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S-%fZ")


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
            if accept_event and ("ACCEPT" in line or "listening" in line.lower()):
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


def capture_reader_thread(
    pipe,
    logfile: Path,
    ready_event: threading.Event | None = None,
    verbose: bool = False,
):
    """Read capture-writer output, persist logs, and detect readiness."""
    logfile.parent.mkdir(parents=True, exist_ok=True)
    saw_ready = False
    with logfile.open("wb") as f:
        for raw in iter(pipe.readline, b""):
            f.write(raw)
            line = raw.decode(errors="replace").rstrip()
            if verbose:
                try:
                    print(f"[dumpcap] {line}")
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
    pcap_file: Path,
    iface: str,
    port: int,
    logs_dir: Path,
    verbose: bool = False,
    transport: str = "tcp",
):
    """Start dumpcap directly and return its process and log-reader threads.

    Running the capture writer directly makes its lifetime observable.  When
    tshark launches dumpcap as a child, signalling tshark can leave dumpcap
    alive and the PCAP unfinalized on some privilege-separated installations.
    """
    if transport not in {"tcp", "udp"}:
        raise ValueError(f"unsupported capture transport: {transport}")
    tshark_cmd = [
        "dumpcap",
        "-i",
        iface,
        "-f",
        f"{transport} port {port}",
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
        raise RuntimeError(f"failed to start dumpcap: {e}") from e

    t_out = threading.Thread(
        target=capture_reader_thread,
        args=(tshark.stdout, tshark_out_log, None, verbose),
    )
    t_err = threading.Thread(
        target=capture_reader_thread,
        args=(tshark.stderr, tshark_err_log, tshark_ready, verbose),
    )
    t_out.daemon = True
    t_err.daemon = True
    t_out.start()
    t_err.start()

    if verbose:
        print("[+] Waiting for dumpcap to be ready...")
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
                "dumpcap exited before capture started.\n"
                f"stdout:\n{out}\n\nstderr:\n{err}"
            )
            raise RuntimeError(msg)
        if tshark_ready.is_set():
            break
        time.sleep(0.1)
    time.sleep(0.2)

    if not tshark_ready.is_set():
        terminate(tshark, "tshark")
        for t in (t_out, t_err):
            t.join(timeout=1)
        raise RuntimeError("dumpcap did not report capture readiness")

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
            "dumpcap exited before capture started.\n"
            f"stdout:\n{out}\n\nstderr:\n{err}"
        )

    return tshark, (t_out, t_err)


def stop_tshark(tshark: subprocess.Popen, threads: tuple):
    """Stop the direct dumpcap writer and wait until the PCAP is finalized."""
    try:
        tshark.send_signal(signal.SIGINT)
    except Exception:
        pass
    try:
        tshark.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(tshark.pid), signal.SIGTERM)
        except Exception:
            pass
        try:
            tshark.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(tshark.pid), signal.SIGKILL)
            except Exception:
                pass
            tshark.wait(timeout=2)
    for t in threads:
        t.join(timeout=2)
    if tshark.poll() is None:
        raise RuntimeError("dumpcap did not terminate cleanly")


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
