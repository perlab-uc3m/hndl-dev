#!/usr/bin/env python3
"""SSH capture with separated simulated-quantum and ground-truth hooks."""

import json
import os
import re
import select
import socket
import subprocess
import threading
import time
from pathlib import Path

from experiment import ArtifactLayout, recovery_spec

from ..common import (
    start_capture,
    start_process,
    stop_capture,
    terminate,
    version_output,
    write_run_manifest,
)

SSH_QUANTUM_RE = re.compile(r"SSH_QUANTUM_(\w+)=\s*([0-9a-fA-F]+)")
SSH_GROUND_TRUTH_RE = re.compile(r"SSH_GROUND_TRUTH_(\w+)=\s*([0-9a-fA-F]+)")


def record_ssh_streams(
    listen_port: int,
    target_port: int,
    client_to_server_file: Path,
    server_to_client_file: Path,
    ready_event: threading.Event,
    stop_event: threading.Event,
    errors: list,
):
    """Forward one loopback SSH connection while recording its wire bytes."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("127.0.0.1", listen_port))
        listener.listen(1)
        listener.settimeout(0.2)
        ready_event.set()

        downstream = None
        while downstream is None and not stop_event.is_set():
            try:
                downstream, _ = listener.accept()
            except socket.timeout:
                continue
        if downstream is None:
            return

        upstream = socket.create_connection(("127.0.0.1", target_port), timeout=3)
        downstream.setblocking(False)
        upstream.setblocking(False)
        peers = {downstream: upstream, upstream: downstream}
        outputs = {downstream: client_to_server_file, upstream: server_to_client_file}
        active = {downstream, upstream}

        with (
            client_to_server_file.open("wb") as c2s,
            server_to_client_file.open("wb") as s2c,
        ):
            handles = {
                client_to_server_file: c2s,
                server_to_client_file: s2c,
            }
            while active and not stop_event.is_set():
                readable, _, _ = select.select(list(active), [], [], 0.2)
                for source in readable:
                    try:
                        data = source.recv(65536)
                    except BlockingIOError:
                        continue
                    if not data:
                        active.discard(source)
                        try:
                            peers[source].shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    handle = handles[outputs[source]]
                    handle.write(data)
                    handle.flush()
                    peers[source].sendall(data)
        downstream.close()
        upstream.close()
    except Exception as exc:
        errors.append(exc)
        ready_event.set()
    finally:
        listener.close()


def ssh_reader_thread(
    pipe,
    logfile: Path,
    quantum_output: dict,
    ground_truth: dict,
    ready_event: threading.Event = None,
):
    """Persist process output and keep oracle data separate from ground truth."""
    logfile.parent.mkdir(parents=True, exist_ok=True)
    with logfile.open("wb") as f:
        for raw in iter(pipe.readline, b""):
            f.write(raw)
            line = raw.decode(errors="replace").rstrip()
            if ready_event and "Server listening" in line:
                ready_event.set()
            quantum_match = SSH_QUANTUM_RE.search(line)
            if quantum_match:
                name, value = quantum_match.group(1), quantum_match.group(2).lower()
                quantum_output.setdefault("records", []).append(
                    {"name": name, "value": value}
                )
                # Keep the first value under the legacy scalar key so initial-
                # exchange consumers cannot silently switch to the last rekey.
                quantum_output.setdefault(name, value)
            truth_match = SSH_GROUND_TRUTH_RE.search(line)
            if truth_match:
                name, value = truth_match.group(1), truth_match.group(2).lower()
                ground_truth.setdefault("records", []).append(
                    {"name": name, "value": value}
                )
                ground_truth.setdefault(name, value)


def _quantum_recoveries(hook_output: dict) -> list[dict]:
    """Pair each private/public hook record without collapsing later rekeys."""
    recoveries = []
    pending_private = None
    for record in hook_output.get("records", []):
        if record["name"] == "EPHEMERAL_PRIV":
            if pending_private is not None:
                raise RuntimeError(
                    "quantum hook emitted two private values without a public value"
                )
            pending_private = record["value"]
        elif record["name"] == "EPHEMERAL_PUB":
            if pending_private is None:
                raise RuntimeError(
                    "quantum hook emitted a public value without a private value"
                )
            recoveries.append(
                {
                    "ephemeral_private": pending_private,
                    "ephemeral_public": record["value"],
                }
            )
            pending_private = None
    if pending_private is not None:
        raise RuntimeError("quantum hook ended with an unpaired private value")
    return recoveries


def generate_host_key(ssh_keygen: Path, keys_dir: Path, verbose: bool = False) -> Path:
    """Generate ED25519 host key for sshd."""
    host_key = keys_dir / "ssh_host_ed25519_key"
    if host_key.exists():
        return host_key
    cmd = [str(ssh_keygen), "-t", "ed25519", "-f", str(host_key), "-N", "", "-q"]
    if verbose:
        print(f"[+] Generating host key: {' '.join(cmd)}")
    subprocess.run(cmd, check=True, capture_output=True)
    return host_key


def generate_user_key(ssh_keygen: Path, keys_dir: Path, verbose: bool = False) -> Path:
    """Generate ED25519 user key for authentication."""
    user_key = keys_dir / "user_ed25519_key"
    if user_key.exists():
        return user_key
    cmd = [str(ssh_keygen), "-t", "ed25519", "-f", str(user_key), "-N", "", "-q"]
    if verbose:
        print(f"[+] Generating user key: {' '.join(cmd)}")
    subprocess.run(cmd, check=True, capture_output=True)
    # Create authorized_keys
    pub_key = keys_dir / "user_ed25519_key.pub"
    auth_keys = keys_dir / "authorized_keys"
    auth_keys.write_text(pub_key.read_text())
    return user_key


def write_sshd_config(
    config_path: Path,
    host_key: Path,
    auth_keys: Path,
    port: int,
    rekey_limit: str | None = None,
) -> Path:
    """Write minimal sshd_config for testing."""
    rekey_line = f"\nRekeyLimit {rekey_limit}" if rekey_limit else ""
    config_path.write_text(
        f"""
Port {port}
ListenAddress 127.0.0.1
HostKey {host_key}
AuthorizedKeysFile {auth_keys}
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
StrictModes no
UsePAM no
Subsystem sftp /usr/lib/openssh/sftp-server
LogLevel DEBUG3
KexAlgorithms curve25519-sha256
Ciphers chacha20-poly1305@openssh.com
HostKeyAlgorithms ssh-ed25519
{rekey_line}
""".strip()
        + "\n"
    )
    return config_path


def capture_ssh(
    sshd: Path,
    ssh: Path,
    ssh_keygen: Path,
    iface: str,
    port: int,
    capture_root: Path,
    verbose: bool = False,
    rekey_limit: str | None = None,
    payload_bytes: int = 0,
) -> dict:
    """Capture one forced-classical SSH session for HN-DL reconstruction."""
    # Ensure all paths are absolute (sshd requires absolute paths)
    sshd = Path(sshd).resolve()
    ssh = Path(ssh).resolve()
    ssh_keygen = Path(ssh_keygen).resolve()
    capture_root = Path(capture_root).resolve()
    if payload_bytes < 0:
        raise ValueError("SSH payload size cannot be negative")

    layout = ArtifactLayout(capture_root)
    layout.create_capture_dirs()
    pcap_dir, logs_dir, keys_dir = (
        layout.archive_dir,
        layout.logs_dir,
        layout.keys_dir,
    )

    pcap_file = pcap_dir / "ssh_session.pcapng"
    client_stream_file = pcap_dir / "ssh_client_to_server.bin"
    server_stream_file = pcap_dir / "ssh_server_to_client.bin"
    backend_port = port + 1
    host_key = generate_host_key(ssh_keygen, keys_dir, verbose)
    user_key = generate_user_key(ssh_keygen, keys_dir, verbose)
    auth_keys = keys_dir / "authorized_keys"
    sshd_config = write_sshd_config(
        keys_dir / "sshd_config", host_key, auth_keys, backend_port, rekey_limit
    )

    quantum_output = {"server": {}, "client": {}}
    ground_truth = {"server": {}, "client": {}}

    if verbose:
        print(f"[+] Output dir: {capture_root}")

    # Capture the public-side connection. The byte-recording relay is also an
    # exact transport-stream archive and permits deterministic testing when the
    # host has not granted dumpcap capture capabilities.
    capture = None
    capture_threads = None
    capture_error = None
    try:
        capture, capture_threads = start_capture(
            pcap_file, iface, port, logs_dir, verbose
        )
    except RuntimeError as exc:
        capture_error = str(exc)
        print(f"[!] PCAP capture unavailable; retaining SSH wire streams: {exc}")

    # Start sshd (debug mode, no fork)
    sshd_cmd = [str(sshd), "-D", "-d", "-f", str(sshd_config), "-h", str(host_key)]
    if verbose:
        print(f"[+] Starting sshd: {' '.join(sshd_cmd)}")

    server = start_process(
        sshd_cmd,
        "sshd",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,
    )
    server_ready = threading.Event()
    t_srv = threading.Thread(
        target=ssh_reader_thread,
        args=(
            server.stderr,
            logs_dir / "sshd_stderr.log",
            quantum_output["server"],
            ground_truth["server"],
            server_ready,
        ),
    )
    t_srv.daemon = True
    t_srv.start()

    # Wait for server
    if verbose:
        print("[+] Waiting for sshd...")
    for _ in range(50):
        if server.poll() is not None:
            break
        if server_ready.is_set():
            break
        time.sleep(0.1)
    if server.poll() is not None:
        t_srv.join(timeout=1)
        if capture is not None:
            stop_capture(capture, capture_threads)
        detail = (logs_dir / "sshd_stderr.log").read_text(errors="replace")
        raise RuntimeError(f"sshd exited before becoming ready:\n{detail}")
    if not server_ready.is_set():
        terminate(server, "sshd")
        if capture is not None:
            stop_capture(capture, capture_threads)
        raise RuntimeError("sshd did not report readiness")
    time.sleep(0.3)

    proxy_ready = threading.Event()
    proxy_stop = threading.Event()
    proxy_errors = []
    t_proxy = threading.Thread(
        target=record_ssh_streams,
        args=(
            port,
            backend_port,
            client_stream_file,
            server_stream_file,
            proxy_ready,
            proxy_stop,
            proxy_errors,
        ),
        daemon=True,
    )
    t_proxy.start()
    if not proxy_ready.wait(timeout=3) or proxy_errors:
        terminate(server, "sshd")
        if capture is not None:
            stop_capture(capture, capture_threads)
        raise RuntimeError(f"SSH recording relay failed: {proxy_errors}")

    # Start ssh client
    ssh_cmd = [
        str(ssh),
        "-v",
        "-v",
        "-v",
        "-F",
        "/dev/null",  # Ignore user config
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        f"IdentityFile={user_key}",
        "-o",
        "BatchMode=yes",
        "-o",
        "KexAlgorithms=curve25519-sha256",
        "-o",
        "Ciphers=chacha20-poly1305@openssh.com",
        "-o",
        "HostKeyAlgorithms=ssh-ed25519",
    ]
    if rekey_limit:
        ssh_cmd.extend(["-o", f"RekeyLimit={rekey_limit}"])
    if payload_bytes:
        remote_command = f"head -c {payload_bytes} /dev/zero; echo SSH_TEST_OK"
    else:
        remote_command = "echo SSH_TEST_OK; exit 0"
    ssh_cmd.extend(
        [
            "-p",
            str(port),
            f"{os.getenv('USER', 'test')}@127.0.0.1",
            remote_command,
        ]
    )
    if verbose:
        print(f"[+] Starting ssh: {' '.join(ssh_cmd)}")

    application_output = logs_dir / "application_stdout.bin"
    application_handle = application_output.open("wb")
    client = start_process(
        ssh_cmd,
        "ssh",
        stdout=application_handle,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,
    )
    t_cli = threading.Thread(
        target=ssh_reader_thread,
        args=(
            client.stderr,
            logs_dir / "ssh_stderr.log",
            quantum_output["client"],
            ground_truth["client"],
        ),
    )
    t_cli.daemon = True
    t_cli.start()

    # Wait for client
    client_error = None
    try:
        timeout = max(10, payload_bytes // 1_000_000 * 5)
        returncode = client.wait(timeout=timeout)
        application_handle.close()
        stdout = application_output.read_bytes()
        t_cli.join(timeout=1)
        if verbose and stdout:
            print(
                f"[+] Client output: {len(stdout)} bytes; "
                f"marker_present={b'SSH_TEST_OK' in stdout}"
            )
        if returncode != 0 or b"SSH_TEST_OK" not in stdout:
            detail = (logs_dir / "ssh_stderr.log").read_text(errors="replace")
            client_error = RuntimeError(
                f"SSH client failed (exit {returncode}); output={stdout!r}\n{detail}"
            )
    except subprocess.TimeoutExpired:
        if verbose:
            print("[!] Client timeout")
        terminate(client, "ssh")
        application_handle.close()
        client_error = RuntimeError("SSH client timed out")

    time.sleep(0.5)
    terminate(server, "sshd")
    t_proxy.join(timeout=2)
    if t_proxy.is_alive():
        proxy_stop.set()
        t_proxy.join(timeout=1)
    if capture is not None:
        stop_capture(capture, capture_threads)
    t_srv.join(timeout=1)
    t_cli.join(timeout=1)
    if proxy_errors:
        raise RuntimeError(f"SSH recording relay failed: {proxy_errors}")
    if client_error is not None:
        raise client_error

    client_oracle = quantum_output["client"]
    recoveries = _quantum_recoveries(client_oracle)
    if not recoveries:
        raise RuntimeError("patched SSH client did not emit the quantum-oracle hook")

    oracle_file = keys_dir / "simulated_quantum_output.json"
    with oracle_file.open("w") as f:
        json.dump(
            {
                "model": "future-recovery-output",
                "algorithm": "curve25519-sha256",
                "recovered_side": "client",
                "ephemeral_private": recoveries[0]["ephemeral_private"],
                "ephemeral_public_check": recoveries[0]["ephemeral_public"],
                "recoveries": recoveries,
            },
            f,
            indent=2,
        )

    truth_file = keys_dir / "ssh_ground_truth.json"
    with truth_file.open("w") as f:
        json.dump(ground_truth, f, indent=2)

    repo_root = Path(__file__).resolve().parents[2]
    implementation_paths = [
        repo_root / "patches" / "openssh-9.9p2-keylog.patch",
        Path(__file__).resolve(),
        repo_root / "capture" / "common.py",
        repo_root / "decryptor" / "ssh" / "derive_ssh.py",
        repo_root / "decryptor" / "ssh" / "oracle.py",
        repo_root / "decryptor" / "core" / "ssh_crypto.py",
        repo_root / "decryptor" / "io" / "pcap_parser.py",
    ]
    evidence_paths = [
        pcap_file,
        client_stream_file,
        server_stream_file,
        oracle_file,
        truth_file,
        sshd_config,
        host_key,
        host_key.with_name(host_key.name + ".pub"),
        user_key,
        user_key.with_name(user_key.name + ".pub"),
        auth_keys,
        logs_dir / "ssh_stderr.log",
        logs_dir / "sshd_stderr.log",
        logs_dir / "tshark_stdout.log",
        logs_dir / "tshark_stderr.log",
        application_output,
    ]
    manifest_file = write_run_manifest(
        capture_root,
        experiment={
            "protocol": "SSH-2",
            "openssh_target": "9.9p2",
            "kex": "curve25519-sha256",
            "host_key": "ssh-ed25519",
            "cipher_c2s": "chacha20-poly1305@openssh.com",
            "cipher_s2c": "chacha20-poly1305@openssh.com",
            "network": "IPv4 loopback via transparent recording relay",
            "public_port": port,
            "backend_port": backend_port,
            "rekey_limit": rekey_limit,
            "payload_bytes": payload_bytes,
            "pcap_available": pcap_file.exists() and pcap_file.stat().st_size > 0,
            "pcap_error": capture_error,
        },
        commands={"sshd": sshd_cmd, "ssh": ssh_cmd},
        binaries=[ssh, sshd, ssh_keygen],
        implementation_paths=implementation_paths,
        artifact_paths=evidence_paths,
        attack_inputs=[
            "pcap/ssh_session.pcapng or both direction-separated wire streams",
            "keys/simulated_quantum_output.json",
        ],
        excluded_from_attack_inputs=[
            "keys/ssh_ground_truth.json",
            "keys/ssh_host_ed25519_key and public key",
            "keys/user_ed25519_key, public key, and authorized_keys",
            "logs/application_stdout.bin",
            "logs/ssh_stderr.log and logs/sshd_stderr.log",
        ],
        recovery=recovery_spec("ssh", None, port),
        schema="hndl-ssh-run-manifest-v1",
        software_extra={
            "ssh_version": version_output([str(ssh), "-V"]),
            "sshd_version": version_output([str(sshd), "-V"]),
        },
    )

    # Report
    print("SSH capture complete.")
    if pcap_file.exists() and pcap_file.stat().st_size:
        print(f"- PCAP: {pcap_file}")
    else:
        print("- PCAP: unavailable on this host")
    print(f"- Client-to-server wire stream: {client_stream_file}")
    print(f"- Server-to-client wire stream: {server_stream_file}")
    print(f"- Simulated quantum output: {oracle_file}")
    print(f"- Comparison-only ground truth: {truth_file}")
    print(f"- Reproduction manifest: {manifest_file}")
    print(f"- Host key: {host_key}")
    print(f"- User key: {user_key}")

    return {
        "mode": "ssh",
        "pcap": str(pcap_file),
        "client_to_server_stream": str(client_stream_file),
        "server_to_client_stream": str(server_stream_file),
        "pcap_error": capture_error,
        "simulated_quantum_output": str(oracle_file),
        "ground_truth": str(truth_file),
        "manifest": str(manifest_file),
        "host_key": str(host_key),
        "user_key": str(user_key),
        "logs": str(logs_dir),
    }
