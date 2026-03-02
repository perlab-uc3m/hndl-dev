#!/usr/bin/env python3
"""SSH capture with ephemeral key logging via patched OpenSSH."""

import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path

from ..common import terminate, tcp_port_open, start_tshark, stop_tshark

# Regex for SSH keylog output from patched OpenSSH
SSH_KEYLOG_RE = re.compile(r"SSH_KEYLOG_(\w+)=\s*([0-9a-fA-F]+)")


def ssh_reader_thread(
    pipe, logfile: Path, keylog: dict, ready_event: threading.Event = None
):
    """Read SSH process output, extract keylog entries, detect readiness."""
    logfile.parent.mkdir(parents=True, exist_ok=True)
    with logfile.open("wb") as f:
        for raw in iter(pipe.readline, b""):
            f.write(raw)
            line = raw.decode(errors="replace").rstrip()
            if ready_event and "Server listening" in line:
                ready_event.set()
            m = SSH_KEYLOG_RE.search(line)
            if m:
                keylog[m.group(1)] = m.group(2).lower()


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
    config_path: Path, host_key: Path, auth_keys: Path, port: int
) -> Path:
    """Write minimal sshd_config for testing."""
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
) -> dict:
    """Capture SSH session with ephemeral key extraction."""
    # Ensure all paths are absolute (sshd requires absolute paths)
    sshd = Path(sshd).resolve()
    ssh = Path(ssh).resolve()
    ssh_keygen = Path(ssh_keygen).resolve()
    capture_root = Path(capture_root).resolve()

    pcap_dir = capture_root / "pcap"
    logs_dir = capture_root / "logs"
    keys_dir = capture_root / "keys"
    for d in (pcap_dir, logs_dir, keys_dir):
        d.mkdir(parents=True, exist_ok=True)

    pcap_file = pcap_dir / "ssh_session.pcapng"
    host_key = generate_host_key(ssh_keygen, keys_dir, verbose)
    user_key = generate_user_key(ssh_keygen, keys_dir, verbose)
    auth_keys = keys_dir / "authorized_keys"
    sshd_config = write_sshd_config(keys_dir / "sshd_config", host_key, auth_keys, port)

    keylog = {"server": {}, "client": {}}

    if verbose:
        print(f"[+] Output dir: {capture_root}")

    # Start tshark
    tshark, tshark_threads = start_tshark(pcap_file, iface, port, logs_dir, verbose)

    # Start sshd (debug mode, no fork)
    sshd_cmd = [str(sshd), "-D", "-d", "-f", str(sshd_config), "-h", str(host_key)]
    if verbose:
        print(f"[+] Starting sshd: {' '.join(sshd_cmd)}")

    server = subprocess.Popen(
        sshd_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid
    )
    server_ready = threading.Event()
    t_srv = threading.Thread(
        target=ssh_reader_thread,
        args=(
            server.stderr,
            logs_dir / "sshd_stderr.log",
            keylog["server"],
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
        if server_ready.is_set() or tcp_port_open("127.0.0.1", port):
            break
        time.sleep(0.1)
    time.sleep(0.3)

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
        "-p",
        str(port),
        f"{os.getenv('USER', 'test')}@127.0.0.1",
        "echo SSH_TEST_OK; exit 0",
    ]
    if verbose:
        print(f"[+] Starting ssh: {' '.join(ssh_cmd)}")

    client = subprocess.Popen(
        ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid
    )
    t_cli = threading.Thread(
        target=ssh_reader_thread,
        args=(client.stderr, logs_dir / "ssh_stderr.log", keylog["client"]),
    )
    t_cli.daemon = True
    t_cli.start()

    # Wait for client
    try:
        stdout, _ = client.communicate(timeout=10)
        if verbose and stdout:
            print(f"[+] Client output: {stdout.decode(errors='replace').strip()}")
    except subprocess.TimeoutExpired:
        if verbose:
            print("[!] Client timeout")
        terminate(client, "ssh")

    time.sleep(0.5)
    terminate(server, "sshd")
    stop_tshark(tshark, tshark_threads)

    # Save keylog
    keylog_file = keys_dir / "ssh_keylog.json"
    with keylog_file.open("w") as f:
        json.dump(keylog, f, indent=2)

    # Report
    print("SSH capture complete.")
    print(f"- PCAP: {pcap_file}")
    print(f"- Keylog: {keylog_file}")
    print(f"- Host key: {host_key}")
    print(f"- User key: {user_key}")

    return {
        "mode": "ssh",
        "pcap": str(pcap_file),
        "keylog": str(keylog_file),
        "host_key": str(host_key),
        "user_key": str(user_key),
        "logs": str(logs_dir),
    }
