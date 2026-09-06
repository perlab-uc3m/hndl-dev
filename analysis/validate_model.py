#!/usr/bin/env python3
"""Empirical validation of the HN-DL storage-cost model.

Runs real captures at controlled payloads for TLS 1.2, TLS 1.3, QUIC, and SSH,
then overlays measured α on the theoretical curves from cost_analysis.py.
"""

import argparse
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import numpy as np

# ---------------------------------------------------------------------------
# Repo layout
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from capture.common import (
    ensure_exec,
    check_tool,
    generate_cert_key,
    start_tshark,
    stop_tshark,
    reader_thread,
    terminate,
)
from capture.ssh.capture_ssh import (
    generate_host_key,
    generate_user_key,
    write_sshd_config,
    ssh_reader_thread,
)

# Re-use the protocol models from cost_analysis so curves are always in sync.
from analysis.cost_analysis import (
    PROTOCOLS,
    TLS12_RSA,
    TLS13_1RTT,
    QUIC_X25519,
    SSH_X25519,
)
from capture.quic.capture_quic import capture_quic
from decryptor.io import run_tshark

# ---------------------------------------------------------------------------
# Plot style (matching cost_analysis.py)
# ---------------------------------------------------------------------------
plt.rcParams["font.family"] = "Ubuntu"

_CMAP = mcolors.LinearSegmentedColormap.from_list("", ["#9fcf69", "#33acdc"])
COLOR_PALETTE = [_CMAP(x) for x in np.linspace(0, 1, 4)]

# ---------------------------------------------------------------------------
# Payload sizes to sweep (bytes of application data)
# ---------------------------------------------------------------------------
PAYLOAD_SIZES = [100, 500, 1_000, 5_000, 20_000, 100_000, 500_000, 1_000_000]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def pcap_total_bytes(pcap_path: Path, skip_pure_acks: bool = True) -> int:
    """Sum frame lengths in a pcapng, excluding pure TCP ACKs by default."""
    cmd = [
        "tshark",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-e",
        "frame.len",
        "-e",
        "tcp.len",
    ]
    result = run_tshark(cmd, pcap_path)
    if result.returncode != 0:
        raise RuntimeError(result.stderr or "tshark failed while measuring PCAP")
    total = 0
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if not parts or not parts[0].strip().isdigit():
            continue
        frame_len = int(parts[0].strip())
        tcp_len_str = parts[1].strip() if len(parts) > 1 else ""
        # tcp.len is empty for non-TCP frames; keep those
        if skip_pure_acks and tcp_len_str.isdigit() and int(tcp_len_str) == 0:
            continue
        total += frame_len
    return total


def _style_ax(ax):
    ax.grid(True, linestyle="--", which="both", color="grey", alpha=0.4)
    ax.set_axisbelow(True)
    ax.tick_params(axis="both", labelsize=14)


# ---------------------------------------------------------------------------
# Capture helpers with controlled payload
# ---------------------------------------------------------------------------


def _capture_tls_controlled(
    openssl: Path,
    tls_version: str,
    cipher: str | None,
    payload_bytes: int,
    port: int,
    verbose: bool,
    tmp_dir: Path,
) -> int:
    """Run one TLS session serving exactly `payload_bytes`, return PCAP bytes."""
    keys_dir = tmp_dir / "keys"
    logs_dir = tmp_dir / "logs"
    pcap_dir = tmp_dir / "pcap"
    for d in (keys_dir, logs_dir, pcap_dir):
        d.mkdir(parents=True, exist_ok=True)

    # Write the payload file for -HTTP mode.
    payload_file = tmp_dir / "payload.bin"
    payload_file.write_bytes(b"A" * payload_bytes)

    cert_pem = keys_dir / "cert.pem"
    key_pem = keys_dir / "key.pem"
    pcap_file = pcap_dir / "session.pcapng"
    keylog_file = keys_dir / "sslkeylog.log"

    base_env = generate_cert_key(openssl, cert_pem, key_pem, keys_dir, verbose)

    tshark, tshark_threads = start_tshark(pcap_file, "lo", port, logs_dir, verbose)

    server_cmd = [
        str(openssl),
        "s_server",
        "-accept",
        str(port),
        "-cert",
        str(cert_pem),
        "-key",
        str(key_pem),
        f"-{tls_version}",
        "-HTTP",
        "-keylogfile",
        str(keylog_file),
    ]
    if cipher:
        server_cmd += ["-cipher", cipher]
    if tls_version == "tls1_3":
        server_cmd += ["-groups", "X25519"]

    if verbose:
        print(f"  [server] {' '.join(server_cmd)}")

    eph_store = {"server": {}, "client": {}}
    server_accept_event = threading.Event()

    server = subprocess.Popen(
        server_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=False,
        preexec_fn=os.setsid,
        env=base_env,
        cwd=str(tmp_dir),
    )
    t_srv_out = threading.Thread(
        target=reader_thread,
        args=(server.stdout, logs_dir / "srv_out.log", "server", eph_store),
    )
    t_srv_err = threading.Thread(
        target=reader_thread,
        args=(
            server.stderr,
            logs_dir / "srv_err.log",
            "server",
            eph_store,
            server_accept_event,
        ),
    )
    for t in (t_srv_out, t_srv_err):
        t.daemon = True
        t.start()

    for _ in range(50):
        if server.poll() is not None:
            stop_tshark(tshark, tshark_threads)
            raise RuntimeError("TLS server exited before becoming ready")
        if server_accept_event.is_set():
            break
        time.sleep(0.1)
    if not server_accept_event.is_set():
        terminate(server, "server")
        stop_tshark(tshark, tshark_threads)
        raise RuntimeError("TLS server did not report readiness")

    # Client sends a GET for the payload file.
    client_cmd = [
        str(openssl),
        "s_client",
        "-connect",
        f"127.0.0.1:{port}",
        f"-{tls_version}",
        "-servername",
        "localhost",
        "-keylogfile",
        str(keylog_file),
        "-quiet",
    ]
    if cipher:
        client_cmd += ["-cipher", cipher]
    if tls_version == "tls1_3":
        client_cmd += ["-groups", "X25519"]

    if verbose:
        print(f"  [client] {' '.join(client_cmd)}")

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
        args=(client.stdout, logs_dir / "cli_out.log", "client", eph_store),
    )
    t_cli_err = threading.Thread(
        target=reader_thread,
        args=(client.stderr, logs_dir / "cli_err.log", "client", eph_store),
    )
    for t in (t_cli_out, t_cli_err):
        t.daemon = True
        t.start()

    # Send HTTP GET.
    try:
        http_req = (
            f"GET /{payload_file.name} HTTP/1.0\r\nHost: localhost\r\n\r\n".encode()
        )
        client.stdin.write(http_req)
        client.stdin.flush()
        client.stdin.close()
    except Exception:
        pass

    try:
        client.wait(timeout=15)
    except subprocess.TimeoutExpired:
        terminate(client, "client")
    t_cli_out.join(timeout=1)
    t_cli_err.join(timeout=1)
    if client.returncode != 0:
        terminate(server, "server")
        stop_tshark(tshark, tshark_threads)
        raise RuntimeError(f"TLS client failed with status {client.returncode}")

    time.sleep(0.5)
    terminate(server, "server")
    stop_tshark(tshark, tshark_threads)

    response = (logs_dir / "cli_out.log").read_bytes()
    if b"A" * min(32, payload_bytes) not in response:
        raise RuntimeError("TLS client did not receive the controlled payload")

    return pcap_total_bytes(pcap_file)


def _capture_ssh_controlled(
    sshd: Path,
    ssh_bin: Path,
    ssh_keygen: Path,
    payload_bytes: int,
    port: int,
    verbose: bool,
    tmp_dir: Path,
) -> int:
    """Run one SSH session transferring `payload_bytes`, return PCAP bytes."""
    keys_dir = tmp_dir / "keys"
    logs_dir = tmp_dir / "logs"
    pcap_dir = tmp_dir / "pcap"
    for d in (keys_dir, logs_dir, pcap_dir):
        d.mkdir(parents=True, exist_ok=True)

    pcap_file = pcap_dir / "session.pcapng"
    host_key = generate_host_key(ssh_keygen, keys_dir, verbose)
    user_key = generate_user_key(ssh_keygen, keys_dir, verbose)
    auth_keys = keys_dir / "authorized_keys"
    sshd_config = write_sshd_config(keys_dir / "sshd_config", host_key, auth_keys, port)

    quantum_output: dict = {"server": {}, "client": {}}
    ground_truth: dict = {"server": {}, "client": {}}
    tshark, tshark_threads = start_tshark(pcap_file, "lo", port, logs_dir, verbose)

    sshd_cmd = [str(sshd), "-D", "-d", "-f", str(sshd_config), "-h", str(host_key)]
    server = subprocess.Popen(
        sshd_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid
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

    for _ in range(50):
        if server.poll() is not None:
            break
        if server_ready.is_set():
            break
        time.sleep(0.1)
    if server.poll() is not None or not server_ready.is_set():
        terminate(server, "sshd")
        stop_tshark(tshark, tshark_threads)
        raise RuntimeError("sshd did not report readiness")
    time.sleep(0.3)

    # Stream exactly payload_bytes from server to client.
    src = "/dev/urandom" if payload_bytes <= 10_000 else "/dev/zero"
    remote_cmd = f"head -c {payload_bytes} {src}"
    ssh_cmd = [
        str(ssh_bin),
        "-F",
        "/dev/null",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        f"IdentityFile={user_key}",
        "-o",
        "BatchMode=yes",
        # Force classical kex so H matches the model.
        "-o",
        "KexAlgorithms=curve25519-sha256",
        "-p",
        str(port),
        f"{os.getenv('USER', 'test')}@127.0.0.1",
        remote_cmd,
    ]
    if verbose:
        print(f"  [ssh] {' '.join(ssh_cmd)}")

    application_output = logs_dir / "application_stdout.bin"
    application_handle = application_output.open("wb")
    client = subprocess.Popen(
        ssh_cmd,
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

    try:
        client.wait(timeout=60)
    except subprocess.TimeoutExpired:
        terminate(client, "ssh")
    application_handle.close()
    t_cli.join(timeout=1)
    if client.returncode != 0:
        terminate(server, "sshd")
        stop_tshark(tshark, tshark_threads)
        raise RuntimeError(f"SSH client failed with status {client.returncode}")
    if application_output.stat().st_size != payload_bytes:
        terminate(server, "sshd")
        stop_tshark(tshark, tshark_threads)
        raise RuntimeError(
            f"SSH payload mismatch: got {application_output.stat().st_size}, "
            f"expected {payload_bytes}"
        )

    time.sleep(0.5)
    terminate(server, "sshd")
    stop_tshark(tshark, tshark_threads)

    return pcap_total_bytes(pcap_file)


def _capture_quic_controlled(
    openssl: Path,
    payload_bytes: int,
    port: int,
    verbose: bool,
    tmp_dir: Path,
) -> int:
    """Run one QUIC exchange with an exact response body size."""
    capture_quic(
        openssl,
        "lo",
        port,
        "X25519",
        tmp_dir,
        verbose,
        response_size=payload_bytes,
    )
    return pcap_total_bytes(tmp_dir / "pcap/quic.pcapng")


# ---------------------------------------------------------------------------
# Per-protocol experimental sweep
# ---------------------------------------------------------------------------

ProtocolSpec = tuple  # (label, display_name, color, marker, capture_fn)


def measure_tls12_rsa(openssl, payload_sizes, port, verbose, tmp_root):
    results = []
    for p in payload_sizes:
        tmp = tmp_root / f"tls12_rsa_{p}"
        tmp.mkdir(parents=True, exist_ok=True)
        print(f"  TLS 1.2 RSA  payload={p:>9,} B ...", end=" ", flush=True)
        try:
            total = _capture_tls_controlled(
                openssl, "tls1_2", "AES128-SHA", p, port, verbose, tmp
            )
            alpha = total / p
            results.append((p, total, alpha))
            print(f"total={total:>8,} B  α={alpha:.3f}")
        except Exception as e:
            print(f"FAILED: {e}")
    return results


def measure_tls13_1rtt(openssl, payload_sizes, port, verbose, tmp_root):
    results = []
    for p in payload_sizes:
        tmp = tmp_root / f"tls13_1rtt_{p}"
        tmp.mkdir(parents=True, exist_ok=True)
        print(f"  TLS 1.3 1RTT payload={p:>9,} B ...", end=" ", flush=True)
        try:
            total = _capture_tls_controlled(
                openssl, "tls1_3", None, p, port, verbose, tmp
            )
            alpha = total / p
            results.append((p, total, alpha))
            print(f"total={total:>8,} B  α={alpha:.3f}")
        except Exception as e:
            print(f"FAILED: {e}")
    return results


def measure_ssh(sshd, ssh_bin, ssh_keygen, payload_sizes, port, verbose, tmp_root):
    results = []
    for p in payload_sizes:
        tmp = tmp_root / f"ssh_{p}"
        tmp.mkdir(parents=True, exist_ok=True)
        print(f"  SSH X25519   payload={p:>9,} B ...", end=" ", flush=True)
        try:
            total = _capture_ssh_controlled(
                sshd, ssh_bin, ssh_keygen, p, port, verbose, tmp
            )
            alpha = total / p
            results.append((p, total, alpha))
            print(f"total={total:>8,} B  α={alpha:.3f}")
        except Exception as e:
            print(f"FAILED: {e}")
    return results


def measure_quic(openssl, payload_sizes, port, verbose, tmp_root):
    results = []
    for payload in payload_sizes:
        tmp = tmp_root / f"quic_x25519_{payload}"
        tmp.mkdir(parents=True, exist_ok=True)
        print(f"  QUIC X25519 payload={payload:>9,} B ...", end=" ", flush=True)
        try:
            total = _capture_quic_controlled(openssl, payload, port, verbose, tmp)
            alpha = total / payload
            results.append((payload, total, alpha))
            print(f"total={total:>8,} B  α={alpha:.3f}")
        except Exception as exc:
            print(f"FAILED: {exc}")
    return results


# ---------------------------------------------------------------------------
# Plot
# ---------------------------------------------------------------------------


def plot_validation(
    empirical: dict,  # {label: [(payload_B, total_B, alpha), ...]}
    protocols,
    outdir: Path,
):
    payloads = np.logspace(2, 8, 300)

    fig, ax = plt.subplots(figsize=(11, 6))
    _style_ax(ax)

    # Theoretical curves
    for p in protocols:
        alphas = [p.alpha(x) for x in payloads]
        ax.plot(
            payloads,
            alphas,
            label=p.name,
            color=p.color,
            linestyle=p.linestyle,
            linewidth=2.0,
        )

    # Reference line
    ax.axhline(y=1, color="grey", linewidth=0.8, linestyle=":", alpha=0.6)
    ax.text(
        payloads[-1] * 0.6,
        1.12,
        r"$\alpha = 1$ (no overhead)",
        fontsize=13,
        color="grey",
        ha="right",
    )

    # Empirical scatter points (one marker style per protocol)
    marker_map = {
        TLS12_RSA.label: ("o", TLS12_RSA.color),
        TLS13_1RTT.label: ("D", TLS13_1RTT.color),
        QUIC_X25519.label: ("v", QUIC_X25519.color),
        SSH_X25519.label: ("^", SSH_X25519.color),
    }
    proto_by_label = {p.label: p for p in protocols}

    for label, pts in empirical.items():
        if not pts:
            continue
        xs = [x[0] for x in pts]
        ys = [x[2] for x in pts]
        mk, col = marker_map.get(label, ("x", "black"))
        ax.scatter(
            xs,
            ys,
            marker=mk,
            color=col,
            s=60,
            zorder=5,
            edgecolors="black",
            linewidths=0.6,
            label=f"{proto_by_label[label].name} (measured)",
        )

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel(
        "Application payload per session (bytes)", fontweight="bold", fontsize=15
    )
    ax.set_ylabel(
        r"Protocol overhead ratio $\alpha$", fontweight="bold", fontsize=15, labelpad=15
    )
    ax.set_title(
        r"Protocol overhead ratio $\alpha$: theory vs. experiment",
        fontweight="bold",
        fontsize=19,
        pad=15,
    )
    ax.set_xlim(payloads[0], payloads[-1])
    ax.set_ylim(0.9, 300)

    # Two-column legend: curves first, then scatter
    handles, labels_leg = ax.get_legend_handles_labels()
    ax.legend(
        handles,
        labels_leg,
        fontsize=13,
        loc="upper right",
        framealpha=0.9,
        edgecolor="black",
        ncol=2,
    )

    fig.tight_layout()
    outpath = outdir / "model_validation.pdf"
    fig.savefig(outpath, dpi=300, bbox_inches="tight")
    print(f"\n[+] Saved: {outpath}")
    plt.close(fig)
    return outpath


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------


def print_summary(empirical, protocols):
    proto_by_label = {p.label: p for p in protocols}
    print("\n" + "=" * 70)
    print("Validation summary  (α_measured vs α_model, Δ = measured − model)")
    print("=" * 70)
    header = (
        f"{'Protocol':<22} {'Payload':>10}  {'α_model':>8}  {'α_meas':>8}  {'Δ':>8}"
    )
    print(header)
    print("-" * 70)
    for label, pts in empirical.items():
        p = proto_by_label.get(label)
        if p is None or not pts:
            continue
        for payload, total, alpha_m in pts:
            alpha_th = p.alpha(payload)
            delta = alpha_m - alpha_th
            print(
                f"{p.name:<22} {payload:>10,}  {alpha_th:>8.3f}  {alpha_m:>8.3f}  {delta:>+8.3f}"
            )
        print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="HN-DL storage model validation")
    parser.add_argument("--outdir", default="paper/figures")
    parser.add_argument(
        "--tmpdir", default=None, help="Where to store captures (default: system temp)"
    )
    parser.add_argument("--port", type=int, default=44443)
    parser.add_argument("--ssh-port", type=int, default=44444)
    parser.add_argument("--quic-port", type=int, default=44445)
    parser.add_argument("--openssl", default=None, help="Path to openssl binary")
    parser.add_argument(
        "--openssh-dir", default=None, help="Path to OpenSSH install dir"
    )
    parser.add_argument(
        "--protocols",
        nargs="+",
        choices=["tls12_rsa", "tls13_1rtt", "quic_x25519", "ssh_x25519"],
        default=["tls12_rsa", "tls13_1rtt", "quic_x25519", "ssh_x25519"],
        help="Which protocols to measure (default: all)",
    )
    parser.add_argument(
        "--payloads",
        nargs="+",
        type=int,
        default=None,
        help="Override payload sizes in bytes",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    os.chdir(REPO_ROOT)
    check_tool("tshark")
    check_tool("capinfos")

    openssl_path = (
        Path(args.openssl) if args.openssl else REPO_ROOT / "openssl/.local/bin/openssl"
    )
    openssh_dir = (
        Path(args.openssh_dir) if args.openssh_dir else REPO_ROOT / "openssh/.local"
    )
    outdir = REPO_ROOT / args.outdir
    outdir.mkdir(parents=True, exist_ok=True)

    ensure_exec(openssl_path, "openssl")

    payload_sizes = args.payloads or PAYLOAD_SIZES

    if args.tmpdir:
        tmp_root = Path(args.tmpdir)
        tmp_root.mkdir(parents=True, exist_ok=True)
        cleanup = False
    else:
        _tmp_obj = tempfile.TemporaryDirectory(prefix="hndl_val_")
        tmp_root = Path(_tmp_obj.name)
        cleanup = True

    empirical: dict[str, list] = {}

    try:
        if "tls12_rsa" in args.protocols:
            print("\n[1/4] TLS 1.2 RSA measurements")
            empirical[TLS12_RSA.label] = measure_tls12_rsa(
                openssl_path, payload_sizes, args.port, args.verbose, tmp_root
            )

        if "tls13_1rtt" in args.protocols:
            print("\n[2/4] TLS 1.3 1-RTT measurements")
            empirical[TLS13_1RTT.label] = measure_tls13_1rtt(
                openssl_path, payload_sizes, args.port, args.verbose, tmp_root
            )

        if "ssh_x25519" in args.protocols:
            sshd = openssh_dir / "sbin/sshd"
            ssh_bin = openssh_dir / "bin/ssh"
            ssh_keygen = openssh_dir / "bin/ssh-keygen"
            for b, n in [(sshd, "sshd"), (ssh_bin, "ssh"), (ssh_keygen, "ssh-keygen")]:
                ensure_exec(b, n)
            print("\n[3/4] SSH X25519 measurements")
            empirical[SSH_X25519.label] = measure_ssh(
                sshd,
                ssh_bin,
                ssh_keygen,
                payload_sizes,
                args.ssh_port,
                args.verbose,
                tmp_root,
            )

        if "quic_x25519" in args.protocols:
            print("\n[4/4] QUIC X25519 measurements")
            empirical[QUIC_X25519.label] = measure_quic(
                openssl_path,
                payload_sizes,
                args.quic_port,
                args.verbose,
                tmp_root,
            )

    finally:
        if cleanup:
            try:
                _tmp_obj.cleanup()
            except Exception:
                pass

    print_summary(empirical, PROTOCOLS)
    plot_validation(empirical, PROTOCOLS, outdir)


if __name__ == "__main__":
    main()
