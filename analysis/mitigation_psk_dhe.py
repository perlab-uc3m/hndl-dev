#!/usr/bin/env python3
"""Experiment C — TLS 1.3 PSK-DHE session rotation mitigation.

Measures per-connection overhead of PSK-DHE resumption and models
the resulting α inflation as a function of rotation interval R.
"""

import argparse
import csv
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
from decryptor.io import run_tshark
from analysis.common import pcap_total_bytes

# ---------------------------------------------------------------------------
# Plot style
# ---------------------------------------------------------------------------
plt.rcParams["font.family"] = "Ubuntu"
plt.rcParams["pdf.fonttype"] = 42
plt.rcParams["ps.fonttype"] = 42

# ---------------------------------------------------------------------------
# Experiment parameters
# ---------------------------------------------------------------------------

N_RESUMPTIONS = 10
N_TRIALS = 3

# Rotation intervals for the α plot
ROTATION_INTERVALS = [
    ("10K", 10_000),
    ("100K", 100_000),
    ("1M", 1_000_000),
    ("None", 0),
]

TLS_PORT = 44452

# TLS 1.3 data-transfer constants
TLS13_REC_HDR = 5
TLS13_AEAD_TAG = 16
TLS13_CONTENT_TYPE = 1
TLS13_MAX_RECORD = 16384
L234_OVERHEAD = 54

# Payload sweep for α plot
PAYLOAD_SIZES = [
    100,
    500,
    1_000,
    5_000,
    10_000,
    50_000,
    100_000,
    500_000,
    1_000_000,
    5_000_000,
]

# Rotation data-transfer experiment: (R, P) sweep for validating E = ceil(P/R).
ROTATION_INTERVALS_EXP = [
    ("10K", 10_000),
    ("100K", 100_000),
    ("1M", 1_000_000),
]
ROTATION_PAYLOAD_EXP = [10_000, 50_000, 100_000, 500_000, 1_000_000]


# ---------------------------------------------------------------------------
# PCAP helpers
# ---------------------------------------------------------------------------


def count_client_hellos(pcap_path: Path, keylog_path: Path) -> int:
    """Count ClientHello messages in a TLS 1.3 PCAP."""
    cmd = [
        "tshark",
        "-r",
        str(pcap_path),
        "-o",
        f"tls.keylog_file:{keylog_path}",
        "-Y",
        "tls.handshake.type==1",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]
    result = run_tshark(cmd, pcap_path, (keylog_path,))
    if result.returncode != 0:
        raise RuntimeError(result.stderr or "tshark failed while counting ClientHello")
    lines = result.stdout.strip().splitlines() if result.stdout.strip() else []
    return len(lines)


def count_handshakes_with_extension(
    pcap_path: Path, handshake_type: int, extension_type: int
) -> int:
    """Count hello messages carrying one named extension."""
    cmd = [
        "tshark",
        "-r",
        str(pcap_path),
        "-Y",
        f"tls.handshake.type=={handshake_type} && "
        f"tls.handshake.extension.type=={extension_type}",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]
    result = run_tshark(cmd, pcap_path)
    if result.returncode != 0:
        raise RuntimeError(result.stderr or "tshark failed while checking handshake")
    return len([line for line in result.stdout.splitlines() if line.strip()])


# ---------------------------------------------------------------------------
# Measure handshake overhead: initial + resumed connections
# ---------------------------------------------------------------------------


def measure_handshake_overhead(
    openssl: Path,
    port: int,
    n_resumptions: int,
    verbose: bool,
    tmp_dir: Path,
) -> tuple[int, int, int]:
    """1 initial + n_resumptions PSK-DHE connections (no data transfer).

    Returns (initial_hs_bytes, total_resumed_bytes, client_hello_count).
    """
    keys_dir = tmp_dir / "keys"
    logs_dir = tmp_dir / "logs"
    pcap_dir = tmp_dir / "pcap"
    sess_dir = tmp_dir / "sessions"
    for d in (keys_dir, logs_dir, pcap_dir, sess_dir):
        d.mkdir(parents=True, exist_ok=True)

    cert_pem = keys_dir / "cert.pem"
    key_pem = keys_dir / "key.pem"
    keylog_file = keys_dir / "sslkeylog.log"

    # We'll capture initial and resumed handshakes separately
    pcap_init = pcap_dir / "initial.pcapng"
    pcap_resum = pcap_dir / "resumed.pcapng"

    base_env = generate_cert_key(openssl, cert_pem, key_pem, keys_dir, verbose)

    # --- Start server (stays alive for all connections) ---
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
        "X25519",
        "-www",
        "-keylogfile",
        str(keylog_file),
    ]

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
    )
    t_out = threading.Thread(
        target=reader_thread,
        args=(server.stdout, logs_dir / "srv_out.log", "server", eph_store),
    )
    t_err = threading.Thread(
        target=reader_thread,
        args=(
            server.stderr,
            logs_dir / "srv_err.log",
            "server",
            eph_store,
            server_accept_event,
        ),
    )
    for t in (t_out, t_err):
        t.daemon = True
        t.start()

    for _ in range(50):
        if server.poll() is not None:
            terminate(server, "server")
            raise RuntimeError("TLS server exited before becoming ready")
        if server_accept_event.is_set():
            break
        time.sleep(0.1)
    if not server_accept_event.is_set():
        terminate(server, "server")
        raise RuntimeError("TLS server did not report readiness")

    sess_file = sess_dir / "session.pem"

    # --- Phase 1: Capture initial handshake ---
    tshark_init, tshark_init_threads = start_tshark(
        pcap_init, "lo", port, logs_dir, verbose
    )

    _do_connection(
        openssl,
        port,
        keylog_file,
        base_env,
        logs_dir,
        sess_in=None,
        sess_out=sess_file,
        label="initial",
        verbose=verbose,
    )

    time.sleep(0.5)
    stop_tshark(tshark_init, tshark_init_threads)

    init_bytes = pcap_total_bytes(pcap_init)

    # --- Phase 2: Capture resumed handshakes ---
    tshark_resum, tshark_resum_threads = start_tshark(
        pcap_resum, "lo", port, logs_dir, verbose
    )

    for i in range(n_resumptions):
        sess_in = sess_file
        sess_out_i = sess_dir / f"session_{i}.pem"
        _do_connection(
            openssl,
            port,
            keylog_file,
            base_env,
            logs_dir,
            sess_in=sess_in,
            sess_out=sess_out_i,
            label=f"resumed-{i}",
            verbose=verbose,
        )
        sess_file = sess_out_i
        time.sleep(0.2)

    time.sleep(0.5)
    stop_tshark(tshark_resum, tshark_resum_threads)

    resum_total = pcap_total_bytes(pcap_resum)

    resumed_psk = count_handshakes_with_extension(pcap_resum, 1, 41)
    resumed_dhe = count_handshakes_with_extension(pcap_resum, 2, 51)
    if resumed_psk != n_resumptions or resumed_dhe != n_resumptions:
        terminate(server, "server")
        raise RuntimeError(
            "resumption validation failed: "
            f"PSK ClientHellos={resumed_psk}, DHE ServerHellos={resumed_dhe}, "
            f"expected={n_resumptions}"
        )

    terminate(server, "server")

    ch_count = count_client_hellos(pcap_init, keylog_file) + count_client_hellos(
        pcap_resum, keylog_file
    )

    return init_bytes, resum_total, ch_count


def _do_connection(
    openssl: Path,
    port: int,
    keylog: Path,
    env: dict,
    logs_dir: Path,
    sess_in: Path | None,
    sess_out: Path | None,
    label: str,
    verbose: bool,
):
    """One s_client connection: handshake + minimal data exchange + close."""
    client_cmd = [
        str(openssl),
        "s_client",
        "-connect",
        f"127.0.0.1:{port}",
        "-tls1_3",
        "-groups",
        "X25519",
        "-servername",
        "localhost",
        "-keylogfile",
        str(keylog),
        "-quiet",
    ]
    if sess_in and sess_in.exists():
        client_cmd += ["-sess_in", str(sess_in)]
    if sess_out:
        client_cmd += ["-sess_out", str(sess_out)]

    if verbose:
        print(f"    [{label}] {' '.join(client_cmd)}")

    eph = {"server": {}, "client": {}}
    client = subprocess.Popen(
        client_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=False,
        preexec_fn=os.setsid,
        env=env,
    )
    t_co = threading.Thread(
        target=reader_thread,
        args=(client.stdout, logs_dir / f"cli_out_{label}.log", "client", eph),
    )
    t_ce = threading.Thread(
        target=reader_thread,
        args=(client.stderr, logs_dir / f"cli_err_{label}.log", "client", eph),
    )
    for t in (t_co, t_ce):
        t.daemon = True
        t.start()

    # Send minimal request and close
    try:
        client.stdin.write(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        client.stdin.flush()
        client.stdin.close()
    except Exception:
        pass

    try:
        client.wait(timeout=10)
    except subprocess.TimeoutExpired:
        terminate(client, f"s_client[{label}]")
    t_co.join(timeout=1)
    t_ce.join(timeout=1)
    if client.returncode != 0:
        raise RuntimeError(f"s_client[{label}] failed with status {client.returncode}")
    if sess_out and (not sess_out.exists() or sess_out.stat().st_size == 0):
        raise RuntimeError(f"s_client[{label}] did not save a session ticket")


# ---------------------------------------------------------------------------
# Rotation data-transfer experiment
# ---------------------------------------------------------------------------


def _do_data_connection(
    openssl: Path,
    port: int,
    keylog: Path,
    env: dict,
    logs_dir: Path,
    filename: str,
    sess_in: Path | None,
    sess_out: Path | None,
    label: str,
    verbose: bool,
    expected_bytes: int,
):
    """One s_client connection: TLS 1.3 handshake + fetch a file via -WWW + close."""
    client_cmd = [
        str(openssl),
        "s_client",
        "-connect",
        f"127.0.0.1:{port}",
        "-tls1_3",
        "-groups",
        "X25519",
        "-servername",
        "localhost",
        "-keylogfile",
        str(keylog),
        "-quiet",
    ]
    if sess_in and sess_in.exists():
        client_cmd += ["-sess_in", str(sess_in)]
    if sess_out:
        client_cmd += ["-sess_out", str(sess_out)]

    if verbose:
        print(f"    [{label}] {' '.join(client_cmd)}")

    eph = {"server": {}, "client": {}}
    client = subprocess.Popen(
        client_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=False,
        preexec_fn=os.setsid,
        env=env,
    )
    t_co = threading.Thread(
        target=reader_thread,
        args=(client.stdout, logs_dir / f"cli_out_{label}.log", "client", eph),
    )
    t_ce = threading.Thread(
        target=reader_thread,
        args=(client.stderr, logs_dir / f"cli_err_{label}.log", "client", eph),
    )
    for t in (t_co, t_ce):
        t.daemon = True
        t.start()

    try:
        request = f"GET /{filename} HTTP/1.0\r\nHost: localhost\r\n\r\n"
        client.stdin.write(request.encode())
        client.stdin.flush()
        client.stdin.close()
    except Exception:
        pass

    try:
        client.wait(timeout=60)
    except subprocess.TimeoutExpired:
        terminate(client, f"s_client[{label}]")
    t_co.join(timeout=1)
    t_ce.join(timeout=1)
    if client.returncode != 0:
        raise RuntimeError(f"s_client[{label}] failed with status {client.returncode}")
    response_path = logs_dir / f"cli_out_{label}.log"
    if not response_path.exists() or response_path.stat().st_size < expected_bytes:
        raise RuntimeError(f"s_client[{label}] received an incomplete response")
    if sess_out and (not sess_out.exists() or sess_out.stat().st_size == 0):
        raise RuntimeError(f"s_client[{label}] did not save a session ticket")


def capture_rotated_transfer(
    openssl: Path,
    port: int,
    payload_bytes: int,
    rotation_bytes: int,
    verbose: bool,
    tmp_dir: Path,
) -> tuple[int, int]:
    """Run E = ceil(P/R) sequential PSK-DHE connections, each fetching R bytes.

    Returns (pcap_total_bytes, E_measured).
    """
    E_expected = max(1, int(np.ceil(payload_bytes / rotation_bytes)))

    keys_dir = tmp_dir / "keys"
    logs_dir = tmp_dir / "logs"
    pcap_dir = tmp_dir / "pcap"
    sess_dir = tmp_dir / "sessions"
    www_dir = tmp_dir / "www"
    for d in (keys_dir, logs_dir, pcap_dir, sess_dir, www_dir):
        d.mkdir(parents=True, exist_ok=True)

    cert_pem = keys_dir / "cert.pem"
    key_pem = keys_dir / "key.pem"
    keylog_file = keys_dir / "sslkeylog.log"
    pcap_file = pcap_dir / "rotation.pcapng"

    base_env = generate_cert_key(openssl, cert_pem, key_pem, keys_dir, verbose)

    # Start TLS server in -WWW mode
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
        "X25519",
        "-keylogfile",
        str(keylog_file),
        "-WWW",
    ]

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
        cwd=str(www_dir),
    )
    t_out = threading.Thread(
        target=reader_thread,
        args=(server.stdout, logs_dir / "srv_out.log", "server", eph_store),
    )
    t_err = threading.Thread(
        target=reader_thread,
        args=(
            server.stderr,
            logs_dir / "srv_err.log",
            "server",
            eph_store,
            server_accept_event,
        ),
    )
    for t in (t_out, t_err):
        t.daemon = True
        t.start()

    for _ in range(50):
        if server.poll() is not None:
            terminate(server, "server")
            raise RuntimeError("TLS server exited before becoming ready")
        if server_accept_event.is_set():
            break
        time.sleep(0.1)
    if not server_accept_event.is_set():
        terminate(server, "server")
        raise RuntimeError("TLS server did not report readiness")
    time.sleep(0.3)

    tshark, tshark_threads = start_tshark(pcap_file, "lo", port, logs_dir, verbose)
    time.sleep(0.5)

    sess_file = None
    for i in range(E_expected):
        chunk_bytes = min(rotation_bytes, payload_bytes - i * rotation_bytes)
        filename = f"data_{i}.bin"
        (www_dir / filename).write_bytes(b"\x00" * chunk_bytes)
        sess_out = sess_dir / f"session_{i}.pem"
        _do_data_connection(
            openssl,
            port,
            keylog_file,
            base_env,
            logs_dir,
            filename=filename,
            sess_in=sess_file,
            sess_out=sess_out,
            label=f"rot-{i}",
            verbose=verbose,
            expected_bytes=chunk_bytes,
        )
        sess_file = sess_out
        time.sleep(0.3)

    time.sleep(0.5)
    stop_tshark(tshark, tshark_threads)
    terminate(server, "server")

    total_bytes = pcap_total_bytes(pcap_file)
    E_measured = count_client_hellos(pcap_file, keylog_file)
    psk_resumptions = count_handshakes_with_extension(pcap_file, 1, 41)
    dhe_handshakes = count_handshakes_with_extension(pcap_file, 2, 51)
    if psk_resumptions != max(0, E_expected - 1) or dhe_handshakes != E_expected:
        raise RuntimeError(
            "rotation was not an initial handshake followed by PSK-DHE: "
            f"PSK resumptions={psk_resumptions}, DHE handshakes={dhe_handshakes}"
        )

    return total_bytes, E_measured


# ---------------------------------------------------------------------------
# Analytical model
# ---------------------------------------------------------------------------


def data_transfer_bytes(plaintext: float) -> float:
    """TLS 1.3 application-data overhead (wire bytes for data portion only)."""
    if plaintext <= 0:
        return 0
    max_payload = TLS13_MAX_RECORD - TLS13_CONTENT_TYPE
    n_records = max(1, int(np.ceil(plaintext / max_payload)))
    p_per_rec = plaintext / n_records
    inner = p_per_rec + TLS13_CONTENT_TYPE
    per_record = TLS13_REC_HDR + inner + TLS13_AEAD_TAG + L234_OVERHEAD
    return n_records * per_record


def alpha_psk_dhe_model(
    plaintext: float, rotation_bytes: int, h_init: float, h_resum: float
) -> float:
    """Analytical α for TLS 1.3 with PSK-DHE rotation."""
    if plaintext <= 0:
        return float("inf")

    if rotation_bytes <= 0:
        e = 1
    else:
        e = max(1, int(np.ceil(plaintext / rotation_bytes)))

    hs_bytes = h_init + (e - 1) * h_resum
    data_bytes = data_transfer_bytes(plaintext)
    return (hs_bytes + data_bytes) / plaintext


# ---------------------------------------------------------------------------
# Plot
# ---------------------------------------------------------------------------


def _style_ax(ax):
    ax.grid(True, linestyle="--", which="both", color="grey", alpha=0.4)
    ax.set_axisbelow(True)
    ax.tick_params(axis="both", labelsize=14)


_CMAP = mcolors.LinearSegmentedColormap.from_list("", ["#9fcf69", "#33acdc"])
ROT_COLORS = {
    10_000: _CMAP(0.0),
    100_000: _CMAP(0.33),
    1_000_000: _CMAP(0.66),
    0: "#888888",
}


def plot_psk_dhe(h_init, h_resum, outdir: Path, rot_results=None):
    """Two-panel figure: α(P) and E(P) for PSK-DHE rotation."""
    payloads = np.logspace(1.5, 7, 400)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    _style_ax(ax1)
    _style_ax(ax2)

    # --- Left: α ---
    for rot_str, rot_bytes in ROTATION_INTERVALS:
        label = f"Rotate every {rot_str}" if rot_bytes > 0 else "No rotation (baseline)"
        alphas = [alpha_psk_dhe_model(x, rot_bytes, h_init, h_resum) for x in payloads]
        ls = "-" if rot_bytes > 0 else "--"
        ax1.plot(
            payloads,
            alphas,
            label=label,
            color=ROT_COLORS[rot_bytes],
            linewidth=2.0,
            linestyle=ls,
        )

    # Reference line
    ax1.axhline(y=1, color="grey", linewidth=0.8, linestyle=":", alpha=0.6)
    ax1.text(
        payloads[-1] * 0.5, 1.08, r"$\alpha = 1$", fontsize=13, color="grey", ha="right"
    )

    # Annotate measured handshake overhead
    ax1.annotate(
        f"Measured handshake overhead:\n"
        f"  $H_{{\\mathrm{{init}}}}$ = {h_init:,.0f} B (full)\n"
        f"  $H_{{\\mathrm{{resum}}}}$ = {h_resum:,.0f} B (PSK-DHE)",
        xy=(0.03, 0.42),
        xycoords="axes fraction",
        fontsize=12,
        family="monospace",
        bbox=dict(boxstyle="round,pad=0.4", fc="#f5f5f5", ec="grey", alpha=0.9),
        verticalalignment="top",
    )

    ax1.set_xscale("log")
    ax1.set_yscale("log")
    ax1.set_xlabel(
        "Application payload per session (bytes)", fontweight="bold", fontsize=15
    )
    ax1.set_ylabel(
        r"Protocol overhead ratio $\alpha$", fontweight="bold", fontsize=15, labelpad=15
    )
    ax1.set_title(
        r"TLS 1.3 PSK-DHE rotation: effect on $\alpha$",
        fontweight="bold",
        fontsize=17,
        pad=15,
    )
    ax1.set_xlim(20, 1e7)
    ax1.set_ylim(0.9, 1000)
    ax1.legend(fontsize=13, loc="upper right", framealpha=0.9, edgecolor="black")

    # --- Right: E ---
    ROT_MARKERS = {10_000: "s", 100_000: "o", 1_000_000: "P"}

    for rot_str, rot_bytes in ROTATION_INTERVALS:
        if rot_bytes <= 0:
            ax2.axhline(
                y=1,
                color=ROT_COLORS[0],
                linewidth=2,
                linestyle="--",
                label="No rotation (E=1)",
            )
            continue
        e_vals = [max(1, int(np.ceil(x / rot_bytes))) for x in payloads]
        ax2.plot(
            payloads,
            e_vals,
            label=f"Rotate every {rot_str}",
            color=ROT_COLORS[rot_bytes],
            linewidth=2.0,
        )

    # Experimental markers on E panel
    if rot_results:
        for rot_str, rot_bytes in ROTATION_INTERVALS:
            if rot_bytes <= 0:
                continue
            pts = [
                (P, E_m) for (rs, rb, P, _, E_m, _) in rot_results if rb == rot_bytes
            ]
            if pts:
                xs, ys = zip(*pts)
                ax2.scatter(
                    xs,
                    ys,
                    marker=ROT_MARKERS.get(rot_bytes, "o"),
                    color=ROT_COLORS[rot_bytes],
                    s=55,
                    zorder=5,
                    edgecolors="black",
                    linewidths=0.5,
                )

    ax2.set_xscale("log")
    ax2.set_yscale("log")
    ax2.set_xlabel(
        "Application payload per session (bytes)", fontweight="bold", fontsize=15
    )
    ax2.set_ylabel(
        "Independent ECDHE exchanges (E)", fontweight="bold", fontsize=15, labelpad=15
    )
    ax2.set_title(
        "TLS 1.3 PSK-DHE rotation: quantum cost multiplier E",
        fontweight="bold",
        fontsize=17,
        pad=15,
    )
    ax2.set_xlim(20, 1e7)
    ax2.legend(fontsize=13, loc="upper left", framealpha=0.9, edgecolor="black")

    fig.tight_layout()
    outpath = outdir / "mitigation_psk_dhe_alpha.pdf"
    fig.savefig(outpath, dpi=300, bbox_inches="tight")
    print(f"\n[+] Saved: {outpath}")
    plt.close(fig)

    return outpath


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Experiment C: TLS 1.3 PSK-DHE session rotation mitigation"
    )
    parser.add_argument("--outdir", default="paper/figures")
    parser.add_argument("--port", type=int, default=TLS_PORT)
    parser.add_argument("--openssl", default=None)
    parser.add_argument("--trials", type=int, default=N_TRIALS)
    parser.add_argument("--resumptions", type=int, default=N_RESUMPTIONS)
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument(
        "--plot-only", action="store_true", help="Skip captures; plot from existing CSV"
    )
    parser.add_argument(
        "--no-rotation",
        action="store_true",
        help="Skip rotation data-transfer experiments",
    )
    args = parser.parse_args()

    os.chdir(REPO_ROOT)
    check_tool("tshark")

    openssl_path = (
        Path(args.openssl) if args.openssl else REPO_ROOT / "openssl/.local/bin/openssl"
    )
    outdir = REPO_ROOT / args.outdir
    outdir.mkdir(parents=True, exist_ok=True)
    csv_path = REPO_ROOT / "analysis/results/mitigation_psk_dhe.csv"

    rot_csv_path = REPO_ROOT / "analysis/results/mitigation_psk_dhe_rotation.csv"

    if args.plot_only:
        with open(csv_path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        h_init = float(rows[0]["h_init_avg"])
        h_resum = float(rows[0]["h_resum_avg"])
        rot_results = []
        if rot_csv_path.exists():
            with open(rot_csv_path) as f:
                for r in csv.DictReader(f):
                    rot_results.append(
                        (
                            r["rotation_interval"],
                            int(r["rotation_bytes"]),
                            int(r["payload_bytes"]),
                            int(r["E_expected"]),
                            int(r["E_measured"]),
                            int(r["pcap_bytes"]),
                        )
                    )
        plot_psk_dhe(h_init, h_resum, outdir, rot_results)
        return

    ensure_exec(openssl_path, "openssl")

    # --- Run measurement trials ---
    init_measurements = []
    resum_measurements = []

    for trial in range(1, args.trials + 1):
        print(f"\n{'='*60}")
        print(
            f"  Trial {trial}/{args.trials}  "
            f"({args.resumptions} resumptions per trial)"
        )
        print(f"{'='*60}")

        with tempfile.TemporaryDirectory(prefix="hndl_psk_") as tmp:
            tmp_path = Path(tmp)
            try:
                h_init, h_resum_total, ch_count = measure_handshake_overhead(
                    openssl_path, args.port, args.resumptions, args.verbose, tmp_path
                )
                h_resum_avg = h_resum_total / args.resumptions
                init_measurements.append(h_init)
                resum_measurements.append(h_resum_avg)
                print(f"  H_init     = {h_init:>6,} B")
                print(
                    f"  H_resum    = {h_resum_total:>6,} B total  "
                    f"({h_resum_avg:>6.0f} B/connection avg)"
                )
                print(f"  ClientHellos = {ch_count}")
                print(f"  E = {ch_count}  (expected {1 + args.resumptions})")
            except Exception as e:
                print(f"  FAILED: {e}")
                import traceback

                traceback.print_exc()

    if not init_measurements:
        print("\nNo successful measurements. Exiting.")
        return

    h_init_avg = np.mean(init_measurements)
    h_resum_avg = np.mean(resum_measurements)
    h_init_std = np.std(init_measurements)
    h_resum_std = np.std(resum_measurements)

    print(f"\n{'='*60}")
    print("  Handshake overhead summary")
    print(f"{'='*60}")
    print(f"  H_init  = {h_init_avg:>7.0f} +/- {h_init_std:>5.0f} B  (full handshake)")
    print(
        f"  H_resum = {h_resum_avg:>7.0f} +/- {h_resum_std:>5.0f} B  (PSK-DHE resumption)"
    )
    print(
        f"  Overhead ratio: {h_resum_avg / h_init_avg:.2f}x " f"(resumption / initial)"
    )

    # Compute α for various rotation intervals and payload sizes
    print(f"\n{'='*70}")
    print("  Projected α for PSK-DHE rotation")
    print(f"{'='*70}")
    print(
        f"{'Rotation':>12}  {'Payload':>10}  {'E':>6}  {'α':>8}  "
        f"{'α_base':>8}  {'inflation':>10}"
    )
    print(f"{'-'*70}")

    results_rows = []
    for rot_str, rot_bytes in ROTATION_INTERVALS:
        for payload in PAYLOAD_SIZES:
            if rot_bytes > 0:
                e = max(1, int(np.ceil(payload / rot_bytes)))
            else:
                e = 1
            alpha = alpha_psk_dhe_model(payload, rot_bytes, h_init_avg, h_resum_avg)
            alpha_base = alpha_psk_dhe_model(payload, 0, h_init_avg, h_resum_avg)
            inflation = alpha / alpha_base if alpha_base > 0 else float("inf")
            results_rows.append(
                {
                    "rotation_interval": rot_str,
                    "rotation_bytes": rot_bytes,
                    "payload_bytes": payload,
                    "E": e,
                    "alpha": f"{alpha:.4f}",
                    "alpha_baseline": f"{alpha_base:.4f}",
                    "inflation": f"{inflation:.3f}",
                    "h_init_avg": f"{h_init_avg:.0f}",
                    "h_resum_avg": f"{h_resum_avg:.0f}",
                }
            )
            print(
                f"{rot_str:>12}  {payload:>10,}  {e:>6}  {alpha:>8.3f}  "
                f"{alpha_base:>8.3f}  {inflation:>9.2f}×"
            )

    # Save CSV
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="") as f:
        fieldnames = [
            "rotation_interval",
            "rotation_bytes",
            "payload_bytes",
            "E",
            "alpha",
            "alpha_baseline",
            "inflation",
            "h_init_avg",
            "h_resum_avg",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results_rows)
    print(f"\n[+] CSV saved: {csv_path}")

    # Also save raw handshake measurements
    raw_csv = REPO_ROOT / "analysis/results/mitigation_psk_dhe_handshake.csv"
    with open(raw_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["trial", "h_init", "h_resum_avg"])
        for i, (hi, hr) in enumerate(zip(init_measurements, resum_measurements)):
            writer.writerow([i + 1, hi, f"{hr:.0f}"])
    print(f"[+] Raw handshake data: {raw_csv}")

    # --- Run rotation data-transfer experiments ---
    rot_results = (
        []
    )  # (rot_str, rot_bytes, payload, E_expected, E_measured, pcap_bytes)
    if not args.no_rotation:
        print(f"\n{'='*70}")
        print("  Rotation data-transfer experiments")
        print(f"{'='*70}")
        total_rot = len(ROTATION_INTERVALS_EXP) * len(ROTATION_PAYLOAD_EXP)
        rot_idx = 0
        for rot_str, rot_bytes in ROTATION_INTERVALS_EXP:
            for payload in ROTATION_PAYLOAD_EXP:
                rot_idx += 1
                E_expected = max(1, int(np.ceil(payload / rot_bytes)))
                print(
                    f"  [{rot_idx}/{total_rot}] R={rot_str}  "
                    f"P={payload:>9,}  E_exp={E_expected:>4} ...",
                    end=" ",
                    flush=True,
                )
                with tempfile.TemporaryDirectory(prefix="hndl_rot_") as tmp:
                    try:
                        pcap_bytes, E_measured = capture_rotated_transfer(
                            openssl_path,
                            args.port,
                            payload,
                            rot_bytes,
                            args.verbose,
                            Path(tmp),
                        )
                        rot_results.append(
                            (
                                rot_str,
                                rot_bytes,
                                payload,
                                E_expected,
                                E_measured,
                                pcap_bytes,
                            )
                        )
                        status = "OK" if E_measured == E_expected else "MISMATCH"
                        print(
                            f"E_meas={E_measured:>4}  pcap={pcap_bytes:>9,}  [{status}]"
                        )
                    except Exception as e:
                        print(f"FAILED: {e}")

        # Save rotation CSV
        rot_csv_path.parent.mkdir(parents=True, exist_ok=True)
        with open(rot_csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "rotation_interval",
                    "rotation_bytes",
                    "payload_bytes",
                    "E_expected",
                    "E_measured",
                    "pcap_bytes",
                ]
            )
            for row in rot_results:
                writer.writerow(row)
        print(f"\n[+] Rotation CSV saved: {rot_csv_path}")

        # Summary
        ok = all(E_m == E_e for (_, _, _, E_e, E_m, _) in rot_results)
        print(f"  All E_measured == E_expected: {ok}")

    plot_psk_dhe(h_init_avg, h_resum_avg, outdir, rot_results)


if __name__ == "__main__":
    main()
