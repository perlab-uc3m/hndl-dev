#!/usr/bin/env python3
"""Experiment A — TLS 1.3 record padding mitigation.

Measures how TLS 1.3 record padding (RFC 8446 §5.4) inflates α.
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

PADDING_LEVELS = [0, 256, 1024, 4096, 16384]  # record_padding block sizes (bytes)
PAYLOAD_SIZES = [100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 1_000_000]

TLS_PORT = 44450

# ---------------------------------------------------------------------------
# PCAP measurement
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Capture helper
# ---------------------------------------------------------------------------


def capture_tls13_padded(
    openssl: Path,
    payload_bytes: int,
    padding_block: int,
    port: int,
    verbose: bool,
    tmp_dir: Path,
) -> int:
    """Run a TLS 1.3 session with a given record padding block size.

    Returns total PCAP bytes (excluding pure ACKs).
    """
    keys_dir = tmp_dir / "keys"
    logs_dir = tmp_dir / "logs"
    pcap_dir = tmp_dir / "pcap"
    for d in (keys_dir, logs_dir, pcap_dir):
        d.mkdir(parents=True, exist_ok=True)

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
        "-tls1_3",
        "-groups",
        "X25519",
        "-HTTP",
        "-keylogfile",
        str(keylog_file),
    ]
    if padding_block > 0:
        server_cmd += ["-record_padding", str(padding_block)]

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
        str(keylog_file),
        "-quiet",
    ]
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


# ---------------------------------------------------------------------------
# Analytical model for padded α
# ---------------------------------------------------------------------------

# TLS 1.3 constants (from cost_analysis.py)
TLS13_HANDSHAKE = 2160
TLS13_HS_PKTS = 16
TLS13_REC_HDR = 5
TLS13_AEAD_TAG = 16
TLS13_CONTENT_TYPE = 1  # inner content type byte
TLS13_MAX_RECORD = 16384
L234_OVERHEAD = 54


def _app_data_bytes(plaintext: float, padding_block: int) -> float:
    """On-wire bytes for TLS 1.3 data records with padding block b.

    With block b, each record's inner plaintext (payload + 1B content type)
    is padded to the next multiple of b before encryption.
    """
    if plaintext <= 0:
        return 0
    b = padding_block
    if b > 0:
        max_inner = (TLS13_MAX_RECORD // b) * b
        max_payload = max_inner - TLS13_CONTENT_TYPE
    else:
        max_payload = TLS13_MAX_RECORD - TLS13_CONTENT_TYPE

    n_records = max(1, int(np.ceil(plaintext / max_payload)))
    p_per_rec = plaintext / n_records

    if b > 0:
        padded_inner = int(np.ceil((p_per_rec + TLS13_CONTENT_TYPE) / b)) * b
    else:
        padded_inner = p_per_rec + TLS13_CONTENT_TYPE

    per_record = TLS13_REC_HDR + padded_inner + TLS13_AEAD_TAG + L234_OVERHEAD
    return n_records * per_record


def alpha_padded_model(
    plaintext: float, padding_block: int, hs_override: float | None = None
) -> float:
    """Analytical α for TLS 1.3 with record padding block b.

    hs_override replaces the theoretical handshake estimate for
    semi-empirical calibration.
    """
    if plaintext <= 0:
        return float("inf")

    app_bytes = _app_data_bytes(plaintext, padding_block)
    if hs_override is not None:
        hs_bytes = hs_override
    else:
        hs_bytes = TLS13_HANDSHAKE + TLS13_HS_PKTS * L234_OVERHEAD
    return (hs_bytes + app_bytes) / plaintext


# ---------------------------------------------------------------------------
# Plot
# ---------------------------------------------------------------------------


def _style_ax(ax):
    ax.grid(True, linestyle="--", which="both", color="grey", alpha=0.4)
    ax.set_axisbelow(True)
    ax.tick_params(axis="both", labelsize=14)


# Colors: green → blue gradient for increasing padding
_CMAP = mcolors.LinearSegmentedColormap.from_list("", ["#9fcf69", "#33acdc"])
PAD_COLORS = {
    0: "#888888",  # grey for baseline
    256: _CMAP(0.1),
    1024: _CMAP(0.4),
    4096: _CMAP(0.7),
    16384: _CMAP(1.0),
}


def plot_padding_alpha(results, outdir: Path):
    """Plot α(P) curves for each padding level with experimental markers."""
    payloads_theory = np.logspace(1.8, 6.2, 300)

    fig, ax = plt.subplots(figsize=(11, 6))
    _style_ax(ax)

    # Extract empirical handshake overhead per padding level.
    # With -record_padding, OpenSSL pads all encrypted server HS records,
    # so the handshake cost grows with padding block size.
    empirical_hs = {}
    for pad in PADDING_LEVELS:
        pts = [(p, pcap) for (pb, p, pcap, _a) in results if pb == pad]
        if pts:
            p_min, pcap_min = min(pts, key=lambda x: x[0])
            data_rec = _app_data_bytes(p_min, pad)
            empirical_hs[pad] = pcap_min - data_rec

    # Semi-empirical model curves
    for pad in PADDING_LEVELS:
        label_str = f"pad={pad} B" if pad > 0 else "No padding (baseline)"
        hs_ov = empirical_hs.get(pad)
        alphas = [
            alpha_padded_model(x, pad, hs_override=hs_ov) for x in payloads_theory
        ]
        ax.plot(
            payloads_theory,
            alphas,
            label=label_str,
            color=PAD_COLORS[pad],
            linewidth=2.0,
            linestyle="-" if pad > 0 else "--",
        )

    # Experimental markers
    markers = {0: "o", 256: "s", 1024: "D", 4096: "^", 16384: "v"}
    for pad in PADDING_LEVELS:
        pts = [(p, a) for (pb, p, _, a) in results if pb == pad]
        if not pts:
            continue
        xs, ys = zip(*pts)
        ax.scatter(
            xs,
            ys,
            marker=markers[pad],
            color=PAD_COLORS[pad],
            s=50,
            zorder=5,
            edgecolors="black",
            linewidths=0.5,
        )

    # Reference line
    ax.axhline(y=1, color="grey", linewidth=0.8, linestyle=":", alpha=0.6)
    ax.text(
        payloads_theory[-1] * 0.5,
        1.08,
        r"$\alpha = 1$",
        fontsize=13,
        color="grey",
        ha="right",
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
        r"TLS 1.3 record padding: effect on $\alpha$",
        fontweight="bold",
        fontsize=19,
        pad=15,
    )
    ax.set_xlim(50, 2e6)
    ax.set_ylim(0.9, 500)
    ax.legend(fontsize=13, loc="upper right", framealpha=0.9, edgecolor="black")

    fig.tight_layout()
    outpath = outdir / "mitigation_padding_alpha.pdf"
    fig.savefig(outpath, dpi=300, bbox_inches="tight")
    print(f"\n[+] Saved: {outpath}")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Experiment A: TLS 1.3 record padding mitigation"
    )
    parser.add_argument("--outdir", default="paper/figures")
    parser.add_argument("--port", type=int, default=TLS_PORT)
    parser.add_argument("--openssl", default=None)
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument(
        "--plot-only", action="store_true", help="Skip captures; plot from existing CSV"
    )
    args = parser.parse_args()

    os.chdir(REPO_ROOT)
    check_tool("tshark")

    openssl_path = (
        Path(args.openssl) if args.openssl else REPO_ROOT / "openssl/.local/bin/openssl"
    )
    outdir = REPO_ROOT / args.outdir
    outdir.mkdir(parents=True, exist_ok=True)
    csv_path = REPO_ROOT / "analysis/results/mitigation_padding.csv"

    if args.plot_only:
        results = []
        with open(csv_path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                results.append(
                    (
                        int(row["padding_block"]),
                        int(row["payload_bytes"]),
                        int(row["pcap_bytes"]),
                        float(row["alpha"]),
                    )
                )
        plot_padding_alpha(results, outdir)
        return

    ensure_exec(openssl_path, "openssl")

    results = []  # [(padding_block, payload_bytes, pcap_bytes, alpha)]

    total_runs = len(PADDING_LEVELS) * len(PAYLOAD_SIZES)
    run_idx = 0

    for pad in PADDING_LEVELS:
        pad_label = f"pad={pad}B" if pad > 0 else "no-padding"
        print(f"\n{'='*60}")
        print(f"  Padding block: {pad_label}")
        print(f"{'='*60}")

        for payload in PAYLOAD_SIZES:
            run_idx += 1
            with tempfile.TemporaryDirectory(prefix="hndl_pad_") as tmp:
                tmp_path = Path(tmp)
                print(
                    f"  [{run_idx}/{total_runs}] {pad_label}  "
                    f"payload={payload:>9,} B ...",
                    end=" ",
                    flush=True,
                )
                try:
                    pcap_bytes = capture_tls13_padded(
                        openssl_path, payload, pad, args.port, args.verbose, tmp_path
                    )
                    alpha = pcap_bytes / payload
                    results.append((pad, payload, pcap_bytes, alpha))
                    alpha_model = alpha_padded_model(payload, pad)
                    delta = alpha - alpha_model
                    print(
                        f"pcap={pcap_bytes:>9,} B  α={alpha:.3f}  "
                        f"(model={alpha_model:.3f}  Δ={delta:+.3f})"
                    )
                except Exception as e:
                    print(f"FAILED: {e}")

    # Save CSV
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["padding_block", "payload_bytes", "pcap_bytes", "alpha"])
        for row in results:
            writer.writerow(row)
    print(f"\n[+] CSV saved: {csv_path}")

    # Print summary
    print(f"\n{'='*70}")
    print("Summary: padding inflation on α")
    print(f"{'='*70}")
    print(
        f"{'Padding':>10}  {'Payload':>10}  {'α_meas':>8}  {'α_model':>8}  {'Inflation':>10}"
    )
    print(f"{'-'*70}")
    baseline = {p: a for (pb, p, _, a) in results if pb == 0}
    for pad, payload, pcap, alpha in results:
        alpha_m = alpha_padded_model(payload, pad)
        base_a = baseline.get(payload, alpha)
        inflation = alpha / base_a if base_a > 0 else float("inf")
        print(
            f"{pad:>10}  {payload:>10,}  {alpha:>8.3f}  {alpha_m:>8.3f}  {inflation:>9.1f}×"
        )

    plot_padding_alpha(results, outdir)


if __name__ == "__main__":
    main()
