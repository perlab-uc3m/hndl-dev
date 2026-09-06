#!/usr/bin/env python3
"""Experiment B — SSH aggressive rekeying mitigation.

Measures how SSH RekeyLimit increases distinct DH exchanges and associated
storage overhead. Whether their attack inputs are simultaneously schedulable
is a separate dependency question; this script does not infer wall-clock
quantum latency from the exchange count.
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
    start_tshark,
    stop_tshark,
    terminate,
)
from capture.ssh.capture_ssh import (
    generate_host_key,
    generate_user_key,
    write_sshd_config,
    ssh_reader_thread,
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

#  RekeyLimit values.  "0" = default (no rekeying).
#  Human-readable SSH notation for config, bytes for analysis.
REKEY_LIMITS = [
    ("64K", 64 * 1024),
    ("256K", 256 * 1024),
    ("1M", 1 * 1024 * 1024),
    ("10M", 10 * 1024 * 1024),
    ("0", 0),
]

PAYLOAD_SIZES = [1_000, 10_000, 100_000, 1_000_000, 5_000_000]

SSH_PORT = 44451

# ---------------------------------------------------------------------------
# PCAP helpers
# ---------------------------------------------------------------------------


def count_newkeys_from_log(log_path: Path) -> int:
    """Count SSH2_MSG_NEWKEYS sent events in an SSH debug log.

    E = count_newkeys (initial handshake produces 1; each rekey adds 1 more).
    """
    if not log_path.exists():
        return 0
    count = 0
    with log_path.open("r", errors="replace") as f:
        for line in f:
            if "SSH2_MSG_NEWKEYS" in line and "sent" in line:
                count += 1
    return count


# ---------------------------------------------------------------------------
# Capture helper
# ---------------------------------------------------------------------------


def capture_ssh_rekey(
    sshd: Path,
    ssh_bin: Path,
    ssh_keygen: Path,
    payload_bytes: int,
    rekey_limit_str: str,
    port: int,
    verbose: bool,
    tmp_dir: Path,
) -> tuple[int, int]:
    """Run an SSH session that transfers `payload_bytes` with the given RekeyLimit.

    Returns (pcap_total_bytes, kexinit_count).
    """
    keys_dir = tmp_dir / "keys"
    logs_dir = tmp_dir / "logs"
    pcap_dir = tmp_dir / "pcap"
    for d in (keys_dir, logs_dir, pcap_dir):
        d.mkdir(parents=True, exist_ok=True)

    pcap_file = pcap_dir / "session.pcapng"
    host_key = generate_host_key(ssh_keygen, keys_dir, verbose)
    user_key = generate_user_key(ssh_keygen, keys_dir, verbose)
    auth_keys = keys_dir / "authorized_keys"
    sshd_config = write_sshd_config(
        keys_dir / "sshd_config",
        host_key,
        auth_keys,
        port,
        rekey_limit_str if rekey_limit_str != "0" else None,
    )

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

    src = "/dev/urandom" if payload_bytes <= 10_000 else "/dev/zero"
    remote_cmd = f"head -c {payload_bytes} {src}"

    ssh_cmd = [
        str(ssh_bin),
        "-vvv",  # verbose: we need to see NEWKEYS in stderr
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
        "-o",
        "KexAlgorithms=curve25519-sha256",
    ]
    # Add RekeyLimit if not "0" (which means default/disabled)
    if rekey_limit_str != "0":
        ssh_cmd += ["-o", f"RekeyLimit={rekey_limit_str}"]

    ssh_cmd += [
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

    timeout = max(30, payload_bytes // 50_000)
    try:
        client.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        terminate(client, "ssh")
    application_handle.close()
    t_cli.join(timeout=1)
    if client.returncode != 0 or application_output.stat().st_size != payload_bytes:
        terminate(server, "sshd")
        stop_tshark(tshark, tshark_threads)
        raise RuntimeError(
            f"SSH transfer failed: status={client.returncode}, "
            f"bytes={application_output.stat().st_size}, expected={payload_bytes}"
        )

    time.sleep(0.5)
    terminate(server, "sshd")
    stop_tshark(tshark, tshark_threads)

    total = pcap_total_bytes(pcap_file)
    cli_log = logs_dir / "ssh_stderr.log"
    newkeys_count = count_newkeys_from_log(cli_log)
    return total, newkeys_count


# ---------------------------------------------------------------------------
# Analytical model
# ---------------------------------------------------------------------------

SSH_HANDSHAKE = 5100
SSH_CHANNEL_OPEN = 1109
SSH_PAD_BLOCK = 8
SSH_MAX_PACKET = 32768
SSH_TAG = 16
SSH_HDR = 4 + 1
L234_OVERHEAD = 54

# Empirical per-rekey overhead (~3 000 B: 2×KEXINIT + KEX_DH + 2×NEWKEYS + TCP).
REKEY_OVERHEAD_EST = 3000


def alpha_rekey_model(
    plaintext: float, rekey_limit_bytes: int, rekey_overhead: float = REKEY_OVERHEAD_EST
) -> float:
    """Analytical α for SSH with aggressive rekeying.

    E(P, R) = max(1, ceil(P/R)) independent DH exchanges.
    This is an ideal plaintext-interval model. OpenSSH enforces RekeyLimit
    using implementation-level cipher-block counters, so measured E can
    differ and is reported independently.
    """
    if plaintext <= 0:
        return float("inf")

    if rekey_limit_bytes <= 0:
        # No rekeying, standard SSH model
        e = 1
    else:
        e = max(1, int(np.ceil(plaintext / rekey_limit_bytes)))

    # Data-transfer portion
    def ssh_padding(plen):
        inner = SSH_HDR + plen
        pad = (-inner) % SSH_PAD_BLOCK
        if pad < 4:
            pad += SSH_PAD_BLOCK
        return pad

    max_payload = SSH_MAX_PACKET - SSH_HDR - 4
    n_packets = max(1, int(np.ceil(plaintext / max_payload)))
    payload_per_pkt = plaintext / n_packets
    pad = ssh_padding(int(payload_per_pkt))
    per_pkt = SSH_HDR + int(payload_per_pkt) + pad + SSH_TAG + L234_OVERHEAD
    data_bytes = n_packets * per_pkt

    # Handshake + channel setup: SSH_HANDSHAKE + SSH_CHANNEL_OPEN (first time)
    # Each rekey adds approximately rekey_overhead bytes
    hs_bytes = SSH_HANDSHAKE + SSH_CHANNEL_OPEN
    rekey_bytes = (e - 1) * rekey_overhead

    total = hs_bytes + data_bytes + rekey_bytes
    # Add L2-4 overhead for handshake packets (approx 16 packets)
    total += 16 * L234_OVERHEAD

    return total / plaintext


# ---------------------------------------------------------------------------
# Plot
# ---------------------------------------------------------------------------


def _style_ax(ax):
    ax.grid(True, linestyle="--", which="both", color="grey", alpha=0.4)
    ax.set_axisbelow(True)
    ax.tick_params(axis="both", labelsize=14)


_CMAP = mcolors.LinearSegmentedColormap.from_list("", ["#9fcf69", "#33acdc"])
REKEY_COLORS = {
    64 * 1024: _CMAP(0.0),
    256 * 1024: _CMAP(0.25),
    1024 * 1024: _CMAP(0.5),
    10 * 1024 * 1024: _CMAP(0.75),
    0: "#888888",  # grey for baseline (no rekey)
}
REKEY_MARKERS = {
    64 * 1024: "v",
    256 * 1024: "^",
    1024 * 1024: "D",
    10 * 1024 * 1024: "s",
    0: "o",
}


def plot_rekey_alpha(results, outdir: Path):
    """Plot α(P) curves for each rekey limit."""
    payloads_theory = np.logspace(2.5, 7, 300)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    _style_ax(ax1)
    _style_ax(ax2)

    # --- Derive empirical rekey overhead from data ---
    baseline_by_payload = {p: pcap for (rs, rb, p, pcap, a, _, _) in results if rb == 0}
    rekey_costs = []
    for rs, rb, p, pcap, a, nk, e in results:
        if rb > 0 and e > 1 and p in baseline_by_payload:
            extra = pcap - baseline_by_payload[p]
            per_rekey = extra / (e - 1)
            rekey_costs.append(per_rekey)
    rekey_overhead = np.mean(rekey_costs) if rekey_costs else REKEY_OVERHEAD_EST

    # --- Derive effective RekeyLimit per nominal config ---
    # OpenSSH counts transport-level bytes toward RekeyLimit.
    effective_rekey = {}
    for rs, rb, p, pcap, a, nk, e in results:
        if rb > 0 and e > 1:
            # effective_R ≈ P / (E - 1) for large E (ignoring initial HS)
            eff = p / (e - 1)
            effective_rekey.setdefault(rb, []).append(eff)
    eff_rekey_map = {}
    for rb, vals in effective_rekey.items():
        eff_rekey_map[rb] = np.mean(vals)

    # --- Left panel: α ---
    for rekey_str, rekey_bytes in REKEY_LIMITS:
        label = (
            f"RekeyLimit={rekey_str}" if rekey_bytes > 0 else "No rekeying (baseline)"
        )
        eff_rb = eff_rekey_map.get(rekey_bytes, rekey_bytes)
        alphas = [alpha_rekey_model(x, eff_rb, rekey_overhead) for x in payloads_theory]
        ls = "-" if rekey_bytes > 0 else "--"
        ax1.plot(
            payloads_theory,
            alphas,
            label=label,
            color=REKEY_COLORS[rekey_bytes],
            linewidth=2.0,
            linestyle=ls,
        )

    for rekey_str, rekey_bytes in REKEY_LIMITS:
        pts = [(p, a) for (rs, rb, p, _, a, _, _) in results if rb == rekey_bytes]
        if not pts:
            continue
        xs, ys = zip(*pts)
        ax1.scatter(
            xs,
            ys,
            marker=REKEY_MARKERS[rekey_bytes],
            color=REKEY_COLORS[rekey_bytes],
            s=50,
            zorder=5,
            edgecolors="black",
            linewidths=0.5,
        )

    ax1.axhline(y=1, color="grey", linewidth=0.8, linestyle=":", alpha=0.6)
    ax1.set_xscale("log")
    ax1.set_yscale("log")
    ax1.set_xlabel("Application payload (bytes)", fontweight="bold", fontsize=15)
    ax1.set_ylabel(
        r"Protocol overhead ratio $\alpha$", fontweight="bold", fontsize=15, labelpad=15
    )
    ax1.set_title(
        r"SSH rekeying: effect on $\alpha$", fontweight="bold", fontsize=17, pad=15
    )
    ax1.set_xlim(300, 1e7)
    ax1.set_ylim(0.9, 200)
    ax1.legend(fontsize=12, loc="upper right", framealpha=0.9, edgecolor="black")

    # --- Right panel: E (independent DH exchanges) ---
    for rekey_str, rekey_bytes in REKEY_LIMITS:
        if rekey_bytes <= 0:
            ax2.axhline(
                y=1,
                color=REKEY_COLORS[0],
                linewidth=2,
                linestyle="--",
                label="No rekeying (E=1)",
            )
            continue
        eff_rb = eff_rekey_map.get(rekey_bytes, rekey_bytes)
        e_theory = [max(1, np.ceil(x / eff_rb)) for x in payloads_theory]
        ax2.plot(
            payloads_theory,
            e_theory,
            label=f"RekeyLimit={rekey_str}",
            color=REKEY_COLORS[rekey_bytes],
            linewidth=2.0,
        )

    # Experimental E values
    for rekey_str, rekey_bytes in REKEY_LIMITS:
        pts = [(p, e) for (rs, rb, p, _, _, _, e) in results if rb == rekey_bytes]
        if not pts:
            continue
        xs, ys = zip(*pts)
        ax2.scatter(
            xs,
            ys,
            marker=REKEY_MARKERS[rekey_bytes],
            color=REKEY_COLORS[rekey_bytes],
            s=50,
            zorder=5,
            edgecolors="black",
            linewidths=0.5,
        )

    ax2.set_xscale("log")
    ax2.set_yscale("log")
    ax2.set_xlabel("Application payload (bytes)", fontweight="bold", fontsize=15)
    ax2.set_ylabel(
        "Independent DH exchanges (E)", fontweight="bold", fontsize=15, labelpad=15
    )
    ax2.set_title(
        "SSH rekeying: quantum cost multiplier E",
        fontweight="bold",
        fontsize=17,
        pad=15,
    )
    ax2.set_xlim(300, 1e7)
    ax2.legend(fontsize=12, loc="upper left", framealpha=0.9, edgecolor="black")

    fig.tight_layout()
    outpath = outdir / "mitigation_rekey_alpha.pdf"
    fig.savefig(outpath, dpi=300, bbox_inches="tight")
    print(f"\n[+] Saved: {outpath}")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Experiment B: SSH aggressive rekeying mitigation"
    )
    parser.add_argument("--outdir", default="paper/figures")
    parser.add_argument("--port", type=int, default=SSH_PORT)
    parser.add_argument("--openssh-dir", default=None)
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument(
        "--plot-only", action="store_true", help="Skip captures; plot from existing CSV"
    )
    args = parser.parse_args()

    os.chdir(REPO_ROOT)
    check_tool("tshark")

    openssh_dir = (
        Path(args.openssh_dir) if args.openssh_dir else REPO_ROOT / "openssh/.local"
    )
    sshd = openssh_dir / "sbin/sshd"
    ssh_bin = openssh_dir / "bin/ssh"
    ssh_keygen = openssh_dir / "bin/ssh-keygen"

    outdir = REPO_ROOT / args.outdir
    outdir.mkdir(parents=True, exist_ok=True)
    csv_path = REPO_ROOT / "analysis/results/mitigation_rekey.csv"

    if args.plot_only:
        results = []
        with open(csv_path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                results.append(
                    (
                        row["rekey_limit"],
                        int(row["rekey_limit_bytes"]),
                        int(row["payload_bytes"]),
                        int(row["pcap_bytes"]),
                        float(row["alpha"]),
                        int(row["newkeys_count"]),
                        int(row["E"]),
                    )
                )
        plot_rekey_alpha(results, outdir)
        return

    for b, n in [(sshd, "sshd"), (ssh_bin, "ssh"), (ssh_keygen, "ssh-keygen")]:
        ensure_exec(b, n)

    # results: [(rekey_str, rekey_bytes, payload, pcap_bytes, alpha, kex_count, E)]
    results = []
    total_runs = len(REKEY_LIMITS) * len(PAYLOAD_SIZES)
    run_idx = 0

    for rekey_str, rekey_bytes in REKEY_LIMITS:
        label = f"RekeyLimit={rekey_str}" if rekey_bytes > 0 else "No rekeying"
        print(f"\n{'='*60}")
        print(f"  {label}")
        print(f"{'='*60}")

        for payload in PAYLOAD_SIZES:
            # Skip cases where rekey_limit > payload: kept for completeness
            run_idx += 1
            with tempfile.TemporaryDirectory(prefix="hndl_rekey_") as tmp:
                tmp_path = Path(tmp)
                print(
                    f"  [{run_idx}/{total_runs}] {label}  "
                    f"payload={payload:>9,} B ...",
                    end=" ",
                    flush=True,
                )
                try:
                    pcap_bytes, newkeys_count = capture_ssh_rekey(
                        sshd,
                        ssh_bin,
                        ssh_keygen,
                        payload,
                        rekey_str,
                        args.port,
                        args.verbose,
                        tmp_path,
                    )
                    alpha = pcap_bytes / payload
                    # E counts distinct DH exchanges. It is not elapsed-time
                    # multiplication without a validated dependency schedule.
                    e = max(1, newkeys_count)
                    results.append(
                        (
                            rekey_str,
                            rekey_bytes,
                            payload,
                            pcap_bytes,
                            alpha,
                            newkeys_count,
                            e,
                        )
                    )
                    print(
                        f"pcap={pcap_bytes:>9,} B  α={alpha:.3f}  "
                        f"NEWKEYS={newkeys_count}  E={e}"
                    )
                except Exception as e:
                    print(f"FAILED: {e}")

    # Save CSV
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "rekey_limit",
                "rekey_limit_bytes",
                "payload_bytes",
                "pcap_bytes",
                "alpha",
                "newkeys_count",
                "E",
            ]
        )
        for row in results:
            writer.writerow(row)
    print(f"\n[+] CSV saved: {csv_path}")

    # Summary
    print(f"\n{'='*80}")
    print("Summary: SSH rekeying effect on α and E")
    print(f"{'='*80}")
    print(
        f"{'RekeyLimit':>12}  {'Payload':>10}  {'α_meas':>8}  {'E_meas':>6}  {'E_theory':>8}  {'α vs base':>10}"
    )
    print(f"{'-'*80}")
    baseline = {p: a for (rs, rb, p, _, a, _, _) in results if rb == 0}
    for rekey_str, rekey_bytes, payload, pcap, alpha, kex, e in results:
        if rekey_bytes > 0:
            e_theory = max(1, int(np.ceil(payload / rekey_bytes)))
        else:
            e_theory = 1
        base_a = baseline.get(payload, alpha)
        inflation = alpha / base_a if base_a > 0 else float("inf")
        print(
            f"{rekey_str:>12}  {payload:>10,}  {alpha:>8.3f}  {e:>6}  {e_theory:>8}  {inflation:>9.2f}×"
        )

    plot_rekey_alpha(results, outdir)


if __name__ == "__main__":
    main()
