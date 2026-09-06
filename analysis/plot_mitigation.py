#!/usr/bin/env python3
"""Mitigation analysis: unified figures and summary table.

Generates unified E(P) figure, per-experiment figures, and a LaTeX
summary table from the Step 1 CSV data.
"""

import argparse
import csv
import os
import subprocess
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import numpy as np

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "analysis" / "results"
FIGURES = REPO_ROOT / "paper" / "figures"

# ---------------------------------------------------------------------------
# Plot style
# ---------------------------------------------------------------------------
plt.rcParams["font.family"] = "Ubuntu"
plt.rcParams["pdf.fonttype"] = 42
plt.rcParams["ps.fonttype"] = 42

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _style_ax(ax):
    ax.grid(True, linestyle="--", which="both", color="grey", alpha=0.4)
    ax.set_axisbelow(True)
    ax.tick_params(axis="both", labelsize=14)


def load_rekey_csv():
    rows = []
    with open(RESULTS / "mitigation_rekey.csv") as f:
        for r in csv.DictReader(f):
            rows.append(
                {
                    "label": r["rekey_limit"],
                    "R": int(r["rekey_limit_bytes"]),
                    "P": int(r["payload_bytes"]),
                    "pcap": int(r["pcap_bytes"]),
                    "alpha": float(r["alpha"]),
                    "E": int(r["E"]),
                }
            )
    return rows


def load_psk_dhe_csv():
    rows = []
    with open(RESULTS / "mitigation_psk_dhe.csv") as f:
        for r in csv.DictReader(f):
            rows.append(
                {
                    "label": r["rotation_interval"],
                    "R": int(r["rotation_bytes"]),
                    "P": int(r["payload_bytes"]),
                    "E": int(r["E"]),
                    "alpha": float(r["alpha"]),
                    "alpha_base": float(r["alpha_baseline"]),
                    "inflation": float(r["inflation"]),
                    "h_init": float(r["h_init_avg"]),
                    "h_resum": float(r["h_resum_avg"]),
                }
            )
    return rows


def load_psk_dhe_rotation_csv():
    """Load TLS 1.3 PSK-DHE rotation experiment results, if available."""
    path = RESULTS / "mitigation_psk_dhe_rotation.csv"
    if not path.exists():
        return []
    rows = []
    with open(path) as f:
        for r in csv.DictReader(f):
            rows.append(
                {
                    "label": r["rotation_interval"],
                    "R": int(r["rotation_bytes"]),
                    "P": int(r["payload_bytes"]),
                    "E_exp": int(r["E_expected"]),
                    "E": int(r["E_measured"]),
                    "pcap": int(r["pcap_bytes"]),
                }
            )
    return rows


def load_padding_csv():
    rows = []
    with open(RESULTS / "mitigation_padding.csv") as f:
        for r in csv.DictReader(f):
            rows.append(
                {
                    "pad": int(r["padding_block"]),
                    "P": int(r["payload_bytes"]),
                    "pcap": int(r["pcap_bytes"]),
                    "alpha": float(r["alpha"]),
                }
            )
    return rows


# ---------------------------------------------------------------------------
# Unified E figure
# ---------------------------------------------------------------------------

# SSH rekey limits we care about
SSH_REKEY_LIMITS = [
    ("64K", 64 * 1024),
    ("256K", 256 * 1024),
    ("1M", 1 * 1024 * 1024),
]

# TLS PSK-DHE rotation intervals
TLS_ROTATION = [
    ("10K", 10_000),
    ("100K", 100_000),
    ("1M", 1_000_000),
]

# Green-to-blue palette
_CMAP = mcolors.LinearSegmentedColormap.from_list("", ["#9fcf69", "#33acdc"])

# 6 evenly-spaced colours: SSH gets green half, TLS gets blue half
SSH_COLORS = {
    64 * 1024: _CMAP(0.0),
    256 * 1024: _CMAP(0.2),
    1 * 1024 * 1024: _CMAP(0.4),
}
TLS_COLORS = {
    10_000: _CMAP(0.6),
    100_000: _CMAP(0.8),
    1_000_000: _CMAP(1.0),
}

SSH_MARKERS = {64 * 1024: "v", 256 * 1024: "^", 1 * 1024 * 1024: "D"}
TLS_MARKERS = {10_000: "s", 100_000: "o", 1_000_000: "P"}


def plot_unified_E(rekey_data, psk_data, outdir: Path, tls_rot_data=None):
    """Unified quantum cost multiplier E(P) for SSH rekey + TLS 1.3 PSK-DHE."""

    payloads = np.logspace(2, 7.2, 500)

    fig, ax = plt.subplots(figsize=(11, 6.5))
    _style_ax(ax)

    # --- Derive effective SSH RekeyLimits from data ---
    effective_ssh = {}
    for row in rekey_data:
        if row["R"] > 0 and row["E"] > 1:
            eff = row["P"] / (row["E"] - 1)
            effective_ssh.setdefault(row["R"], []).append(eff)
    eff_ssh_map = {rb: np.mean(vals) for rb, vals in effective_ssh.items()}

    # --- SSH E curves ---
    for label, R in SSH_REKEY_LIMITS:
        eff_R = eff_ssh_map.get(R, R)
        e_vals = [max(1, int(np.ceil(x / eff_R))) for x in payloads]
        ax.plot(
            payloads,
            e_vals,
            label=f"SSH RekeyLimit={label}",
            color=SSH_COLORS[R],
            linewidth=2.0,
            linestyle="-",
        )

    # SSH experimental points
    for label, R in SSH_REKEY_LIMITS:
        pts = [
            (row["P"], row["E"]) for row in rekey_data if row["R"] == R and row["E"] > 0
        ]
        if pts:
            xs, ys = zip(*pts)
            ax.scatter(
                xs,
                ys,
                marker=SSH_MARKERS[R],
                color=SSH_COLORS[R],
                s=55,
                zorder=5,
                edgecolors="black",
                linewidths=0.5,
            )

    # --- TLS 1.3 PSK-DHE E curves ---
    for label, R in TLS_ROTATION:
        e_vals = [max(1, int(np.ceil(x / R))) for x in payloads]
        ax.plot(
            payloads,
            e_vals,
            label=f"TLS 1.3 PSK-DHE R={label}",
            color=TLS_COLORS[R],
            linewidth=2.0,
            linestyle="--",
        )

    # TLS experimental points (rotation data-transfer experiment)
    if tls_rot_data:
        for label, R in TLS_ROTATION:
            pts = [
                (row["P"], row["E"])
                for row in tls_rot_data
                if row["R"] == R and row["E"] > 0
            ]
            if pts:
                xs, ys = zip(*pts)
                ax.scatter(
                    xs,
                    ys,
                    marker=TLS_MARKERS[R],
                    color=TLS_COLORS[R],
                    s=55,
                    zorder=5,
                    edgecolors="black",
                    linewidths=0.5,
                )

    # --- Baseline ---
    ax.axhline(
        y=1,
        color="#888888",
        linewidth=2,
        linestyle=":",
        label="TLS 1.3 KeyUpdate (E=1 always)",
        zorder=1,
    )

    # --- Formatting ---
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel(
        "Application payload per session (bytes)", fontweight="bold", fontsize=15
    )
    ax.set_ylabel(
        "Independent DH / ECDHE exchanges (E)",
        fontweight="bold",
        fontsize=15,
        labelpad=15,
    )
    ax.set_title(
        "Quantum cost multiplier: SSH rekeying vs. TLS 1.3 PSK-DHE rotation",
        fontweight="bold",
        fontsize=17,
        pad=15,
    )
    ax.set_xlim(100, 1.5e7)
    ax.set_ylim(0.8, 600)

    # Custom legend: group SSH and TLS
    ax.legend(fontsize=12, loc="upper left", framealpha=0.9, edgecolor="black", ncol=1)

    # NOTE: per-exchange overhead numbers belong in the figure caption,
    # not as an in-plot annotation.

    fig.tight_layout()
    outpath = outdir / "mitigation_rekey_E.pdf"
    fig.savefig(outpath, dpi=300, bbox_inches="tight")
    print(f"[+] Saved: {outpath}")
    plt.close(fig)
    return outpath


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------


def compute_summary_table(padding_data, rekey_data, psk_data):
    """Build the summary table rows from experimental data."""
    rows = []

    # --- Padding entries ---
    baseline_alpha = {r["P"]: r["alpha"] for r in padding_data if r["pad"] == 0}

    # Max padding (16384), small payload (100 B)
    r100 = [r for r in padding_data if r["pad"] == 16384 and r["P"] == 100]
    if r100:
        rows.append(
            {
                "mitigation": "TLS 1.3 record padding (16\\,KB block)",
                "axis": r"$\alpha$ (storage)",
                "parameter": "100\\,B payload",
                "inflation": f"$\\alpha$: {baseline_alpha.get(100, 0):.1f}$\\times$ $\\to$ "
                f"{r100[0]['alpha']:.0f}$\\times$",
                "overhead": "+16\\,KB/record",
            }
        )

    # Max padding (16384), large payload (1 MB)
    r1m = [r for r in padding_data if r["pad"] == 16384 and r["P"] == 1_000_000]
    if r1m:
        rows.append(
            {
                "mitigation": "TLS 1.3 record padding (16\\,KB block)",
                "axis": r"$\alpha$ (storage)",
                "parameter": "1\\,MB payload",
                "inflation": f"$\\alpha$: {baseline_alpha.get(1_000_000, 0):.3f}$\\times$ $\\to$ "
                f"{r1m[0]['alpha']:.3f}$\\times$",
                "overhead": "Negligible ($<$0.2\\%)",
            }
        )

    # --- SSH rekey entries ---
    baseline_ssh = {r["P"]: r for r in rekey_data if r["R"] == 0}

    # 64K rekey, 1 MB payload
    r_ssh_1m = [r for r in rekey_data if r["R"] == 64 * 1024 and r["P"] == 1_000_000]
    if r_ssh_1m:
        r = r_ssh_1m[0]
        base = baseline_ssh.get(1_000_000, {})
        oh_bytes = r["pcap"] - base.get("pcap", r["pcap"])
        oh_pct = oh_bytes / base.get("pcap", r["pcap"]) * 100 if base else 0
        rows.append(
            {
                "mitigation": "SSH rekey (\\texttt{RekeyLimit 64K})",
                "axis": "$E$ (quantum)",
                "parameter": "1\\,MB transfer",
                "inflation": f"$E$: 1 $\\to$ {r['E']}",
                "overhead": f"+{oh_bytes/1000:.1f}\\,KB ({oh_pct:.1f}\\%)",
            }
        )

    # 64K rekey, 5 MB payload
    r_ssh_5m = [r for r in rekey_data if r["R"] == 64 * 1024 and r["P"] == 5_000_000]
    if r_ssh_5m:
        r = r_ssh_5m[0]
        base = baseline_ssh.get(5_000_000, {})
        oh_bytes = r["pcap"] - base.get("pcap", r["pcap"])
        oh_pct = oh_bytes / base.get("pcap", r["pcap"]) * 100 if base else 0
        rows.append(
            {
                "mitigation": "SSH rekey (\\texttt{RekeyLimit 64K})",
                "axis": "$E$ (quantum)",
                "parameter": "5\\,MB transfer",
                "inflation": f"$E$: 1 $\\to$ {r['E']}",
                "overhead": f"+{oh_bytes/1000:.1f}\\,KB ({oh_pct:.1f}\\%)",
            }
        )

    # --- TLS PSK-DHE entries ---
    # 100K rotation, 1 MB
    r_tls_1m = [r for r in psk_data if r["R"] == 100_000 and r["P"] == 1_000_000]
    if r_tls_1m:
        r = r_tls_1m[0]
        oh_pct = (r["inflation"] - 1) * 100
        rows.append(
            {
                "mitigation": "TLS 1.3 PSK-DHE rotation (100\\,KB)",
                "axis": "$E$ (quantum)",
                "parameter": "1\\,MB transfer",
                "inflation": f"$E$: 1 $\\to$ {r['E']}",
                "overhead": f"{oh_pct:.1f}\\% storage inflation",
            }
        )

    # 10K rotation, 5 MB
    r_tls_5m = [r for r in psk_data if r["R"] == 10_000 and r["P"] == 5_000_000]
    if r_tls_5m:
        r = r_tls_5m[0]
        oh_pct = (r["inflation"] - 1) * 100
        rows.append(
            {
                "mitigation": "TLS 1.3 PSK-DHE rotation (10\\,KB)",
                "axis": "$E$ (quantum)",
                "parameter": "5\\,MB transfer",
                "inflation": f"$E$: 1 $\\to$ {r['E']}",
                "overhead": f"{oh_pct:.1f}\\% storage inflation",
            }
        )

    # --- TLS KeyUpdate (no effect) ---
    rows.append(
        {
            "mitigation": "TLS 1.3 \\texttt{KeyUpdate}",
            "axis": "$E$ (quantum)",
            "parameter": "Any",
            "inflation": "$E$: 1 $\\to$ 1 (no effect)",
            "overhead": "None",
        }
    )

    # --- Legacy elimination ---
    rows.append(
        {
            "mitigation": "Disable TLS 1.2 RSA",
            "axis": "Scope",
            "parameter": "---",
            "inflation": "All-sessions $\\to$ per-session",
            "overhead": "None",
        }
    )
    rows.append(
        {
            "mitigation": "Disable TLS 1.3 0-RTT",
            "axis": "Early data",
            "parameter": "---",
            "inflation": "PSK-derived 0-RTT exposure eliminated",
            "overhead": "+1 RTT",
        }
    )

    return rows


def print_summary_table(rows):
    """Print the summary table to the console."""
    print(f"\n{'='*100}")
    print("  Mitigation Effectiveness Summary")
    print(f"{'='*100}")
    fmt = "{:<42} {:<16} {:<16} {:<28} {:<20}"
    print(
        fmt.format(
            "Mitigation", "Cost axis", "Parameter", "Measured inflation", "Overhead"
        )
    )
    print("-" * 100)
    for r in rows:
        # Strip LaTeX for console display
        mit = (
            r["mitigation"]
            .replace("\\texttt{", "")
            .replace("}", "")
            .replace("\\,", ",")
        )
        axis = r["axis"].replace("$", "").replace("\\alpha", "α").replace("\\to", "→")
        inf = (
            r["inflation"]
            .replace("$", "")
            .replace("\\alpha", "α")
            .replace("\\to", "→")
            .replace("\\times", "×")
        )
        oh = r["overhead"].replace("\\,", ",").replace("$<$", "<").replace("\\%", "%")
        print(fmt.format(mit, axis, r["parameter"].replace("\\,", ","), inf, oh))
    print(f"{'='*100}\n")


def write_latex_table(rows, outdir: Path):
    """Write the summary table as a standalone LaTeX file fragment."""
    outpath = outdir / "mitigation_summary_table.tex"
    lines = []
    lines.append(r"\begin{table*}[htbp]")
    lines.append(r"\centering")
    lines.append(
        r"\caption{Experimentally measured mitigation effectiveness. Each row shows the "
        r"cost axis targeted, the measured inflation of that axis, and the overhead "
        r"imposed on the defender.}"
    )
    lines.append(r"\label{tab:mitigation-summary}")
    lines.append(r"\small")
    lines.append(r"\begin{tabular}{llllll}")
    lines.append(r"\hline")
    lines.append(
        r"\textbf{Mitigation} & \textbf{Cost axis} & \textbf{Parameter} & "
        r"\textbf{Measured inflation} & \textbf{Defender overhead} \\"
    )
    lines.append(r"\hline")
    for r in rows:
        line = (
            f"{r['mitigation']} & {r['axis']} & {r['parameter']} & "
            f"{r['inflation']} & {r['overhead']} \\\\"
        )
        lines.append(line)
    lines.append(r"\hline")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table*}")
    lines.append("")

    outpath.write_text("\n".join(lines))
    print(f"[+] Saved: {outpath}")
    return outpath


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Step 2: Mitigation analysis & figures"
    )
    parser.add_argument(
        "--unified", action="store_true", help="Generate unified E figure only"
    )
    parser.add_argument(
        "--table", action="store_true", help="Generate summary table only"
    )
    parser.add_argument(
        "--all-plots",
        action="store_true",
        help="Also regenerate per-experiment figures",
    )
    args = parser.parse_args()

    os.chdir(REPO_ROOT)
    FIGURES.mkdir(parents=True, exist_ok=True)
    do_all = not args.unified and not args.table

    # Load data
    padding_data = load_padding_csv()
    rekey_data = load_rekey_csv()
    psk_data = load_psk_dhe_csv()

    # --- Per-experiment figures (delegate to individual scripts) ---
    if do_all and args.all_plots:
        print("\n--- Regenerating per-experiment figures ---")
        for script in [
            "mitigation_padding.py",
            "mitigation_rekey.py",
            "mitigation_psk_dhe.py",
        ]:
            print(f"  Running {script} --plot-only ...")
            subprocess.run(
                [sys.executable, str(REPO_ROOT / "analysis" / script), "--plot-only"],
                check=True,
            )

    # --- Unified E figure ---
    if do_all or args.unified:
        print("\n--- Generating unified E figure ---")
        tls_rot_data = load_psk_dhe_rotation_csv()
        plot_unified_E(rekey_data, psk_data, FIGURES, tls_rot_data)

    # --- Summary table ---
    if do_all or args.table:
        print("\n--- Generating summary table ---")
        table_rows = compute_summary_table(padding_data, rekey_data, psk_data)
        print_summary_table(table_rows)
        write_latex_table(table_rows, REPO_ROOT / "paper")


if __name__ == "__main__":
    main()
