#!/usr/bin/env python3
"""Plot recorded exchange counts without fitting plaintext RekeyLimit thresholds."""
import argparse
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def plot_counts(results_dir, outdir):
    with (results_dir / "mitigation_rekey.csv").open() as handle:
        ssh = list(csv.DictReader(handle))
    with (results_dir / "mitigation_psk_dhe_rotation.csv").open() as handle:
        tls = list(csv.DictReader(handle))

    plt.rcParams.update({"font.family": "DejaVu Sans", "pdf.fonttype": 42})
    fig, axes = plt.subplots(
        2, 1, figsize=(3.5, 3.4), sharex=False, sharey=True, gridspec_kw={"hspace": 0.40}
    )
    ax_ssh, ax_tls = axes
    colors = ["#548b37", "#83b64e", "#369faa", "#287cb8"]
    ssh_markers = ["v", "^", "D", "s"]
    ssh_limits = sorted(
        {int(row["rekey_limit_bytes"]) for row in ssh if int(row["rekey_limit_bytes"])}
    )
    for idx, (limit, color) in enumerate(zip(ssh_limits, colors)):
        points = sorted(
            (int(row["payload_bytes"]), int(row["E"]))
            for row in ssh
            if int(row["rekey_limit_bytes"]) == limit
        )
        if limit % (1024 * 1024) == 0:
            label = f"{limit / (1024 * 1024):g} MiB"
        else:
            label = f"{limit / 1024:g} KiB"
        ax_ssh.scatter(
            *zip(*points),
            color=color,
            marker=ssh_markers[idx],
            s=28,
            edgecolors="black",
            linewidths=0.45,
            label=label,
            zorder=3,
        )

    tls_limits = sorted({int(row["rotation_bytes"]) for row in tls})
    tls_markers = ["s", "D", "^"]
    min_payload = min(int(row["payload_bytes"]) for row in ssh + tls)
    tls_data_min = min(int(row["payload_bytes"]) for row in tls)
    tls_data_max = max(int(row["payload_bytes"]) for row in tls)
    for idx, (limit, color) in enumerate(zip(tls_limits, colors[1:])):
        boundaries = [tls_data_min]
        boundaries.extend(
            multiple * limit
            for multiple in range(tls_data_min // limit + 1, tls_data_max // limit + 1)
            if multiple * limit > tls_data_min
        )
        if boundaries[-1] < tls_data_max:
            boundaries.append(tls_data_max)
        counts = [(payload + limit - 1) // limit for payload in boundaries]
        ax_tls.step(
            boundaries,
            counts,
            where="post",
            color=color,
            linestyle="--",
            linewidth=1.2,
            label=(
                f"R = {limit / 1_000_000:g} MB"
                if limit % 1_000_000 == 0
                else f"R = {limit / 1000:g} kB"
            ),
        )
        points = sorted(
            (int(row["payload_bytes"]), int(row["E_measured"]))
            for row in tls
            if int(row["rotation_bytes"]) == limit
        )
        ax_tls.scatter(
            *zip(*points),
            color=color,
            marker=tls_markers[idx],
            s=28,
            edgecolors="black",
            linewidths=0.45,
            zorder=3,
        )

    for ax, title in (
        (ax_ssh, "SSH: measured exchanges"),
        (ax_tls, "TLS 1.3: model and measurements"),
    ):
        ax.axhline(1, color="0.5", linestyle=":", linewidth=0.9)
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_ylim(0.8, 140)
        ax.tick_params(axis="both", labelsize=7)
        ax.set_title(title, fontsize=9, pad=8)
        ax.grid(which="both", alpha=0.2)
    ax_ssh.set_xlim(min_payload / 1.3, 1e7)
    # A small log-space pad keeps endpoint marker strokes inside the axes.
    ax_tls.set_xlim(tls_data_min / 1.05, tls_data_max * 1.10)
    fig.supylabel("Fresh key exchanges, $E$", x=0.07, fontsize=8)
    ax_tls.set_xlabel("Payload P (bytes)", fontsize=8)
    ax_ssh.legend(title="RekeyLimit", fontsize=6, title_fontsize=6, loc="upper left")
    ax_tls.legend(
        title="Rotation interval", fontsize=7, title_fontsize=7, loc="upper left"
    )

    fig.subplots_adjust(left=0.25, right=0.98, bottom=0.10, top=0.96, hspace=0.40)
    outdir.mkdir(parents=True, exist_ok=True)
    fig.savefig(
        outdir / "mitigation_rekey_E.pdf",
        bbox_inches="tight",
        metadata={"CreationDate": None},
    )
    plt.close(fig)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=Path("analysis/results"))
    parser.add_argument("--outdir", type=Path, default=Path("analysis/figures"))
    args = parser.parse_args()
    plot_counts(args.results_dir, args.outdir)
