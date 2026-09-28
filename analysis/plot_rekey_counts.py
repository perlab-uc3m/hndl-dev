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
    fig, ax = plt.subplots(figsize=(7.2, 4.8))
    colors = ["#548b37", "#83b64e", "#369faa", "#287cb8"]
    limits = sorted(
        {int(row["rekey_limit_bytes"]) for row in ssh if int(row["rekey_limit_bytes"])}
    )
    # RekeyLimit is a transport counter. The capture points do not locate
    # its application-byte transitions, so do not interpolate between them.
    for limit, color in zip(limits, colors):
        pts = sorted(
            (int(r["payload_bytes"]), int(r["E"]))
            for r in ssh
            if int(r["rekey_limit_bytes"]) == limit
        )
        ax.scatter(
            *zip(*pts),
            color=color,
            marker="o",
            s=26,
            label=f"SSH {limit/1024:g} KiB nominal",
        )

    # TLS connection rotation is configured by application bytes. The model
    # E=ceil(P/R) therefore has exact step locations; markers are observations.
    maximum_payload = max(int(r["payload_bytes"]) for r in tls)
    minimum_payload = min(int(r["payload_bytes"]) for r in tls)
    for limit, color in zip(
        sorted({int(r["rotation_bytes"]) for r in tls}), colors[1:]
    ):
        boundaries = [minimum_payload]
        boundaries.extend(
            multiple * limit
            for multiple in range(1, maximum_payload // limit + 1)
            if multiple * limit > minimum_payload
        )
        if boundaries[-1] < maximum_payload:
            boundaries.append(maximum_payload)
        counts = [(payload + limit - 1) // limit for payload in boundaries]
        ax.step(
            boundaries,
            counts,
            where="pre",
            color=color,
            linestyle="--",
            linewidth=1.2,
            label=f"TLS rotation {limit/1000:g} kB",
        )
        pts = sorted(
            (int(r["payload_bytes"]), int(r["E_measured"]))
            for r in tls
            if int(r["rotation_bytes"]) == limit
        )
        ax.scatter(*zip(*pts), color=color, marker="s", s=18, zorder=3)

    ax.axhline(1, color="0.5", linestyle=":", label="Full handshake + KeyUpdate")
    ax.set(
        xscale="log",
        yscale="log",
        xlabel="Application payload (bytes)",
        ylabel="Fresh key exchanges, E",
    )
    ax.grid(which="both", alpha=0.2)
    ax.legend(fontsize=8, ncol=2, loc="upper left")
    fig.tight_layout()
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
