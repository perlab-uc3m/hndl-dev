#!/usr/bin/env python3
"""Effective quantum multiplier under partial transcript extraction.

E_eff(L, R) = ceil(L / R) when the adversary targets only the first L
bytes.  Generates a heatmap across realistic (L, R) combinations.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import matplotlib.ticker as mticker
import numpy as np

# ---------------------------------------------------------------------------
# Plot style (matches project palette)
# ---------------------------------------------------------------------------
plt.rcParams["font.family"] = "Ubuntu"
plt.rcParams["pdf.fonttype"] = 42
plt.rcParams["ps.fonttype"] = 42

_CMAP = mcolors.LinearSegmentedColormap.from_list("", ["#9fcf69", "#33acdc"])


def _style_ax(ax):
    ax.tick_params(axis="both", labelsize=14)


def _fmt_bytes(x, _=None):
    """Format byte values for axis ticks."""
    if x >= 1e6:
        return f"{x / 1e6:.0f} MB"
    if x >= 1e3:
        return f"{x / 1e3:.0f} KB"
    return f"{x:.0f} B"


def generate_figure(outdir: Path) -> Path:
    """Heatmap of E_eff(L, R) with contour overlay."""

    # -----------------------------------------------------------------------
    # Axis ranges.  R_min = 2 KB (per-rekey overhead floor).
    # L_min = 500 B (minimum meaningful adversary target).
    # -----------------------------------------------------------------------
    R_MIN = 2e3
    R_MAX = 10e6
    L_MIN = 500
    L_MAX = 5e6

    n = 300
    L_vals = np.logspace(np.log10(L_MIN), np.log10(L_MAX), n)
    R_vals = np.logspace(np.log10(R_MIN), np.log10(R_MAX), n)

    L_grid, R_grid = np.meshgrid(L_vals, R_vals)
    E_eff = np.ceil(L_grid / R_grid)
    E_eff = np.clip(E_eff, 1, None)

    fig, ax = plt.subplots(figsize=(7, 5))
    _style_ax(ax)

    # Heatmap
    norm = mcolors.LogNorm(vmin=1, vmax=500)
    im = ax.pcolormesh(
        L_vals, R_vals, E_eff, cmap=_CMAP, norm=norm, shading="auto", rasterized=True
    )

    # Contour lines at key thresholds
    contour_levels = [1, 2, 5, 10, 25, 50, 100]
    cs = ax.contour(
        L_vals,
        R_vals,
        E_eff,
        levels=contour_levels,
        colors="white",
        linewidths=0.8,
        linestyles="--",
    )

    # Place contour labels as plain text, all at the same x position.
    _label_x = 3_000_000
    _elabels = [
        (1, _label_x, _label_x / 1),
        (2, _label_x, _label_x / 2),
        (5, _label_x, _label_x / 5),
        (10, _label_x, _label_x / 10),
        (25, _label_x, _label_x / 25),
        (50, _label_x, _label_x / 50),
        (100, _label_x, _label_x / 100),
    ]
    for _e, _lx, _ry in _elabels:
        ax.text(
            _lx,
            _ry,
            f"E={_e}",
            fontsize=9,
            color="black",
            ha="center",
            va="center",
            bbox=dict(
                boxstyle="round,pad=0.1",
                facecolor="white",
                alpha=0.55,
                edgecolor="none",
            ),
        )

    # E=1 region boundary (R >= L)
    diag_L = np.logspace(np.log10(max(L_MIN, R_MIN)), np.log10(min(L_MAX, R_MAX)), 200)
    ax.plot(diag_L, diag_L, color="white", linewidth=2.0, linestyle="-")

    # Label the R=L diagonal (rotation computed after layout is finalized).
    mid = len(diag_L) // 3
    _rl_text = ax.text(
        diag_L[mid] * 1.3,
        diag_L[mid] * 1.3,
        "$R = L$  ($E_{\\mathrm{eff}}=1$)",
        fontsize=12,
        color="black",
        fontweight="bold",
        rotation=0,
        rotation_mode="anchor",
        ha="left",
        va="bottom",
        bbox=dict(
            boxstyle="round,pad=0.15", facecolor="white", alpha=0.55, edgecolor="none"
        ),
    )

    # Mark realistic adversary targets
    targets = [
        (4_000, "credentials\n(4 KB)"),
        (16_000, "first HTTP\nrequest\n(16 KB)"),
        (64_000, "first DB\nquery\n(64 KB)"),
        (256_000, "first page\nload\n(256 KB)"),
    ]
    for L_target, label in targets:
        ax.axvline(x=L_target, color="white", linewidth=0.6, alpha=0.5)
        ax.text(
            L_target,
            R_MAX * 0.75,
            label,
            fontsize=9,
            color="black",
            ha="center",
            va="top",
            alpha=0.9,
        )

    # --- Annotate the per-rekey overhead floor ---
    ax.axhline(y=3000, color="white", linewidth=1.0, linestyle=":", alpha=0.6)
    ax.text(
        L_MIN * 1.3,
        3000 * 1.15,
        "per-rekey overhead ($\\approx$3 KB)",
        fontsize=10,
        color="black",
        fontstyle="italic",
        alpha=0.85,
        va="bottom",
    )

    # Axes
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlim(L_MIN, L_MAX)
    ax.set_ylim(R_MIN, R_MAX)

    ax.set_xlabel("Adversary extraction target $L$", fontweight="bold", fontsize=15)
    ax.set_ylabel("Rekeying interval $R$", fontweight="bold", fontsize=15)

    ax.xaxis.set_major_formatter(mticker.FuncFormatter(_fmt_bytes))
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(_fmt_bytes))

    # Ensure the y-axis starting value (2 KB) appears as a labelled tick
    default_yticks = [t for t in ax.get_yticks() if R_MIN < t <= R_MAX]
    ax.set_yticks([R_MIN] + default_yticks)
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(_fmt_bytes))

    # Colorbar
    cbar = fig.colorbar(im, ax=ax, pad=0.02)
    cbar.set_label("$E_{\\mathrm{eff}}$", fontsize=14, fontweight="bold")

    fig.tight_layout()

    # Compute diagonal rotation after layout is finalized.
    fig.canvas.draw()
    _p1 = ax.transData.transform((diag_L[mid], diag_L[mid]))
    _p2 = ax.transData.transform((diag_L[mid + 20], diag_L[mid + 20]))
    _angle = np.degrees(np.arctan2(_p2[1] - _p1[1], _p2[0] - _p1[0]))
    _rl_text.set_rotation(_angle)

    outpath = outdir / "mitigation_partial_E.pdf"
    fig.savefig(outpath, dpi=300, bbox_inches="tight")
    print(f"[+] Saved: {outpath}")
    plt.close(fig)
    return outpath


def print_table():
    """Print a compact table of E_eff for representative (L, R) pairs."""
    L_vals = [4_000, 16_000, 64_000, 256_000, 1_000_000, 5_000_000]
    R_vals = [10_000, 16_000, 64_000, 128_000, 1_000_000, 10_000_000]

    print(f"\n{'':>12}", end="")
    for L in L_vals:
        print(f"  L={_fmt_bytes(L):>8}", end="")
    print()
    print("-" * (14 + 12 * len(L_vals)))
    for R in R_vals:
        print(f"R={_fmt_bytes(R):>9}", end="")
        for L in L_vals:
            E = max(1, int(np.ceil(L / R)))
            print(f"  {E:>10}", end="")
        print()


def main():
    parser = argparse.ArgumentParser(description="Generate E_eff(L, R) heatmap")
    parser.add_argument("--outdir", default="paper/figures")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    outdir = repo_root / args.outdir
    outdir.mkdir(parents=True, exist_ok=True)

    generate_figure(outdir)
    print_table()


if __name__ == "__main__":
    main()
