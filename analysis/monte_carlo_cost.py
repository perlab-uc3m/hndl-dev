#!/usr/bin/env python3
"""Monte Carlo sensitivity analysis for HN-DL harvest cost.

Parameterises the deterministic model from cost_analysis.py with
distributional inputs and runs N draws to produce annual and
cumulative harvest-cost estimates.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import numpy as np

# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------
RNG_SEED = 42

# ---------------------------------------------------------------------------
# Plot style  — identical to cost_analysis.py
# ---------------------------------------------------------------------------
plt.rcParams["font.family"] = "Ubuntu"
plt.rcParams["pdf.fonttype"] = 42
plt.rcParams["ps.fonttype"] = 42

_CMAP = mcolors.LinearSegmentedColormap.from_list("", ["#9fcf69", "#33acdc"])
# 5 distinct colours for harvest-fraction groups (0.1%, 0.5%, 1%, 5%, 10%)
_N_FRACTIONS = 5
COLOR_PALETTE = [_CMAP(x) for x in np.linspace(0, 1, _N_FRACTIONS)]


def _style_ax(ax):
    ax.grid(True, linestyle="--", which="both", color="grey", alpha=0.4)
    ax.set_axisbelow(True)
    ax.tick_params(axis="both", labelsize=14)


# ===================================================================
#  Configuration — single place to tune every distributional input
# ===================================================================


@dataclass
class MCConfig:
    """All Monte Carlo parameters in one place.

    Payload: log-normal (median ≈ 2 MB, calibrated to HTTP Archive 2024).
    Storage cost: uniform band around $/TB-yr baseline.
    Traffic growth and media-cost decline: uniform draws.
    """

    # --- Session payload (log-normal in bytes) ---
    payload_log_mu: float = np.log(2e6)
    payload_log_sigma: float = 1.5

    global_traffic_zb_year: float = 8.8  # ITU 2025

    harvest_fractions: list[float] = field(
        default_factory=lambda: [0.001, 0.005, 0.01, 0.05, 0.10]
    )
    harvest_labels: list[str] = field(
        default_factory=lambda: ["0.1%", "0.5%", "1%", "5%", "10%"]
    )

    storage_cost_tb_year: float = 12.16  # AWS OpEx upper bound
    storage_cost_band: float = 0.30  # ±30% uniform
    is_capex: bool = False

    traffic_growth_lo: float = 0.20
    traffic_growth_hi: float = 0.30

    media_decline_lo: float = -0.10
    media_decline_hi: float = 0.20

    retention_years: list[int] = field(default_factory=lambda: [5, 10, 15])

    n_draws: int = 10_000


# ===================================================================
#  Core Monte Carlo engine
# ===================================================================


def _representative_alpha(payload_bytes: np.ndarray) -> np.ndarray:
    """Vectorised TLS 1.3 α (analytical model from cost_analysis.py)."""
    H = 2160.0
    n_hs = 16
    r = 5.0
    t = 16.0
    e = 1.0
    ell = 54.0
    M = 16384.0

    max_payload_per_rec = M - e  # TLSInnerPlaintext content type consumes 1 B
    n_records = np.maximum(1, np.ceil(payload_bytes / max_payload_per_rec))
    payload_per_rec = payload_bytes / n_records
    per_record = r + payload_per_rec + t + e + ell
    app_bytes = n_records * per_record
    hs_bytes = H + n_hs * ell
    total = hs_bytes + app_bytes
    return total / payload_bytes


def run_monte_carlo(cfg: MCConfig, rng: np.random.Generator):
    """Run the full Monte Carlo and return results dict."""
    n = cfg.n_draws

    # --- Draw random inputs ---
    payload = rng.lognormal(
        mean=cfg.payload_log_mu, sigma=cfg.payload_log_sigma, size=n
    )
    payload = np.clip(payload, 100, 1e9)

    cost_lo = cfg.storage_cost_tb_year * (1 - cfg.storage_cost_band)
    cost_hi = cfg.storage_cost_tb_year * (1 + cfg.storage_cost_band)
    storage_cost = rng.uniform(cost_lo, cost_hi, size=n)

    growth_rate = rng.uniform(cfg.traffic_growth_lo, cfg.traffic_growth_hi, size=n)
    media_decline = rng.uniform(cfg.media_decline_lo, cfg.media_decline_hi, size=n)

    alpha = _representative_alpha(payload)
    global_bytes_per_day = cfg.global_traffic_zb_year * 1e21 / 365.0
    sessions_per_day = global_bytes_per_day / payload

    # --- Annual cost for each harvest fraction ---
    annual_cost = {}
    for fi, frac in enumerate(cfg.harvest_fractions):
        # Annual stored bytes
        annual_stored_bytes = sessions_per_day * frac * (alpha * payload) * 365.0
        annual_stored_tb = annual_stored_bytes / 1e12
        annual_cost[fi] = annual_stored_tb * storage_cost

    # --- Cumulative cost over retention horizons ---
    cumulative_cost = {}
    for fi, frac in enumerate(cfg.harvest_fractions):
        cumulative_cost[fi] = {}
        for ti, T_r in enumerate(cfg.retention_years):
            # Calendar-year accounting.  Under recurring capacity rental, all
            # retained cohorts are charged at that calendar year's unit price;
            # acquisition-year pricing cannot be frozen for a cohort's life.
            cum = np.zeros(n)
            # V_0 = annual stored TB for base year
            annual_stored_bytes_base = (
                sessions_per_day * frac * (alpha * payload) * 365.0
            )
            V_0 = annual_stored_bytes_base / 1e12  # TB
            C_0 = storage_cost  # $/TB

            inventory = np.zeros(n)
            for year in range(T_r):
                V_i = V_0 * (1 + growth_rate) ** year
                C_i = C_0 * (1 - media_decline) ** year
                if cfg.is_capex:
                    cum += V_i * C_i
                else:
                    inventory += V_i
                    cum += inventory * C_i

            cumulative_cost[fi][ti] = cum

    return {
        "annual_cost": annual_cost,
        "cumulative_cost": cumulative_cost,
        "payload": payload,
        "alpha": alpha,
        "storage_cost": storage_cost,
        "growth_rate": growth_rate,
        "media_decline": media_decline,
        "cfg": cfg,
    }


# ===================================================================
#  Plotting
# ===================================================================


def plot_annual_cost_violin(results: dict, outdir: Path) -> Path:
    """Violin plot: annual harvest cost ($B/yr) per harvest fraction."""
    cfg = results["cfg"]
    fig, ax = plt.subplots(figsize=(10, 6))
    _style_ax(ax)

    data = []
    positions = []
    colors = []
    for fi, (frac, label) in enumerate(zip(cfg.harvest_fractions, cfg.harvest_labels)):
        cost_b = results["annual_cost"][fi] / 1e9  # $ → $B
        data.append(cost_b)
        positions.append(fi)
        colors.append(COLOR_PALETTE[fi])

    parts = ax.violinplot(
        data,
        positions=positions,
        showmeans=False,
        showmedians=False,
        showextrema=False,
    )
    for i, body in enumerate(parts["bodies"]):
        body.set_facecolor(colors[i])
        body.set_edgecolor("black")
        body.set_alpha(0.75)
        body.set_linewidth(0.8)

    # Overlay box plots for quartiles + median
    bp = ax.boxplot(
        data,
        positions=positions,
        widths=0.12,
        patch_artist=True,
        showfliers=False,
        medianprops=dict(color="white", linewidth=2),
        boxprops=dict(linewidth=0.8),
        whiskerprops=dict(linewidth=0.8),
        capprops=dict(linewidth=0.8),
    )
    for i, patch in enumerate(bp["boxes"]):
        patch.set_facecolor(colors[i])
        patch.set_alpha(0.9)

    # Add median annotations
    for fi in range(len(cfg.harvest_fractions)):
        med = np.median(data[fi])
        q25, q75 = np.percentile(data[fi], [25, 75])
        ax.annotate(
            f"${med:,.1f}B",
            xy=(fi, med),
            xytext=(0.35, 0),
            textcoords="offset fontsize",
            fontsize=12,
            fontweight="bold",
            color=colors[fi],
            va="center",
        )

    ax.set_xticks(positions)
    ax.set_xticklabels(cfg.harvest_labels, fontsize=15)
    ax.set_xlabel(
        "Harvest fraction of global encrypted traffic", fontweight="bold", fontsize=15
    )
    ax.set_ylabel(
        "Annual harvest cost (\\$B/year)", fontweight="bold", fontsize=15, labelpad=15
    )
    ax.set_title(
        f"Monte Carlo sensitivity: annual HN-DL cost " f"({cfg.n_draws:,} draws)",
        fontweight="bold",
        fontsize=17,
        pad=15,
    )
    ax.set_yscale("log")

    # Add parameter annotation box
    med_payload = np.exp(cfg.payload_log_mu)
    ann_text = (
        f"Session payload: log-normal "
        f"(median {med_payload/1e6:.1f} MB, σ={cfg.payload_log_sigma})\n"
        f"Storage cost: \\${cfg.storage_cost_tb_year}/TB-yr "
        f"± {cfg.storage_cost_band*100:.0f}%\n"
        f"Global traffic: {cfg.global_traffic_zb_year} ZB/yr"
    )
    ax.text(
        0.02,
        0.98,
        ann_text,
        transform=ax.transAxes,
        fontsize=11,
        verticalalignment="top",
        bbox=dict(
            boxstyle="round,pad=0.4", facecolor="white", edgecolor="grey", alpha=0.85
        ),
    )

    fig.tight_layout()
    outpath = outdir / "mc_annual_cost.pdf"
    fig.savefig(outpath, dpi=300, bbox_inches="tight")
    print(f"[+] Saved: {outpath}")
    plt.close(fig)
    return outpath


def plot_cumulative_cost_shaded(results: dict, outdir: Path) -> Path:
    """Fan-chart ribbon plot: cumulative cost vs. harvest fraction.

    Nested percentile bands (90%, 50%) plus median line, one layer per
    retention horizon T_r.
    """
    cfg = results["cfg"]

    # Four series: Annual (1 yr), T_r = 5, 10, 15 yr
    _cmap = mcolors.LinearSegmentedColormap.from_list("", ["#9fcf69", "#33acdc"])
    _all_years = [1] + list(cfg.retention_years)  # [1, 5, 10, 15]
    _norm = [y / max(_all_years) for y in _all_years]  # [0.067, 0.33, 0.67, 1.0]
    _all_colors = [_cmap(t) for t in _norm]
    annual_color = _all_colors[0]
    tr_colors = _all_colors[1:]

    # --- Continuous harvest-fraction axis ---
    frac_min, frac_max = 0.001, 0.10  # 0.1 % – 10 %
    fracs = np.logspace(np.log10(frac_min), np.log10(frac_max), 300)
    frac_pct = fracs * 100  # for the x-axis label

    # Use the 1% reference bucket to derive per-draw "unit cost"
    ref_fi = 2  # index of 1 % in harvest_fractions
    ref_frac = cfg.harvest_fractions[ref_fi]

    fig, ax = plt.subplots(figsize=(11, 6))
    _style_ax(ax)

    # Plot from largest T_r (back) to smallest (front)
    for ti in reversed(range(len(cfg.retention_years))):
        T_r = cfg.retention_years[ti]
        color = tr_colors[ti]

        # Per-draw unit cost ($B per unit fraction)
        unit_cost = results["cumulative_cost"][ref_fi][ti] / (1e9 * ref_frac)

        # Percentile profiles across the continuous fraction axis
        p5 = np.percentile(unit_cost, 5) * fracs
        p25 = np.percentile(unit_cost, 25) * fracs
        p50 = np.median(unit_cost) * fracs
        p75 = np.percentile(unit_cost, 75) * fracs
        p95 = np.percentile(unit_cost, 95) * fracs

        # Outer band  (5th–95th percentile)
        ax.fill_between(frac_pct, p5, p95, alpha=0.18, color=color, linewidth=0)
        # Inner band  (25th–75th percentile)
        ax.fill_between(frac_pct, p25, p75, alpha=0.35, color=color, linewidth=0)
        # Median line
        ax.plot(
            frac_pct,
            p50,
            color=color,
            linewidth=2.5,
            label=f"Cumulative, $T_r$ = {T_r} yr",
            zorder=4,
        )

    # --- Annual cost ribbon (front-most) ---
    unit_annual = results["annual_cost"][ref_fi] / (1e9 * ref_frac)

    p5_a = np.percentile(unit_annual, 5) * fracs
    p25_a = np.percentile(unit_annual, 25) * fracs
    p50_a = np.median(unit_annual) * fracs
    p75_a = np.percentile(unit_annual, 75) * fracs
    p95_a = np.percentile(unit_annual, 95) * fracs

    ax.fill_between(frac_pct, p5_a, p95_a, alpha=0.18, color=annual_color, linewidth=0)
    ax.fill_between(frac_pct, p25_a, p75_a, alpha=0.35, color=annual_color, linewidth=0)
    ax.plot(
        frac_pct, p50_a, color=annual_color, linewidth=2.5, label="Annual", zorder=4
    )

    # --- Error-bar markers at simulated harvest fractions ---
    _markers = ["o", "s", "D"]  # one per T_r (annual uses "^")
    for ti in range(len(cfg.retention_years)):
        color = tr_colors[ti]
        for fi, frac in enumerate(cfg.harvest_fractions):
            cost_b = results["cumulative_cost"][fi][ti] / 1e9
            med = np.median(cost_b)
            p5 = np.percentile(cost_b, 5)
            p95 = np.percentile(cost_b, 95)
            ax.errorbar(
                frac * 100,
                med,
                yerr=[[med - p5], [p95 - med]],
                fmt=_markers[ti % len(_markers)],
                color=color,
                markeredgecolor="black",
                markeredgewidth=0.7,
                markersize=5,
                ecolor="black",
                elinewidth=0.9,
                capsize=3,
                capthick=0.9,
                zorder=7,
            )

    # Annual cost error-bar markers
    for fi, frac in enumerate(cfg.harvest_fractions):
        cost_b = results["annual_cost"][fi] / 1e9
        med = np.median(cost_b)
        p5 = np.percentile(cost_b, 5)
        p95 = np.percentile(cost_b, 95)
        ax.errorbar(
            frac * 100,
            med,
            yerr=[[med - p5], [p95 - med]],
            fmt="^",
            color=annual_color,
            markeredgecolor="black",
            markeredgewidth=0.7,
            markersize=5,
            ecolor="black",
            elinewidth=0.9,
            capsize=3,
            capthick=0.9,
            zorder=7,
        )

    # --- Formatting ---
    ax.set_xscale("log")
    ax.set_yscale("log")

    # Nice percentage tick labels
    xtick_vals = [0.1, 0.5, 1, 5, 10]
    ax.set_xticks(xtick_vals)
    ax.set_xticklabels(
        [f"{v}%" if v >= 1 else f"{v}%" for v in xtick_vals], fontsize=14
    )
    ax.set_xlim(frac_pct[0] * 0.7, frac_pct[-1] * 1.4)

    ax.set_xlabel(
        "Harvest fraction of global encrypted traffic", fontweight="bold", fontsize=15
    )
    ax.set_ylabel("HN-DL cost (\\$B)", fontweight="bold", fontsize=15, labelpad=15)
    ax.set_title(
        f"Monte Carlo HN-DL cost sensitivity " f"({cfg.n_draws:,} draws)",
        fontweight="bold",
        fontsize=17,
        pad=15,
    )

    # Legend (ordered: Annual, then T_r ascending)
    handles, labels = ax.get_legend_handles_labels()
    tr_h, tr_l = handles[:-1], labels[:-1]
    ann_h, ann_l = handles[-1:], labels[-1:]
    ordered_h = ann_h + tr_h[::-1]
    ordered_l = ann_l + tr_l[::-1]
    ax.legend(
        ordered_h,
        ordered_l,
        fontsize=13,
        loc="upper left",
        framealpha=0.9,
        edgecolor="black",
    )

    # Parameter annotation box
    med_payload = np.exp(cfg.payload_log_mu)
    ann_text = (
        f"σ={cfg.payload_log_sigma})\n"
        f"Storage: \\${cfg.storage_cost_tb_year}/TB-yr "
        f"± {cfg.storage_cost_band*100:.0f}%\n"
        f"Traffic growth: "
        f"{cfg.traffic_growth_lo*100:.0f}–"
        f"{cfg.traffic_growth_hi*100:.0f}%/yr\n"
        f"Media cost Δ: "
        f"{cfg.media_decline_lo*100:+.0f} to "
        f"{cfg.media_decline_hi*100:+.0f}%/yr"
    )
    ax.text(
        0.98,
        0.03,
        ann_text,
        transform=ax.transAxes,
        fontsize=10,
        verticalalignment="bottom",
        horizontalalignment="right",
        bbox=dict(
            boxstyle="round,pad=0.4", facecolor="white", edgecolor="grey", alpha=0.85
        ),
    )

    fig.tight_layout()
    outpath = outdir / "mc_cumulative_cost.pdf"
    fig.savefig(outpath, dpi=300, bbox_inches="tight")
    print(f"[+] Saved: {outpath}")
    plt.close(fig)
    return outpath


def print_summary_table(results: dict):
    """Print summary to stdout."""
    cfg = results["cfg"]

    print("\n" + "=" * 72)
    print("Monte Carlo Sensitivity Analysis — Summary")
    print("=" * 72)

    # Input distribution summary
    payload = results["payload"]
    print(f"\nInput distributions ({cfg.n_draws:,} draws):")
    print(
        f"  Session payload  : median {np.median(payload)/1e6:.2f} MB, "
        f"mean {np.mean(payload)/1e6:.2f} MB, "
        f"P5={np.percentile(payload, 5)/1e3:.0f} KB, "
        f"P95={np.percentile(payload, 95)/1e6:.1f} MB"
    )
    print(
        f"  Storage α        : median {np.median(results['alpha']):.3f}, "
        f"mean {np.mean(results['alpha']):.3f}, "
        f"P5={np.percentile(results['alpha'], 5):.3f}, "
        f"P95={np.percentile(results['alpha'], 95):.2f}"
    )
    print(
        f"  Storage cost     : U({cfg.storage_cost_tb_year*(1-cfg.storage_cost_band):.1f}, "
        f"{cfg.storage_cost_tb_year*(1+cfg.storage_cost_band):.1f}) $/TB-yr"
    )
    print(
        f"  Traffic growth   : U({cfg.traffic_growth_lo*100:.0f}%, "
        f"{cfg.traffic_growth_hi*100:.0f}%)"
    )
    print(
        f"  Media cost Δ     : U({cfg.media_decline_lo*100:+.0f}%, "
        f"{cfg.media_decline_hi*100:+.0f}%)"
    )

    # Annual cost table
    print(f"\n{'Harvest':<10} {'Median':>12} {'Mean':>12} {'P5':>12} {'P95':>12}")
    print("-" * 60)
    for fi, (frac, label) in enumerate(zip(cfg.harvest_fractions, cfg.harvest_labels)):
        c = results["annual_cost"][fi] / 1e9
        print(
            f"{label:<10} ${np.median(c):>10,.1f}B ${np.mean(c):>10,.1f}B "
            f"${np.percentile(c, 5):>10,.1f}B ${np.percentile(c, 95):>10,.1f}B"
        )

    # Cumulative cost table
    for ti, T_r in enumerate(cfg.retention_years):
        print(f"\nCumulative cost — T_r = {T_r} years:")
        print(f"{'Harvest':<10} {'Median':>12} {'Mean':>12} {'P5':>12} {'P95':>12}")
        print("-" * 60)
        for fi, (frac, label) in enumerate(
            zip(cfg.harvest_fractions, cfg.harvest_labels)
        ):
            c = results["cumulative_cost"][fi][ti] / 1e9
            print(
                f"{label:<10} ${np.median(c):>10,.1f}B ${np.mean(c):>10,.1f}B "
                f"${np.percentile(c, 5):>10,.1f}B ${np.percentile(c, 95):>10,.1f}B"
            )


# ===================================================================
#  CLI
# ===================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Monte Carlo sensitivity analysis for HN-DL harvest cost"
    )
    parser.add_argument(
        "--draws",
        type=int,
        default=10_000,
        help="Number of Monte Carlo draws (default: 10,000)",
    )
    parser.add_argument(
        "--outdir",
        default="paper/figures",
        help="Output directory for figures (default: paper/figures)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=RNG_SEED,
        help=f"RNG seed for reproducibility (default: {RNG_SEED})",
    )
    # Allow overriding key parameters from CLI for quick experiments
    parser.add_argument(
        "--payload-mu",
        type=float,
        default=None,
        help="Override payload_log_mu (ln-bytes)",
    )
    parser.add_argument(
        "--payload-sigma",
        type=float,
        default=None,
        help="Override payload_log_sigma",
    )
    parser.add_argument(
        "--traffic-zb",
        type=float,
        default=None,
        help="Override global traffic (ZB/year)",
    )
    parser.add_argument(
        "--storage-cost",
        type=float,
        default=None,
        help="Override baseline storage cost ($/TB-year)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    outdir = repo_root / args.outdir
    outdir.mkdir(parents=True, exist_ok=True)

    cfg = MCConfig(n_draws=args.draws)
    if args.payload_mu is not None:
        cfg.payload_log_mu = args.payload_mu
    if args.payload_sigma is not None:
        cfg.payload_log_sigma = args.payload_sigma
    if args.traffic_zb is not None:
        cfg.global_traffic_zb_year = args.traffic_zb
    if args.storage_cost is not None:
        cfg.storage_cost_tb_year = args.storage_cost

    rng = np.random.default_rng(args.seed)

    print(f"Running Monte Carlo with {cfg.n_draws:,} draws (seed={args.seed})...")
    results = run_monte_carlo(cfg, rng)

    plot_annual_cost_violin(results, outdir)
    plot_cumulative_cost_shaded(results, outdir)
    print_summary_table(results)


if __name__ == "__main__":
    main()
