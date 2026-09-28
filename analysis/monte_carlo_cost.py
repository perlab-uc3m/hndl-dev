#!/usr/bin/env python3
"""Conditional storage-cost scenarios, not forecasts of adversary spending.

Traffic is observed bytes, not plaintext. One price, growth rate and price
decline are drawn per scenario. Rates stay fixed along each trajectory.
"""
from __future__ import annotations

import argparse
import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

try:
    from .storage_model import (
        REFERENCE_USD_PER_TB_YEAR,
        annual_archive_tb,
        recurring_storage_cost,
    )
except ImportError:
    from storage_model import (
        REFERENCE_USD_PER_TB_YEAR,
        annual_archive_tb,
        recurring_storage_cost,
    )

RNG_SEED = 42
plt.rcParams.update({"font.family": "DejaVu Sans", "pdf.fonttype": 42})
COLORS = ["#548b37", "#83b64e", "#369faa", "#287cb8"]


@dataclass
class MCConfig:
    global_traffic_zb_year: float = 8.8
    retention_ratio: float = 1.0
    harvest_fractions: tuple[float, ...] = (0.001, 0.005, 0.01, 0.05, 0.10)
    storage_cost_tb_year: float = REFERENCE_USD_PER_TB_YEAR
    storage_cost_band: float = 0.30
    traffic_growth_lo: float = 0.20
    traffic_growth_hi: float = 0.30
    media_decline_lo: float = -0.10
    media_decline_hi: float = 0.20
    retention_years: tuple[int, ...] = (5, 10, 15)
    n_draws: int = 10_000

    def __post_init__(self):
        if self.n_draws < 1 or not self.retention_years:
            raise ValueError("positive draw count and retention horizons required")
        if any(t < 1 or int(t) != t for t in self.retention_years):
            raise ValueError("retention horizons must be positive whole years")
        if not self.harvest_fractions or any(f <= 0 for f in self.harvest_fractions):
            raise ValueError("positive harvest fractions required for log plots")
        for fraction in self.harvest_fractions:
            annual_archive_tb(
                self.global_traffic_zb_year, fraction, self.retention_ratio
            )
        values = [
            self.storage_cost_tb_year,
            self.storage_cost_band,
            self.traffic_growth_lo,
            self.traffic_growth_hi,
            self.media_decline_lo,
            self.media_decline_hi,
        ]
        if not np.isfinite(values).all():
            raise ValueError("scenario parameters must be finite")
        if self.storage_cost_tb_year <= 0 or not 0 <= self.storage_cost_band < 1:
            raise ValueError("positive price and a price band in [0, 1) required")
        if not -1 < self.traffic_growth_lo <= self.traffic_growth_hi:
            raise ValueError("invalid traffic growth range")
        if not self.media_decline_lo <= self.media_decline_hi < 1:
            raise ValueError("invalid price decline range")
        if self.global_traffic_zb_year <= 0 or self.retention_ratio <= 0:
            raise ValueError("positive traffic and retention ratio required for plots")


def run_monte_carlo(cfg: MCConfig, rng: np.random.Generator):
    price = rng.uniform(
        cfg.storage_cost_tb_year * (1 - cfg.storage_cost_band),
        cfg.storage_cost_tb_year * (1 + cfg.storage_cost_band),
        cfg.n_draws,
    )
    growth = rng.uniform(cfg.traffic_growth_lo, cfg.traffic_growth_hi, cfg.n_draws)
    decline = rng.uniform(cfg.media_decline_lo, cfg.media_decline_hi, cfg.n_draws)
    years = np.arange(max(cfg.retention_years))
    prices = price[:, None] * (1 - decline[:, None]) ** years
    volume_factors = (1 + growth[:, None]) ** years
    annual, cumulative = {}, {}
    for fi, fraction in enumerate(cfg.harvest_fractions):
        base = annual_archive_tb(
            cfg.global_traffic_zb_year, fraction, cfg.retention_ratio
        )
        annual[fi] = base * price
        cohorts = base * volume_factors
        cumulative[fi] = {
            ti: recurring_storage_cost(cohorts[:, :horizon], prices[:, :horizon])
            for ti, horizon in enumerate(cfg.retention_years)
        }
    return {
        "cfg": cfg,
        "annual_cost": annual,
        "cumulative_cost": cumulative,
        "storage_cost": price,
        "growth_rate": growth,
        "media_decline": decline,
    }


def summary_rows(results):
    rows = []
    cfg = results["cfg"]
    for fi, fraction in enumerate(cfg.harvest_fractions):
        series = [(1, results["annual_cost"][fi])]
        series += [
            (h, results["cumulative_cost"][fi][ti])
            for ti, h in enumerate(cfg.retention_years)
        ]
        for horizon, costs in series:
            quantiles = np.percentile(costs, [5, 25, 50, 75, 95])
            rows.append(
                {
                    "fraction": fraction,
                    "years": horizon,
                    **dict(
                        zip(
                            ("p05_usd", "p25_usd", "median_usd", "p75_usd", "p95_usd"),
                            quantiles,
                        )
                    ),
                    "mean_usd": float(np.mean(costs)),
                }
            )
    return rows


def _save(fig, outdir, name):
    fig.tight_layout()
    fig.savefig(outdir / name, bbox_inches="tight", metadata={"CreationDate": None})
    plt.close(fig)


def plot_cumulative_cost_shaded(results, outdir):
    cfg = results["cfg"]
    fracs = np.geomspace(min(cfg.harvest_fractions), max(cfg.harvest_fractions), 250)
    ref = cfg.harvest_fractions[0]
    series = [("One cohort, one year", results["annual_cost"][0])]
    series += [
        (f"{h}-year accumulation", results["cumulative_cost"][0][ti])
        for ti, h in enumerate(cfg.retention_years)
    ]
    fig, ax = plt.subplots(figsize=(10, 5.2))
    for i, (label, values) in enumerate(series):
        q = np.percentile(values / (ref * 1e9), [5, 25, 50, 75, 95])[:, None] * fracs
        color = COLORS[i % len(COLORS)]
        ax.fill_between(100 * fracs, q[0], q[4], color=color, alpha=0.14)
        ax.fill_between(100 * fracs, q[1], q[3], color=color, alpha=0.30)
        ax.plot(100 * fracs, q[2], color=color, label=label, linewidth=2)
    ax.set(
        xscale="log",
        yscale="log",
        xlabel="Retained fraction of reference traffic",
        ylabel="Storage cost (USD billion)",
    )
    ticks = np.array(cfg.harvest_fractions) * 100
    ax.set_xticks(ticks, [f"{x:g}%" for x in ticks])
    ax.grid(which="both", alpha=0.2)
    ax.legend(loc="upper left", fontsize=10)
    note = (
        f"{cfg.n_draws:,} scenario draws; ρ={cfg.retention_ratio:g}\n"
        f"Initial price: USD {cfg.storage_cost_tb_year:.2f}/TB-year ± {100*cfg.storage_cost_band:g}%\n"
        f"Traffic growth: {100*cfg.traffic_growth_lo:g} to {100*cfg.traffic_growth_hi:g}%/year\n"
        f"Price decline δ: {100*cfg.media_decline_lo:g} to {100*cfg.media_decline_hi:g}%/year"
    )
    ax.text(
        0.98,
        0.03,
        note,
        transform=ax.transAxes,
        ha="right",
        va="bottom",
        fontsize=9,
        bbox={"facecolor": "white", "edgecolor": "0.7", "alpha": 0.95},
    )
    _save(fig, outdir, "mc_cumulative_cost.pdf")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--draws", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=RNG_SEED)
    parser.add_argument("--traffic-zb", type=float, default=8.8)
    parser.add_argument(
        "--storage-cost",
        type=float,
        default=REFERENCE_USD_PER_TB_YEAR,
        help="USD per decimal TB-year",
    )
    parser.add_argument(
        "--retention-ratio",
        type=float,
        default=1.0,
        help="archived bytes / selected observed bytes",
    )
    parser.add_argument("--outdir", type=Path, default=Path("analysis/figures"))
    parser.add_argument("--results-dir", type=Path, default=Path("analysis/results"))
    args = parser.parse_args()
    cfg = MCConfig(
        n_draws=args.draws,
        global_traffic_zb_year=args.traffic_zb,
        storage_cost_tb_year=args.storage_cost,
        retention_ratio=args.retention_ratio,
    )
    results = run_monte_carlo(cfg, np.random.default_rng(args.seed))
    args.outdir.mkdir(parents=True, exist_ok=True)
    args.results_dir.mkdir(parents=True, exist_ok=True)
    plot_cumulative_cost_shaded(results, args.outdir)
    rows = summary_rows(results)
    with (args.results_dir / "mc_storage_summary.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    metadata = {
        "seed": args.seed,
        "config": asdict(cfg),
        "numpy_version": np.__version__,
        "bit_generator": "PCG64",
        "units": "decimal TB; nominal USD; 365-day years",
        "accounting": "whole cohort charged in acquisition year; common horizon",
        "price_source": "https://aws.amazon.com/s3/pricing/",
        "price_checked": "2026-09-28",
        "billing_gib_month_usd": 0.00099,
    }
    (args.results_dir / "mc_storage_config.json").write_text(
        json.dumps(metadata, indent=2) + "\n"
    )
    for row in rows:
        if row["fraction"] == 0.01:
            print(
                f"1% harvest, {row['years']:2d} year(s): median {row['median_usd']/1e9:.3f} B USD; "
                f"P5–P95 {row['p05_usd']/1e9:.3f}–{row['p95_usd']/1e9:.3f}"
            )


if __name__ == "__main__":
    main()
