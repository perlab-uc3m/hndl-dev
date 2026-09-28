"""Numerical checks independent of plotting and of the paper's rounded values."""

import unittest
import numpy as np

from analysis.storage_model import (
    REFERENCE_USD_PER_TB_YEAR,
    annual_archive_tb,
    recurring_storage_cost,
)
from analysis.monte_carlo_cost import MCConfig, run_monte_carlo
from analysis.quantum_work import recovery_cost


class StorageTests(unittest.TestCase):
    def test_units(self):
        self.assertEqual(annual_archive_tb(8.8, 0.01), 88_000_000)
        self.assertAlmostEqual(REFERENCE_USD_PER_TB_YEAR * 2**30 / 1e12, 12 * 0.00099)

    def test_hand_calculated_calendar_prices(self):
        self.assertEqual(recurring_storage_cost([10, 20], [5, 4]), 170)
        self.assertEqual(recurring_storage_cost([10], [5]), 50)

    def test_constant_price_triangle(self):
        self.assertEqual(recurring_storage_cost([10] * 4, [3] * 4), 300)

    def test_independent_cohort_sum(self):
        rng = np.random.default_rng(7)
        cohorts, prices = rng.uniform(1, 100, (2, 5, 8))
        expected = [
            sum(a[i] * sum(p[i:]) for i in range(8)) for a, p in zip(cohorts, prices)
        ]
        np.testing.assert_allclose(recurring_storage_cost(cohorts, prices), expected)

    def test_monte_carlo_against_scalar_double_sum(self):
        cfg = MCConfig(n_draws=8)
        result = run_monte_carlo(cfg, np.random.default_rng(42))
        for draw in range(cfg.n_draws):
            for fi, fraction in enumerate(cfg.harvest_fractions):
                base = annual_archive_tb(cfg.global_traffic_zb_year, fraction)
                for ti, horizon in enumerate(cfg.retention_years):
                    expected = sum(
                        base
                        * (1 + result["growth_rate"][draw]) ** i
                        * sum(
                            result["storage_cost"][draw]
                            * (1 - result["media_decline"][draw]) ** j
                            for j in range(i, horizon)
                        )
                        for i in range(horizon)
                    )
                    self.assertAlmostEqual(
                        result["cumulative_cost"][fi][ti][draw] / expected, 1
                    )

    def test_scaling_and_reproducibility(self):
        first = run_monte_carlo(MCConfig(n_draws=16), np.random.default_rng(42))
        second = run_monte_carlo(
            MCConfig(n_draws=16, retention_ratio=0.5), np.random.default_rng(42)
        )
        for ti in range(3):
            np.testing.assert_allclose(
                first["cumulative_cost"][2][ti], 10 * first["cumulative_cost"][0][ti]
            )
            np.testing.assert_allclose(
                second["cumulative_cost"][2][ti], 0.5 * first["cumulative_cost"][2][ti]
            )

    def test_fixed_rates_and_one_year_boundary(self):
        cfg = MCConfig(
            n_draws=2,
            storage_cost_band=0,
            retention_years=(1, 10),
            traffic_growth_lo=0.25,
            traffic_growth_hi=0.25,
            media_decline_lo=-0.1,
            media_decline_hi=-0.1,
        )
        result = run_monte_carlo(cfg, np.random.default_rng(2))
        np.testing.assert_equal(
            result["annual_cost"][2], result["cumulative_cost"][2][0]
        )
        # Independently evaluated using the geometric-series closed form.
        base = 88_000_000 * REFERENCE_USD_PER_TB_YEAR
        expected = base / 0.25 * (1.25 * (1.375**10 - 1) / 0.375 - (1.1**10 - 1) / 0.1)
        np.testing.assert_allclose(result["cumulative_cost"][2][1], expected)

    def test_invalid_inputs(self):
        for kwargs in (
            {"n_draws": 0},
            {"media_decline_hi": 1},
            {"retention_ratio": -1},
            {"storage_cost_tb_year": float("nan")},
        ):
            with self.assertRaises(ValueError):
                MCConfig(**kwargs)


class QuantumTests(unittest.TestCase):
    def test_work_and_parallel_latency(self):
        for workers, expected in ((1, 37), (4, 10), (37, 1), (64, 1)):
            self.assertEqual(recovery_cost(37, workers), (37, expected))
            self.assertEqual(recovery_cost(37, workers, chain=True), (37, 37))

    def test_runtime_scaling(self):
        self.assertEqual(recovery_cost(37, 4, 3.8), (140.6, 38.0))


if __name__ == "__main__":
    unittest.main()
