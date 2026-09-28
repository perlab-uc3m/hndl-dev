"""Capacity-rental accounting; decimal traffic units and nominal USD."""

import numpy as np


# AWS calls 2**30 bytes a billing GB. Traffic TB below means 10**12 bytes.
AWS_USD_PER_GIB_MONTH = 0.00099
REFERENCE_USD_PER_TB_YEAR = AWS_USD_PER_GIB_MONTH * 12 * 10**12 / 2**30


def annual_archive_tb(traffic_zb, fraction, retention_ratio=1.0):
    """Convert observed traffic to archive TB without adding payload overhead."""
    if not np.isfinite([traffic_zb, fraction, retention_ratio]).all():
        raise ValueError("archive inputs must be finite")
    if traffic_zb < 0 or not 0 <= fraction <= 1 or retention_ratio < 0:
        raise ValueError("invalid traffic, fraction, or retention ratio")
    return traffic_zb * 1e9 * fraction * retention_ratio


def recurring_storage_cost(cohorts, prices):
    """Charge all retained TB at each year's USD/(TB year) price.

    The final axis is calendar year; leading axes may contain Monte Carlo
    draws. A whole new cohort is charged in its acquisition year. No cohort
    expires before the common horizon. There is no discounting or retrieval.
    """
    cohorts, prices = np.broadcast_arrays(
        np.asarray(cohorts, dtype=float), np.asarray(prices, dtype=float)
    )
    if cohorts.ndim == 0 or cohorts.shape[-1] == 0:
        raise ValueError("at least one storage year is required")
    if not (np.isfinite(cohorts).all() and np.isfinite(prices).all()):
        raise ValueError("cohorts and prices must be finite")
    if (cohorts < 0).any() or (prices < 0).any():
        raise ValueError("cohorts and prices must be non-negative")
    return np.sum(np.cumsum(cohorts, axis=-1) * prices, axis=-1)
