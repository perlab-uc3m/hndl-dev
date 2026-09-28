#!/usr/bin/env python3
"""Work and ideal elapsed time for equal-duration quantum recovery jobs.

These are scheduling scenarios, not hardware or cryptanalytic lower bounds.
"""
import argparse
import csv
from pathlib import Path

import numpy as np


def recovery_cost(jobs: int, workers: int, time_per_job: float = 1.0, *, chain=False):
    """Return processor time and elapsed time for independent jobs or one chain.

    Each worker supplies all qubits and magic-state throughput for one job.
    Classical decryption, communication, and queueing are omitted.
    """
    if jobs < 1 or int(jobs) != jobs or workers < 1 or int(workers) != workers:
        raise ValueError("positive integer job and worker counts required")
    if not np.isfinite(time_per_job) or time_per_job <= 0:
        raise ValueError("time per job must be finite and positive")
    work = jobs * time_per_job
    waves = jobs if chain else (jobs + workers - 1) // workers
    return work, waves * time_per_job


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=Path("analysis/results"))
    args = parser.parse_args()
    args.results_dir.mkdir(parents=True, exist_ok=True)
    workers = np.arange(1, 65)
    rows = []
    for m in workers:
        work, independent = recovery_cost(37, int(m))
        _, chain = recovery_cost(37, int(m), chain=True)
        rows.append(
            {
                "jobs": 37,
                "workers": m,
                "work_over_Tq": work,
                "independent_time_over_Tq": independent,
                "chain_time_over_Tq": chain,
            }
        )
    with (args.results_dir / "quantum_parallelism.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
