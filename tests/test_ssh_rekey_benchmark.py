import tempfile
import unittest
from pathlib import Path

from scripts.ssh_rekey_benchmark import (
    attach_rekey_diagnostics,
    observed_rekeys,
    parse_time_file,
    percentile,
    summarize,
)


class BenchmarkAccountingTests(unittest.TestCase):
    def test_percentile_interpolates_and_rejects_empty_input(self):
        self.assertEqual(percentile([1, 2, 3, 4, 5], 0.95), 4.8)
        with self.assertRaises(ValueError):
            percentile([], 0.5)

    def test_gnu_time_and_rekey_logs_are_parsed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metrics = root / "client.time"
            metrics.write_text(
                "user_seconds=1.25\n"
                "system_seconds=0.50\n"
                "max_rss_kib=4096\n"
                "voluntary_context_switches=7\n"
                "involuntary_context_switches=2\n"
            )
            parsed = parse_time_file(metrics)
            self.assertEqual(parsed["cpu_seconds"], 1.75)
            log = root / "ssh.log"
            log.write_bytes(b"SSH2_MSG_NEWKEYS sent\n" * 4)
            self.assertEqual(observed_rekeys(log), 3)

    def test_summary_compares_matched_limit_to_default(self):
        samples = [
            {
                "workload": "bulk",
                "nominal_rtt_ms": 20,
                "rekey_limit": "default",
                "elapsed_seconds": 2.0,
                "throughput_mib_s": 10.0,
                "endpoint_cpu_seconds": 1.0,
                "observed_rekeys": 0,
            },
            {
                "workload": "bulk",
                "nominal_rtt_ms": 20,
                "rekey_limit": "64K",
                "elapsed_seconds": 2.5,
                "throughput_mib_s": 8.0,
                "endpoint_cpu_seconds": 1.5,
                "observed_rekeys": 3,
            },
        ]
        rows = summarize(samples)
        aggressive = next(row for row in rows if row["rekey_limit"] == "64K")
        self.assertAlmostEqual(
            aggressive["throughput_mib_s_mean_vs_default_percent"], -20.0
        )
        self.assertAlmostEqual(
            aggressive["endpoint_cpu_seconds_mean_vs_default_percent"], 50.0
        )
        attach_rekey_diagnostics(
            rows,
            [
                {
                    "workload": "bulk",
                    "nominal_rtt_ms": 20,
                    "rekey_limit": "64K",
                    "observed_rekeys": 7,
                }
            ],
        )
        self.assertEqual(aggressive["diagnostic_observed_rekeys"], 7)


if __name__ == "__main__":
    unittest.main()
