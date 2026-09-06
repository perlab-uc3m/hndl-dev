import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from analysis.common import pcap_total_bytes


class PcapAccountingTests(unittest.TestCase):
    def test_excludes_tcp_acks_but_keeps_udp(self):
        output = "60\t0\n100\t46\n120\t\n"
        completed = subprocess.CompletedProcess([], 0, output, "")
        with patch("analysis.common.run_tshark", return_value=completed):
            self.assertEqual(pcap_total_bytes(Path("capture.pcapng")), 220)

    def test_can_include_all_frames(self):
        output = "60\t0\n100\t46\n"
        completed = subprocess.CompletedProcess([], 0, output, "")
        with patch("analysis.common.run_tshark", return_value=completed):
            self.assertEqual(
                pcap_total_bytes(Path("capture.pcapng"), skip_pure_acks=False),
                160,
            )


if __name__ == "__main__":
    unittest.main()
