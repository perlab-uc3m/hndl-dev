"""Shared measurement primitives for HN-DL analysis experiments."""

from pathlib import Path

from decryptor.io import run_tshark


def pcap_total_bytes(pcap_path: Path, skip_pure_acks: bool = True) -> int:
    """Sum captured frame lengths, optionally excluding pure TCP ACKs."""
    command = [
        "tshark",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-e",
        "frame.len",
        "-e",
        "tcp.len",
    ]
    result = run_tshark(command, pcap_path)
    if result.returncode != 0:
        raise RuntimeError(result.stderr or "tshark failed while measuring PCAP")

    total = 0
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if not fields or not fields[0].strip().isdigit():
            continue
        frame_length = int(fields[0].strip())
        tcp_length = fields[1].strip() if len(fields) > 1 else ""
        # tcp.len is empty for non-TCP frames, so UDP traffic is retained.
        if skip_pure_acks and tcp_length.isdigit() and int(tcp_length) == 0:
            continue
        total += frame_length
    return total
