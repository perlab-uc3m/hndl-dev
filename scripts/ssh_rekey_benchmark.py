#!/usr/bin/env python3
"""Benchmark OpenSSH rekey overhead with bulk and interactive workloads."""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import re
import select
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from capture.common import now_ts, version_output
from capture.ssh.capture_ssh import (
    generate_host_key,
    generate_user_key,
    write_sshd_config,
)
from experiment import ConfigurationError, normalize_ssh_rekey_limit, sha256_file


TIME_FORMAT = "\n".join(
    (
        "user_seconds=%U",
        "system_seconds=%S",
        "max_rss_kib=%M",
        "voluntary_context_switches=%w",
        "involuntary_context_switches=%c",
    )
)
TIME_INTEGER_FIELDS = {
    "max_rss_kib",
    "voluntary_context_switches",
    "involuntary_context_switches",
}
NEWKEYS_SENT_RE = re.compile(rb"SSH2_MSG_NEWKEYS sent")
MAX_INTERACTIVE_LINE_BYTES = 32769


@dataclass
class DelayedRelay:
    """Forward one TCP connection with a disclosed per-read one-way delay."""

    public_port: int
    backend_port: int
    one_way_delay_seconds: float
    log_path: Path

    def __post_init__(self) -> None:
        self.ready = threading.Event()
        self.finished = threading.Event()
        self.errors: list[str] = []
        self._stop = threading.Event()
        self._sockets: list[socket.socket] = []
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._started = False

    def start(self) -> None:
        self._thread.start()
        self._started = True
        if not self.ready.wait(timeout=5):
            raise RuntimeError("SSH delay relay did not become ready")
        if self.errors:
            raise RuntimeError(self.errors[0])

    def stop(self) -> None:
        self._stop.set()
        for connection in list(self._sockets):
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass
        if self._started:
            self._thread.join(timeout=3)

    def _pump(self, source: socket.socket, destination: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                chunk = source.recv(65536)
            except OSError:
                return
            if not chunk:
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return
            if self.one_way_delay_seconds:
                time.sleep(self.one_way_delay_seconds)
            try:
                destination.sendall(chunk)
            except OSError:
                return

    def _run(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sockets.append(listener)
        try:
            listener.bind(("127.0.0.1", self.public_port))
            listener.listen(1)
            listener.settimeout(0.2)
            self.ready.set()
            downstream = None
            while downstream is None and not self._stop.is_set():
                try:
                    downstream, _ = listener.accept()
                except socket.timeout:
                    continue
            if downstream is None:
                return
            upstream = socket.create_connection(
                ("127.0.0.1", self.backend_port), timeout=5
            )
            self._sockets.extend((downstream, upstream))
            pumps = (
                threading.Thread(
                    target=self._pump, args=(downstream, upstream), daemon=True
                ),
                threading.Thread(
                    target=self._pump, args=(upstream, downstream), daemon=True
                ),
            )
            for pump in pumps:
                pump.start()
            for pump in pumps:
                pump.join()
        except Exception as exc:
            self.errors.append(str(exc))
            self.ready.set()
        finally:
            self.finished.set()
            self.log_path.write_text(
                json.dumps(
                    {
                        "model": "user-space TCP stream relay",
                        "one_way_delay_ms": self.one_way_delay_seconds * 1000,
                        "nominal_rtt_ms": self.one_way_delay_seconds * 2000,
                        "delay_granularity": "each forwarded socket read",
                        "errors": self.errors,
                    },
                    indent=2,
                )
                + "\n"
            )
            try:
                listener.close()
            except OSError:
                pass


@dataclass
class TimedInetdServer:
    """Run one quiet sshd session directly on an accepted inetd-style socket."""

    backend_port: int
    command: list[str]
    metrics_path: Path
    stderr_path: Path

    def __post_init__(self) -> None:
        self.ready = threading.Event()
        self.finished = threading.Event()
        self.errors: list[str] = []
        self.returncode: int | None = None
        self.process: subprocess.Popen | None = None
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()
        if not self.ready.wait(timeout=5):
            raise RuntimeError("inetd-style benchmark listener did not become ready")
        if self.errors:
            raise RuntimeError(self.errors[0])

    def wait(self, timeout: float = 5) -> None:
        if not self.finished.wait(timeout=timeout):
            self.stop()
            raise RuntimeError("benchmark sshd did not exit after its session")
        if self.errors:
            raise RuntimeError(self.errors[0])
        # Portable sshd's inetd monitor returns 255 after an otherwise clean
        # authenticated disconnect. The caller reaches this point only after
        # the client succeeded and the complete application result was checked.
        if self.returncode not in {0, 255}:
            detail = self.stderr_path.read_text(errors="replace")
            raise RuntimeError(
                f"benchmark sshd exited with status {self.returncode}: {detail}"
            )

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        if self.process is not None:
            _terminate_group(self.process)
        self._thread.join(timeout=3)

    def _run(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.settimeout(0.2)
        self._listener = listener
        connection = None
        try:
            listener.bind(("127.0.0.1", self.backend_port))
            listener.listen(1)
            self.ready.set()
            while connection is None and not self._stop.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
            if connection is None:
                return
            with self.stderr_path.open("wb") as stderr:
                self.process = subprocess.Popen(
                    _timed(self.command, self.metrics_path),
                    stdin=connection,
                    stdout=connection,
                    stderr=stderr,
                    start_new_session=True,
                )
                connection.close()
                connection = None
                self.returncode = self.process.wait()
        except Exception as exc:
            self.errors.append(str(exc))
            self.ready.set()
        finally:
            if connection is not None:
                connection.close()
            listener.close()
            self.finished.set()


def percentile(values: Iterable[float], quantile: float) -> float:
    """Return a linearly interpolated sample percentile."""
    ordered = sorted(float(value) for value in values)
    if not ordered:
        raise ValueError("cannot calculate a percentile of an empty sequence")
    if not 0 <= quantile <= 1:
        raise ValueError("quantile must be between zero and one")
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def distribution(values: Iterable[float], prefix: str) -> dict[str, float]:
    """Summarize a non-empty numeric sample under stable field names."""
    sample = [float(value) for value in values]
    if not sample:
        return {}
    return {
        f"{prefix}_mean": statistics.fmean(sample),
        f"{prefix}_median": statistics.median(sample),
        f"{prefix}_p95": percentile(sample, 0.95),
        f"{prefix}_min": min(sample),
        f"{prefix}_max": max(sample),
    }


def parse_time_file(path: Path) -> dict[str, float | int]:
    """Parse the deliberately simple GNU time output used by this script."""
    metrics: dict[str, float | int] = {}
    for line in path.read_text().splitlines():
        if not line or "=" not in line:
            continue
        name, value = line.split("=", 1)
        metrics[name] = int(value) if name in TIME_INTEGER_FIELDS else float(value)
    required = {"user_seconds", "system_seconds", *TIME_INTEGER_FIELDS}
    missing = required.difference(metrics)
    if missing:
        raise RuntimeError(f"incomplete GNU time output in {path}: {sorted(missing)}")
    metrics["cpu_seconds"] = float(metrics["user_seconds"]) + float(
        metrics["system_seconds"]
    )
    return metrics


def observed_rekeys(log_path: Path) -> int:
    """Count completed rekeys, excluding the initial NEWKEYS exchange."""
    exchanges = len(NEWKEYS_SENT_RE.findall(log_path.read_bytes()))
    return max(0, exchanges - 1)


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return candidate.getsockname()[1]


def _timed(command: list[str], metrics_path: Path) -> list[str]:
    return [
        "/usr/bin/time",
        "--format",
        TIME_FORMAT,
        "--output",
        str(metrics_path),
        "--",
        *command,
    ]


def _terminate_group(process: subprocess.Popen, grace: float = 2.0) -> None:
    if process.poll() is not None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=grace)
            return
        except subprocess.TimeoutExpired:
            continue


def _drain(pipe: BinaryIO, path: Path, ready: threading.Event | None = None) -> None:
    with path.open("wb") as output:
        for line in iter(pipe.readline, b""):
            output.write(line)
            if ready is not None and b"Server listening" in line:
                ready.set()


def _base_ssh_command(
    ssh: Path,
    user_key: Path,
    port: int,
    rekey_limit: str | None,
    verbose: bool = False,
) -> list[str]:
    command = [
        str(ssh),
        "-F",
        "/dev/null",
        "-T",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        f"IdentityFile={user_key}",
        "-o",
        "BatchMode=yes",
        "-o",
        "KexAlgorithms=curve25519-sha256",
        "-o",
        "Ciphers=chacha20-poly1305@openssh.com",
        "-o",
        "HostKeyAlgorithms=ssh-ed25519",
    ]
    if verbose:
        command.insert(1, "-v")
    if rekey_limit:
        command.extend(("-o", f"RekeyLimit={rekey_limit}"))
    command.extend(
        (
            "-p",
            str(port),
            f"{os.getenv('USER', 'test')}@127.0.0.1",
        )
    )
    return command


def _start_client(
    command: list[str],
    sample_dir: Path,
    stdin: int | None = None,
) -> tuple[subprocess.Popen, threading.Thread]:
    process = subprocess.Popen(
        _timed(command, sample_dir / "client.time"),
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,
        bufsize=0,
    )
    reader = threading.Thread(
        target=_drain,
        args=(process.stderr, sample_dir / "ssh_stderr.log"),
        daemon=True,
    )
    reader.start()
    return process, reader


def _read_with_deadline(file_descriptor: int, size: int, deadline: float) -> bytes:
    """Read only when data is available, enforcing the sample deadline."""
    if size <= 0:
        raise RuntimeError("interactive response exceeds the configured bound")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("SSH workload exceeded its deadline")
    readable, _, _ = select.select([file_descriptor], [], [], remaining)
    if not readable:
        raise TimeoutError("SSH workload exceeded its deadline")
    return os.read(file_descriptor, size)


def _readline_with_deadline(file_descriptor: int, deadline: float) -> bytes:
    """Read one bounded interactive response without an unbounded pipe wait."""
    response = bytearray()
    while not response.endswith(b"\n"):
        chunk = _read_with_deadline(
            file_descriptor, MAX_INTERACTIVE_LINE_BYTES - len(response), deadline
        )
        if not chunk:
            break
        response.extend(chunk)
        if len(response) > MAX_INTERACTIVE_LINE_BYTES:
            raise RuntimeError("interactive response exceeds the configured bound")
    return bytes(response)


def _run_bulk(
    command: list[str], sample_dir: Path, payload_bytes: int, timeout: float
) -> dict:
    process, stderr_reader = _start_client(
        [*command, f"head -c {payload_bytes} /dev/zero"], sample_dir
    )
    started = time.monotonic()
    deadline = started + timeout
    chunks = 0
    received = 0
    timestamps: list[float] = []
    try:
        while True:
            chunk = _read_with_deadline(process.stdout.fileno(), 65536, deadline)
            if not chunk:
                break
            received += len(chunk)
            chunks += 1
            timestamps.append(time.monotonic())
        returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except (OSError, TimeoutError, subprocess.TimeoutExpired):
        _terminate_group(process)
        raise
    finally:
        stderr_reader.join(timeout=2)
    finished = time.monotonic()
    if returncode != 0:
        raise RuntimeError(f"bulk SSH client exited with status {returncode}")
    if received != payload_bytes:
        raise RuntimeError(
            f"bulk workload received {received}, expected {payload_bytes}"
        )
    gaps = [later - earlier for earlier, later in zip(timestamps, timestamps[1:])]
    elapsed = finished - started
    return {
        "application_bytes": received,
        "elapsed_seconds": elapsed,
        "throughput_mib_s": received / (1024 * 1024) / elapsed,
        "time_to_first_byte_seconds": timestamps[0] - started,
        "read_chunks": chunks,
        "read_gap_seconds_p95": percentile(gaps, 0.95) if gaps else 0.0,
        "read_gap_seconds_max": max(gaps, default=0.0),
    }


def _run_interactive(
    command: list[str],
    sample_dir: Path,
    rounds: int,
    message_bytes: int,
    timeout: float,
) -> dict:
    remote = "while IFS= read -r line; do printf '%s\\n' \"$line\"; done"
    process, stderr_reader = _start_client(
        [*command, remote], sample_dir, stdin=subprocess.PIPE
    )
    payload = b"x" * message_bytes + b"\n"
    started = time.monotonic()
    deadline = started + timeout
    latencies: list[float] = []
    try:
        warmup_started = time.monotonic()
        process.stdin.write(b"warmup\n")
        process.stdin.flush()
        warmup_response = _readline_with_deadline(process.stdout.fileno(), deadline)
        warmup_seconds = time.monotonic() - warmup_started
        if warmup_response != b"warmup\n":
            raise RuntimeError("interactive warm-up response was corrupted")
        for _ in range(rounds):
            exchange_started = time.monotonic()
            process.stdin.write(payload)
            process.stdin.flush()
            response = _readline_with_deadline(process.stdout.fileno(), deadline)
            latencies.append(time.monotonic() - exchange_started)
            if response != payload:
                raise RuntimeError("interactive response was corrupted")
        process.stdin.close()
        returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except (BrokenPipeError, OSError, TimeoutError, subprocess.TimeoutExpired):
        _terminate_group(process)
        raise
    finally:
        stderr_reader.join(timeout=2)
    elapsed = time.monotonic() - started
    if returncode != 0:
        raise RuntimeError(f"interactive SSH client exited with status {returncode}")
    return {
        "application_bytes": rounds * len(payload) * 2,
        "elapsed_seconds": elapsed,
        "warmup_exchange_seconds": warmup_seconds,
        "rounds": rounds,
        "message_bytes": message_bytes,
        "latency_seconds_mean": statistics.fmean(latencies),
        "latency_seconds_median": statistics.median(latencies),
        "latency_seconds_p95": percentile(latencies, 0.95),
        "latency_seconds_max": max(latencies),
    }


def _run_sample(
    sshd: Path,
    ssh: Path,
    host_key: Path,
    user_key: Path,
    auth_keys: Path,
    sample_dir: Path,
    workload: str,
    rekey_limit: str | None,
    nominal_rtt_ms: int,
    bulk_bytes: int,
    interactive_rounds: int,
    interactive_bytes: int,
    timeout: float,
    diagnostic: bool = False,
) -> dict:
    sample_dir.mkdir(parents=True)
    public_port = _available_port()
    backend_port = _available_port()
    while backend_port == public_port:
        backend_port = _available_port()
    config = write_sshd_config(
        sample_dir / "sshd_config",
        host_key,
        auth_keys,
        backend_port,
        rekey_limit,
        "DEBUG1" if diagnostic else "ERROR",
    )
    server_command = [
        str(sshd),
        "-i",
        "-e",
        "-f",
        str(config),
        "-h",
        str(host_key),
    ]
    server = TimedInetdServer(
        backend_port,
        server_command,
        sample_dir / "server.time",
        sample_dir / "sshd_stderr.log",
    )
    relay = DelayedRelay(
        public_port,
        backend_port,
        nominal_rtt_ms / 2000,
        sample_dir / "relay.json",
    )
    try:
        server.start()
        relay.start()
        client_command = _base_ssh_command(
            ssh, user_key, public_port, rekey_limit, verbose=diagnostic
        )
        if workload == "bulk":
            workload_result = _run_bulk(client_command, sample_dir, bulk_bytes, timeout)
        else:
            workload_result = _run_interactive(
                client_command,
                sample_dir,
                interactive_rounds,
                interactive_bytes,
                timeout,
            )
        relay.stop()
        server.wait(timeout=5)
        if relay.errors:
            raise RuntimeError(f"delay relay failed: {relay.errors[0]}")
        client_time = parse_time_file(sample_dir / "client.time")
        server_time = parse_time_file(sample_dir / "server.time")
        client_log = sample_dir / "ssh_stderr.log"
        result = {
            "workload": workload,
            "rekey_limit": rekey_limit or "default",
            "nominal_rtt_ms": nominal_rtt_ms,
            "diagnostic_logging": diagnostic,
            "server_returncode": server.returncode,
            **workload_result,
            "client": client_time,
            "server": server_time,
            "endpoint_cpu_seconds": float(client_time["cpu_seconds"])
            + float(server_time["cpu_seconds"]),
            "commands": {
                "sshd": server_command,
                "ssh": [*client_command, "<workload-command>"],
            },
        }
        if diagnostic:
            result["observed_rekeys"] = observed_rekeys(client_log)
        return result
    finally:
        relay.stop()
        server.stop()


def summarize(samples: list[dict]) -> list[dict]:
    """Aggregate repetitions and calculate matched default-relative effects."""
    grouped: dict[tuple[str, int, str], list[dict]] = {}
    for sample in samples:
        key = (
            str(sample["workload"]),
            int(sample["nominal_rtt_ms"]),
            str(sample["rekey_limit"]),
        )
        grouped.setdefault(key, []).append(sample)

    rows = []
    numeric_fields = (
        "elapsed_seconds",
        "throughput_mib_s",
        "time_to_first_byte_seconds",
        "read_gap_seconds_p95",
        "read_gap_seconds_max",
        "latency_seconds_mean",
        "latency_seconds_p95",
        "latency_seconds_max",
        "endpoint_cpu_seconds",
        "observed_rekeys",
    )
    for key, group in sorted(grouped.items()):
        workload, rtt, limit = key
        row = {
            "workload": workload,
            "nominal_rtt_ms": rtt,
            "rekey_limit": limit,
            "repetitions": len(group),
        }
        for field in numeric_fields:
            values = [float(sample[field]) for sample in group if field in sample]
            row.update(distribution(values, field))
        rows.append(row)

    baselines = {
        (row["workload"], row["nominal_rtt_ms"]): row
        for row in rows
        if row["rekey_limit"] == "default"
    }
    comparison_fields = (
        "elapsed_seconds_mean",
        "throughput_mib_s_mean",
        "endpoint_cpu_seconds_mean",
        "read_gap_seconds_max_mean",
        "latency_seconds_p95_mean",
        "latency_seconds_max_mean",
    )
    for row in rows:
        baseline = baselines.get((row["workload"], row["nominal_rtt_ms"]))
        if baseline is None:
            continue
        for field in comparison_fields:
            if field not in row or not baseline.get(field):
                continue
            row[f"{field}_vs_default_percent"] = (
                (float(row[field]) / float(baseline[field])) - 1
            ) * 100
    return rows


def attach_rekey_diagnostics(rows: list[dict], diagnostics: list[dict]) -> None:
    """Attach separately observed rekey counts without timing verbose runs."""
    observed = {
        (
            diagnostic["workload"],
            diagnostic["nominal_rtt_ms"],
            diagnostic["rekey_limit"],
        ): diagnostic["observed_rekeys"]
        for diagnostic in diagnostics
    }
    for row in rows:
        key = (row["workload"], row["nominal_rtt_ms"], row["rekey_limit"])
        if key in observed:
            row["diagnostic_observed_rekeys"] = observed[key]


def _flatten_sample(sample: dict) -> dict:
    flat = {key: value for key, value in sample.items() if not isinstance(value, dict)}
    for endpoint in ("client", "server"):
        for key, value in sample[endpoint].items():
            flat[f"{endpoint}_{key}"] = value
    return flat


def _write_csv(path: Path, rows: list[dict]) -> None:
    fields = sorted({field for row in rows for field in row})
    with path.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _preflight(openssh_dir: Path) -> tuple[Path, Path, Path]:
    required = {
        "GNU time": Path("/usr/bin/time"),
        "ssh": openssh_dir / "bin/ssh",
        "ssh-keygen": openssh_dir / "bin/ssh-keygen",
        "sshd": openssh_dir / "sbin/sshd",
    }
    missing = [name for name, path in required.items() if not os.access(path, os.X_OK)]
    if missing:
        raise RuntimeError(f"missing required executable(s): {', '.join(missing)}")
    return required["sshd"], required["ssh"], required["ssh-keygen"]


def _has_capture_instrumentation(binary: Path) -> bool:
    """Detect the compile-time HN-DL hook without executing the binary."""
    markers = (b"SSH_QUANTUM_EPHEMERAL_PRIV", b"SSH_GROUND_TRUTH_SHARED_SECRET")
    contents = binary.read_bytes()
    return any(marker in contents for marker in markers)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--openssh-dir",
        type=Path,
        default=REPO_ROOT / "openssh-benchmark/.local",
        help="clean OpenSSH prefix (default: ./openssh-benchmark/.local)",
    )
    parser.add_argument(
        "--allow-instrumented",
        action="store_true",
        help="allow capture hooks for harness checks; invalid for paper timing",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        help="new result directory (default: ./data/<timestamp>-ssh-rekey-benchmark)",
    )
    parser.add_argument("--rekey-limits", nargs="+", default=("default", "64K"))
    parser.add_argument("--rtt-ms", nargs="+", type=int, default=(0, 20, 80))
    parser.add_argument(
        "--workloads",
        nargs="+",
        choices=("bulk", "interactive"),
        default=("bulk", "interactive"),
    )
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--bulk-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--interactive-rounds", type=int, default=100)
    parser.add_argument("--interactive-bytes", type=int, default=4096)
    parser.add_argument("--timeout-seconds", type=float, default=180)
    parser.add_argument(
        "--skip-rekey-diagnostics",
        action="store_true",
        help="skip separate verbose runs that count completed rekeys",
    )
    return parser


def main() -> int:
    parser = _parser()
    args = parser.parse_args()
    if args.repetitions <= 0:
        parser.error("--repetitions must be positive")
    if args.bulk_bytes <= 0 or args.interactive_rounds <= 0:
        parser.error("bulk bytes and interactive rounds must be positive")
    if args.interactive_bytes <= 0 or args.interactive_bytes > 32768:
        parser.error("--interactive-bytes must be between 1 and 32768")
    if args.timeout_seconds <= 0 or any(delay < 0 for delay in args.rtt_ms):
        parser.error("timeout and RTT values must be non-negative (timeout nonzero)")
    try:
        normalized_limits = [
            (
                None
                if limit.strip().lower() == "default"
                else normalize_ssh_rekey_limit(limit)
            )
            for limit in args.rekey_limits
        ]
    except ConfigurationError as exc:
        parser.error(str(exc))
    if len({limit or "default" for limit in normalized_limits}) != len(
        normalized_limits
    ):
        parser.error("--rekey-limits contains duplicates")

    openssh_dir = args.openssh_dir.resolve()
    try:
        sshd, ssh, ssh_keygen = _preflight(openssh_dir)
    except RuntimeError as exc:
        print(f"Preflight failed: {exc}", file=sys.stderr)
        return 2
    instrumented = _has_capture_instrumentation(ssh) or _has_capture_instrumentation(
        sshd
    )
    if instrumented and not args.allow_instrumented:
        print(
            "Preflight failed: this OpenSSH build contains HN-DL capture hooks. "
            "Build a clean benchmark copy with "
            "'./scripts/build_openssh.sh -p ./openssh-benchmark -c -S -b -i'. "
            "Use --allow-instrumented only to test the harness, never for paper timing.",
            file=sys.stderr,
        )
        return 2
    output_root = (
        args.output_root.resolve()
        if args.output_root
        else REPO_ROOT / "data" / f"{now_ts()}-ssh-rekey-benchmark"
    )
    if output_root.exists():
        if not output_root.is_dir() or any(output_root.iterdir()):
            parser.error(f"output path is not an empty directory: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)
    key_dir = output_root / "keys"
    key_dir.mkdir()
    host_key = generate_host_key(ssh_keygen, key_dir)
    user_key = generate_user_key(ssh_keygen, key_dir)
    auth_keys = key_dir / "authorized_keys"

    samples: list[dict] = []
    diagnostics: list[dict] = []
    sequence = 0
    print(f"Results: {output_root}")
    try:
        for repetition in range(1, args.repetitions + 1):
            for rtt in args.rtt_ms:
                for workload in args.workloads:
                    limits = (
                        normalized_limits
                        if repetition % 2
                        else list(reversed(normalized_limits))
                    )
                    for limit in limits:
                        sequence += 1
                        label = limit or "default"
                        sample_dir = (
                            output_root
                            / "runs"
                            / f"{sequence:03d}-{workload}-{rtt}ms-{label}"
                        )
                        print(
                            f"[{sequence}] {workload}, RTT={rtt} ms, "
                            f"RekeyLimit={label}, repetition={repetition}"
                        )
                        result = _run_sample(
                            sshd,
                            ssh,
                            host_key,
                            user_key,
                            auth_keys,
                            sample_dir,
                            workload,
                            limit,
                            rtt,
                            args.bulk_bytes,
                            args.interactive_rounds,
                            args.interactive_bytes,
                            args.timeout_seconds,
                        )
                        result["sequence"] = sequence
                        result["repetition"] = repetition
                        (sample_dir / "result.json").write_text(
                            json.dumps(result, indent=2) + "\n"
                        )
                        samples.append(result)

        if not args.skip_rekey_diagnostics:
            for rtt in args.rtt_ms:
                for workload in args.workloads:
                    for limit in normalized_limits:
                        sequence += 1
                        label = limit or "default"
                        sample_dir = (
                            output_root / "diagnostics" / f"{workload}-{rtt}ms-{label}"
                        )
                        print(
                            f"[{sequence}] diagnostic {workload}, RTT={rtt} ms, "
                            f"RekeyLimit={label}"
                        )
                        result = _run_sample(
                            sshd,
                            ssh,
                            host_key,
                            user_key,
                            auth_keys,
                            sample_dir,
                            workload,
                            limit,
                            rtt,
                            args.bulk_bytes,
                            args.interactive_rounds,
                            args.interactive_bytes,
                            args.timeout_seconds,
                            diagnostic=True,
                        )
                        (sample_dir / "result.json").write_text(
                            json.dumps(result, indent=2) + "\n"
                        )
                        diagnostics.append(result)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        (output_root / "partial_results.json").write_text(
            json.dumps(
                {
                    "schema": "hndl-ssh-rekey-benchmark-v1",
                    "complete": False,
                    "error": str(exc),
                    "samples": samples,
                    "diagnostics": diagnostics,
                    "summary": summarize(samples),
                },
                indent=2,
            )
            + "\n"
        )
        print(f"Benchmark failed: {exc}", file=sys.stderr)
        print(f"Partial evidence retained at: {output_root}", file=sys.stderr)
        return 1

    summaries = summarize(samples)
    attach_rekey_diagnostics(summaries, diagnostics)
    _write_csv(output_root / "samples.csv", [_flatten_sample(row) for row in samples])
    _write_csv(output_root / "summary.csv", summaries)
    manifest = {
        "schema": "hndl-ssh-rekey-benchmark-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "scope": (
            "Matched endpoint benchmark; nominal nonzero RTT uses a user-space "
            "stream relay with half-RTT delay on each forwarded socket read."
        ),
        "configuration": {
            "rekey_limits": [limit or "default" for limit in normalized_limits],
            "nominal_rtt_ms": args.rtt_ms,
            "workloads": args.workloads,
            "repetitions": args.repetitions,
            "bulk_bytes": args.bulk_bytes,
            "interactive_rounds": args.interactive_rounds,
            "interactive_bytes": args.interactive_bytes,
            "timeout_seconds": args.timeout_seconds,
            "capture_instrumentation_present": instrumented,
            "measurement_eligible": not instrumented,
            "timed_samples_use_diagnostic_logging": False,
            "separate_rekey_diagnostics": not args.skip_rekey_diagnostics,
        },
        "software": {
            "python": sys.version,
            "platform": platform.platform(),
            "uname": list(platform.uname()),
            "ssh_version": version_output([str(ssh), "-V"]),
            "sshd_version": version_output([str(sshd), "-V"]),
            "time_version": version_output(["/usr/bin/time", "--version"]),
            "repository_commit": version_output(
                ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"]
            ).splitlines()[0],
            "repository_dirty": bool(
                version_output(["git", "-C", str(REPO_ROOT), "status", "--porcelain"])
            ),
            "initial_load_average": list(os.getloadavg()),
        },
        "sha256": {
            "script": sha256_file(Path(__file__)),
            "ssh": sha256_file(ssh),
            "sshd": sha256_file(sshd),
        },
        "samples": samples,
        "diagnostics": diagnostics,
        "summary": summaries,
    }
    (output_root / "results.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(
        f"Completed {len(samples)} timed runs and {len(diagnostics)} "
        "untimed diagnostic runs."
    )
    print(f"Machine-readable results: {output_root / 'results.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
