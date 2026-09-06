#!/usr/bin/env python3
"""Run every supported HN-DL capture-and-recovery mode once."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DROP_RE = re.compile(r"Packets received/dropped.*?:\s*(\d+)/(\d+)")
MANIFEST_SCHEMAS = {"hndl-run-manifest-v1", "hndl-ssh-run-manifest-v1"}


@dataclass(frozen=True)
class Scenario:
    name: str
    slug: str
    arguments: tuple[str, ...]
    pcaps: tuple[str, ...]
    derived: str


@dataclass(frozen=True)
class Outcome:
    name: str
    passed: bool
    seconds: float
    detail: str


def _available_port(kind: int, require_successor: bool = False) -> int:
    """Return a currently unused loopback port (and optionally its successor)."""
    for _ in range(100):
        first = socket.socket(socket.AF_INET, kind)
        second = None
        try:
            first.bind(("127.0.0.1", 0))
            port = first.getsockname()[1]
            if require_successor:
                if port == 65535:
                    continue
                second = socket.socket(socket.AF_INET, kind)
                second.bind(("127.0.0.1", port + 1))
            return port
        except OSError:
            continue
        finally:
            first.close()
            if second is not None:
                second.close()
    raise RuntimeError("could not allocate a free loopback port")


def _scenarios(ssh_payload_bytes: int, ssh_rekey_limit: str) -> list[Scenario]:
    return [
        Scenario(
            "TLS 1.2 RSA",
            "tls12-rsa",
            (
                "-p",
                "tls12",
                "-m",
                "rsa",
                "--port",
                str(_available_port(socket.SOCK_STREAM)),
            ),
            ("pcap/tls12_rsa.pcapng",),
            "derived/nss_derived.keylog",
        ),
        Scenario(
            "TLS 1.3 1-RTT",
            "tls13-1rtt",
            (
                "-p",
                "tls13",
                "-m",
                "1rtt",
                "--port",
                str(_available_port(socket.SOCK_STREAM)),
            ),
            ("pcap/tls13_1rtt.pcapng",),
            "derived/nss_derived.keylog",
        ),
        Scenario(
            "TLS 1.3 0-RTT",
            "tls13-0rtt",
            (
                "-p",
                "tls13",
                "-m",
                "0rtt",
                "--port",
                str(_available_port(socket.SOCK_STREAM)),
            ),
            (
                "pcap/tls13_0rtt_phase1_initial.pcapng",
                "pcap/tls13_0rtt_phase2_resumption.pcapng",
            ),
            "derived/nss_0rtt.keylog",
        ),
        Scenario(
            "QUIC",
            "quic",
            ("-p", "quic", "--port", str(_available_port(socket.SOCK_DGRAM))),
            ("pcap/quic.pcapng",),
            "derived/nss_derived.keylog",
        ),
        Scenario(
            "SSH rekey",
            "ssh-rekey",
            (
                "-p",
                "ssh",
                "--port",
                str(_available_port(socket.SOCK_STREAM, require_successor=True)),
                "--ssh-rekey-limit",
                ssh_rekey_limit,
                "--ssh-payload-bytes",
                str(ssh_payload_bytes),
            ),
            ("pcap/ssh_session.pcapng",),
            "derived/ssh_derived_keys.json",
        ),
    ]


def _preflight() -> None:
    required_tools = ("dumpcap", "tshark")
    missing_tools = [name for name in required_tools if shutil.which(name) is None]
    required_binaries = (
        REPO_ROOT / "openssl/.local/bin/openssl",
        REPO_ROOT / "openssl/.local/bin/quic_server",
        REPO_ROOT / "openssh/.local/bin/ssh",
        REPO_ROOT / "openssh/.local/bin/ssh-keygen",
        REPO_ROOT / "openssh/.local/sbin/sshd",
    )
    missing_binaries = [
        str(path)
        for path in required_binaries
        if not path.is_file() or not os.access(path, os.X_OK)
    ]
    if missing_tools or missing_binaries:
        problems = [*(f"missing tool: {name}" for name in missing_tools)]
        problems.extend(
            f"missing or non-executable binary: {path}" for path in missing_binaries
        )
        raise RuntimeError("; ".join(problems))

    probe = subprocess.run(["dumpcap", "-D"], capture_output=True, text=True)
    if probe.returncode != 0:
        raise RuntimeError(probe.stderr.strip() or "dumpcap cannot list interfaces")


def _capture_directory(data_root: Path) -> Path:
    captures = [path for path in data_root.iterdir() if path.is_dir()]
    if len(captures) != 1:
        raise RuntimeError(f"expected one capture directory, found {len(captures)}")
    return captures[0]


def _validate_capture(capture: Path, scenario: Scenario) -> str:
    manifest_path = capture / "manifest.json"
    if not manifest_path.is_file():
        raise RuntimeError("manifest.json was not produced")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schema") not in MANIFEST_SCHEMAS:
        raise RuntimeError("unexpected or missing manifest schema")

    packet_total = 0
    for relative in scenario.pcaps:
        pcap = capture / relative
        if not pcap.is_file() or pcap.stat().st_size == 0:
            raise RuntimeError(f"missing or empty PCAP: {relative}")

    derived = capture / scenario.derived
    if not derived.is_file() or derived.stat().st_size == 0:
        raise RuntimeError(f"missing derived result: {scenario.derived}")
    extra_detail = ""
    if scenario.slug == "ssh-rekey":
        recovery = json.loads(derived.read_text())
        result = recovery.get("result", recovery)
        epochs = result.get("epochs_recovered", 0)
        if not result.get("success") or epochs < 2:
            raise RuntimeError("SSH did not recover at least two authenticated epochs")
        if not result.get("expected_plaintext_recovered"):
            raise RuntimeError("SSH did not recover the expected application plaintext")
        if not result.get("oracle_boundary_pass"):
            raise RuntimeError("SSH recovery violated the oracle evidence boundary")
        extra_detail = f", {epochs} epochs"

    summaries = []
    for log in capture.glob("logs/**/tshark_stderr.log"):
        matches = DROP_RE.findall(log.read_text(errors="replace"))
        if not matches:
            continue
        received, dropped = (int(value) for value in matches[-1])
        if dropped:
            raise RuntimeError(f"dumpcap reported {dropped} dropped packets in {log}")
        packet_total += received
        summaries.append(f"{received} packets")
    if not summaries or packet_total == 0:
        raise RuntimeError("dumpcap did not record a packet/drop summary")
    return ", ".join(summaries) + extra_detail


def _matching_processes(token: str) -> list[int]:
    """Find descendants that still reference this scenario's unique path."""
    matches = []
    own_pid = os.getpid()
    for entry in Path("/proc").glob("[0-9]*"):
        pid = int(entry.name)
        if pid == own_pid:
            continue
        try:
            command = (
                (entry / "cmdline")
                .read_bytes()
                .replace(b"\0", b" ")
                .decode(errors="replace")
            )
        except (OSError, ValueError):
            continue
        if token in command:
            matches.append(pid)
    return matches


def _terminate_processes(processes: list[int]) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid in processes:
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
        time.sleep(0.2)
        processes = [pid for pid in processes if Path(f"/proc/{pid}").exists()]
        if not processes:
            return


def _run_scenario(
    scenario: Scenario, work_root: Path, verbose: bool, timeout_seconds: float
) -> Outcome:
    data_root = work_root / scenario.slug
    data_root.mkdir()
    command = [
        sys.executable,
        str(REPO_ROOT / "hndl.py"),
        *scenario.arguments,
        "--data-root",
        str(data_root),
    ]
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - started
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        (data_root / "smoke_stdout.log").write_text(stdout)
        (data_root / "smoke_stderr.log").write_text(stderr)
        remnants = _matching_processes(str(data_root))
        if remnants:
            _terminate_processes(remnants)
        return Outcome(
            scenario.name,
            False,
            elapsed,
            f"pipeline exceeded {timeout_seconds:g}s timeout",
        )
    elapsed = time.monotonic() - started
    (data_root / "smoke_stdout.log").write_text(result.stdout)
    (data_root / "smoke_stderr.log").write_text(result.stderr)
    if verbose or result.returncode != 0:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)

    try:
        if result.returncode != 0:
            raise RuntimeError(f"pipeline exited with status {result.returncode}")
        detail = _validate_capture(_capture_directory(data_root), scenario)
        time.sleep(0.2)
        remnants = _matching_processes(str(data_root))
        if remnants:
            _terminate_processes(remnants)
            raise RuntimeError(f"leaked child processes: {remnants}")
        return Outcome(scenario.name, True, elapsed, detail)
    except (OSError, ValueError, RuntimeError) as exc:
        remnants = _matching_processes(str(data_root))
        if remnants:
            _terminate_processes(remnants)
        return Outcome(scenario.name, False, elapsed, str(exc))


def _print_summary(outcomes: list[Outcome]) -> None:
    width = max(len(outcome.name) for outcome in outcomes)
    print("\nHN-DL integration smoke test")
    print("=" * (width + 43))
    for outcome in outcomes:
        status = "PASS" if outcome.passed else "FAIL"
        print(
            f"{outcome.name:<{width}}  {status:4}  "
            f"{outcome.seconds:6.2f}s  {outcome.detail}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep", action="store_true", help="retain successful artifacts"
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--ssh-payload-bytes", type=int, default=100_000)
    parser.add_argument("--ssh-rekey-limit", default="64K")
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=90,
        help="maximum runtime for each mode (default: 90)",
    )
    args = parser.parse_args()

    if args.ssh_payload_bytes <= 0:
        parser.error("--ssh-payload-bytes must be positive")
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")

    try:
        _preflight()
    except RuntimeError as exc:
        print(f"Preflight failed: {exc}", file=sys.stderr)
        return 2

    work_root = Path(tempfile.mkdtemp(prefix="hndl-smoke-"))
    print(f"Artifacts: {work_root}")
    outcomes = [
        _run_scenario(scenario, work_root, args.verbose, args.timeout_seconds)
        for scenario in _scenarios(args.ssh_payload_bytes, args.ssh_rekey_limit)
    ]
    _print_summary(outcomes)

    passed = all(outcome.passed for outcome in outcomes)
    if passed and not args.keep:
        shutil.rmtree(work_root)
        print("All modes passed; temporary artifacts removed.")
    else:
        print(f"Artifacts retained at: {work_root}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
