#!/usr/bin/env python3
"""Key material I/O: ephemeral keys, diagnostics, traces."""

import json
import sys
from pathlib import Path


def read_json(path: Path):
    """Read and parse JSON file."""
    try:
        return json.loads(path.read_text())
    except Exception as e:
        sys.exit(f"Failed to read {path}: {e}")


def load_ephemeral_keys(capture_dir: Path):
    """Load server and client ephemeral keys from capture directory."""
    server_e = read_json(capture_dir / "keys/server_ephemeral.json")
    client_e = read_json(capture_dir / "keys/client_ephemeral.json")
    return server_e, client_e


def save_diagnostics(derived_dir: Path, diagnostics: dict, debug: bool = False):
    """Save diagnostics bundle to JSON."""
    try:
        (derived_dir / "diagnostics.json").write_text(json.dumps(diagnostics, indent=2))
        if debug:
            print(f"[dbg] Wrote diagnostics to {derived_dir / 'diagnostics.json'}")
    except Exception as e:
        if debug:
            print(f"[dbg] Failed to write diagnostics: {e}")


def save_key_schedule_trace(
    derived_dir: Path, trace: dict, filename: str, debug: bool = False
):
    """Save key schedule trace to JSON."""
    try:
        (derived_dir / filename).write_text(json.dumps(trace, indent=2))
        if debug:
            print(f"[dbg] Wrote key schedule trace to {derived_dir / filename}")
    except Exception as e:
        if debug:
            print(f"[dbg] Failed to write key schedule trace: {e}")


def save_transcript_hashes(
    derived_dir: Path,
    th_hello_hex: str,
    th_finished_hex: str | None,
    hash_name: str,
    debug: bool = False,
):
    """Save transcript hashes to JSON."""
    try:
        meta = {
            "th_hello_hex": th_hello_hex,
            "th_finished_hex": th_finished_hex,
            "hash": hash_name,
        }
        (derived_dir / "transcript_hashes.json").write_text(json.dumps(meta, indent=2))
        if debug:
            print(
                f"[dbg] Wrote transcript hashes to {derived_dir / 'transcript_hashes.json'}"
            )
    except Exception as e:
        if debug:
            print(f"[dbg] Failed to write transcript hashes: {e}")


def save_handshake_messages(
    derived_dir: Path,
    ch: bytes,
    sh: bytes,
    th_hello_full: str,
    th_hello_body: str | None,
    debug: bool = False,
):
    """Save ClientHello, ServerHello, and th_hello variants."""
    try:
        (derived_dir / "client_hello.bin").write_bytes(ch)
        (derived_dir / "server_hello.bin").write_bytes(sh)
        (derived_dir / "th_hello_full.hex").write_text(th_hello_full + "\n")
        if th_hello_body is not None:
            (derived_dir / "th_hello_body.hex").write_text(th_hello_body + "\n")
    except Exception as e:
        if debug:
            print(f"[dbg] Failed to persist CH/SH or th_hello variants: {e}")


def load_th_finished(
    derived_dir: Path, th_finished_arg: str | None, debug: bool = False
) -> str | None:
    """Load th_finished from CLI argument or file."""
    if th_finished_arg:
        if debug:
            print(f"[dbg] Using th_finished from CLI: {th_finished_arg[:40]}...")
        return th_finished_arg.strip()

    th_finished_file = derived_dir / "th_finished.hex"
    if th_finished_file.exists():
        th_finished_hex = th_finished_file.read_text().strip()
        if debug:
            print(
                f"[dbg] Found th_finished in {th_finished_file}: {th_finished_hex[:40]}..."
            )
        return th_finished_hex

    return None


def save_th_finished(derived_dir: Path, th_finished_hex: str, debug: bool = False):
    """Save th_finished to file."""
    th_finished_file = derived_dir / "th_finished.hex"
    th_finished_file.write_text(th_finished_hex)
    if debug:
        print(f"[+] Saved th_finished to {th_finished_file}")
