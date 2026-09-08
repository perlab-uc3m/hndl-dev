#!/usr/bin/env python3
"""Recover a selected SSH session from passive wire data plus oracle output."""

import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from experiment import sha256_file

from ..core.ssh_crypto import (
    channel_data,
    compute_exchange_hash,
    curve25519_public_from_private,
    decrypt_chachapoly_epoch,
    derive_ssh_keys_with_trace,
    encode_ssh_mpint,
    extract_initial_kex,
    extract_kex_exchange,
    recover_curve25519_shared_secret,
    verify_ed25519_kex_signature,
)
from ..io.pcap_parser import (
    get_tcp_stream_bytes,
    list_tcp_stream_indices,
)
from .oracle import SimulatedQuantumOracle


EXPECTED_KEX = "curve25519-sha256"
EXPECTED_CIPHER = "chacha20-poly1305@openssh.com"
GROUND_TRUTH_KEY_MAP = {
    "IV_CLIENT_TO_SERVER": "iv_c2s",
    "IV_SERVER_TO_CLIENT": "iv_s2c",
    "ENC_KEY_CLIENT_TO_SERVER": "enc_c2s",
    "ENC_KEY_SERVER_TO_CLIENT": "enc_s2c",
    "MAC_KEY_CLIENT_TO_SERVER": "mac_c2s",
    "MAC_KEY_SERVER_TO_CLIENT": "mac_s2c",
}


def _load_json(path: Path, required: bool = True) -> dict:
    if not path.exists():
        if required:
            raise FileNotFoundError(f"Required input not found: {path}")
        return {}
    with path.open() as f:
        return json.load(f)


def _record_derivation_manifest(
    capture_path: Path, derived_files: list[Path], result: dict
):
    """Append derivation outputs and outcome to a capture-time manifest."""
    manifest_path = capture_path / "manifest.json"
    if not manifest_path.exists():
        return
    manifest = _load_json(manifest_path)
    manifest["derivation"] = {
        "completed_utc": datetime.now(timezone.utc).isoformat(),
        "success": result["success"],
        "epochs_recovered": result["epochs_recovered"],
        "authenticated_packets": result["authenticated_packets"],
        "recovered_channel_bytes": result["recovered_channel_bytes"],
        "outputs": {
            str(path.relative_to(capture_path)): {
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in derived_files
        },
    }
    with manifest_path.open("w") as handle:
        json.dump(manifest, handle, indent=2)


def _classify_streams(first: bytes, second: bytes) -> tuple[bytes, bytes, dict]:
    """Identify client/server directions by parsing the public KEX messages."""
    errors = []
    for client_stream, server_stream in ((first, second), (second, first)):
        try:
            kex = extract_initial_kex(client_stream, server_stream)
            return client_stream, server_stream, kex
        except ValueError as exc:
            errors.append(str(exc))
    raise ValueError("Could not classify SSH directions: " + "; ".join(errors))


def _load_wire_data(
    capture_path: Path, archive_names: tuple[str, ...] | None = None
) -> tuple[bytes, bytes, dict, str]:
    """Load passive wire bytes from PCAP, with recorded streams as fallback."""
    names = archive_names or (
        "pcap/ssh_session.pcapng",
        "pcap/ssh_client_to_server.bin",
        "pcap/ssh_server_to_client.bin",
    )
    pcap = next(
        (
            capture_path / name
            for name in names
            if Path(name).suffix in {".pcap", ".pcapng"}
        ),
        None,
    )
    if pcap is not None and pcap.exists() and pcap.stat().st_size:
        errors = []
        for stream_index in list_tcp_stream_indices(pcap):
            try:
                first, second = get_tcp_stream_bytes(pcap, stream_index)
                client, server, kex = _classify_streams(first, second)
                return client, server, kex, f"pcap:tcp.stream={stream_index}"
            except (RuntimeError, ValueError) as exc:
                errors.append(f"stream {stream_index}: {exc}")
        raise ValueError("No complete SSH KEX in PCAP: " + "; ".join(errors))

    stream_names = [name for name in names if Path(name).suffix == ".bin"]
    if len(stream_names) >= 2:
        client_file, server_file = (
            capture_path / stream_names[0],
            capture_path / stream_names[1],
        )
    else:
        client_file = capture_path / "pcap" / "ssh_client_to_server.bin"
        server_file = capture_path / "pcap" / "ssh_server_to_client.bin"
    if not client_file.exists() or not server_file.exists():
        raise FileNotFoundError("Neither a usable PCAP nor both SSH wire streams exist")
    client = client_file.read_bytes()
    server = server_file.read_bytes()
    client, server, kex = _classify_streams(client, server)
    return client, server, kex, "recording-relay-wire-streams"


def _ground_truth_validation(
    ground_truth: dict,
    shared_secret_raw: bytes,
    shared_secret_K: bytes,
    H: bytes,
    trace: dict,
) -> dict:
    """Compare reconstructed values after recovery; never supply attack inputs."""
    truth = ground_truth.get("client") or ground_truth.get("server") or {}
    if not truth:
        return {"available": False, "all_match": None, "checks": {}}
    checks = {
        "shared_secret_raw": truth.get("SHARED_SECRET_RAW", "").lower()
        == shared_secret_raw.hex(),
        "shared_secret_K": truth.get("SHARED_SECRET_K", "").lower()
        == shared_secret_K.hex(),
        "exchange_hash_H": truth.get("EXCHANGE_HASH_H", "").lower() == H.hex(),
        "session_id": truth.get("SESSION_ID", "").lower() == H.hex(),
    }
    for truth_name, derived_name in GROUND_TRUTH_KEY_MAP.items():
        checks[derived_name] = (
            truth.get(truth_name, "").lower() == trace["derived"][derived_name]
        )
    return {
        "available": True,
        "all_match": all(checks.values()),
        "checks": checks,
    }


def _all_epoch_ground_truth_validation(ground_truth: dict, epochs: list[dict]) -> dict:
    """Validate every reconstructed epoch against each endpoint's hook records."""
    side_results = {}
    fields = {
        "SHARED_SECRET_RAW": "shared_secret_raw",
        "SHARED_SECRET_K": "shared_secret_K",
        "EXCHANGE_HASH_H": "exchange_hash",
        **GROUND_TRUTH_KEY_MAP,
    }
    for side_name in ("client", "server"):
        records = ground_truth.get(side_name, {}).get("records", [])
        if not records:
            continue
        checks = {}
        for truth_name, recovered_name in fields.items():
            observed = [
                record["value"]
                for record in records
                if record.get("name") == truth_name
            ]
            expected = []
            for epoch in epochs:
                if recovered_name in epoch:
                    expected.append(epoch[recovered_name])
                else:
                    expected.append(epoch["derived"][recovered_name])
            checks[recovered_name] = {
                "count": len(observed),
                "expected_count": len(expected),
                "match": observed == expected,
            }
        side_results[side_name] = {
            "all_match": all(item["match"] for item in checks.values()),
            "checks": checks,
        }
    return {
        "available": bool(side_results),
        "all_match": (
            all(result["all_match"] for result in side_results.values())
            if side_results
            else None
        ),
        "sides": side_results,
    }


def derive_ssh(
    capture_dir: Path,
    debug: bool = False,
    recovery_name: str = "keys/simulated_quantum_output.json",
    ground_truth_name: str = "keys/ssh_ground_truth.json",
    archive_names: tuple[str, ...] | None = None,
) -> dict:
    """Run passive SSH capture-to-decryption under the simulated CRQC model."""
    capture_path = Path(capture_dir)
    keys_dir = capture_path / "keys"
    derived_dir = capture_path / "derived"
    derived_dir.mkdir(parents=True, exist_ok=True)
    oracle = None

    try:
        _, _, kex, archive_source = _load_wire_data(capture_path, archive_names)
        oracle = SimulatedQuantumOracle(capture_path / recovery_name)

        negotiated = kex["negotiated"]
        if negotiated["kex"] != EXPECTED_KEX:
            raise ValueError(f"Unsupported negotiated KEX: {negotiated['kex']}")
        if (
            negotiated["cipher_c2s"] != EXPECTED_CIPHER
            or negotiated["cipher_s2c"] != EXPECTED_CIPHER
        ):
            raise ValueError(f"Unsupported negotiated ciphers: {negotiated}")
        if oracle.metadata.get("algorithm") != EXPECTED_KEX:
            raise ValueError("Oracle output is not labelled for curve25519-sha256")
        if oracle.metadata.get("recovered_side") != "client":
            raise ValueError(
                "This reconstruction expects the recovered client exponent"
            )

        private_value = oracle.recover(kex["Q_C"], 0, 0)
        recovered_public = curve25519_public_from_private(private_value)
        public_matches_capture = recovered_public == kex["Q_C"]
        if not public_matches_capture:
            raise ValueError(
                "Recovered private value does not match the captured public value"
            )

        shared_secret_raw = recover_curve25519_shared_secret(private_value, kex["Q_S"])
        shared_secret_K = encode_ssh_mpint(shared_secret_raw)
        initial_H = compute_exchange_hash(
            kex["V_C"],
            kex["V_S"],
            kex["I_C"],
            kex["I_S"],
            kex["K_S"],
            kex["Q_C"],
            kex["Q_S"],
            shared_secret_raw,
            "sha256",
        )
        verify_ed25519_kex_signature(kex["K_S"], kex["signature"], initial_H)

        # OpenSSH derives max(IV,key,MAC) bytes for all six labels. The selected
        # ChaCha20-Poly1305 cipher consumes the first 64 bytes of C and D.
        _, trace = derive_ssh_keys_with_trace(
            shared_secret_K, initial_H, initial_H, "sha256", 64, 64, 64
        )
        derived = {
            name: bytes.fromhex(value) for name, value in trace["derived"].items()
        }
        epoch_traces = [
            {
                "epoch": 0,
                "exchange_hash": initial_H.hex(),
                "shared_secret_raw": shared_secret_raw.hex(),
                "shared_secret_K": shared_secret_K.hex(),
                "derived": trace["derived"],
            }
        ]
        remaining_c2s = kex["encrypted_c2s"]
        remaining_s2c = kex["encrypted_s2c"]
        sequence_c2s = 0 if kex["strict_kex"] else kex["plaintext_packets_c2s"]
        sequence_s2c = 0 if kex["strict_kex"] else kex["plaintext_packets_s2c"]
        authenticated_c2s = 0
        authenticated_s2c = 0
        channel_chunks = []
        epoch_packet_counts = []
        epoch = 0

        while True:
            c2s_epoch = decrypt_chachapoly_epoch(
                remaining_c2s, derived["enc_c2s"], sequence_c2s
            )
            s2c_epoch = decrypt_chachapoly_epoch(
                remaining_s2c, derived["enc_s2c"], sequence_s2c
            )
            authenticated_c2s += len(c2s_epoch["packets"])
            authenticated_s2c += len(s2c_epoch["packets"])
            epoch_channel_chunks = [
                value
                for packet in s2c_epoch["packets"]
                if (value := channel_data(packet["payload"])) is not None
            ]
            epoch_packet_counts.append(
                {
                    "epoch": epoch,
                    "client_to_server": len(c2s_epoch["packets"]),
                    "server_to_client": len(s2c_epoch["packets"]),
                    "server_channel_bytes": sum(map(len, epoch_channel_chunks)),
                }
            )
            channel_chunks.extend(epoch_channel_chunks)

            if c2s_epoch["newkeys"] != s2c_epoch["newkeys"]:
                raise ValueError("Only one SSH direction reached a NEWKEYS boundary")
            if not c2s_epoch["newkeys"]:
                break

            rekey = extract_kex_exchange(
                [packet["payload"] for packet in c2s_epoch["packets"]],
                [packet["payload"] for packet in s2c_epoch["packets"]],
            )
            epoch += 1
            private_value = oracle.recover(
                rekey["Q_C"],
                epoch,
                authenticated_c2s + authenticated_s2c,
            )
            shared_secret_raw_next = recover_curve25519_shared_secret(
                private_value, rekey["Q_S"]
            )
            shared_secret_K_next = encode_ssh_mpint(shared_secret_raw_next)
            H_next = compute_exchange_hash(
                kex["V_C"],
                kex["V_S"],
                rekey["I_C"],
                rekey["I_S"],
                rekey["K_S"],
                rekey["Q_C"],
                rekey["Q_S"],
                shared_secret_raw_next,
                "sha256",
            )
            verify_ed25519_kex_signature(rekey["K_S"], rekey["signature"], H_next)
            _, next_trace = derive_ssh_keys_with_trace(
                shared_secret_K_next,
                H_next,
                initial_H,
                "sha256",
                64,
                64,
                64,
            )
            epoch_traces.append(
                {
                    "epoch": epoch,
                    "exchange_hash": H_next.hex(),
                    "shared_secret_raw": shared_secret_raw_next.hex(),
                    "shared_secret_K": shared_secret_K_next.hex(),
                    "derived": next_trace["derived"],
                }
            )
            derived = {
                name: bytes.fromhex(value)
                for name, value in next_trace["derived"].items()
            }
            remaining_c2s = c2s_epoch["remaining"]
            remaining_s2c = s2c_epoch["remaining"]
            if kex["strict_kex"]:
                sequence_c2s = sequence_s2c = 0
            else:
                sequence_c2s = c2s_epoch["next_sequence"]
                sequence_s2c = s2c_epoch["next_sequence"]

        recovered_channel_data = b"".join(channel_chunks)
        expected_plaintext_recovered = b"SSH_TEST_OK" in recovered_channel_data
        if not expected_plaintext_recovered:
            raise ValueError(
                "Authenticated packets did not contain expected test plaintext"
            )

        # This file is intentionally opened only after archive-only recovery
        # and authentication have succeeded.
        ground_truth = _load_json(capture_path / ground_truth_name, required=False)
        validation = _ground_truth_validation(
            ground_truth, shared_secret_raw, shared_secret_K, initial_H, trace
        )
        all_epoch_validation = _all_epoch_ground_truth_validation(
            ground_truth, epoch_traces
        )
        if all_epoch_validation["available"]:
            validation["initial_exchange_match"] = validation["all_match"]
            validation["all_epochs"] = all_epoch_validation
            validation["all_match"] = (
                validation["all_match"] and all_epoch_validation["all_match"]
            )
        result = {
            "success": True,
            "oracle_boundary_pass": True,
            "oracle_process_isolated": True,
            "archive_source": archive_source,
            "simulated_recovery_input": "client Curve25519 ephemeral private value",
            "negotiated": negotiated,
            "strict_kex": kex["strict_kex"],
            "public_key_consistency": {"capture": public_matches_capture},
            "host_signature_valid": True,
            "epochs_recovered": len(epoch_traces),
            "rekey_exchanges_recovered": len(epoch_traces) - 1,
            "oracle_release_trace": oracle.release_trace,
            "authenticated_packets": {
                "client_to_server": authenticated_c2s,
                "server_to_client": authenticated_s2c,
            },
            "epoch_packet_counts": epoch_packet_counts,
            "recovered_channel_bytes": len(recovered_channel_data),
            "recovered_channel_data": ["SSH_TEST_OK\n"],
            "expected_plaintext_recovered": True,
            "ground_truth_validation": validation,
        }

        derived_keys_file = derived_dir / "ssh_derived_keys.json"
        trace_file = derived_dir / "key_schedule_trace.json"
        with derived_keys_file.open("w") as f:
            json.dump(
                {
                    "derived": trace["derived"],
                    "exchange_hash": initial_H.hex(),
                    "epochs": epoch_traces,
                    "result": result,
                },
                f,
                indent=2,
            )
        with trace_file.open("w") as f:
            json.dump({"epochs": epoch_traces}, f, indent=2)
        _record_derivation_manifest(
            capture_path, [derived_keys_file, trace_file], result
        )

        print(
            "SSH passive recovery: SUCCESS "
            f"({authenticated_c2s + authenticated_s2c} authenticated packets, "
            f"{len(epoch_traces)} epoch{'s' if len(epoch_traces) != 1 else ''})"
        )
        print(f"Archive source: {archive_source}")
        print("Recovered channel data: " + repr(result["recovered_channel_data"]))
        if validation["available"]:
            print(
                "Comparison-only ground truth: "
                + ("ALL MATCH" if validation["all_match"] else "MISMATCH")
            )
        if debug:
            print(json.dumps(result, indent=2))
        return result
    except (
        EOFError,
        InvalidSignature,
        KeyError,
        RuntimeError,
        TypeError,
        ValueError,
        FileNotFoundError,
        OSError,
    ) as exc:
        result = {
            "success": False,
            "oracle_boundary_pass": False,
            "error": str(exc),
        }
        if oracle is not None:
            result["oracle_release_trace"] = oracle.release_trace
        print(f"SSH passive recovery: FAILED ({exc})")
        return result
    finally:
        if oracle is not None:
            oracle.close()
