"""Process-isolated simulated quantum oracle for SSH recovery experiments."""

import json
import multiprocessing
from pathlib import Path

from ..core.ssh_crypto import curve25519_public_from_private


def _oracle_server(path: str, connection) -> None:
    """Release a private value only for its matching public archive value."""
    try:
        with Path(path).open() as handle:
            data = json.load(handle)
        recoveries = data.get("recoveries") or [
            {
                "ephemeral_private": data["ephemeral_private"],
                "ephemeral_public": data["ephemeral_public_check"],
            }
        ]
        connection.send(
            {
                "ok": True,
                "metadata": {
                    "algorithm": data.get("algorithm"),
                    "recovered_side": data.get("recovered_side"),
                },
            }
        )
        used = set()
        while True:
            request = connection.recv()
            if request is None:
                break
            public_value = request.get("ephemeral_public", "").lower()
            match = next(
                (
                    (index, item)
                    for index, item in enumerate(recoveries)
                    if index not in used
                    and item.get("ephemeral_public", "").lower() == public_value
                ),
                None,
            )
            if match is None:
                connection.send(
                    {
                        "ok": False,
                        "error": "no unreleased scalar matches this public value",
                    }
                )
                continue
            index, item = match
            used.add(index)
            connection.send(
                {"ok": True, "ephemeral_private": item["ephemeral_private"]}
            )
    except (EOFError, KeyError, OSError, TypeError, ValueError) as exc:
        try:
            connection.send({"ok": False, "error": str(exc)})
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        connection.close()


class SimulatedQuantumOracle:
    """Query interface exposing only simulated future ECDLP outputs."""

    def __init__(self, path: Path):
        if not path.exists():
            raise FileNotFoundError(f"Required input not found: {path}")
        # Python 3.14 defaults to forkserver, whose control socket is both
        # unnecessary here and unavailable in some restricted runners.
        context = multiprocessing.get_context("fork")
        parent, child = context.Pipe()
        self._connection = parent
        self._process = context.Process(
            target=_oracle_server, args=(str(path), child), daemon=True
        )
        self._process.start()
        child.close()
        if not parent.poll(5):
            self.close()
            raise RuntimeError("simulated quantum oracle did not start")
        response = parent.recv()
        if not response.get("ok"):
            self.close()
            raise ValueError(response.get("error", "simulated quantum oracle failed"))
        self.metadata = response["metadata"]
        self.release_trace = []

    def recover(
        self,
        public_value: bytes,
        epoch: int,
        authenticated_packets_before_release: int,
    ) -> bytes:
        event = {
            "epoch": epoch,
            "public_value": public_value.hex(),
            "public_input_recovered_from": (
                "plaintext initial key exchange"
                if epoch == 0
                else "authenticated preceding-epoch transport"
            ),
            "authenticated_packets_before_release": authenticated_packets_before_release,
            "status": "requested",
        }
        self.release_trace.append(event)
        self._connection.send({"ephemeral_public": public_value.hex()})
        if not self._connection.poll(5):
            event["status"] = "timeout"
            raise RuntimeError("simulated quantum oracle did not respond")
        response = self._connection.recv()
        if not response.get("ok"):
            event["status"] = "rejected"
            raise ValueError(response.get("error", "simulated recovery failed"))
        private_value = bytes.fromhex(response["ephemeral_private"])
        if curve25519_public_from_private(private_value) != public_value:
            event["status"] = "inconsistent"
            raise ValueError("oracle scalar does not match the recovered public value")
        event["status"] = "released"
        return private_value

    def close(self) -> None:
        if getattr(self, "_connection", None) is not None:
            try:
                self._connection.send(None)
            except (BrokenPipeError, EOFError, OSError):
                pass
            self._connection.close()
            self._connection = None
        if getattr(self, "_process", None) is not None:
            self._process.join(timeout=1)
            if self._process.is_alive():
                self._process.terminate()
                self._process.join(timeout=1)
            self._process = None
