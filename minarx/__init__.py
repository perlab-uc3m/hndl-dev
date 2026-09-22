"""MinARX: protocol-aware minimal archives for the HN-DL experiment.

The archive contains public wire evidence only.  Simulated future-recovery
outputs (for example an RSA private key or a recovered ECDHE scalar) are
supplied separately when the archive is decoded.
"""

from .archive import ArchiveError, compact_capture, inspect_archive, materialize_archive

__all__ = [
    "ArchiveError",
    "compact_capture",
    "inspect_archive",
    "materialize_archive",
]
