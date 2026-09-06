"""Key derivation from network captures (TLS 1.2, TLS 1.3, QUIC, SSH).

Protocol modules are intentionally not imported eagerly.  Besides reducing
startup work, this keeps ``python -m decryptor.derive`` from importing its
target module once through the package and then executing it a second time.
"""


def derive(*args, **kwargs):
    """Lazily dispatch to :func:`decryptor.derive.derive`."""
    from .derive import derive as _derive

    return _derive(*args, **kwargs)


def recover_protocol(*args, **kwargs):
    """Lazily dispatch to the typed recovery API."""
    from .derive import recover_protocol as _recover_protocol

    return _recover_protocol(*args, **kwargs)


__all__ = ["derive", "recover_protocol"]
