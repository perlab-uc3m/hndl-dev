"""Small canonical binary primitives used by every MinARX protocol codec."""

from __future__ import annotations

from dataclasses import dataclass


MAX_FIELD_SIZE = 1 << 31


class DecodeError(ValueError):
    """Raised when an archive payload is malformed or exceeds a limit."""


def encode_uvarint(value: int) -> bytes:
    if value < 0:
        raise ValueError("uvarint cannot encode a negative value")
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


@dataclass
class Reader:
    data: bytes
    offset: int = 0

    def byte(self) -> int:
        if self.offset >= len(self.data):
            raise DecodeError("truncated byte")
        value = self.data[self.offset]
        self.offset += 1
        return value

    def uvarint(self, maximum: int = MAX_FIELD_SIZE) -> int:
        value = 0
        shift = 0
        for _ in range(10):
            octet = self.byte()
            value |= (octet & 0x7F) << shift
            if not octet & 0x80:
                if value > maximum:
                    raise DecodeError(f"integer {value} exceeds limit {maximum}")
                return value
            shift += 7
        raise DecodeError("overlong uvarint")

    def take(self, length: int) -> bytes:
        if length < 0 or self.offset + length > len(self.data):
            raise DecodeError("truncated field")
        value = self.data[self.offset : self.offset + length]
        self.offset += length
        return value

    def blob(self, maximum: int = MAX_FIELD_SIZE) -> bytes:
        return self.take(self.uvarint(maximum))

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise DecodeError(f"{len(self.data) - self.offset} trailing payload bytes")


def encode_blob(value: bytes) -> bytes:
    return encode_uvarint(len(value)) + value
