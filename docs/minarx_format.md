# MinARX minimal protocol archive

MinARX is the experiment's **minimal archive** format. Its purpose is narrow:
retain the public wire evidence needed by a protocol-specific future decoder,
remove capture and
protocol fields that can be reconstructed deterministically, and keep the
simulated future-recovery output out of both the file and the byte count.

MinARX is a new experimental container and set of projections in this
repository. It is not a claim that framing removal, entropy coding, or
protocol-aware serialization is new, nor a proof of a globally minimal
encoding. “Minimal” below means the smallest conservative sufficient
representation implemented for the explicitly tested profiles.

## The invariant boundary

Each archive has two physically separate regions:

1. **protocol layout**: directions, lengths, clear transcript bytes, and other
   structure needed to reconstruct a decoder-compatible stream; and
2. **opaque bytes**: bytes copied verbatim and never entropy-coded (including
   complete QUIC datagrams and SSH streams with their clear prefixes).

Only the protocol-layout region may be passed to DEFLATE or LZMA. The opaque
region is never entropy-coded. Consequently, changing an application payload
from repetitive bytes to random bytes without changing its length cannot
change the archive size or the reported saving. This is tested automatically.

For TLS 1.3, every protected record has outer content type
`application_data`, so its whole fragment—including encrypted handshake or
application data—is opaque. For TLS 1.2, application records and all records
after each direction's ChangeCipherSpec are opaque. Complete QUIC datagrams are
opaque because header protection can sample ciphertext/tag bytes. The ordered
SSH ciphertext stream is opaque because packet lengths are encrypted.

These rules follow the record and transcript dependencies in the local copies
of RFC 5246, RFC 7627, RFC 8446, RFC 9000, RFC 9001, and RFC 4253 under
[`references/`](../references/).

## Version 1 binary layout

All integers in the fixed header are unsigned and network-byte-order:

```text
magic "MINARX\r\n"                  8 bytes
version                              u8
profile_id                           u8
layout_compression                   u8  (0 none, 1 DEFLATE, 2 LZMA)
flags                                u8  (zero in v1)
server_port                          u16
raw_capture_bytes                    u32
transport_payload_bytes              u32
stored_layout_bytes                  u32
plain_layout_bytes                   u32
opaque_bytes                         u32
stored protocol-layout region        variable
opaque protected/application region  variable, verbatim
SHA-256 of every preceding byte      32 bytes
```

The fixed overhead is 66 bytes (34-byte header plus 32-byte digest). Version 1
limits each declared region/counter to 2 GiB. The digest
detects archive corruption; it is not a MAC. Protocol authentication is still
checked after future key recovery by the protocol decoder.

The stable profile ID replaces a verbose per-file JSON manifest. Protocol,
mode, ciphersuite, hash, KEX, resumption, and early-data semantics are obtained
from the versioned profile registry. The port and aggregate counters are the
only per-capture facts in the fixed header. Source PCAP names are deterministic
for each mode and are therefore omitted.

## Protocol projections

| Protocol category | Deterministically omitted or compactly represented | Verbatim opaque region |
|---|---|---|
| TLS 1.2 RSA, EMS/no-EMS | PCAP/Ethernet/IP/TCP envelope; retransmissions; TLS record type/version/length; directional ordering | application records and records after ChangeCipherSpec |
| TLS 1.3 full handshake | capture/transport envelope; TLS record headers; directional ordering | every protected TLS 1.3 record fragment |
| TLS 1.3 ticket resumption/0-RTT | same projection, for both initial and resumption captures | protected bytes from both phases |
| TLS 1.3 external PSK | same TLS-record projection, without assuming a DH KeyShare | every protected TLS 1.3 record fragment |
| QUIC v1 | PCAP/Ethernet/IP/UDP envelope; readiness probes; datagram direction/length descriptors | complete QUIC datagrams, including tags and header-protection samples |
| SSH initial/rekey stream | PCAP/Ethernet/IP/TCP envelope; retransmissions; directional chunk descriptors | ordered SSH byte streams |

The TLS policies preserve clear transcript bytes rather than assuming that a
future compromise reveals a live transcript hash state. Certificate bytes are
not assumed to be globally shared or free. QUIC authentication tags are not
stripped: RFC 9001 permits header-protection samples to overlap tag bytes.

SSH is deliberately conservative. Packet lengths are encrypted, so MinARX
round-trips the ordered directional streams rather than assuming packet
boundaries. The public decoder then performs its normal isolated-oracle
recovery and authenticates the controlled channel marker.

## Profiles and categories

List the exact registry with:

```bash
python3 -m minarx profiles
```

The 16 registered profiles cover these reporting categories:

- TLS 1.2 RSA without EMS;
- TLS 1.2 RSA with EMS, separated by CBC/GCM ciphersuite;
- TLS 1.3 full handshake, separated by negotiated AEAD/hash;
- TLS 1.3 ticket resumption with 0-RTT;
- TLS 1.3 external PSK without DHE;
- QUIC v1, separated by TLS ciphersuite; and
- SSH initial/rekey stream, separated by negotiated cipher.

Savings are **not a universal constant per protocol**. They vary with record or
packet counts, certificate/transcript lengths, connection IDs, retransmissions,
and recordization. For a fixed trace structure and opaque-byte length they are
independent of application contents. Profiles prevent ciphersuite, EMS,
resumption, and early-data cases from being silently combined.

TLS selected ciphersuite, EMS, PSK selection, early-data offer, and X25519
selection are checked at archive creation. QUIC v1 is checked from its long
header and its TLS ServerHello ciphersuite is parsed from the public Initial
exchange. SSH KEX and both directional ciphers are checked from the clear
KEXINIT messages, and the live SSH experiment authenticates recovered channel
data.

## Byte accounting

For an archive with raw capture size `R`, transport payload `T`, opaque length
`O`, uncompressed layout `L`, compressed layout `C`, and fixed overhead
`F = 66`:

```text
structural baseline             = R - O
MinARX structural, pre-entropy  = F + L
MinARX structural, final        = F + C
deterministic pruning           = (R - O) - (F + L)
layout entropy saving           = L - C
total structural saving         = (R - O) - (F + C)
MinARX total                    = O + F + C
capture envelope removed       = R - T
protocol projection saving     = (T - O) - L
total saved                     = (R - T) + ((T - O) - L) + (L - C) - F
```

Subtracting `O` on both sides is what leaves application/protected content out
of the comparison. The report presents deterministic pruning separately from
optional layout compression. A negative value is possible for very small
captures because the fixed checksum/header cost exceeds removed framing.

Generate a checksum-verified table rather than transcribing values:

```bash
python3 scripts/archive_size_table.py data/*.minarx --format markdown
python3 scripts/archive_size_table.py data/*.minarx --format latex
```

The paper-facing live driver additionally requires authenticated application
recovery and binds source manifests, archives, and implementation files by
SHA-256:

```bash
python3 scripts/minarx_experiment.py data/<capture> [...] \
  --output-root data/minarx-results
```

The checked reference results are
`analysis/results/minarx_live_2026-09-22.json` and `.csv`.

## Creation and future decoding

```bash
python3 -m minarx compact \
  --capture-dir data/TRACE-tls13-capture \
  --protocol tls13 --mode 1rtt \
  --profile tls13-full-aes128gcm \
  --output data/TRACE-tls13-1rtt.minarx

python3 -m minarx inspect data/TRACE-tls13-1rtt.minarx

python3 -m decryptor.derive \
  --compacted data/TRACE-tls13-1rtt.minarx \
  --recovery-dir recovered-material \
  --output-dir derived-from-minarx
```

The compacted mode verifies the archive, reconstructs a short-lived synthetic
PCAP, copies only the protocol's declared future-recovery input, runs the normal
derivation path, and deletes the synthetic capture. Reference key logs are not
copied and recovery inputs are not counted as archive bytes.

The dedicated test suite is:

```bash
python3 -m pytest -q tests/test_minarx.py
```

It covers every registered profile, exact transport round trips, TLS 1.3
keyshare/shared-secret reconstruction, profile mismatch rejection, checksum
failure, compacted derivation, layout-only compression, and the
repetitive-versus-random opaque-payload size invariant.
