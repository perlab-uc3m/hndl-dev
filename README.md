# HN-DL

Harvest Now, Decrypt Later. This tool captures selected TLS 1.2, TLS 1.3,
QUIC, and SSH configurations, then reconstructs keys and authenticated
plaintext from the retained wire data. It models a future adversary that can
solve the relevant asymmetric problem; it does not implement the quantum
algorithm itself.

Instrumented OpenSSL and OpenSSH export a private value during the handshake.
That value is the simulated output of the future RSA/ECDLP computation. The
reconstruction path may consume that value and public wire data only.
Separately labelled endpoint state is retained solely for post-reconstruction
comparison and is never used to supply an intermediate attack value.

For TLS 1.3 and QUIC, `keys/simulated_quantum_output.json` contains exactly one
recovered X25519 private value and its public consistency check. Peer and local
key shares are parsed again from the capture. Complete endpoint exports are in
`openssl_ephemeral_ground_truth.json`; the decoder never reads them. TLS 1.2
uses `simulated_quantum_output.pem` as the recovered long-term RSA key and
retains `key.pem` as endpoint state.

## Setup

```bash
sudo apt install openssl wireshark tshark python3 python3-cryptography build-essential autoconf automake zlib1g-dev libssl-dev
# Installs under ./openssl/.local, the default used by hndl.py.
./scripts/build_openssl.sh -c -b -i
./scripts/build_quic_server.sh
./scripts/build_openssh.sh -c -b -i
```

Live capture also requires permission to run `dumpcap` on the selected
interface. On Debian/Ubuntu, enable non-root packet capture during Wireshark
package configuration and add the user to the `wireshark` group, then start a
new login session. Verify with `dumpcap -D` before running the pipeline.

## Usage

Each invocation captures a session and derives the symmetric keys in one step:

```bash
python3 hndl.py --protocol ssh
python3 hndl.py --protocol ssh --ssh-rekey-limit 64K --ssh-payload-bytes 300000
python3 hndl.py --protocol tls13 --mode 1rtt
python3 hndl.py --protocol tls13 --mode 0rtt
python3 hndl.py --protocol tls13 --mode 0rtt --tls13-resumption-kex psk-only
python3 hndl.py --protocol tls13 --mode 0rtt --tls13-grandchild
python3 hndl.py --protocol tls13 --mode external-psk
python3 hndl.py --protocol tls12 --mode rsa
python3 hndl.py --protocol quic
```

The controlled 0-RTT scenario keeps one `s_server` process alive across ticket
issuance and use, disables its anti-replay rejection for this first-use test,
and fails unless OpenSSL reports both a resumed TLS 1.3 session and accepted
early data. This setting makes the reconstruction experiment deterministic; it
is not a deployment recommendation.

The optional PSK modes make the resumption dependencies executable. The
`psk-only` child has no fresh DH contribution; the default `psk-dhe` child has
one. `--tls13-grandchild` captures a third connection using a ticket issued by
the child. `external-psk` generates an independently provisioned PSK and stores
only its explicitly modeled later-compromise copy as a recovery input; the live
command-line value is redacted from the manifest.

The two phases can also run independently:

```bash
python3 hndl.py -p tls13 -m 1rtt --capture-only
python3 hndl.py recover data/2025-...-tls13-1rtt-capture
```

Recovery reads the protocol, mode, capture port, archives, simulated-recovery
input, comparison-only state, and expected outputs from `manifest.json`.
`--decrypt-only` remains available for compatibility; any supplied protocol,
mode, or port is treated as an assertion and must agree with the manifest.

Build standalone archive-policy experiments from a retained capture with:

```bash
python3 hndl.py archive data/2025-...-tls13-1rtt-capture --policy all
python3 hndl.py recover data/policy-archives/2025-...-compact
```

Each generated archive contains the retained wire representation and declared
future-recovery input (simulated asymmetric recovery or external-PSK
compromise), but no SSL key log, SSH ground truth, or other endpoint secret. The
`raw` policy retains the PCAP, `reassembled`
retains ordered TCP payloads or UDP datagrams, and `compact` retains
objective-specific protocol units visible at collection time. Their manifests
record exact byte counts, source and implementation hashes, and the evidence
boundary. The compact result is an achieved sufficient representation for the
controlled application marker, not a proof of a universal minimum.

For a development check of every supported mode, run:

```bash
python3 scripts/smoke_test.py
python3 scripts/smoke_test.py --archive-policies
```

This performs fresh TLS 1.2 RSA, TLS 1.3 1-RTT, genuine TLS 1.3 0-RTT,
TLS 1.3 external-PSK, QUIC, and forced-rekey SSH captures on dynamically
selected loopback ports. It
requires the binaries from the setup section and working `dumpcap` permissions.
The test fails on an incomplete pipeline, missing or empty evidence, packet
drops, an SSH run with fewer than two authenticated transport epochs, or a
leaked capture/server process. Artifacts are created outside the repository
and removed after a complete pass; `--keep` retains them, and `--verbose`
prints each pipeline's output. Each mode has a 90-second timeout by default;
use `--timeout-seconds` on unusually slow systems.

Run the complete four-case PSK causality matrix with one command:

```bash
python3 scripts/psk_matrix_test.py
```

It creates three live captures covering a pure-PSK child, a PSK-DHE child with
early data and a ticket-using grandchild, and an independent external PSK. It
checks positive recovery without endpoint ground truth and negative recovery
when each required PSK, fresh DH output, or child ticket state is withheld or
substituted. Use `--keep` or `--output-root` to retain the JSON evidence.

Measure the defender-side cost of aggressive OpenSSH rekeying with:

```bash
./scripts/build_openssh.sh -p "$PWD/openssh-benchmark" -c -S -b -i
python3 scripts/ssh_rekey_benchmark.py \
  --rekey-limits default 64K --rtt-ms 0 20 80 --repetitions 5
```

The matched matrix runs bulk and interactive workloads against the pinned
OpenSSH build and records client CPU, server CPU, throughput, first-byte time,
interactive latency, transfer gaps, context switches, and observed rekey
counts. It alternates limit order between repetitions and writes raw
`samples.csv`, aggregated `summary.csv`, per-run logs, and a hash-bound
`results.json` under `data/` by default. Nonzero nominal RTT uses a portable
user-space TCP stream relay with half the requested delay in each direction;
the relay applies delay per forwarded socket read and is explicitly recorded
as an emulation, not presented as kernel-level `netem` measurement. This
benchmark requires `/usr/bin/time` and a second, uninstrumented OpenSSH build,
but not packet-capture permission: the capture build prints evidence on every
exchange and would bias aggressive-rekey timing. The benchmark rejects those
hooks by default;
`--allow-instrumented --openssh-dir ./openssh/.local` exists only for short
harness checks and produces results marked ineligible for paper timing.

To rerun archive policies over retained captures with isolated negative
controls and machine-readable JSON/CSV output, use:

```bash
python3 scripts/archive_policy_test.py data/<capture> [...] --output-root results --keep
```

For every policy this withholds all ground truth, authenticates the application
marker, flips one retained bit, withholds the simulated recovery result, and
checks that transient decoder adapters have been removed. For each compact
archive it also corrupts retained ciphertext and recomputes the outer manifest
hash; recovery must still fail at the protocol-authentication boundary.

Output lands in `data/<timestamp>-<protocol>-capture/` with subdirectories
`pcap/`, `keys/`, `logs/`, and `derived/`. TLS/QUIC derived secrets use NSS
keylog format. SSH writes a JSON recovery record containing its reconstructed
keys, authenticated-packet counts, oracle-release trace, and recovered channel
data. Every capture writes `manifest.json` with reproduction commands (secret
arguments are redacted), versions, machine details, the evidence boundary, and
SHA-256 hashes of the relevant code, binaries, and evidence. Successful
recovery also writes `derived/recovery_provenance.json`, binding the result to
hashes of the source manifest, passive archive, simulated quantum output,
comparison-only inputs, and recovery implementation.

## How it works

The pipeline has three stages. First, `capture/` runs a local client and server
while dumpcap records the wire. Invoking the capture writer directly ensures
that it has stopped and finalized the PCAP before analysis; tshark then
dissects the retained file. The SSH experiment additionally records the two
exact byte streams through a transparent loopback relay; this keeps the
protocol reconstruction test runnable on hosts where dumpcap lacks capture
permission. Second, `decryptor/` consumes the simulated asymmetric-recovery
output and the passive archive. Third, it reconstructs the protocol key
schedule and proves success through authenticated application-data recovery.
TLS and QUIC success requires authenticated recovery of the known application
request or response. When a comparison-only key log is present, every expected
derived secret must also match it. Policy archives deliberately omit that log;
successful authenticated plaintext is the independent recovery proof. A
handshake-only result or absent plaintext marker remains a failure.

Reassembled and compact archives are decoded through a short-lived synthetic
PCAP envelope so the same protocol decoders test every policy. Synthetic link,
IP, TCP, and UDP headers are never stored in the archive, are excluded from its
byte count, and are deleted after recovery. Compact pruning is conservative:
TLS 1.3 ciphertext is retained when its handshake/application role is not
visible at collection time, QUIC retains bytes needed for header protection,
and SSH retains direction-separated ciphertext streams because packet lengths
are encrypted. Consequently compact output need not be smaller than
reassembled output for every small capture.

The public Python API uses `ExperimentConfig`, `CaptureResult`, and
`RecoveryResult` from `experiment.py`. Capture and recovery dispatch directly
in-process: the exact returned capture directory is used, so concurrent runs
do not race through a “latest directory” lookup. A scope-bound process
lifecycle finalizes registered dumpcap writers and terminates registered
clients or servers after exceptional exits.

The implemented classical test configurations are deliberately narrow:
X25519 with TLS 1.3/QUIC, RSA key transport with `AES128-SHA` for TLS 1.2, and
Curve25519 plus `chacha20-poly1305@openssh.com` for SSH. The QUIC native
Handshake decoder supports AES-GCM cipher suites; the capture CLI rejects
non-X25519 groups. These boundaries are experiment scope, not claims about all
possible protocol configurations.

The SSH experiment deliberately forces `curve25519-sha256`,
`ssh-ed25519`, and `chacha20-poly1305@openssh.com`; it does not claim these are
current OpenSSH defaults. The decoder parses both public KEXINIT messages and
Curve25519 shares, recomputes the SSH `mpint` shared secret and exchange hash,
verifies the host signature, derives all RFC 4253 keys, verifies every
Poly1305 tag, and recovers `SSH_TEST_OK`. The endpoint-computed shared secret,
exchange hash, session ID, and derived keys live in
`ssh_ground_truth.json` and are comparison-only.

For a forced-rekey run, every hook event is retained. The attack process cannot
read the private-value file directly: a separate oracle process releases a
scalar only when queried with the matching public share. The decoder obtains a
later share only after authenticating and decrypting the preceding transport
epoch, records that release order, keeps the initial exchange hash as the SSH
session identifier, and then advances to the next epoch. Removing the
ground-truth file does not affect recovery.

## Structure

```text
hndl.py                 Main entrypoint
experiment.py           Typed config/results and manifest validation
archive_policy.py       Standalone raw/reassembled/compact archive policies
pyproject.toml          Dependencies, console entry point, formatting/tests
capture/
    capture.py          Capture CLI
    tls13/              Full, resumed, grandchild and external-PSK capture
    tls12/              RSA key exchange capture
    quic/               QUIC (TLS 1.3 over UDP) capture
    ssh/                SSH (Curve25519) capture
decryptor/
    derive.py           Derivation CLI
    tls13/              Full, early-data, resumed and external-PSK derivation
    tls12/              derive_rsa.py
    quic/               derive_quic.py
    ssh/                derive_ssh.py
    core/               Cryptographic primitives (HKDF, PRF, key schedule)
    io/                 PCAP parsing, key material I/O
analysis/               Cost models, mitigation experiments, figures
    results/            CSV data from experiments
scripts/                Builds, integration tests, and SSH rekey benchmark
tests/                  Fast public crypto, manifest, archive and cleanup tests
patches/                Source patches
```

`analysis/validate_model.py` performs the advertised four-protocol payload
sweep, including QUIC. It rejects failed or incomplete application transfers
and excludes pure TCP ACKs while retaining UDP frames. The analytical storage
curves are engineering models calibrated to the stated capture policy; they
are not information-theoretic lower bounds. `analysis/monte_carlo_cost.py`
charges the full retained inventory at each calendar year's recurring unit
price (or only new media in explicit CapEx mode).

The checked-in CSV files under `analysis/results/` are prior measurements, not
generated fixtures. Regenerate them after capture-harness or model changes
before using their numerical values in the paper; the scripts fail rather than
silently recording zero-byte captures when dumpcap cannot read the interface
or tshark cannot reopen an artifact.

On Ubuntu systems whose AppArmor profile permits dumpcap to write a capture in
the project but prevents tshark from reopening it, the tshark helper retries
from a private, short-lived directory under `/tmp`. The original PCAP remains
the evidence artifact and is never modified; auxiliary key logs are staged
with mode `0600` only for that subprocess invocation.

## Formatting

```bash
black .
```

Install the development tools and run the fast published tests with:

```bash
python3 -m pip install -e '.[dev]'
python3 -m unittest discover -s tests -v
```
