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
python3 hndl.py --protocol tls12 --mode rsa
python3 hndl.py --protocol quic
```

The controlled 0-RTT scenario keeps one `s_server` process alive across ticket
issuance and use, disables its anti-replay rejection for this first-use test,
and fails unless OpenSSL reports both a resumed TLS 1.3 session and accepted
early data. This setting makes the reconstruction experiment deterministic; it
is not a deployment recommendation.

The two phases can also run independently:

```bash
python3 hndl.py -p tls13 -m 1rtt --capture-only
python3 hndl.py recover data/2025-...-tls13-1rtt-capture
```

Recovery reads the protocol, mode, capture port, archives, simulated-recovery
input, comparison-only state, and expected outputs from `manifest.json`.
`--decrypt-only` remains available for compatibility; any supplied protocol,
mode, or port is treated as an assertion and must agree with the manifest.

For a development check of every supported mode, run:

```bash
python3 scripts/smoke_test.py
```

This performs fresh TLS 1.2 RSA, TLS 1.3 1-RTT, genuine TLS 1.3 0-RTT,
QUIC, and forced-rekey SSH captures on dynamically selected loopback ports. It
requires the binaries from the setup section and working `dumpcap` permissions.
The test fails on an incomplete pipeline, missing or empty evidence, packet
drops, an SSH run with fewer than two authenticated transport epochs, or a
leaked capture/server process. Artifacts are created outside the repository
and removed after a complete pass; `--keep` retains them, and `--verbose`
prints each pipeline's output. Each mode has a 90-second timeout by default;
use `--timeout-seconds` on unusually slow systems.

Output lands in `data/<timestamp>-<protocol>-capture/` with subdirectories
`pcap/`, `keys/`, `logs/`, and `derived/`. TLS/QUIC derived secrets use NSS
keylog format. SSH writes a JSON recovery record containing its reconstructed
keys, authenticated-packet counts, oracle-release trace, and recovered channel
data. Every capture writes `manifest.json` with exact commands, versions,
machine details, the evidence boundary, and SHA-256 hashes of the relevant
code, binaries, and evidence. Successful recovery also writes
`derived/recovery_provenance.json`, binding the result to hashes of the source
manifest, passive archive, simulated quantum output, comparison-only inputs,
and recovery implementation.

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
TLS and QUIC success requires all expected derived secrets to match the
comparison-only key log and tshark to recover the known application request or
response. A missing key log, handshake-only result, or absent plaintext marker
is a failure rather than a vacuous success.

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
pyproject.toml          Dependencies, console entry point, formatting/tests
capture/
    capture.py          Capture CLI
    tls13/              1-RTT and 0-RTT capture
    tls12/              RSA key exchange capture
    quic/               QUIC (TLS 1.3 over UDP) capture
    ssh/                SSH (Curve25519) capture
decryptor/
    derive.py           Derivation CLI
    tls13/              derive_1rtt.py, derive_0rtt.py
    tls12/              derive_rsa.py
    quic/               derive_quic.py
    ssh/                derive_ssh.py
    core/               Cryptographic primitives (HKDF, PRF, key schedule)
    io/                 PCAP parsing, key material I/O
analysis/               Cost models, mitigation experiments, figures
    results/            CSV data from experiments
scripts/                Build scripts and the all-mode integration smoke test
tests/                  Fast public manifest, dispatch, and cleanup tests
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
