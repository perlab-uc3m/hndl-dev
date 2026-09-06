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

## Setup

```bash
sudo apt install openssl wireshark tshark python3 python3-cryptography build-essential autoconf automake zlib1g-dev libssl-dev
./scripts/build_openssl.sh -c -b -i
./scripts/build_quic_server.sh
./scripts/build_openssh.sh -c -b -i
```

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

The two phases can also run independently:

```bash
python3 hndl.py -p tls13 -m 1rtt --capture-only
python3 hndl.py -p tls13 --decrypt-only data/2025-...-tls13-1rtt-capture
```

Output lands in `data/<timestamp>-<protocol>-capture/` with subdirectories
`pcap/`, `keys/`, `logs/`, and `derived/`. TLS/QUIC derived secrets use NSS
keylog format. SSH writes a JSON recovery record containing its reconstructed
keys, authenticated-packet counts, oracle-release trace, and recovered channel
data. SSH capture also writes `manifest.json` with exact commands, versions,
machine details, and SHA-256 hashes of the relevant code, binaries, and evidence.

## How it works

The pipeline has three stages. First, `capture/` runs a local client and server
while tshark records the wire. The SSH experiment additionally records the two
exact byte streams through a transparent loopback relay; this keeps the
protocol reconstruction test runnable on hosts where dumpcap lacks capture
permission. Second, `decryptor/` consumes the simulated asymmetric-recovery
output and the passive archive. Third, it reconstructs the protocol key
schedule and proves success through authenticated application-data recovery.

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
scripts/                Build scripts for patched OpenSSL/OpenSSH
patches/                Source patches
```

## Formatting

```bash
black .
```
