# HN-DL

Harvest Now, Decrypt Later. This tool captures TLS 1.2, TLS 1.3, QUIC, and SSH traffic, then derives session keys from the captured ephemeral key material. It demonstrates how a future adversary with the ability to solve the underlying asymmetric problems (RSA factoring, discrete log, ECDLP) could decrypt archived sessions.

The simulation instruments OpenSSL and OpenSSH to export ephemeral private keys during the handshake. These stand in for the quantum computation that would recover the same values from the public keys visible on the wire.

## Setup

```bash
sudo apt install openssl wireshark tshark python3 build-essential autoconf automake zlib1g-dev libssl-dev
./scripts/build_openssl.sh -c -b -i
./scripts/build_quic_server.sh
./scripts/build_openssh.sh -c -b -i
```

## Usage

Each invocation captures a session and derives the symmetric keys in one step:

```bash
python3 hndl.py --protocol ssh
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

Output lands in `data/<timestamp>-<protocol>-capture/` with subdirectories `pcap/`, `keys/`, `logs/`, and `derived/`. To inspect decrypted traffic, point Wireshark's TLS pre-master secret log to the keylog file printed at the end of each run.

## How it works

The pipeline has three stages. First, `capture/` runs a local client and server over the chosen protocol while tshark records the wire. Patched OpenSSL or OpenSSH exports ephemeral secrets during the handshake. Second, `decryptor/` replays the key schedule: it loads the private key, extracts the ClientHello and ServerHello from the PCAP, computes the shared secret, and walks the protocol's key derivation (HKDF for TLS 1.3 and QUIC per RFC 8446/9001, PRF for TLS 1.2 per RFC 5246, or the hash chain of RFC 4253 for SSH). Third, the derived secrets are written in NSS keylog format so Wireshark can decrypt the session.

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
