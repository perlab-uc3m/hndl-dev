#!/usr/bin/env python3
"""Storage-cost model for HN-DL attacks.

Computes the protocol overhead ratio α = bytes_stored / bytes_plaintext
for TLS 1.2, TLS 1.3, QUIC, and SSH across a range of payload sizes.
"""

import argparse
from dataclasses import dataclass
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import numpy as np

# ---------------------------------------------------------------------------
# Plot style
# ---------------------------------------------------------------------------
plt.rcParams["font.family"] = "Ubuntu"
plt.rcParams["pdf.fonttype"] = 42
plt.rcParams["ps.fonttype"] = 42

# Green-to-blue palette from the project's plotting style
_CMAP = mcolors.LinearSegmentedColormap.from_list("", ["#9fcf69", "#33acdc"])
COLOR_PALETTE = [_CMAP(x) for x in np.linspace(0, 1, 5)]

# ---------------------------------------------------------------------------
# Protocol storage models
# ---------------------------------------------------------------------------

L234_OVERHEAD = 54  # Ethernet 14 + IP 20 + TCP 20
L234_UDP_OVERHEAD = 42  # Ethernet 14 + IP 20 + UDP 8
TLS_MAX_RECORD = 16384  # RFC 8446 / RFC 5246
SSH_MAX_PACKET = 32768  # RFC 4253 §6.1


@dataclass
class ProtocolModel:
    """Deterministic per-session storage model for one protocol/mode."""

    name: str
    label: str
    handshake: int  # total handshake bytes on wire (both directions)
    tcp_hs_pkts: int  # TCP packets in handshake phase
    record_header: int  # per-record header bytes
    aead_tag: int  # AEAD tag / MAC per record
    extra_per_rec: int  # fixed extra per record (e.g. TLS 1.3 content-type byte)
    padding_block_size: int  # SSH block alignment (RFC 4253 §6); 0 for TLS/QUIC
    max_record: int  # max app-data bytes per record/packet
    channel_overhead: int  # SSH channel-layer framing; 0 for TLS
    is_udp: bool
    color: str
    linestyle: str
    marker: str

    def _ssh_padding(self, payload_per_record: float) -> float:
        """SSH per-packet padding (RFC 4253 §6): padding_length byte + padding."""
        if self.padding_block_size == 0:
            return 0
        bs = self.padding_block_size
        # RFC 4253 §6: length(packet_length||padding_length||payload||padding)
        # must be a multiple of the cipher block size (or 8, whichever larger).
        # The packet_length field itself is 4 bytes and is included.
        inner = self.record_header + 1 + int(payload_per_record)
        rem = inner % bs
        pad = (bs - rem) % bs  # raw alignment, may be 0
        if pad < 4:
            pad += bs
        return 1 + pad  # padding_length field + actual padding bytes

    def session_bytes(self, plaintext: float) -> float:
        """Total bytes an adversary must store for this session."""
        if self.padding_block_size > 0:
            min_padding_overhead = 5  # padding_length + min 4 B padding
            max_payload_per_rec = (
                self.max_record
                - self.record_header
                - self.aead_tag
                - min_padding_overhead
            )
        else:
            max_payload_per_rec = self.max_record - self.aead_tag - self.extra_per_rec
        n_records = max(1, int(np.ceil(plaintext / max_payload_per_rec)))
        payload_per_rec = plaintext / n_records
        padding = self._ssh_padding(payload_per_rec)
        l234 = L234_UDP_OVERHEAD if self.is_udp else L234_OVERHEAD
        per_record = (
            self.record_header
            + payload_per_rec
            + self.aead_tag
            + self.extra_per_rec
            + padding
            + l234
        )
        app_bytes = n_records * per_record
        hs_bytes = self.handshake + self.tcp_hs_pkts * l234
        return hs_bytes + self.channel_overhead + app_bytes

    def alpha(self, plaintext: float) -> float:
        """Protocol overhead ratio α = stored / plaintext."""
        if plaintext <= 0:
            return float("inf")
        return self.session_bytes(plaintext) / plaintext


# ---- Protocol definitions ----

TLS12_RSA = ProtocolModel(
    name="TLS 1.2 RSA (no FS)",
    label="tls12_rsa",
    handshake=1620,
    tcp_hs_pkts=14,
    record_header=5,
    aead_tag=36,  # CBC padding + HMAC-SHA1
    extra_per_rec=0,
    padding_block_size=0,
    max_record=TLS_MAX_RECORD,
    channel_overhead=0,
    is_udp=False,
    color=COLOR_PALETTE[0],
    linestyle="-",
    marker="o",
)

TLS12_ECDHE = ProtocolModel(
    name="TLS 1.2 ECDHE (FS)",
    label="tls12_ecdhe",
    handshake=1800,
    tcp_hs_pkts=14,
    record_header=5,
    aead_tag=24,  # 8 B explicit nonce + 16 B GCM tag
    extra_per_rec=0,
    padding_block_size=0,
    max_record=TLS_MAX_RECORD,
    channel_overhead=0,
    is_udp=False,
    color=COLOR_PALETTE[1],
    linestyle="--",
    marker="s",
)

TLS13_1RTT = ProtocolModel(
    name="TLS 1.3 ECDHE (FS)",
    label="tls13_1rtt",
    handshake=2160,
    tcp_hs_pkts=16,
    record_header=5,
    aead_tag=16,  # GCM 16-byte tag
    extra_per_rec=1,  # inner content type byte
    padding_block_size=0,
    max_record=TLS_MAX_RECORD,
    channel_overhead=0,
    is_udp=False,
    color=COLOR_PALETTE[2],
    linestyle="-.",
    marker="D",
)

# H=5100 B: classical curve25519-sha256 + ed25519 host key + pubkey auth
# (not sntrup761x25519 PQ-hybrid default of OpenSSH ≥ 9.x).
# channel_overhead=1109 B: empirical residual from channel-layer framing
# (service-request, userauth, channel-open/close, window-adjust, etc.).
SSH_X25519 = ProtocolModel(
    name="SSH X25519 (FS)",
    label="ssh_x25519",
    handshake=5100,
    tcp_hs_pkts=22,
    record_header=4,
    aead_tag=16,
    extra_per_rec=0,
    padding_block_size=8,
    max_record=SSH_MAX_PACKET,
    channel_overhead=1109,
    is_udp=False,
    color=COLOR_PALETTE[3],
    linestyle=":",
    marker="^",
)

# QUIC: UDP transport (RFC 9000), TLS 1.3 key schedule (RFC 9001).
# Short-header: flags(1) + DCID(8) + PN(2) = 11 B.
# Effective per-datagram payload ≈ 1350 B (MTU 1400 minus header + AEAD).
QUIC_MAX_DATAGRAM_PAYLOAD = 1350

QUIC_X25519 = ProtocolModel(
    name="QUIC X25519 (FS)",
    label="quic_x25519",
    handshake=2400,
    tcp_hs_pkts=10,
    record_header=11,
    aead_tag=16,
    extra_per_rec=0,
    padding_block_size=0,
    max_record=QUIC_MAX_DATAGRAM_PAYLOAD,
    channel_overhead=0,
    is_udp=True,
    color=COLOR_PALETTE[4],
    linestyle=(0, (3, 1, 1, 1)),
    marker="v",
)

PROTOCOLS = [TLS12_RSA, TLS12_ECDHE, TLS13_1RTT, QUIC_X25519, SSH_X25519]

# ---------------------------------------------------------------------------
# Global traffic parameters (for Plot 2)
# ---------------------------------------------------------------------------

GLOBAL_ENCRYPTED_TRAFFIC_PB_PER_DAY = 10_400  # ~3.8 ZB/year ÷ 365
AVERAGE_SESSION_PAYLOAD = 2e6  # 2 MB
SESSIONS_PER_DAY = GLOBAL_ENCRYPTED_TRAFFIC_PB_PER_DAY * 1e15 / AVERAGE_SESSION_PAYLOAD


def _style_ax(ax):
    ax.grid(True, linestyle="--", which="both", color="grey", alpha=0.4)
    ax.set_axisbelow(True)
    ax.tick_params(axis="both", labelsize=14)


def plot_amplification(protocols, outdir: Path):
    """α vs. plaintext payload size."""
    payloads = np.logspace(2, 8, 300)  # 100 B to 100 MB

    fig, ax = plt.subplots(figsize=(11, 6))
    _style_ax(ax)

    for p in protocols:
        alphas = [p.alpha(x) for x in payloads]
        ax.plot(
            payloads,
            alphas,
            label=p.name,
            color=p.color,
            linestyle=p.linestyle,
            linewidth=2.0,
        )

    # Reference line at α = 1
    ax.axhline(y=1, color="grey", linewidth=0.8, linestyle=":", alpha=0.6)
    ax.text(
        payloads[-1] * 0.6,
        1.12,
        r"$\alpha = 1$ (no overhead)",
        fontsize=13,
        color="grey",
        ha="right",
    )

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel(
        "Application payload per session (bytes)", fontweight="bold", fontsize=15
    )
    ax.set_ylabel(
        r"Protocol overhead ratio $\alpha$", fontweight="bold", fontsize=15, labelpad=15
    )
    ax.set_title(
        r"Protocol overhead ratio $\alpha$ vs. session payload",
        fontweight="bold",
        fontsize=19,
        pad=15,
    )
    ax.set_xlim(payloads[0], payloads[-1])
    ax.set_ylim(0.9, 300)
    ax.legend(fontsize=14, loc="upper right", framealpha=0.9, edgecolor="black")

    fig.tight_layout()
    outpath = outdir / "storage_amplification.pdf"
    fig.savefig(outpath, dpi=300, bbox_inches="tight")
    print(f"[+] Saved: {outpath}")
    plt.close(fig)
    return outpath


def plot_global_storage(protocols, outdir: Path):
    """Daily storage cost at global scale."""
    harvest_fractions = [
        (0.01, "1%", "-", 2.0),
        (0.10, "10%", "--", 1.8),
        (1.00, "100%", ":", 1.5),
    ]
    session_payloads = np.logspace(3, 7, 200)  # 1 KB to 10 MB

    fig, ax = plt.subplots(figsize=(11, 6))
    _style_ax(ax)

    for p in protocols:
        for frac, frac_label, ls, lw in harvest_fractions:
            n_sessions = SESSIONS_PER_DAY * frac
            daily_pb = np.array(
                [p.session_bytes(sp) * n_sessions / 1e15 for sp in session_payloads]
            )
            # Only label once per protocol (use the first fraction)
            label = f"{p.name}" if frac == harvest_fractions[0][0] else None
            ax.plot(
                session_payloads,
                daily_pb,
                color=p.color,
                linestyle=ls,
                linewidth=lw,
                label=label,
                alpha=0.85,
            )

    # Add annotations for the harvest fraction bands
    # Annotate at the right edge, mid-protocol
    ref_proto = PROTOCOLS[0]
    for frac, frac_label, _, _ in harvest_fractions:
        n_sessions = SESSIONS_PER_DAY * frac
        y_val = ref_proto.session_bytes(session_payloads[-1]) * n_sessions / 1e15
        ax.annotate(
            f"Harvest {frac_label}",
            xy=(session_payloads[-1], y_val),
            fontsize=12,
            fontweight="bold",
            color="#444444",
            ha="right",
            va="bottom",
            xytext=(-5, 5),
            textcoords="offset points",
        )

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Average session payload (bytes)", fontweight="bold", fontsize=15)
    ax.set_ylabel("Daily storage (PB)", fontweight="bold", fontsize=15, labelpad=15)
    ax.set_title(
        "Daily HN-DL storage at global scale", fontweight="bold", fontsize=19, pad=15
    )
    ax.legend(fontsize=14, loc="upper left", framealpha=0.9, edgecolor="black")

    fig.tight_layout()
    outpath = outdir / "global_storage_cost.pdf"
    fig.savefig(outpath, dpi=300, bbox_inches="tight")
    print(f"[+] Saved: {outpath}")
    plt.close(fig)
    return outpath


def validate_against_pcaps(protocols, data_dir: Path):
    """Quick single-point check against existing PCAPs (full sweep in validate_model.py)."""
    pcap_map: dict[str, tuple[str, str, int]] = {
        # "tls13_1rtt": ("YYYY-MM-DDTHH-MM-SSZ-tls13-1rtt-capture",
        #                "pcap/tls13_1rtt.pcapng", <payload_B>),
        # "tls12_rsa":  ("YYYY-MM-DDTHH-MM-SSZ-tls12-rsa-capture",
        #                "pcap/tls12_rsa.pcapng",  <payload_B>),
        # "ssh_x25519": ("YYYY-MM-DDTHH-MM-SSZ-ssh-capture",
        #                "pcap/session.pcapng",     <payload_B>),
    }

    if not pcap_map:
        print("\n=== PCAP Validation ===")
        print(
            "  (no entries configured; run analysis/validate_model.py for full validation)"
        )
        return

    print("\n=== PCAP Validation ===")
    print(
        f"{'Protocol':<22} {'Payload (B)':>12} {'PCAP (B)':>10} {'Model (B)':>10} {'Δ':>8}"
    )
    print("-" * 68)

    for p in protocols:
        if p.label not in pcap_map:
            continue
        cap_dir, pcap_rel, payload = pcap_map[p.label]
        pcap_path = data_dir / cap_dir / pcap_rel
        if not pcap_path.exists():
            print(f"{p.name:<22} {'N/A':>12}")
            continue
        pcap_size = pcap_path.stat().st_size
        model_size = p.session_bytes(payload)
        delta_pct = (model_size - pcap_size) / pcap_size * 100
        print(
            f"{p.name:<22} {payload:>12,} {pcap_size:>10,} {model_size:>10,.0f} {delta_pct:>+7.1f}%"
        )


def print_summary_table(protocols):
    """Print summary table of protocol parameters and key α values."""
    print("\n=== Protocol Parameters ===")
    print(
        f"{'Protocol':<22} {'HS (B)':>8} {'Rec hdr':>8} {'AEAD tag':>8} "
        f"{'α(1KB)':>8} {'α(100KB)':>8} {'α(10MB)':>8}"
    )
    print("-" * 78)
    for p in protocols:
        a1k = p.alpha(1_000)
        a100k = p.alpha(100_000)
        a10m = p.alpha(10_000_000)
        print(
            f"{p.name:<22} {p.handshake:>8,} {p.record_header:>8} {p.aead_tag:>8} "
            f"{a1k:>8.1f} {a100k:>8.2f} {a10m:>8.3f}"
        )

    print(
        f"\n=== Global Daily Storage (avg payload = {AVERAGE_SESSION_PAYLOAD/1e6:.0f} MB) ==="
    )
    print(f"Sessions/day: {SESSIONS_PER_DAY:.2e}")
    for frac_label, frac in [("1%", 0.01), ("10%", 0.10), ("100%", 1.00)]:
        n = SESSIONS_PER_DAY * frac
        print(f"\n  Harvest fraction: {frac_label} ({n:.2e} sessions/day)")
        for p in protocols:
            daily_bytes = p.session_bytes(AVERAGE_SESSION_PAYLOAD) * n
            daily_pb = daily_bytes / 1e15
            daily_eb = daily_bytes / 1e18
            print(
                f"    {p.name:<22} {daily_pb:>10,.1f} PB/day  ({daily_eb:>6.3f} EB/day)"
            )


def verify_minimal_archive():
    """Verify per-record overhead claims from the minimal-archive appendix."""
    print("\n=== Minimal-Archive Analysis (Appendix verification) ===\n")

    # Per-protocol parameters: (name, ω, ω_min, M)
    # ω     = full per-record wire overhead (bytes beyond payload ciphertext)
    # ω_min = minimal per-record overhead after stripping tags + constants
    # M     = maximum record payload size
    specs = [
        # TLS 1.3: header 5B (3B constant + 2B length) + inner content type 1B + tag 16B = 22B
        #          ω_min: length 2B + inner content type 1B = 3B
        ("TLS 1.3", 22, 3, TLS_MAX_RECORD),
        # SSH: record_header 4B + avg padding overhead 8.5B + tag 16B = 28.5B
        #      ω_min: record_header 4B + avg padding overhead 8.5B = 12.5B
        ("SSH", 28.5, 12.5, SSH_MAX_PACKET),
        # QUIC: short header 11B + tag 16B = 27B
        #       ω_min: short header 11B = 11B
        ("QUIC", 27, 11, QUIC_MAX_DATAGRAM_PAYLOAD),
    ]

    print(
        f"  {'Protocol':<10} {'ω':>6} {'ω_min':>6} {'M':>7}"
        f"  {'α_∞':>8} {'α_∞,min':>8} {'|Δα|':>10}"
    )
    print("  " + "-" * 60)

    max_delta = 0.0
    max_delta_tcp = 0.0
    ok = True

    for name, omega, omega_min, M in specs:
        alpha_inf = 1 + omega / M
        alpha_inf_min = 1 + omega_min / M
        delta = abs(alpha_inf - alpha_inf_min)

        is_tcp = name != "QUIC"
        max_delta = max(max_delta, delta)
        if is_tcp:
            max_delta_tcp = max(max_delta_tcp, delta)

        print(
            f"  {name:<10} {omega:>6.1f} {omega_min:>6.1f} {M:>7}"
            f"  {alpha_inf:>8.4f} {alpha_inf_min:>8.4f} {delta:>10.2e}"
        )

    # Verify paper claims
    print()

    # Claim 1: paper Table states specific ω, ω_min, α_∞, α_{∞,min} values
    checks = [
        ("TLS 1.3 α_∞ ≈ 1.0013", abs(1 + 22 / TLS_MAX_RECORD - 1.0013) < 5e-5),
        ("TLS 1.3 α_∞,min ≈ 1.0002", abs(1 + 3 / TLS_MAX_RECORD - 1.0002) < 5e-5),
        ("SSH α_∞ ≈ 1.0009", abs(1 + 28.5 / SSH_MAX_PACKET - 1.0009) < 5e-5),
        ("SSH α_∞,min ≈ 1.0004", abs(1 + 12.5 / SSH_MAX_PACKET - 1.0004) < 5e-5),
        ("QUIC α_∞ ≈ 1.020", abs(1 + 27 / QUIC_MAX_DATAGRAM_PAYLOAD - 1.020) < 5e-4),
        (
            "QUIC α_∞,min ≈ 1.008",
            abs(1 + 11 / QUIC_MAX_DATAGRAM_PAYLOAD - 1.008) < 5e-4,
        ),
        # Claim 2: max |Δα| = 1.2e-2 (QUIC)
        (
            "|Δα| max (QUIC) = 1.2e-2",
            abs(max_delta - 16 / QUIC_MAX_DATAGRAM_PAYLOAD) < 1e-6,
        ),
        # Claim 3: TCP-based |Δα| < 1.2e-3
        ("TCP |Δα| < 1.2e-3", max_delta_tcp < 1.2e-3),
        # Claim 4 (cost_analysis.tex): α_{∞,min} differs from α_∞ by < 1.2e-2
        ("max |Δα| < 1.2e-2", max_delta < 1.2e-2),
    ]

    for desc, passed in checks:
        status = "OK" if passed else "FAIL"
        if not passed:
            ok = False
        print(f"  [{status}] {desc}")

    # Print ω decomposition for cross-reference
    print("\n  ω decomposition:")
    print(f"    TLS 1.3: header(5) + inner_ct(1) + tag(16) = {5+1+16}")
    print(
        f"    SSH:     rec_hdr(4) + pad_len(1) + avg_pad(7.5) + tag(16) = {4+1+7.5+16}"
    )
    print(f"    QUIC:    short_hdr(1+8+2) + tag(16) = {11+16}")
    print(f"\n  ω_min decomposition:")
    print(f"    TLS 1.3: length(2) + inner_ct(1) = {2+1}")
    print(f"    SSH:     rec_hdr(4) + pad_len(1) + avg_pad(7.5) = {4+1+7.5}")
    print(f"    QUIC:    short_hdr(1+8+2) = {1+8+2}")

    print(f"\n  All checks passed: {ok}")
    return ok


def main():
    parser = argparse.ArgumentParser(description="HN-DL storage cost analysis")
    parser.add_argument(
        "--outdir",
        default="paper/figures",
        help="Output directory for figures (default: paper/figures)",
    )
    parser.add_argument(
        "--data-dir", default="data", help="Data directory with PCAPs (default: data)"
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    outdir = repo_root / args.outdir
    outdir.mkdir(parents=True, exist_ok=True)
    data_dir = repo_root / args.data_dir

    plot_amplification(PROTOCOLS, outdir)
    plot_global_storage(PROTOCOLS, outdir)

    validate_against_pcaps(PROTOCOLS, data_dir)
    print_summary_table(PROTOCOLS)
    verify_minimal_archive()


if __name__ == "__main__":
    main()
