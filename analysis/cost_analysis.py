#!/usr/bin/env python3
"""Per-session protocol overhead model for HN-DL captures.

Computes the protocol overhead ratio α = bytes_stored / bytes_plaintext
for TLS 1.2, TLS 1.3, QUIC, and SSH across a range of payload sizes.
Global retention costs use storage_model.py and monte_carlo_cost.py; compact
archive measurements use scripts/minarx_experiment.py and retain authentication tags.
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
SSH_MAX_PACKET = 32768  # Assumed SSH packet-size scale, not a protocol limit.


@dataclass
class ProtocolModel:
    """Approximate per-session storage model for one protocol/mode."""

    name: str
    label: str
    handshake: int  # total handshake bytes on wire (both directions)
    tcp_hs_pkts: int  # TCP packets in handshake phase
    record_header: int  # per-record header bytes
    aead_tag: float  # AEAD tag / MAC/padding expansion per record
    extra_per_rec: int  # fixed extra per record (e.g. TLS 1.3 content-type byte)
    padding_block_size: int  # SSH block alignment (RFC 4253 §6); 0 for TLS/QUIC
    max_record: int  # max app-data bytes per record/packet
    channel_overhead: int  # SSH channel-layer framing; 0 for TLS
    is_udp: bool
    color: str
    linestyle: str
    marker: str

    def _mean_ssh_padding(self) -> float:
        """Mean length byte plus padding, assuming uniform alignment residues."""
        if self.padding_block_size == 0:
            return 0
        # Padding spans 4 through block_size + 3 bytes; add its length byte.
        return 1 + 4 + (self.padding_block_size - 1) / 2

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
            # For TLS this is the maximum application fragment; AEAD expansion
            # is allowed outside that limit. For QUIC it is an explicitly
            # modelled effective application payload per datagram.
            max_payload_per_rec = self.max_record
        n_records = max(1, int(np.ceil(plaintext / max_payload_per_rec)))
        payload_per_rec = plaintext / n_records
        padding = self._mean_ssh_padding()
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
    # TLS 1.2 CBC: 16 B explicit IV + 20 B HMAC-SHA1 + 8.5 B mean
    # padding (padding bytes plus the padding-length byte).
    aead_tag=44.5,
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
    max_record=TLS_MAX_RECORD - 1,
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
        f"{'α(1kB)':>8} {'α(100kB)':>8} {'α(10MB)':>8}"
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

    validate_against_pcaps(PROTOCOLS, data_dir)
    print_summary_table(PROTOCOLS)


if __name__ == "__main__":
    main()
