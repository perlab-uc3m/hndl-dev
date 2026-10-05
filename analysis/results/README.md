# Results used by the paper

`minarx_live_2026-09-22.{json,csv}` is the source of Table III in
`main_review_2.tex`: six reported capture/archive sizes and authenticated
recovery checks. The 28 September files are an independent replication using
new captures. Their sizes differ, notably for SSH and TLS 1.3 0-RTT; they do
not replace the 22 September table values.

The manuscript cites public commit
`4cd96284ffe398e1e02f39230f9762c3c3834c6e`, which includes those reference
results and the storage-model configuration. The corrections below postdate
that snapshot and need a subsequent public revision to be available on GitHub.

## TLS rotation correction, 5 October 2026

`mitigation_psk_dhe_rotation.csv` contains a fresh 15-configuration sweep. Each
connection requests `min(R, remaining)` application bytes. An initial full
handshake is followed by PSK-DHE resumptions. Checks require the scheduled
number of ClientHellos, server acceptance of the PSK on every resumption, and
a distinct server key share per connection. The script chooses `ceil(P/R)`
connections; matching that count validates the capture and negotiated
handshakes, not a separately predicted rotation law.

`mitigation_psk_dhe_rotation_2026-10-05.json` records tool versions, the source
hash used for the sweep, capture hashes, and observed PSK/key-share checks.
The captures were inspected again for server PSK acceptance and distinct
key shares; these checks are now part of the capture helper. Reproduce with
`python3 analysis/mitigation_psk_dhe.py` from the repository root (patched
OpenSSL and packet-capture permissions required). Byte counts can vary with
packetization and timing; handshake counts and total requested application
bytes are the deterministic checks.

`mitigation_psk_dhe_rotation_legacy.csv` preserves the superseded file. Its
exchange counts are unchanged, but some captures fetched a full `R` bytes
when fewer remained (e.g., a 10 kB request with a 1 MB interval). Those byte
counts must not be used as measurements of the requested payload.

## Analysis entry points

Use `storage_model.py` and `monte_carlo_cost.py` for global retention costs.
`cost_analysis.py` supplies per-session protocol overhead only; the obsolete
3.8 ZB/year calculation and tag-stripping archive check have been removed.
Compact archives retain authentication tags and are evaluated by
`scripts/minarx_experiment.py`.

Figure 4 uses `plot_rekey_counts.py`: markers are observed exchanges; TLS
curves are configured connection counts. Figure 5 uses
`mitigation_padding.py --plot-only`: markers are measurements; curves use
setup overhead fitted to the smallest payload. The y-axis now includes the
100-byte, 16 KiB-padding measurement.
