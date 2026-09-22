#!/usr/bin/env python3
"""Render invariant byte accounting from verified MinARX archives."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from minarx import inspect_archive


def rows(paths: list[Path]) -> list[dict]:
    result = []
    for path in paths:
        item = inspect_archive(path)
        raw = int(item["raw_capture_bytes"])
        structural_baseline = int(item["structural_baseline_bytes"])
        structural_final = int(item["structural_bytes_after_entropy_coding"])
        saved = structural_baseline - structural_final
        result.append(
            {
                "category": item["category"],
                "profile": item["profile"]["name"],
                "raw": raw,
                "opaque": int(item["opaque_bytes"]),
                "transport": int(item["transport_payload_bytes"]),
                "envelope": int(item["capture_envelope_bytes"]),
                "clear": int(item["clear_protocol_bytes"]),
                "layout": int(item["protocol_layout_bytes"]),
                "fixed": int(item["fixed_container_bytes"]),
                "projection": int(item["protocol_projection_saving_bytes"]),
                "baseline": structural_baseline,
                "pre_entropy": int(item["structural_bytes_before_entropy_coding"]),
                "structural": structural_final,
                "compact": int(item["archive_bytes"]),
                "pruned": int(item["deterministic_pruning_bytes"]),
                "entropy": int(item["layout_entropy_saving_bytes"]),
                "saved": saved,
                "percent": 100 * saved / structural_baseline if structural_baseline else 0.0,
            }
        )
    return result


def markdown(items: list[dict]) -> str:
    lines = [
        "| Category | Profile | Raw capture (B) | Transport payload (B) | Opaque, verbatim (B) | Capture envelope removed (B) | Clear protocol (B) | Plain MinARX layout (B) | Protocol projection saving (B) | Fixed container (B) | Layout compression saving (B) | MinARX total (B) | Total saved (B) |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in items:
        lines.append(
            f"| {item['category']} | `{item['profile']}` | {item['raw']} | "
            f"{item['transport']} | {item['opaque']} | {item['envelope']} | "
            f"{item['clear']} | {item['layout']} | {item['projection']} | "
            f"{item['fixed']} | {item['entropy']} | {item['compact']} | "
            f"{item['raw'] - item['compact']} |"
        )
    return "\n".join(lines)


def latex(items: list[dict]) -> str:
    lines = [
        r"\begin{tabular}{llrrrrrrrrrrr}",
        r"\hline",
        r"Category & Profile & Raw & Transport & Opaque & Envelope & Clear & Layout & Projection & Fixed & Compression & MinARX & Saved \\",
        r"\hline",
    ]
    for item in items:
        category = item["category"].replace("_", r"\_")
        profile = item["profile"].replace("_", r"\_")
        lines.append(
            f"{category} & {profile} & {item['raw']:,} & {item['transport']:,} & "
            f"{item['opaque']:,} & {item['envelope']:,} & {item['clear']:,} & "
            f"{item['layout']:,} & {item['projection']:,} & {item['fixed']:,} & "
            f"{item['entropy']:,} & {item['compact']:,} & "
            f"{item['raw'] - item['compact']:,} \\\\"
        )
    lines.extend([r"\hline", r"\end{tabular}"])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="+", type=Path)
    parser.add_argument("--format", choices=["markdown", "latex"], default="markdown")
    args = parser.parse_args()
    items = rows(args.archives)
    print(markdown(items) if args.format == "markdown" else latex(items))


if __name__ == "__main__":
    main()
