#!/usr/bin/env python3
"""CLI helper to merge scanner JSON files into consolidated_report.json."""

from __future__ import annotations

import argparse
from pathlib import Path

from services.aggregate import aggregate_reports, save_consolidated_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate scanner reports")
    parser.add_argument("inputs", nargs="+", help="Scanner JSON file paths")
    parser.add_argument(
        "-o",
        "--output",
        default="reports/consolidated_report.json",
        help="Output consolidated report path",
    )
    parser.add_argument("--scan-id", default=None)
    parser.add_argument("--repository", default=None)
    args = parser.parse_args()

    report = aggregate_reports(args.inputs, scan_id=args.scan_id, repository=args.repository)
    output = save_consolidated_report(report, Path(args.output))
    print(f"Wrote {len(report.findings)} findings to {output}")


if __name__ == "__main__":
    main()
