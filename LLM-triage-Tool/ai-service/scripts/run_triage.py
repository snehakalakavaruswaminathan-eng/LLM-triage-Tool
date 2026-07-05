#!/usr/bin/env python3
"""CI entry point: aggregate scanner outputs and run AI triage."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.aggregate import aggregate_reports, save_consolidated_report  # noqa: E402
from services.triage_service import TriageService  # noqa: E402


async def _run(args: argparse.Namespace) -> int:
    inputs = [Path(path) for path in args.inputs]
    missing = [str(path) for path in inputs if not path.exists()]
    if missing:
        print(f"Missing scanner report(s): {', '.join(missing)}", file=sys.stderr)
        return 1

    report = aggregate_reports(
        inputs,
        scan_id=args.scan_id,
        repository=args.repository,
    )
    consolidated_path = save_consolidated_report(report, Path(args.output))
    print(f"Consolidated {len(report.findings)} findings -> {consolidated_path}")

    if args.aggregate_only:
        return 0

    result = await TriageService().run(
        report=report,
        create_patches=args.create_patches,
        create_draft_prs=args.create_draft_prs,
        write_reports=True,
    )

    summary = {
        "scan_id": result.scan_id,
        "total_raw_findings": result.total_raw_findings,
        "total_after_dedup": result.total_after_dedup,
        "top_findings": len(result.top_findings),
        "patch_files": result.patch_files,
        "draft_pr_urls": result.draft_pr_urls,
        "report_json_path": result.report_json_path,
        "report_md_path": result.report_md_path,
        "llm_mock_mode": result.llm_mock_mode,
    }
    print(json.dumps(summary, indent=2))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate scanner reports and run AI triage")
    parser.add_argument(
        "inputs",
        nargs="*",
        default=[
            "scanner-output/semgrep.json",
            "scanner-output/trivy.json",
            "scanner-output/checkov.json",
            "scanner-output/gitleaks.json",
            "scanner-output/zap.json",
        ],
        help="Scanner JSON report paths",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="reports/consolidated_report.json",
        help="Consolidated report output path",
    )
    parser.add_argument("--scan-id", default=None)
    parser.add_argument("--repository", default="juice-shop/juice-shop")
    parser.add_argument("--aggregate-only", action="store_true")
    parser.add_argument("--no-patches", action="store_true")
    parser.add_argument("--create-draft-prs", action="store_true")
    args = parser.parse_args()

    args.create_patches = not args.no_patches
    raise SystemExit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
