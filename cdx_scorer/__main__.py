"""CycloneDX License Analysis Scorer.

Usage:
    python -m cdx_scorer /path/to/cdx-reports/
    python -m cdx_scorer /path/to/cdx-reports/ --answer-key answer_key.md -o results.csv

Takes CycloneDX 1.6 JSON reports from one or more SCA tools, compares them
against the expected license findings in the answer key, and generates a CSV
worksheet showing per-finding matches and misses across tools.
"""

import argparse
import sys
from pathlib import Path

# Allow running as script or module
sys.path.insert(0, str(Path(__file__).parent.parent))

from cdx_scorer.cdx_parser import load_cdx_reports
from cdx_scorer.license_key_parser import parse_license_key
from cdx_scorer.matcher import match_all_tools
from cdx_scorer.csv_writer import write_csv


DEFAULT_ANSWER_KEY = Path(__file__).parent.parent / "answer_key.md"


def main():
    parser = argparse.ArgumentParser(
        description="Score CycloneDX SBOM reports against the license-testbed answer key."
    )
    parser.add_argument(
        "cdx_dir",
        help="Directory containing CycloneDX JSON reports (one per tool).",
    )
    parser.add_argument(
        "--answer-key", "-a",
        default=str(DEFAULT_ANSWER_KEY),
        help=f"Path to answer_key.md (default: {DEFAULT_ANSWER_KEY}).",
    )
    parser.add_argument(
        "--output", "-o",
        default="license_worksheet.csv",
        help="Output CSV path (default: license_worksheet.csv).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed per-tool diagnostics.",
    )

    args = parser.parse_args()

    # Validate inputs
    cdx_dir = Path(args.cdx_dir)
    if not cdx_dir.is_dir():
        print(f"Error: {cdx_dir} is not a directory.", file=sys.stderr)
        sys.exit(1)

    ak_path = Path(args.answer_key)
    if not ak_path.exists():
        print(f"Error: Answer key not found at {ak_path}", file=sys.stderr)
        sys.exit(1)

    # Load answer key (LICENSE section only)
    print(f"Loading license findings from {ak_path}...")
    expected_entries = parse_license_key(ak_path)
    if not expected_entries:
        print("Error: No LICENSE_COMP entries found in answer key.", file=sys.stderr)
        sys.exit(1)

    print(f"  {len(expected_entries)} expected license findings")
    for entry in expected_entries:
        context = "dev" if entry.is_dev else ("transitive" if entry.is_transitive else "prod")
        print(f"  {entry.uid:30s} {entry.package:30s} {entry.expected_license:25s} [{context}]")

    # Load CycloneDX reports
    print(f"\nScanning {cdx_dir} for CycloneDX JSON reports...")
    reports = load_cdx_reports(cdx_dir)
    if not reports:
        print("Error: No valid CycloneDX reports found.", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(reports)} tool(s): {', '.join(reports.keys())}\n")

    for tool_name, report in reports.items():
        meta = report["metadata"]
        print(f"  {tool_name}: {meta['total_components']} components, "
              f"SBOM v{meta['spec_version']}")

    # Cross-reference
    print("\nCross-referencing...")
    all_results = match_all_tools(reports, expected_entries)

    for tool_name, results in all_results.items():
        found = sum(1 for r in results if r.found)
        matched_license = sum(1 for r in results if r.license_match)
        print(f"  {tool_name}: {found}/{len(results)} components found, "
              f"{matched_license} license matches")

    # Generate CSV
    csv_content = write_csv(all_results, args.output)
    print(f"\nWorksheet written to {args.output}")

    if args.verbose:
        # Show cross-tool comparison
        print("\n--- Cross-Tool Comparison ---")
        tool_names = list(all_results.keys())
        if len(tool_names) >= 2:
            t1, t2 = tool_names[0], tool_names[1]
            r1 = all_results[t1]
            r2 = all_results[t2]

            # Found in t1 but not t2
            only_in_t1 = [r for r in r1 if r.found and
                          not any(x.uid == r.uid and x.found for x in r2)]
            only_in_t2 = [r for r in r2 if r.found and
                          not any(x.uid == r.uid and x.found for x in r1)]

            if only_in_t1:
                print(f"\n  Found ONLY by {t1}:")
                for r in only_in_t1:
                    print(f"    {r.package}")
            if only_in_t2:
                print(f"\n  Found ONLY by {t2}:")
                for r in only_in_t2:
                    print(f"    {r.package}")

        # Show which MANUAL-evaluation rows need filling
        print("\nManual policy rows requiring evaluator input: see Worksheet.")
        print("Rated categories: B1 (copyleft detection), B2 (non-OSI flagging),")
        print("B3 (dev/prod differentiation), B4 (transitive discovery).")


if __name__ == "__main__":
    main()
