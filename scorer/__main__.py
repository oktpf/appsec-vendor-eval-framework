#!/usr/bin/env python3
"""CLI entry point: parse SARIF reports, match against answer key, generate scorecard.

Usage:
    python -m scorer /path/to/sarif-reports/ --output scorecard.md
    python -m scorer /path/to/sarif-reports/ --answer-key custom_key.md --verbose
"""

import argparse
import json
import sys
from pathlib import Path

# Allow running as script or module
sys.path.insert(0, str(Path(__file__).parent.parent))

from scorer.answer_key_parser import load_answer_key
from scorer.sarif_parser import load_sarif_reports
from scorer.matcher import match_findings, LINE_TOLERANCE
from scorer.scorer import calculate_scores, generate_scorecard


DEFAULT_ANSWER_KEY = Path(__file__).parent.parent / "appsec-vendor-eval-framework" / "answer_key.md"


def main():
    parser = argparse.ArgumentParser(
        description="Score SARIF reports against the appsec-vendor-eval answer key."
    )
    parser.add_argument(
        "sarif_dir",
        help="Directory containing .sarif files (one per tool, or nested by tool name).",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output path for scorecard markdown (default: stdout + <sarif_dir>/scorecard.md).",
    )
    parser.add_argument(
        "--answer-key", "-a",
        default=str(DEFAULT_ANSWER_KEY),
        help=f"Path to answer_key.md (default: {DEFAULT_ANSWER_KEY}).",
    )
    parser.add_argument(
        "--line-tolerance", "-t",
        type=int,
        default=LINE_TOLERANCE,
        help=f"Line number matching tolerance in ±lines (default: {LINE_TOLERANCE}).",
    )
    parser.add_argument(
        "--json-output", "-j",
        default=None,
        help="Also write detailed match results as JSON to this path.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed matching diagnostics.",
    )

    args = parser.parse_args()

    # Validate inputs
    sarif_dir = Path(args.sarif_dir)
    if not sarif_dir.is_dir():
        print(f"Error: {sarif_dir} is not a directory.", file=sys.stderr)
        sys.exit(1)

    answer_key_path = Path(args.answer_key)
    if not answer_key_path.exists():
        print(f"Error: Answer key not found at {answer_key_path}", file=sys.stderr)
        sys.exit(1)

    # Override line tolerance if specified
    import scorer.matcher
    scorer.matcher.LINE_TOLERANCE = args.line_tolerance

    # Load answer key
    print(f"Loading answer key from {answer_key_path}...")
    ak = load_answer_key(answer_key_path)
    print(f"  {ak['total_vulns']} known vulnerabilities, {ak['total_honeypots']} honeypots")
    for tb, entries in sorted(ak["by_testbed"].items()):
        vulns = [e for e in entries if not e.is_honeypot]
        hps = [e for e in entries if e.is_honeypot]
        print(f"  {tb}: {len(vulns)} vulns, {len(hps)} honeypots")

    # Load SARIF reports
    print(f"\nScanning {sarif_dir} for .sarif files...")
    reports = load_sarif_reports(sarif_dir)
    if not reports:
        print("Error: No .sarif files found.", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(reports)} tool(s): {', '.join(reports.keys())}\n")

    # Match and score each tool
    all_scores = []
    all_results = {}

    for tool_name, findings in sorted(reports.items()):
        print(f"--- {tool_name} ({len(findings)} findings) ---")

        result = match_findings(findings, answer_key_path)
        score = calculate_scores(result, tool_name)

        print(f"  True Positives:     {score.total_tp}")
        print(f"  False Negatives:    {score.total_fn}")
        print(f"  Honeypot Hits (FP): {score.total_honeypot_hits}")
        print(f"  Unmatched Findings: {score.total_unmatched}")
        print(f"  Detection Score:    {score.detection_accuracy_total}/40")
        print(f"  Specialized Score:  {score.specialized_coverage_total}/40")
        print(f"  Automated Total:    {score.automated_total}/80")

        if args.verbose:
            # Show missed vulns
            if result["false_negatives"]:
                print(f"\n  Missed vulnerabilities ({len(result['false_negatives'])}):")
                for fn in result["false_negatives"][:10]:
                    loc = f"{fn.source_file}:{fn.source_line}" if fn.source_file else "unknown"
                    print(f"    {fn.uid} ({fn.cwe}) at {loc}")
                if len(result["false_negatives"]) > 10:
                    print(f"    ... and {len(result['false_negatives']) - 10} more")

            # Show honeypot hits
            if result["honeypot_hits"]:
                print(f"\n  Honeypot false positives ({len(result['honeypot_hits'])}):")
                for hp in result["honeypot_hits"][:10]:
                    entry = hp.matched_entry
                    loc = f"{entry.source_file}:{entry.source_line}" if entry.source_file else "unknown"
                    print(f"    {hp.finding.rule_id} → {entry.uid} at {loc}")
                if len(result["honeypot_hits"]) > 10:
                    print(f"    ... and {len(result['honeypot_hits']) - 10} more")

        print()
        all_scores.append(score)
        all_results[tool_name] = {
            "tp": score.total_tp,
            "fn": score.total_fn,
            "hp_hits": score.total_honeypot_hits,
            "unmatched": score.total_unmatched,
            "detection_score": score.detection_accuracy_total,
            "specialized_score": score.specialized_coverage_total,
            "automated_total": score.automated_total,
        }

    # Generate scorecard
    print("Generating scorecard...")
    markdown = generate_scorecard(all_scores)

    # Determine output path
    output_path = args.output
    if not output_path:
        output_path = str(sarif_dir / "scorecard.md")

    Path(output_path).write_text(markdown)
    print(f"Scorecard written to {output_path}")

    # Optional JSON output
    if args.json_output:
        Path(args.json_output).write_text(json.dumps(all_results, indent=2))
        print(f"Detailed results written to {args.json_output}")

    # Print ranking summary
    print("\n" + "=" * 60)
    print("RANKING")
    print("=" * 60)
    sorted_scores = sorted(all_scores, key=lambda s: s.automated_total, reverse=True)
    for i, score in enumerate(sorted_scores, 1):
        print(f"  {i}. {score.tool_name}: {score.automated_total}/80 "
              f"(TP={score.total_tp}, FN={score.total_fn}, HP={score.total_honeypot_hits})")


if __name__ == "__main__":
    main()
