"""Generate a CSV worksheet from CycloneDX cross-reference results."""

import csv
import io
from pathlib import Path
from .matcher import MatchResult


def generate_csv(all_results: dict[str, list[MatchResult]],
                 output_path: str | Path | None = None) -> str:
    """Generate a CSV worksheet from cross-reference results.

    Each row is an expected license finding. Columns:
      UID, Package, Version, Expected License, Category, Risk,
      Context (dev/transitive/prod), <tool1>_found, <tool1>_license_match,
      <tool1>_has_spdx_id, <tool1>_dev_tagged, <tool1>_expression_ok,
      <tool2>_found, ...
      Manual: Copyleft Classified, Manual: Policy Blocked, Manual: Notes

    Returns the CSV as a string.
    """
    tool_names = list(all_results.keys())
    results_for_tool = all_results

    # Get the full result list from first tool (all entries)
    if not tool_names:
        return "No tools to compare."

    first_tool_results = results_for_tool[tool_names[0]]
    total_entries = len(first_tool_results)

    # Build CSV
    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    header = [
        "UID", "Package", "Version", "Expected License", "Category", "Risk",
        "Context",
    ]
    for t in tool_names:
        header += [
            f"[{t}] Found",
            f"[{t}] License Match",
            f"[{t}] SPDX ID (vs name)",
            f"[{t}] Dev Tagged",
            f"[{t}] Expression OK",
        ]

    # Manual columns (empty, for evaluator to fill)
    header += [
        "Manual: Copyleft Classified",
        "Manual: Policy Blocked",
        "Manual: Severity Correct",
        "Manual: Notes",
    ]

    writer.writerow(header)

    # Data rows — key by UID
    for i in range(total_entries):
        # Get the entry info from first tool
        first = first_tool_results[i]
        row = [
            first.uid,
            first.package,
            first.version,
            first.expected_license,
            first.category,
            first.risk,
            _get_context_label(first),
        ]

        for t in tool_names:
            res = results_for_tool[t][i]
            row += [
                "YES" if res.found else "MISSING",
                "MATCH" if res.license_match else ("MISMATCH" if res.found else ""),
                "SPDX-ID" if res.has_spdx_id else ("TEXT" if res.found else ""),
                "DEV" if res.dev_tagged else ("PROD" if res.found else ""),
                "OK" if res.expression_correct else ("PRESENT" if res.has_expression else ""),
            ]

        # Manual columns (empty for user)
        row += ["", "", "", ""]
        writer.writerow(row)

    # Summary rows (after all findings, before policy rows)
    writer.writerow([])
    writer.writerow(["--- SCORING SUMMARY ---"])
    summary_headers = ["Tool"]
    for t in tool_names:
        summary_headers += [f"{t}"]
    writer.writerow(summary_headers)

    # Count per tool
    for metric in ["Found", "License Match", "SPDX ID (not free-text)", "Dev Tagged", "Expression OK"]:
        row = [metric]
        for t in tool_names:
            count = 0
            for res in results_for_tool[t]:
                if metric == "Found" and res.found:
                    count += 1
                elif metric == "License Match" and res.license_match:
                    count += 1
                elif metric == "SPDX ID (not free-text)" and res.has_spdx_id:
                    count += 1
                elif metric == "Dev Tagged" and res.dev_tagged:
                    count += 1
                elif metric == "Expression OK" and res.expression_correct:
                    count += 1
            row.append(str(count))
        writer.writerow(row)

    # Component completeness
    row = ["Components in SBOM"]
    for t in tool_names:
        row.append(str(len(results_for_tool[t])))
    writer.writerow(row)

    # Policy evaluation rows (empty, for manual fill-in)
    writer.writerow([])
    writer.writerow(["--- POLICY & MANUAL EVALUATION ---"])
    row = [
        "Question",
    ] + [f"[{t}]" for t in tool_names] + [
        "Max Points",
        "Notes",
    ]
    writer.writerow(row)

    policy_questions = [
        ("B1a: ffmpeg-static identified as GPL-3.0 (strong copyleft)", 0.5),
        ("B1b: agpl-pkg identified as AGPL-3.0 (network copyleft)", 0.5),
        ("B1c: lgpl-pkg identified as LGPL-2.1 (weak copyleft, distinct from GPL)", 0.5),
        ("B1d: Tool has copyleft-specific risk category/badge", 0.5),
        ("B2a: busl-pkg flagged as non-OSI", 0.5),
        ("B2b: sspl-pkg flagged as non-OSI", 0.5),
        ("B3a: ffmpeg-static (prod GPL) severity HIGHER than dev-only-gpl", 0.5),
        ("B3b: dev-only-gpl noted as dev-only / lower severity", 0.5),
        ("B4a: libvips transitive dep visible in tree", 0.5),
        ("B4b: Dependency path sharp -> libvips shown", 0.5),
    ]

    for question, max_pts in policy_questions:
        qrow = [question] + ["" for _ in tool_names] + [str(max_pts), ""]
        writer.writerow(qrow)

    # Score summary
    writer.writerow([])
    tot_sbom = 5  # Part A max
    tot_policy = 5  # Part B max
    writer.writerow(["Part A: CycloneDX SBOM Accuracy", "", f"Max: {tot_sbom}"])
    writer.writerow(["Part B: Policy & Classification", "", f"Max: {tot_policy}"])
    writer.writerow(["LICENSE ANALYSIS TOTAL", "", f"Max: {tot_sbom + tot_policy}"])

    return output.getvalue()


def _get_context_label(res) -> str:
    """Get human-readable context label."""
    if res.is_transitive:
        return f"transitive (via {res.via})" if res.via else "transitive"
    if res.is_dev:
        return "devDependency"
    return "prod (runtime)"


def write_csv(all_results: dict[str, list[MatchResult]],
              output_path: str | Path):
    """Generate and write the CSV to a file."""
    csv_content = generate_csv(all_results)
    Path(output_path).write_text(csv_content)
    return csv_content
