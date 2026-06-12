"""Match SARIF findings against answer key entries using fuzzy matching."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .answer_key_parser import AnswerEntry, load_answer_key
from .sarif_parser import SarifFinding


# How many lines of tolerance for line number matching
LINE_TOLERANCE = 5


@dataclass
class MatchResult:
    """Result of matching a SARIF finding against an answer key entry."""
    finding: SarifFinding
    matched_entry: Optional[AnswerEntry]
    is_true_positive: bool
    is_honeypot_hit: bool
    match_score: float  # 0.0-1.0 confidence


def normalize_path(path: str) -> str:
    """Normalize a file path for comparison.

    Handles:
    - Different path separators
    - Leading ./ or /
    - Testbed prefixes (e.g. 'reflection-testbed/python/app.py' → 'python/app.py')
    """
    p = Path(path)
    # Normalize separators
    normalized = str(p).replace('\\', '/')

    # Strip leading ./ or /
    normalized = normalized.lstrip('./').lstrip('/')

    return normalized


def paths_match(sarif_path: str, answer_path: str) -> bool:
    """Check if two file paths refer to the same file."""
    s_norm = normalize_path(sarif_path)
    a_norm = normalize_path(answer_path)

    # Exact match
    if s_norm == a_norm:
        return True

    # SARIF path may include testbed prefix; check if answer path is a suffix
    if s_norm.endswith('/' + a_norm):
        return True

    # Answer path may be relative; check basename match with parent context
    s_parts = s_norm.split('/')
    a_parts = a_norm.split('/')

    # Check if the last N components match (where N = len(answer_path parts))
    if len(s_parts) >= len(a_parts):
        if s_parts[-len(a_parts):] == a_parts:
            return True

    return False


def lines_match(finding_lines: list[int], answer_lines: list[int]) -> bool:
    """Check if any finding line is within tolerance of any answer line."""
    for f_line in finding_lines:
        for a_line in answer_lines:
            if abs(f_line - a_line) <= LINE_TOLERANCE:
                return True
    return False


def cwe_matches(finding_cwe: Optional[str], answer_cwe: str) -> bool:
    """Check if CWE IDs match."""
    if not finding_cwe:
        return False
    return finding_cwe.upper() == answer_cwe.upper()


def compute_match_score(
    path_match: bool,
    line_match: bool,
    cwe_match: bool,
) -> float:
    """Compute a confidence score for a potential match."""
    score = 0.0
    if path_match:
        score += 0.4
    if line_match:
        score += 0.4
    if cwe_match:
        score += 0.2
    return score


def match_findings(
    findings: list[SarifFinding],
    answer_key_path: str,
) -> dict:
    """Match SARIF findings against the answer key.

    Returns a structured result with TPs, FNs, honeypot hits, and unmatched findings.
    """
    ak = load_answer_key(answer_key_path)
    vulns = ak["vulnerabilities"]
    honeypots = ak["honeypots"]

    matched_vuln_ids: set[str] = set()
    matched_honeypot_ids: set[str] = set()

    true_positives: list[MatchResult] = []
    honeypot_hits: list[MatchResult] = []
    unmatched_findings: list[SarifFinding] = []

    for finding in findings:
        best_match: Optional[tuple[AnswerEntry, float]] = None
        best_score = 0.0

        # Check against vulnerabilities first
        for entry in vulns:
            if not entry.relevant_files or not entry.relevant_lines:
                continue

            path_ok = any(
                paths_match(finding.file_path, af) for af in entry.relevant_files
            )
            line_ok = lines_match(finding.relevant_lines, entry.relevant_lines)
            cwe_ok = cwe_matches(finding.cwe, entry.cwe)

            score = compute_match_score(path_ok, line_ok, cwe_ok)

            # Require at least path OR line match to consider it a hit
            if score > best_score and (path_ok or line_ok):
                best_score = score
                best_match = (entry, score)

        # Check against honeypots
        hp_match: Optional[tuple[AnswerEntry, float]] = None
        hp_score = 0.0
        for entry in honeypots:
            if not entry.source_file:
                continue

            path_ok = paths_match(finding.file_path, entry.source_file)
            line_ok = (
                lines_match(
                    finding.relevant_lines, [entry.source_line]
                )
                if entry.source_line
                else False
            )
            cwe_ok = cwe_matches(finding.cwe, entry.cwe)

            score = compute_match_score(path_ok, line_ok, cwe_ok)

            if score > hp_score and (path_ok or line_ok):
                hp_score = score
                hp_match = (entry, score)

        # Decide the classification
        # If it matches a honeypot better than a vuln, it's an FP
        if hp_match and hp_match[1] >= best_score:
            entry, score = hp_match
            matched_honeypot_ids.add(entry.uid)
            honeypot_hits.append(MatchResult(
                finding=finding,
                matched_entry=entry,
                is_true_positive=False,
                is_honeypot_hit=True,
                match_score=score,
            ))
        elif best_match and best_match[1] >= 0.4:
            # Minimum threshold for a TP match
            entry, score = best_match
            matched_vuln_ids.add(entry.uid)
            true_positives.append(MatchResult(
                finding=finding,
                matched_entry=entry,
                is_true_positive=True,
                is_honeypot_hit=False,
                match_score=score,
            ))
        else:
            unmatched_findings.append(finding)

    # False negatives = vulns not matched
    false_negatives = [e for e in vulns if e.uid not in matched_vuln_ids]

    return {
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "honeypot_hits": honeypot_hits,
        "unmatched_findings": unmatched_findings,
        "matched_vuln_ids": matched_vuln_ids,
        "matched_honeypot_ids": matched_honeypot_ids,
        "total_vulns": len(vulns),
        "total_honeypots": len(honeypots),
    }
