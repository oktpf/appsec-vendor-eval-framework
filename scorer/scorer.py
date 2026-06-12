"""Calculate rubric scores from match results and generate scorecard markdown."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .answer_key_parser import AnswerEntry, load_answer_key
from .matcher import MatchResult


# Testbed → rubric category mapping for Category 5 scoring
TESTBED_CATEGORY_MAP = {
    "access-control-testbed": ("Authorization & Access Control", 10),
    "database-testbed": ("Stored Procedure / Database Code Analysis", 5),
    "reflection-testbed": ("Reflection & Dynamic Code Detection", 5),
    "cloud-iac-testbed": ("IaC / Cloud Misconfiguration Detection", 10),
    "web-vulns-testbed": ("Web Application Vulnerability Detection", 10),
    "mass-assignment-testbed": ("Authorization & Access Control", 0),  # bonus, folded into auth
}

# Difficulty weights for scoring
DIFFICULTY_WEIGHT = {
    "easy": 1.0,
    "medium": 1.5,
    "hard": 2.0,
}


@dataclass
class VendorScore:
    """Calculated scores for a single vendor/tool."""
    tool_name: str

    # Category 1: Detection Accuracy (40 pts)
    tp_rate_score: float = 0.0       # /15
    fp_rate_score: float = 0.0       # /10
    complex_dataflow_score: float = 0.0  # /10
    reachability_score: Optional[float] = None  # /5 (manual)

    # Category 5: Specialized Detection (40 pts)
    auth_score: float = 0.0          # /10
    database_score: float = 0.0      # /5
    reflection_score: float = 0.0    # /5
    iac_score: float = 0.0          # /10
    web_score: float = 0.0          # /10

    # Counts
    total_tp: int = 0
    total_fn: int = 0
    total_honeypot_hits: int = 0
    total_unmatched: int = 0

    # Per-testbed breakdowns
    testbed_results: dict[str, dict] = field(default_factory=dict)

    @property
    def detection_accuracy_total(self) -> float:
        reach = self.reachability_score if self.reachability_score is not None else 0
        return round(self.tp_rate_score + self.fp_rate_score +
                     self.complex_dataflow_score + reach, 1)

    @property
    def specialized_coverage_total(self) -> float:
        return round(self.auth_score + self.database_score +
                     self.reflection_score + self.iac_score + self.web_score, 1)

    @property
    def automated_total(self) -> float:
        return round(self.detection_accuracy_total + self.specialized_coverage_total, 1)

    @property
    def max_automated(self) -> float:
        return 40 + 40  # Cat 1 + Cat 5


def calculate_scores(
    match_result: dict,
    tool_name: str,
) -> VendorScore:
    """Calculate rubric scores from match results."""
    score = VendorScore(tool_name=tool_name)

    total_vulns = match_result["total_vulns"]
    tps = match_result["true_positives"]
    fns = match_result["false_negatives"]
    hp_hits = match_result["honeypot_hits"]
    unmatched = match_result["unmatched_findings"]

    score.total_tp = len(tps)
    score.total_fn = len(fns)
    score.total_honeypot_hits = len(hp_hits)
    score.total_unmatched = len(unmatched)

    # --- Category 1: Detection Accuracy (40 pts) ---

    # True Positive Rate (15 pts): % of known vulns detected, weighted by difficulty
    if total_vulns > 0:
        weighted_detected = sum(
            DIFFICULTY_WEIGHT.get(m.matched_entry.difficulty, 1.0)
            for m in tps
        )
        weighted_total = sum(
            DIFFICULTY_WEIGHT.get(e.difficulty, 1.0)
            for e in fns + [m.matched_entry for m in tps]
        )
        score.tp_rate_score = round(
            (weighted_detected / weighted_total * 15) if weighted_total > 0 else 0, 1
        )

    # False Positive Rate (10 pts): penalize honeypot hits + excessive unmatched
    total_findings = len(tps) + len(hp_hits) + len(unmatched)
    if total_vulns > 0:
        fp_ratio = (len(hp_hits) + len(unmatched)) / (total_vulns + len(hp_hits) + len(unmatched))
        # Score: 10 for near-zero noise, 0 for unusable noise
        score.fp_rate_score = round(max(0, 10 * (1 - fp_ratio)), 1)

    # Complex Dataflow (10 pts): based on hard/medium findings detected
    hard_medium_vulns = [e for e in fns + [m.matched_entry for m in tps]
                         if e.difficulty in ("hard", "medium")]
    hard_medium_detected = [m for m in tps
                            if m.matched_entry.difficulty in ("hard", "medium")]
    if hard_medium_vulns:
        score.complex_dataflow_score = round(
            len(hard_medium_detected) / len(hard_medium_vulns) * 10, 1
        )

    # --- Category 5: Specialized Detection Coverage (40 pts) ---

    # Group TPs and FNs by testbed
    tp_by_testbed: dict[str, list[MatchResult]] = {}
    fn_by_testbed: dict[str, list[AnswerEntry]] = {}

    for m in tps:
        tb = m.matched_entry.testbed
        tp_by_testbed.setdefault(tb, []).append(m)

    for e in fns:
        tb = e.testbed
        fn_by_testbed.setdefault(tb, []).append(e)

    # Score each sub-category
    for testbed, (category_name, max_pts) in TESTBED_CATEGORY_MAP.items():
        detected = len(tp_by_testbed.get(testbed, []))
        missed = len(fn_by_testbed.get(testbed, []))
        total = detected + missed

        if total > 0:
            cat_score = round(detected / total * max_pts, 1)
        else:
            cat_score = 0.0

        # Always store per-testbed results (even bonus categories)
        score.testbed_results[testbed] = {
            "detected": detected,
            "missed": missed,
            "total": total,
            "score": cat_score if max_pts > 0 else None,
            "max_pts": max_pts,
        }

        if max_pts == 0:
            continue  # Skip scoring bonus categories

        # Map to score fields
        if category_name == "Authorization & Access Control":
            score.auth_score = max(score.auth_score, cat_score)
        elif category_name == "Stored Procedure / Database Code Analysis":
            score.database_score = cat_score
        elif category_name == "Reflection & Dynamic Code Detection":
            score.reflection_score = cat_score
        elif category_name == "IaC / Cloud Misconfiguration Detection":
            score.iac_score = cat_score
        elif category_name == "Web Application Vulnerability Detection":
            score.web_score = cat_score

    return score


def generate_scorecard(
    scores: list[VendorScore],
    output_path: Optional[str] = None,
) -> str:
    """Generate a markdown scorecard comparing all vendors."""
    lines = []
    lines.append("# Vendor Scorecard — Automated SARIF Analysis\n")
    lines.append("Generated by `scorer` from SARIF reports.\n")

    # Summary ranking table
    lines.append("## Ranking (Automated Categories: Detection + Specialized Coverage)\n")
    lines.append("| Rank | Tool | Cat 1: Detection (40) | Cat 5: Specialized (40) | Automated Total (80) | TPs | FNs | HP Hits |\n")
    lines.append("|------|------|----------------------:|------------------------:|---------------------:|----:|----:|--------:|\n")

    sorted_scores = sorted(scores, key=lambda s: s.automated_total, reverse=True)
    for i, score in enumerate(sorted_scores, 1):
        lines.append(
            f"| {i} | **{score.tool_name}** | "
            f"{score.detection_accuracy_total}/40 | "
            f"{score.specialized_coverage_total}/40 | "
            f"**{score.automated_total}/80** | "
            f"{score.total_tp} | {score.total_fn} | {score.total_honeypot_hits} |\n"
        )

    lines.append("")

    # Per-vendor detail
    for score in sorted_scores:
        lines.append(f"## {score.tool_name}\n")

        # Category 1 breakdown
        lines.append("### Category 1: Detection Accuracy & Depth (40 pts)\n")
        lines.append("| Sub-category | Max | Score |\n")
        lines.append("|:-------------|----:|------:|\n")
        lines.append(f"| True Positive Rate (weighted) | 15 | {score.tp_rate_score} |\n")
        lines.append(f"| False Positive Rate | 10 | {score.fp_rate_score} |\n")
        lines.append(f"| Complex Dataflow (hard/medium) | 10 | {score.complex_dataflow_score} |\n")
        reach_str = f"{score.reachability_score}" if score.reachability_score is not None else "(manual)"
        lines.append(f"| Reachability Analysis (SCA) | 5 | {reach_str} |\n")
        lines.append(f"| **Subtotal** | **40** | **{score.detection_accuracy_total}** |\n\n")

        # Category 5 breakdown
        lines.append("### Category 5: Specialized Detection Coverage (40 pts)\n")
        lines.append("| Sub-category | Max | Score |\n")
        lines.append("|:-------------|----:|------:|\n")
        lines.append(f"| Authorization & Access Control | 10 | {score.auth_score} |\n")
        lines.append(f"| Stored Procedure / Database Code Analysis | 5 | {score.database_score} |\n")
        lines.append(f"| Reflection & Dynamic Code Detection | 5 | {score.reflection_score} |\n")
        lines.append(f"| IaC / Cloud Misconfiguration Detection | 10 | {score.iac_score} |\n")
        lines.append(f"| Web Application Vulnerability Detection | 10 | {score.web_score} |\n")
        lines.append(f"| **Subtotal** | **40** | **{score.specialized_coverage_total}** |\n\n")

        # Per-testbed results
        lines.append("### Testbed Breakdown\n")
        lines.append("| Testbed | Detected | Missed | Total | Score |\n")
        lines.append("|---------|---------:|-------:|------:|------:|\n")

        testbed_order = [
            "secret-testbed", "reflection-testbed", "access-control-testbed",
            "database-testbed", "cloud-iac-testbed", "web-vulns-testbed",
            "mass-assignment-testbed",
        ]

        for tb in testbed_order:
            if tb in score.testbed_results:
                r = score.testbed_results[tb]
                if r["score"] is not None:
                    lines.append(
                        f"| {tb} | {r['detected']} | {r['missed']} | "
                        f"{r['total']} | {r['score']}/{r['max_pts']} |\n"
                    )
                else:
                    # Bonus category (no rubric points) — show raw counts
                    lines.append(
                        f"| {tb} | {r['detected']} | {r['missed']} | "
                        f"{r['total']} | (bonus) |\n"
                    )
            elif tb == "secret-testbed":
                lines.append("| secret-testbed | — | — | — | (secrets/IaC scanner) |\n")

        lines.append("")

        # Honeypot hits detail
        if score.total_honeypot_hits > 0:
            lines.append(f"### Honeypot False Positives ({score.total_honeypot_hits})\n")
            lines.append("These honeypots were flagged as vulnerabilities (FP penalty applied).\n\n")

        # Manual categories placeholder
        lines.append("### Manual Categories (fill in after evaluation)\n")
        lines.append("| Category | Max | Score | Notes |\n")
        lines.append("|:---------|----:|------:|-------|\n")
        lines.append("| 2. DevEx & Remediation | 25 | | |\n")
        lines.append("| 3. CI/CD Integration | 20 | | |\n")
        lines.append("| 4. Admin & Triage | 15 | | |\n\n")

    # Cross-vendor comparison
    lines.append("## Cross-Vendor Comparison\n")
    lines.append("| Tool | TPR Score | FPR Score | Dataflow | Auth | DB | Reflection | IaC | Web |\n")
    lines.append("|------|----------:|----------:|---------:|-----:|---:|-----------:|----:|----:|\n")
    for score in sorted_scores:
        lines.append(
            f"| {score.tool_name} | {score.tp_rate_score} | {score.fp_rate_score} | "
            f"{score.complex_dataflow_score} | {score.auth_score} | "
            f"{score.database_score} | {score.reflection_score} | "
            f"{score.iac_score} | {score.web_score} |\n"
        )

    if output_path:
        Path(output_path).write_text('\n'.join(lines))

    return '\n'.join(lines)
