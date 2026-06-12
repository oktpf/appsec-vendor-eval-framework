"""SARIF-based automated scorer for appsec-vendor-eval."""

from .answer_key_parser import load_answer_key
from .sarif_parser import load_sarif_reports, SarifFinding
from .matcher import match_findings
from .scorer import calculate_scores, generate_scorecard, VendorScore

__all__ = [
    "load_answer_key",
    "load_sarif_reports",
    "match_findings",
    "calculate_scores",
    "generate_scorecard",
    "SarifFinding",
    "VendorScore",
]
