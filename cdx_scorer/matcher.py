"""Cross-reference tool CycloneDX components against expected license entries."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .cdx_parser import Component
from .license_key_parser import LicenseEntry


@dataclass
class MatchResult:
    """Result of comparing one tool's SBOM against one expected license entry."""
    uid: str
    package: str
    version: str
    expected_license: str
    category: str
    risk: str
    is_dev: bool
    is_transitive: bool
    via: str = ""

    # Match results
    found: bool = False                # component present in SBOM?
    license_match: bool = False        # license ID matches expected?
    has_spdx_id: bool = False          # uses license.id not license.name?
    dev_tagged: bool = False           # dev dependency correctly tagged?
    purl: str = ""                     # package URL from SBOM

    # For dual license check
    has_expression: bool = False
    expression_correct: bool = False


def normalize_component_name(name: str) -> str:
    """Normalize a package name for comparison.

    Handles:
    - @scoped/packages
    - file:// paths for workspace packages
    - npm vs purl naming
    """
    # Strip file:// paths
    if name.startswith("file://"):
        name = name.rsplit("/", 1)[-1].rsplit("@", 1)[0]
    return name.lower()


def match_tool(tool_components: list[Component],
               expected_entries: list[LicenseEntry]) -> list[MatchResult]:
    """Match one tool's SBOM components against expected license entries."""
    results = []

    for entry in expected_entries:
        # Find matching component by name (case-insensitive)
        entry_name_norm = normalize_component_name(entry.package)
        matched_comp = None

        for comp in tool_components:
            comp_name_norm = normalize_component_name(comp.name)
            if entry_name_norm == comp_name_norm:
                matched_comp = comp
                break

        if matched_comp is None:
            # Also check purl-based matching
            for comp in tool_components:
                purl_name = comp.purl.split("/")[-1].split("@")[0].lower()
                if entry_name_norm == purl_name:
                    matched_comp = comp
                    break

        if matched_comp is None:
            # Not found
            results.append(MatchResult(
                uid=entry.uid,
                package=entry.package,
                version=entry.version,
                expected_license=entry.expected_license,
                category=entry.category,
                risk=entry.risk,
                is_dev=entry.is_dev,
                is_transitive=entry.is_transitive,
                found=False,
            ))
            continue

        # Component found — check license
        # Normalize expected license for comparison
        expected_norm = entry.expected_license.strip().lower()

        actual_license = ""
        has_spdx_id = False
        has_expression = False
        expression_correct = False

        if matched_comp.license_expression:
            actual_license = matched_comp.license_expression
            has_expression = True
            expression_correct = actual_license.strip().lower() == expected_norm
        elif matched_comp.license_id:
            actual_license = matched_comp.license_id
            has_spdx_id = True
        elif matched_comp.license_name:
            actual_license = matched_comp.license_name

        # Check license match (allow minor SPDX syntax differences)
        license_match = (
            actual_license.strip().lower() == expected_norm
            or actual_license.strip().lower().replace("-only", "").replace("-or-later", "")
            == expected_norm.replace("-only", "").replace("-or-later", "")
        )

        # Dev tagging
        dev_tagged = matched_comp.is_dev

        results.append(MatchResult(
            uid=entry.uid,
            package=entry.package,
            version=matched_comp.version,
            expected_license=entry.expected_license,
            category=entry.category,
            risk=entry.risk,
            is_dev=entry.is_dev,
            is_transitive=entry.is_transitive,
            found=True,
            license_match=license_match,
            has_spdx_id=has_spdx_id,
            dev_tagged=dev_tagged,
            purl=matched_comp.purl,
            has_expression=has_expression,
            expression_correct=expression_correct,
        ))

    return results


def match_all_tools(reports: dict[str, dict],
                    expected_entries: list[LicenseEntry]) -> dict[str, list[MatchResult]]:
    """Match all tool SBOMs against expected license entries.

    Returns {tool_name: [MatchResult, ...]}
    """
    all_results = {}
    for tool_name, report in reports.items():
        all_results[tool_name] = match_tool(report["components"], expected_entries)
    return all_results
