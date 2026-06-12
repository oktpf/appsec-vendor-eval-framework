"""Parse SARIF 2.1.0 files into normalized finding records."""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class SarifFinding:
    """A single finding extracted from a SARIF report."""
    tool_name: str
    rule_id: str
    cwe: Optional[str] = None
    message: str = ""
    file_path: str = ""
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    level: str = "warning"  # error/warning/note
    # Raw SARIF path for debugging
    _sarif_path: str = ""

    @property
    def relevant_lines(self) -> list[int]:
        lines = []
        if self.start_line:
            lines.append(self.start_line)
        if self.end_line and self.end_line != self.start_line:
            lines.append(self.end_line)
        return lines


def extract_cwe(result: dict) -> Optional[str]:
    """Extract CWE ID from various SARIF locations."""
    # Check properties.cweIds (common pattern)
    props = result.get("properties", {})
    if isinstance(props, dict):
        cwe_ids = props.get("cweIds") or props.get("CWE-IDs") or props.get("cwe")
        if cwe_ids:
            if isinstance(cwe_ids, list):
                return str(cwe_ids[0])
            return str(cwe_ids)

    # Check rule properties
    rule = result.get("rule", {}) or {}
    rule_props = rule.get("properties", {})
    if isinstance(rule_props, dict):
        cwe = rule_props.get("cwe") or rule_props.get("CWE-ID")
        if cwe:
            return str(cwe)

    # Check ruleId itself (e.g. "CWE-79")
    rule_id = result.get("ruleId", "")
    cwe_match = re.search(r'(CWE-\d+)', rule_id, re.IGNORECASE)
    if cwe_match:
        return cwe_match.group(1).upper()

    # Check message for CWE reference
    msg = result.get("message", {})
    if isinstance(msg, dict):
        text = msg.get("text", "")
    else:
        text = str(msg)
    cwe_match = re.search(r'(CWE-\d+)', text)
    if cwe_match:
        return cwe_match.group(1).upper()

    return None


def extract_file_path(result: dict, run: dict) -> str:
    """Extract normalized file path from SARIF result."""
    locations = result.get("locations", [])
    if not locations:
        return ""

    loc = locations[0]
    physical = loc.get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {})
    uri = artifact.get("uri", "") or artifact.get("index", -1)

    if isinstance(uri, int):
        # Resolve from artifacts array
        artifacts = run.get("artifacts", [])
        if 0 <= uri < len(artifacts):
            uri = artifacts[uri].get("location", {}).get("uri", "")

    return str(uri) if uri else ""


def extract_lines(result: dict) -> tuple[Optional[int], Optional[int]]:
    """Extract start/end line from SARIF result."""
    locations = result.get("locations", [])
    if not locations:
        return None, None

    loc = locations[0]
    physical = loc.get("physicalLocation", {})
    region = physical.get("region", {})

    start_line = region.get("startLine")
    end_line = region.get("endLine")

    # Some tools put line in snippet
    if not start_line:
        messages = result.get("messages", [])
        for msg in messages:
            if isinstance(msg, dict):
                text = msg.get("text", "")
                line_match = re.search(r'line\s+(\d+)', text)
                if line_match:
                    start_line = int(line_match.group(1))
                    break

    return start_line, end_line


def parse_sarif(path: str | Path) -> list[SarifFinding]:
    """Parse a SARIF 2.1.0 file into normalized findings."""
    sarif_data = json.loads(Path(path).read_text())
    findings: list[SarifFinding] = []

    for run in sarif_data.get("runs", []):
        # Extract tool name
        tool_info = run.get("tool", {})
        driver = tool_info.get("driver", {})
        tool_name = driver.get("name", "unknown")

        for result in run.get("results", []):
            file_path = extract_file_path(result, run)
            start_line, end_line = extract_lines(result)
            cwe = extract_cwe(result)

            # Extract message
            msg = result.get("message", {})
            if isinstance(msg, dict):
                message = msg.get("text", "")
            else:
                message = str(msg)

            # Extract level
            level = result.get("level", "warning")

            finding = SarifFinding(
                tool_name=tool_name,
                rule_id=result.get("ruleId", ""),
                cwe=cwe,
                message=message[:500],  # Truncate long messages
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                level=level or "warning",
                _sarif_path=str(path),
            )
            findings.append(finding)

    return findings


def load_sarif_reports(directory: str | Path) -> dict[str, list[SarifFinding]]:
    """Load all SARIF files from a directory.

    Returns dict mapping tool name → list of findings.
    Supports both individual .sarif files and subdirectories per tool.
    """
    dir_path = Path(directory)
    all_findings: dict[str, list[SarifFinding]] = {}

    # Find all .sarif files recursively
    for sarif_file in sorted(dir_path.rglob("*.sarif")):
        findings = parse_sarif(sarif_file)
        for f in findings:
            all_findings.setdefault(f.tool_name, []).append(f)

    return all_findings
