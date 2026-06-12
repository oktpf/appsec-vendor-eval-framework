"""Parse the LICENSE section of answer_key.md into expected license entries."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class LicenseEntry:
    """A single expected license finding from the answer key."""
    uid: str
    package: str
    version: str
    expected_license: str          # SPDX ID or expression
    category: str                  # strong-copyleft, weak-copyleft, non-osi-commercial, permissive, etc.
    risk: str                      # Critical, High, Medium, Low, None
    is_dev: bool = False           # True if in devDependencies
    is_transitive: bool = False    # True if transitive dep
    via: str = ""                  # For transitive: parent package


def parse_license_key(path: str | Path) -> list[LicenseEntry]:
    """Parse the LICENSE section of answer_key.md into structured entries.

    Handles table formats like:

    | UID | Package | Version | Expected License (SPDX) | Category | Risk |
    |-----|---------|---------|------------------------|----------|------|
    | LICENSE_COMP_FFMPEG | ffmpeg-static | ^5.1.0 | GPL-3.0-or-later | strong-copyleft | High |
    """
    content = Path(path).read_text()

    # Find the LICENSE section
    lic_start = content.find("# LICENSE:")
    if lic_start < 0:
        print("Warning: No LICENSE section found in answer_key.md")
        return []

    # Parse tables within the LICENSE section
    entries = []
    lines = content[lic_start:].splitlines()

    # Track which subsection we're in
    subsection = ""
    in_table = False
    headers = []
    header_line_no = 0

    for i, line in enumerate(lines):
        # Check for subsection headers
        subsection_match = re.match(r'^###\s+(.+)', line)
        if subsection_match:
            sub = subsection_match.group(1).lower()
            # Categorize subsection
            if 'direct dependencies — real npm' in sub:
                subsection = 'direct-npm'
            elif 'direct dependencies — workspace' in sub:
                subsection = 'direct-workspace'
            elif 'transitive dependencies' in sub:
                subsection = 'transitive'
            elif 'dev dependencies' in sub:
                subsection = 'dev'
            else:
                subsection = ''
            in_table = False
            continue

        # Detect table start
        if line.startswith('| ') and ' UID ' in line and '|' in line:
            headers = [h.strip() for h in line.strip('|').split('|')]
            in_table = True
            header_line_no = i
            continue

        # Detect table separator row
        if in_table and line.startswith('|---') or line.startswith('|:---'):
            continue

        # Parse table data rows
        if in_table and line.startswith('| '):
            cells = [c.strip() for c in line.strip('|').split('|')]

            # Map cells to meaning based on column count
            # Expected columns: UID, Package, Version, Expected License, Category, Risk
            if len(cells) >= 6:
                uid = cells[0] if cells[0] else ""
                pkg = cells[1] if len(cells) > 1 else ""
                ver = cells[2] if len(cells) > 2 else ""
                lic = cells[3] if len(cells) > 3 else ""
                cat = cells[4] if len(cells) > 4 else ""
                risk = cells[5] if len(cells) > 5 else ""

                # Clean markdown bold/italic
                lic = clean_md(lic)
                cat = clean_md(cat)
                risk = clean_md(risk)

                if uid.startswith("LICENSE_"):
                    # Determine dev/transitive context from subsection
                    is_dev = subsection == 'dev'
                    is_transitive = subsection == 'transitive'

                    entries.append(LicenseEntry(
                        uid=uid,
                        package=pkg,
                        version=ver,
                        expected_license=lic,
                        category=cat.lower(),
                        risk=risk.lower(),
                        is_dev=is_dev,
                        is_transitive=is_transitive,
                    ))

        # Detect table end
        if in_table and not line.startswith('|') and i > header_line_no + 1:
            in_table = False

    return entries


def clean_md(text: str) -> str:
    """Remove markdown bold/italic markers from text."""
    text = text.replace('**', '')
    text = text.replace('*', '')
    return text.strip()
