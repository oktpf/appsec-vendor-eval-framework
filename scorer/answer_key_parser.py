"""Parse answer_key.md into structured vulnerability and honeypot entries."""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class AnswerEntry:
    """A single known vulnerability or honeypot from the answer key."""
    uid: str
    testbed: str
    cwe: str
    difficulty: str  # easy/medium/hard
    is_honeypot: bool
    source_file: Optional[str] = None  # e.g. "python/app.py"
    source_line: Optional[int] = None
    sink_file: Optional[str] = None
    sink_line: Optional[int] = None
    description: str = ""
    # For secrets (file:line format in answer key)
    secret_name: Optional[str] = None

    @property
    def relevant_lines(self) -> list[int]:
        """All line numbers that should match a finding for this entry."""
        lines = []
        if self.source_line:
            lines.append(self.source_line)
        if self.sink_line and self.sink_line != self.source_line:
            lines.append(self.sink_line)
        return lines

    @property
    def relevant_files(self) -> list[str]:
        """All file paths that should match a finding for this entry."""
        files = []
        if self.source_file:
            files.append(self.source_file)
        if self.sink_file and self.sink_file != self.source_file:
            files.append(self.sink_file)
        return files


def parse_answer_key(path: str | Path) -> list[AnswerEntry]:
    """Parse answer_key.md into structured entries.

    Handles:
    - SAST findings with UID, Source/Sink file:line, CWE, difficulty
    - Secret findings (NAME:file:line format)
    - Honeypot entries (HP-N with File:, Expected FP:)
    """
    content = Path(path).read_text()
    entries: list[AnswerEntry] = []

    # Track current testbed context
    current_testbed = None

    # Testbed section headers
    testbed_pattern = re.compile(
        r'##\s+([a-zA-Z0-9_-]+-testbed)\s+\(',
        re.IGNORECASE,
    )

    # Honeypot section header
    honeypot_section = re.compile(r'#\s+HONEYPOTS', re.IGNORECASE)

    # Parse testbed sections
    for line in content.split('\n'):
        m = testbed_pattern.search(line)
        if m:
            current_testbed = m.group(1).lower()
            continue

        if honeypot_section.search(line):
            # We're in the honeypot section — handled separately below
            break

    # Parse SAST findings (UID blocks)
    uid_pattern = re.compile(r'UID:\s+(\S+)')
    cwe_pattern = re.compile(r'(CWE-\d+)')
    source_pattern = re.compile(r'Source:\s+([\w./-]+):(\d+)')
    sink_pattern = re.compile(r'Sink:\s+([\w./-]+):(\d+)')
    difficulty_pattern = re.compile(r'Difficulty:\s+(\w+)')

    # Split into blocks by ### or #### numbered headers
    uid_blocks = re.split(r'(?=^#{3,4}\s+\d+\.)', content, flags=re.MULTILINE)

    for block in uid_blocks:
        uid_match = uid_pattern.search(block)
        if not uid_match:
            continue

        uid = uid_match.group(1)

        # Determine testbed from context
        entry_testbed = _find_testbed_for_uid(content, uid)

        # Extract CWE
        cwe_match = cwe_pattern.search(block)
        cwe = cwe_match.group(1) if cwe_match else "UNKNOWN"

        # Extract Source/Sink
        source_match = source_pattern.search(block)
        sink_match = sink_pattern.search(block)
        difficulty_match = difficulty_pattern.search(block)

        entry = AnswerEntry(
            uid=uid,
            testbed=entry_testbed or "unknown",
            cwe=cwe,
            difficulty=difficulty_match.group(1).lower() if difficulty_match else "medium",
            is_honeypot=False,
            source_file=source_match.group(1) if source_match else None,
            source_line=int(source_match.group(2)) if source_match else None,
            sink_file=sink_match.group(1) if sink_match else None,
            sink_line=int(sink_match.group(2)) if sink_match else None,
        )
        entries.append(entry)

    # Parse secrets section (NAME:file:line format)
    secrets_section = re.search(
        r'## Hardcoded Credentials.*?```(.+?)```',
        content,
        re.DOTALL,
    )
    if secrets_section:
        for line in secrets_section.group(1).strip().split('\n'):
            line = line.strip()
            if not line or ':' not in line:
                continue
            parts = line.split(':')
            if len(parts) >= 3:
                secret_name = parts[0]
                file_path = ':'.join(parts[1:-1])  # handle paths with colons
                line_num = int(parts[-1])
                entries.append(AnswerEntry(
                    uid=f"SECRET_{secret_name}",
                    testbed="secret-testbed",
                    cwe="CWE-798",
                    difficulty="easy",
                    is_honeypot=False,
                    source_file=file_path,
                    source_line=line_num,
                    secret_name=secret_name,
                ))

    # Parse honeypot entries (HP-N)
    hp_pattern = re.compile(r'###\s+HP-(\d+):')
    hp_uid_pattern = re.compile(r'UID:\s+(HONEY_\S+)')
    hp_file_pattern = re.compile(r'File:\s+(.+?)(?:\n|$)')
    hp_cwe_pattern = re.compile(r'Expected FP:\s*(CWE-\d+)')

    in_honeypots = False
    current_hp_testbed = None
    for line in content.split('\n'):
        if honeypot_section.search(line):
            in_honeypots = True
            continue

        if not in_honeypots:
            continue

        # Track honeypot testbed subsections
        tb_match = re.match(r'##\s+(\S+)-testbed\s+honeypots', line, re.IGNORECASE)
        if tb_match:
            current_hp_testbed = tb_match.group(1).lower() + "-testbed"
            continue

        hp_match = hp_pattern.search(line)
        if hp_match:
            hp_num = int(hp_match.group(1))

            # Find the block for this honeypot
            idx = content.find(line)
            # Find next ### or end of section
            next_hp = content.find('\n### ', idx + 1)
            next_section = content.find('\n## ', idx + 1)
            end_idx = min(
                x for x in [next_hp, next_section, len(content)] if x > idx
            )
            block = content[idx:end_idx]

            hp_uid_match = hp_uid_pattern.search(block)
            hp_file_match = hp_file_pattern.search(block)
            hp_cwe_match = hp_cwe_pattern.search(block)

            # Try to extract line number from file path
            hp_file = hp_file_match.group(1).strip() if hp_file_match else ""
            hp_source_file = None
            hp_source_line = None

            # Some honeypots have file:line, others just file
            line_in_file = re.match(r'(.+?):(\d+)', hp_file)
            if line_in_file:
                hp_source_file = line_in_file.group(1)
                hp_source_line = int(line_in_file.group(2))
            elif hp_file:
                hp_source_file = hp_file

            entries.append(AnswerEntry(
                uid=f"HP-{hp_num}",
                testbed=current_hp_testbed or "unknown",
                cwe=hp_cwe_match.group(1) if hp_cwe_match else "UNKNOWN",
                difficulty="medium",
                is_honeypot=True,
                source_file=hp_source_file,
                source_line=hp_source_line,
                description=line.strip(),
            ))

    return entries


def _find_testbed_for_uid(content: str, uid: str) -> Optional[str]:
    """Find which testbed section contains a given UID."""
    testbeds = [
        "secret-testbed", "reflection-testbed", "access-control-testbed",
        "database-testbed", "cloud-iac-testbed", "web-vulns-testbed",
        "mass-assignment-testbed",
    ]

    uid_idx = content.find(f"UID: {uid}")
    if uid_idx < 0:
        return None

    # Search backwards for the nearest testbed header BEFORE this UID
    best_pos = -1
    best_tb = None
    for tb in testbeds:
        # Find all occurrences of this testbed header before the UID
        pos = content.find(f"## {tb}", 0, uid_idx)
        while pos != -1 and pos < uid_idx:
            if pos > best_pos:
                best_pos = pos
                best_tb = tb
            pos = content.find(f"## {tb}", pos + 1, uid_idx)

    if best_tb:
        return best_tb

    # Fallback: check UID prefix patterns
    uid_upper = uid.upper()
    prefix_map = {
        "SECRET_": "secret-testbed",
        "REFLECTION_": "reflection-testbed",
        "ACCESS_": "access-control-testbed",
        "DATABASE_": "database-testbed",
        "CLOUD_": "cloud-iac-testbed",
        "WEB_": "web-vulns-testbed",
        "MASSASSIGN_": "mass-assignment-testbed",
    }
    for prefix, tb in prefix_map.items():
        if uid_upper.startswith(prefix):
            return tb

    return None


def load_answer_key(path: str | Path) -> dict:
    """Load answer key and return organized by testbed."""
    entries = parse_answer_key(path)

    by_testbed: dict[str, list[AnswerEntry]] = {}
    for entry in entries:
        by_testbed.setdefault(entry.testbed, []).append(entry)

    vulns = [e for e in entries if not e.is_honeypot]
    honeypots = [e for e in entries if e.is_honeypot]

    return {
        "all": entries,
        "vulnerabilities": vulns,
        "honeypots": honeypots,
        "by_testbed": by_testbed,
        "total_vulns": len(vulns),
        "total_honeypots": len(honeypots),
    }
