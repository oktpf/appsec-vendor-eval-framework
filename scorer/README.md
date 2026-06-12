# SARIF Scorer

Automated scoring engine for the appsec-vendor-eval framework. Parses SARIF 2.1.0 reports from any SAST/SCA/IaC scanner, matches findings against the answer key, and generates ranked scorecards.

## Quick Start

```bash
# Drop .sarif files into a directory (one per tool, or nested by tool name)
cd /workspace/appsec-vendor-eval
python3 -m scorer /path/to/sarif-reports/

# Output: <sarif-dir>/scorecard.md + console ranking summary
```

## Usage

```bash
# Basic — scan all .sarif files in directory, output scorecard.md
python3 -m scorer ./vendor-scans/

# Custom output path
python3 -m scorer ./vendor-scans/ -o results.md

# Custom answer key
python3 -m scorer ./vendor-scans/ -a /path/to/answer_key.md

# Wider line tolerance (default: ±5 lines)
python3 -m scorer ./vendor-scans/ -t 10

# Verbose — show missed vulns and honeypot hits per tool
python3 -m scorer ./vendor-scans/ -v

# Also export detailed JSON results
python3 -m scorer ./vendor-scans/ -j results.json
```

## SARIF Directory Layout

Any structure works — the scorer finds all `.sarif` files recursively:

```
vendor-scans/
├── semgrep.sarif
├── codeql.sarif
└── tools/
    ├── checkmarx.sarif
    └── veracode.sarif
```

Tool name is extracted from `runs[].tool.driver.name` inside each SARIF file.

## What It Scores (Automated)

| Category | Max Points | How It's Calculated |
|----------|-----------|-------------------|
| **1. Detection Accuracy** | 40 | TPR (difficulty-weighted), FPR penalty, complex dataflow detection |
| **5. Specialized Coverage** | 40 | Per-testbed detection rates: Auth(10), DB(5), Reflection(5), IaC(10), Web(10) |
| **Automated Total** | **80** | Sum of Categories 1 + 5 |

Categories 2-4 (DevEx, CI/CD, Admin) require manual evaluation — placeholders are included in the scorecard.

## Matching Logic

A SARIF finding matches an answer key entry when:

1. **File path matches** — normalized comparison (handles testbed prefixes, path separators)
2. **Line number within tolerance** — default ±5 lines from source/sink
3. **CWE matches** (bonus signal) — extracted from `ruleId`, `properties.cwe`, or message text

Minimum match threshold: 0.4 confidence (requires at least path OR line match).

## Honeypot Detection

If a finding matches a honeypot entry's location better than any real vulnerability, it's classified as a **honeypot false positive** and penalizes the FPR score. The answer key defines 29 honeypots across all testbeds.

## Output

### Console Summary
```
RANKING
============================================================
  1. Semgrep: 52.3/80 (TP=87, FN=32, HP=3)
  2. CodeQL: 48.1/80 (TP=82, FN=37, HP=1)
  3. Checkmarx: 41.7/80 (TP=75, FN=44, HP=8)
```

### Scorecard Markdown (`scorecard.md`)
- Ranking table with all tools
- Per-tool breakdowns: Category 1 + Category 5 scores
- Testbed-level detection counts
- Honeypot FP details
- Cross-vendor comparison matrix
- Manual category placeholders

## Architecture

| Module | Purpose |
|--------|---------|
| `answer_key_parser.py` | Parse answer_key.md into structured entries (UIDs, files, lines, CWEs, honeypots) |
| `sarif_parser.py` | Parse SARIF 2.1.0 files into normalized finding records |
| `matcher.py` | Fuzzy-match SARIF findings against answer key entries |
| `scorer.py` | Calculate rubric scores and generate scorecard markdown |

## Python API

```python
from scorer import load_answer_key, load_sarif_reports, match_findings, calculate_scores, generate_scorecard

# Load answer key
ak = load_answer_key("appsec-vendor-eval-framework/answer_key.md")

# Parse SARIF files
reports = load_sarif_reports("./vendor-scans/")  # {tool_name: [findings]}

# Match and score each tool
all_scores = []
for tool_name, findings in reports.items():
    result = match_findings(findings, "appsec-vendor-eval-framework/answer_key.md")
    score = calculate_scores(result, tool_name)
    all_scores.append(score)

# Generate scorecard
markdown = generate_scorecard(all_scores, output_path="scorecard.md")
```

## Known Limitations

- **Secret detection**: Hardcoded credential findings in SARIF are matched by file:line only (no secret name matching). Tools that report secrets differently may need custom handling.
- **Cross-file taint chains**: The matcher scores a finding as TP if it matches either the source or sink line. It doesn't verify the full chain is reported.
- **CWE extraction**: Relies on tools embedding CWE IDs in SARIF `ruleId`, `properties.cwe`, or message text. Tools that don't include CWEs lose the bonus matching signal but can still match on file:line.

## Test Data

`test-sarif/testscanner.sarif` — sample SARIF with 15 findings (13 TPs, 2 honeypot hits) for validating the scorer pipeline.
