# Quantitative Scoring Rubric

This rubric uses a weighted point system (Total: 150 points) to ensure objective evaluation.

## 1. Detection Accuracy & Depth (40 Points)
*   **True Positive Rate (15 pts):** Percentage of known vulnerabilities (from the answer key) successfully detected. (Score = % detected * 15)
*   **False Positive Rate (10 pts):** Penalize tools that generate excessive noise. (10 pts for near-zero noise, 0 pts for unusable noise levels requiring massive triage).
*   **Complex Dataflow (10 pts):** Ability to track taint across multiple files, second-order injections, and complex frameworks (e.g., catching the `secret-testbed` CWE-89 spanning `apis.py` and `db_utils.py`).
*   **Reachability Analysis (5 pts):** (SCA Specific) Can the tool determine if a vulnerable transitive dependency is actually *reachable* from the first-party code?

## 2. Developer Experience (DevEx) & Remediation (25 Points)
*   **Actionability of Findings (10 pts):** Are the findings clear? Do they explain *why* the code is vulnerable and *how* to fix it?
*   **Auto-Remediation / Auto-Fix (10 pts):** Does the tool provide one-click AI-generated fixes? Are the fixes actually functional and secure? (Test this by applying the fix and running unit tests).
*   **IDE Integration (5 pts):** Quality of the VS Code, IntelliJ, or JetBrains plugins. Does it scan locally before the commit?

## 3. CI/CD & Workflow Integration (20 Points)
*   **Pipeline Speed (10 pts):** Scan times must not block developers. (10 pts for scans < 2 mins, 5 pts for < 10 mins, 0 pts for > 30 mins).
*   **PR/MR Annotations (5 pts):** Ability to post inline comments directly on the changed lines of code in the PR.
*   **Ease of Deployment (5 pts):** Is the scanner a simple binary/container, or does it require complex compilation steps and deep environmental access?

## 4. Administration & Triage (15 Points)
*   **Triage UI/UX (5 pts):** The quality of the central dashboard for security engineers. Is it easy to filter, assign, and suppress findings?
*   **Custom Rules Engine (5 pts):** Can the security team easily write custom rules (e.g., Semgrep, CodeQL, CxQL) to catch internal business-logic flaws?
*   **Reporting & Compliance (5 pts):** Ability to export SBOMs (CycloneDX, SPDX) and generate compliance reports (OWASP Top 10, PCI-DSS).

## 5. Specialized Detection Coverage (40 Points)
*   **Authorization & Access Control (10 pts):** IDOR, mass assignment (CWE-915), privilege escalation, race conditions, business logic flaws (access-control-testbed + mass-assignment-testbed)
*   **Stored Procedure / Database Code Analysis (5 pts):** TSQL/PLSQL injection in stored procedures (database-testbed)
*   **Reflection & Dynamic Code Detection (5 pts):** Unsafe reflection, eval/exec patterns (reflection-testbed)
*   **IaC / Cloud Misconfiguration Detection (10 pts):** Terraform, Dockerfile, K8s, CloudFormation findings (cloud-iac-testbed)
*   **Web Application Vulnerability Detection (10 pts):** Broken auth, crypto failures, XSS/SSTI, HTTP protocol flaws, shadow APIs (web-vulns-testbed)

## 6. License Analysis & SCA Compliance (10 Points)

**Objective:** Evaluate the tool's ability to detect, classify, and enforce policy on open source dependency licenses — with critical focus on copyleft and commercially-restrictive licenses.

### 6a. CycloneDX SBOM Accuracy (5 pts)

Score based on the CycloneDX 1.6 SBOM the tool generates from the `license-testbed` repository:

| Criterion | Points | How to Evaluate |
|-----------|--------|-----------------|
| All dependencies listed in SBOM | 1 | Compare SBOM `components[]` count against `npm ls --all` count. Missing components = partial credit. |
| License IDs are SPDX-valid | 1 | Every `licenses[].license.id` should match an SPDX identifier. Count entries with `"name"` instead of `"id"` as errors. |
| Dual-license correctly expressed | 1 | `node-forge` license `(BSD-3-Clause OR GPL-2.0)` should appear in SBOM as a license expression, not a single license choice. |
| Transitive dependencies included | 1 | `@img/sharp-libvips-*` (LGPL-3.0-or-later) must appear as a component with its correct license, not omitted as transitive noise. |
| Dev vs production context | 1 | Dependencies in `devDependencies` should be tagged (e.g., CycloneDX `properties` with `dependency-type=dev` or scoped under `services`). |

### 6b. Policy & Classification Accuracy (5 pts)

Score based on the tool's UI, CLI, or policy engine output — not directly visible in the SBOM itself:

**Strong Copyleft Detection (2 pts)**
- Tool correctly identifies `ffmpeg-static` as GPL-3.0-or-later (strong copyleft) — 1 pt
- Tool correctly identifies `@license-testbed/agpl-pkg` as AGPL-3.0-only (network copyleft / critical) — 1 pt

**Non-OSI / Commercial Restriction Detection (1 pt)**
- Tool flags `@license-testbed/busl-pkg` (BUSL-1.1) and `@license-testbed/sspl-pkg` (SSPL-1.0) as non-OSI-approved or commercially-restrictive — 0.5 pt each

**Dev-vs-Production Differentiation (1 pt)**
- Tool assigns HIGHER severity to `ffmpeg-static` (GPL-3.0, dependencies, production code) than to `@license-testbed/dev-only-gpl` (GPL-3.0, devDependencies, test file only) — 1 pt

**Transitive Discovery (1 pt)**
- Tool surfaces `@img/sharp-libvips-*` (LGPL-3.0-or-later) as a transitive dependency with a clear path `sharp → @img/sharp-libvips-linux-x64` — 1 pt

### Scoring Reference

See `CYCLONEDX_WORKKSHEET.md` for the manual evaluation worksheet. See `answer_key.md` (LICENSE section) for the complete list of expected findings.

## Honeypot / False Positive Handling

Each SAST testbed contains deliberate honeypots — patterns that appear vulnerable but are safe in context (sanitized input, hardcoded arguments, package restrictions). Vendors that flag these as real findings incur False Positive penalties under Category 1. Total honeypots across all SAST testbeds: **30** (see answer_key.md HP-1 through HP-30).

The `license-testbed` has no honeypots — license analysis is a policy enforcement test, not a vulnerability scan.
