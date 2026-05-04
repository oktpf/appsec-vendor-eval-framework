# Quantitative Scoring Rubric

This rubric uses a weighted point system (Total: 100 points) to ensure objective evaluation.

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
