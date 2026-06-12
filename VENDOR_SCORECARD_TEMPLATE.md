# Vendor Scorecard

**Vendor Name:** _____________________
**Evaluator:** ______________________
**Date:** __________________________

| Category | Max Points | Vendor Score | Notes / Justification |
| :--- | :---: | :---: | :--- |
| **1. Detection Accuracy (40)** | | | |
| True Positive Rate | 15 | | |
| False Positive Rate | 10 | | |
| Complex Dataflow | 10 | | |
| Reachability Analysis (SCA) | 5 | | |
| **2. DevEx & Remediation (25)**| | | |
| Actionability of Findings | 10 | | |
| Auto-Remediation / Auto-Fix | 10 | | |
| IDE Integration | 5 | | |
| **3. CI/CD Integration (20)** | | | |
| Pipeline Speed | 10 | | |
| PR/MR Annotations | 5 | | |
| Ease of Deployment | 5 | | |
| **4. Admin & Triage (15)** | | | |
| Triage UI/UX | 5 | | |
| Custom Rules Engine | 5 | | |
| Reporting & Compliance | 5 | | |
| **5. Specialized Detection Coverage (40)**| | | |
| Authorization & Access Control | 10 | | |
| Stored Procedure / Database Code Analysis | 5 | | |
| Reflection & Dynamic Code Detection | 5 | | |
| IaC / Cloud Misconfiguration Detection | 10 | | |
| Web Application Vulnerability Detection | 10 | | |
| **6. License Analysis & SCA Compliance (10)**| | | |
| CycloneDX SBOM Accuracy | 5 | | See CycloneDX Worksheet |
| Policy & Classification Accuracy | 5 | | See CycloneDX Worksheet |
| **TOTAL SCORE** | **150** | **0** | |

## Key Findings (Testbed Results Summary)

### secret-testbed
*   **Found SAST:** [x]/11
*   **Found Secrets:** [x]/23
*   **Found Transitive CVE:** Yes/No
*   **Missed Critical Items:** (List items from the answer key that were missed)

### reflection-testbed
*   **Found SAST:** [x]/8
*   **Found IaC:** N/A
*   **Missed Critical Items:** (List items from the answer key that were missed)

### access-control-testbed
*   **Found SAST:** [x]/14
*   **Found IaC:** N/A
*   **Missed Critical Items:** (List items from the answer key that were missed)

### database-testbed
*   **Found SAST:** [x]/8
*   **Found IaC:** N/A
*   **Missed Critical Items:** (List items from the answer key that were missed)

### cloud-iac-testbed
*   **Found SAST:** N/A
*   **Found IaC:** [x]/10
*   **Missed Critical Items:** (List items from the answer key that were missed)

### web-vulns-testbed
*   **Found SAST:** [x]/18
*   **Found IaC:** N/A
*   **Missed Critical Items:** (List items from the answer key that were missed)

### mass-assignment-testbed
*   **Found CWE-915 (Mass Assignment):** [x]/30
*   **Languages:** Java, .NET, Node.js, Python
*   **Missed Critical Items:** (List items from the answer key that were missed)

### license-testbed (SCA License Analysis)
*   **SBOM Components Found:** [x]/30+ (should cover all direct + transitive dependencies)
*   **SPDX License Accuracy:** [x]/11 (see answer key LICENSE section)
*   **Strong Copyleft Detected:** [x]/3 (GPL-3.0 ffmpeg-static, AGPL-3.0 agpl-pkg, GPL-2.0 my-gpl-package)
*   **Non-OSI Licenses Flagged:** [x]/2 (BUSL-1.1 busl-pkg, SSPL-1.0 sspl-pkg)
*   **Dev/Prod Differentiation:** Yes/No (does tool downgrade dev-only GPL vs prod GPL?)
*   **Transitive Copyleft Found:** Yes/No (LGPL-3.0 via sharp → libvips)
*   **Dual-License Correctly Expressed:** Yes/No (node-forge BSD-3-Clause OR GPL-2.0)
*   **Missed Critical Items:** (List items from the answer key that were missed)

## Honeypot Results (False Positives)

| Testbed | Honeypots Flagged | Honeypot IDs | FP Penalty Impact |
|---------|-------------------|--------------|-------------------|
| reflection-testbed | [x]/4 | HP-1 to HP-4 | |
| access-control-testbed | [x]/4 | HP-5 to HP-8 | |
| database-testbed | [x]/3 | HP-9 to HP-11 | |
| cloud-iac-testbed | [x]/4 | HP-12 to HP-15 | |
| web-vulns-testbed | [x]/5 | HP-16 to HP-20 | |
| mass-assignment-testbed | [x]/10 | HP-21 to HP-30 | |
| license-testbed | N/A | No honeypots | N/A — policy test |
| **TOTAL** | **[x]/30** | | Category 1 FP Rate penalty |

## Aggregate Summary

| Testbed | Total Findings | True Positives | False Negatives | Honeypots (FP traps) | Notes |
|---------|----------------|----------------|-----------------|---------------------|-------|
| secret-testbed | 34 | | | 0 | 11 SAST + 23 secrets |
| reflection-testbed | 8 | | | 4 | Java+Python reflection/dynamic code |
| access-control-testbed | 14 | | | 4 | Authorization/business logic |
| database-testbed | 8 | | | 3 | TSQL/PLSQL stored procedures |
| cloud-iac-testbed | 10 | | | 4 | Terraform/Docker/K8s/CloudFormation |
| web-vulns-testbed | 18 | | | 5 | Web vulns, auth, crypto, XSS, SSTI |
| mass-assignment-testbed | 30 | | | 10 | CWE-915 across Java/.NET/Node/Python |
| license-testbed | 11 | | | 0 | 11 license findings (see answer_key) |
| **TOTAL** | **133** | | | **30** | 59 SAST + 10 IaC + 23 secrets + 30 CWE-915 + 11 license |

## CycloneDX License Worksheet Results

See `CYCLONEDX_WORKSHEET.md` for the detailed per-finding breakdown and policy evaluation.

| Sub-Category | Max Points | Vendor Score |
|-------------|:----------:|:------------:|
| CycloneDX SBOM Accuracy (components, SPDX IDs, dual-license, transitives, dev/prod) | 5 | |
| Policy & Classification Accuracy (strong copyleft, non-OSI, dev/prod diff, transitive) | 5 | |
| **License Analysis Total** | **10** | |

## Qualitative Notes
*   **Strengths:**
*   **Weaknesses:**
*   **Support Experience:** (How responsive was the vendor during the tuning phase?)
