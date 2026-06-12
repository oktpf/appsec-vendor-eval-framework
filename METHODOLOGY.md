# Evaluation Methodology

The evaluation must be conducted in an objective, controlled environment to ensure all vendors are measured against the same baseline.

## 1. Test Targets (The Codebases)
Select 3-5 repositories for the evaluation:
*   **The Custom Benchmark (`secret-testbed`):** Used to test the limitations of the scan engine (deep dataflow, second-order analysis, exotic secret formats, transitive dependencies).
*   **Large Monolith:** A massive, legacy internal application (e.g., millions of lines of Java or C#). Used to test scan speed, memory consumption, and false positive generation at scale.
*   **Modern Microservice:** A modern application (e.g., Go, Node.js, Rust) to test language support and modern framework coverage.
*   **Infrastructure/Serverless Repo:** A repository heavy with Terraform, CloudFormation, Dockerfiles, and Lambda functions to test IaC and serverless coverage.
*   **SCA License Analysis (`license-testbed`):** A Node.js application with dependencies spanning the full OSI license spectrum — from MIT to AGPL-3.0 and non-OSI licenses (BUSL, SSPL). Used to test SCA tool license detection, SBOM generation (CycloneDX 1.6), copyleft classification, and policy enforcement. See [github.com/oktpf/license-testbed](https://github.com/oktpf/license-testbed).

## 2. Evaluation Phases

### Phase 1: The Blind Test (Out of the Box)
1. Provide the vendors with read-access to the test repositories (or run their CLI tools locally).
2. **Crucial:** Do not allow the vendors to tune their rulesets or configure custom dataflows yet.
3. Run the scans using the default "out-of-the-box" configuration.
4. Measure the raw results: Scan time, True Positives (TPs) caught, False Positives (FPs) generated, and False Negatives (FNs) missed.

### Phase 2: The Tuning Phase
1. Share the results of the Blind Test with the vendors.
2. Allow them 3-5 days to tune their engines (e.g., adding custom rules, ignoring test directories, defining custom sinks/sources).
3. Re-run the scans.
4. Measure the delta. This tests the *configurability* of the tool and the quality of the vendor's support team. Can the tool be easily tuned to eliminate the FPs discovered in Phase 1?

### Phase 3: The Developer Experience (DevEx) Test
1. Integrate the tool into a test CI/CD pipeline (e.g., GitHub Actions, GitLab CI).
2. Measure the integration effort (hours/days).
3. Open a Pull Request that introduces a new vulnerability.
4. Evaluate the feedback loop:
    * Did it block the build?
    * Was the PR comment clear and actionable?
    * (For AI-native tools) Did it provide a functional auto-fix?

## 3. The "Answer Key" Protocol
For the custom `secret-testbed`, use the generated `answer_key.md`.
*   Score a **True Positive (TP)** if the tool accurately identifies the Source and Sink lines for the given CWE.
*   Score a **False Negative (FN)** if the tool misses an item on the answer key.
*   Score a **False Positive (FP)** if the tool flags an issue that is definitively not exploitable (e.g., test data, unreachable code). Note: AI-native tools should excel at reducing FPs through reachability analysis.

## 4. CycloneDX License Evaluation Protocol

For the `license-testbed`, SCA tools are evaluated via CycloneDX SBOM output rather than SARIF (which SAST tools use). Use this protocol:

### 4a. Generate the SBOM

Run the SCA tool against the `license-testbed` repository and export a **CycloneDX 1.6** BOM. Methods vary by tool:

| Tool Type | Typical Method |
|-----------|---------------|
| **Proprietary SCA platform** | Click "Export SBOM" or use API endpoint |
| **CLI scanner** | `tool scan --format cyclonedx-json -o bom.json` |
| **Lockfile-based** | `cyclonedx-bom -o bom.json` (or `npm sbom` for Node.js 22+) |

Collect the CycloneDX JSON output for evaluation. A reference SBOM can be generated from the lockfile:

```bash
cd /workspace/appsec-vendor-eval/license-testbed
npx @cyclonedx/bom --output bom.json
```

### 4b. Evaluate Against the Answer Key

Use `answer_key.md` (LICENSE section) and `CYCLONEDX_WORKSHEET.md` to score:

1. **Component coverage** — does the SBOM include all 30+ components (direct + transitive)?
2. **License accuracy** — does each component's `licenses[].license.id` match the expected SPDX identifier?
3. **Expression handling** — are dual-licenses like `(BSD-3-Clause OR GPL-2.0)` correctly rendered?
4. **Dev/prod context** — are devDependencies tagged with `dependency-type=dev` or similar?
5. **Transitive inclusion** — are nested dependencies like `@img/sharp-libvips-*` present?

### 4c. Manual Policy Evaluation

Beyond the SBOM itself, several criteria require looking at the tool's UI or policy engine:

- **Copyleft classification** — does the tool's UI show GPL-3.0 as a "high risk" category?
- **Policy enforcement** — can the tool block a build based on AGPL-3.0 or BUSL-1.1 presence?
- **Severity differentiation** — does the tool treat devDependency GPL-3.0 differently from production GPL-3.0?
- **Remediation guidance** — does the tool suggest alternatives or explain the license restriction?

Record these in the **Policy & Classification Accuracy** section of the CycloneDX worksheet.
