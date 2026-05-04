# Evaluation Methodology

The evaluation must be conducted in an objective, controlled environment to ensure all vendors are measured against the same baseline.

## 1. Test Targets (The Codebases)
Select 3-5 repositories for the evaluation:
*   **The Custom Benchmark (`secret-testbed`):** Used to test the limitations of the scan engine (deep dataflow, second-order analysis, exotic secret formats, transitive dependencies). 
*   **Large Monolith:** A massive, legacy internal application (e.g., millions of lines of Java or C#). Used to test scan speed, memory consumption, and false positive generation at scale.
*   **Modern Microservice:** A modern application (e.g., Go, Node.js, Rust) to test language support and modern framework coverage.
*   **Infrastructure/Serverless Repo:** A repository heavy with Terraform, CloudFormation, Dockerfiles, and Lambda functions to test IaC and serverless coverage.

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
