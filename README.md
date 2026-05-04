# AppSec Vendor Evaluation Framework

A quantitative, objective framework for evaluating Application Security testing tools (SAST, SCA, Secrets Scanners), including traditional static engines and modern AI-native tools.

## Objective
To provide a reproducible, data-driven methodology for conducting "bake-offs" (Proof of Concepts) between competing AppSec vendors. This framework focuses on empirical evidence (True Positives, False Positives) rather than marketing claims, while also weighing Developer Experience (DevEx) and CI/CD integration.

## Contents
1. [Evaluation Methodology](METHODOLOGY.md): Step-by-step guide on how to conduct the evaluation.
2. [Scoring Rubric](SCORING_RUBRIC.md): The point system used to objectively rate vendors across various categories.
3. [Vendor Scorecard Template](VENDOR_SCORECARD_TEMPLATE.md): A blank template to record vendor scores.
4. [Evaluation Plan](EVALUATION_PLAN.md): The timeline and phases for a typical 3-4 week PoC.

## Using the Secret-Testbed
This framework is designed to be used in conjunction with the `secret-testbed` repository, a custom-built, highly weaponized project containing intentionally vulnerable code (complex SAST findings spanning multiple files, obfuscated secrets, and transitive CVEs).

Because vendors often pre-train their models or fine-tune their rulesets against public benchmarks (like OWASP Benchmark or WebGoat), the custom `secret-testbed` provides a "zero-day" evaluation environment that the vendors have never seen before.
