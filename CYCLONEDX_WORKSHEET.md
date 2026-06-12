# CycloneDX SCA License Analysis Worksheet

Evaluate SCA tools against the `license-testbed` repository by comparing their CycloneDX 1.6 SBOM
output against the expected findings in `answer_key.md` (LICENSE section).

## How to Use

1. Run the SCA tool on the `license-testbed` repo and export a CycloneDX 1.6 JSON BOM
2. Fill in Part A — compare each component's license against the answer key
3. Fill in Part B — observe the tool's UI/CLI/CI output for policy classification
4. Calculate the score and transfer to `VENDOR_SCORECARD_TEMPLATE.md` §6

---

## Part A: CycloneDX SBOM Accuracy (5 pts)

### A1. Component Completeness (1 pt)

Does the SBOM `components[]` array include all expected direct + transitive dependencies?

Compare the SBOM's `components` count against the expected 30+:

| Expected | Actual | Notes |
|----------|--------|-------|
| All direct npm deps (11) | ___ / 11 | List missing: _______________ |
| All workspace deps (13) | ___ / 13 | List missing: _______________ |
| Transitive deps key items | ___ / 1 | `@img/sharp-libvips-*` present? ___ |
| Dev deps (mocha, chai, etc.) | ___ / 4 | Present? ___ |

**Pass (1 pt):** All 25+ direct deps and key transitive dep present in `components[]`.
**Partial (0.5 pt):** 20-24 components present.
**Fail (0 pt):** Fewer than 20 components, or critical items (ffmpeg-static, agpl-pkg) missing.

> **Score: ___ / 1**

### A2. SPDX License Identifier Accuracy (1 pt)

Each component's license should use `licenses[].license.id` (SPDX ID), not `licenses[].license.name`
(free-text label).

| UID | Package | Expected SPDX ID | CycloneDX `license.id` | Match? |
|-----|---------|-----------------|------------------------|--------|
| LICENSE_COMP_FFMPEG | ffmpeg-static | `GPL-3.0-or-later` | ___ | Y / N |
| LICENSE_COMP_AGPL | @license-testbed/agpl-pkg | `AGPL-3.0-only` | ___ | Y / N |
| LICENSE_COMP_LGPL | @license-testbed/lgpl-pkg | `LGPL-2.1-only` | ___ | Y / N |
| LICENSE_COMP_MPL | @license-testbed/mpl-pkg | `MPL-2.0` | ___ | Y / N |
| LICENSE_COMP_BUSL | @license-testbed/busl-pkg | `BUSL-1.1` | ___ | Y / N |
| LICENSE_COMP_SSPL | @license-testbed/sspl-pkg | `SSPL-1.0` | ___ | Y / N |
| LICENSE_COMP_DEVONLYGPL | @license-testbed/dev-only-gpl | `GPL-3.0-only` | ___ | Y / N |
| LICENSE_COMP_WTFPL | @license-testbed/wtfpl-pkg | `WTFPL` | ___ | Y / N |
| LICENSE_COMP_UNLICENSE | @license-testbed/unlicense-pkg | `Unlicense` | ___ | Y / N |
| LICENSE_COMP_BSD3 | source-map / bsd3-pkg | `BSD-3-Clause` | ___ | Y / N |
| LICENSE_COMP_0BSD | zerobsd-pkg / tslib | `0BSD` | ___ | Y / N |
| LICENSE_COMP_SPDXIDS | spdx-license-ids | `CC0-1.0` | ___ | Y / N |

**Pass (1 pt):** All 12+ checked entries use `license.id` with correct SPDX identifiers.
**Partial (0.5 pt):** 8-11 correct, or some use `license.name` (free text) instead of `license.id`.
**Fail (0 pt):** Most entries use free-text names or have wrong SPDX IDs.

> **Score: ___ / 1**

### A3. Dual-License Expression Handling (1 pt)

`node-forge` is licensed as `(BSD-3-Clause OR GPL-2.0)` — an SPDX license expression, not a single license.

Check how the SBOM handles this:

| SBOM Field | Expected | Actual | Correct? |
|------------|----------|--------|----------|
| `licenses[].license.id` | N/A — use expression | ___ | |
| `licenses[].expression` | `(BSD-3-Clause OR GPL-2.0)` | ___ | Y / N |
| OR individual `license` entries | Both BSD-3-Clause AND GPL-2.0 listed | ___ | Y / N |

**Pass (1 pt):** SBOM correctly expresses the dual license (either as an expression field or with both license options listed). MUST NOT silently show only BSD-3-Clause.
**Fail (0 pt):** Only one license shown (especially if it's just BSD-3-Clause), which hides the GPL-2.0 option.

> **Score: ___ / 1**

### A4. Transitive Dependency Inclusion (1 pt)

The `sharp` package (Apache-2.0) depends on `@img/sharp-libvips-linux-x64` (LGPL-3.0-or-later).

| Criterion | Expected | Actual | Correct? |
|-----------|----------|--------|----------|
| `@img/sharp-libvips-linux-x64` in `components[]` | Yes | ___ | Y / N |
| License set to `LGPL-3.0-or-later` | Yes | ___ | Y / N |
| Dependency path visible | `sharp` → `@img/sharp-libvips-*` | ___ | Y / N / N/A |

**Pass (1 pt):** The libvips transitive dep is present with correct license, and the dependency chain
is traceable (via `dependencies[]` or `dependsOn[]` fields).

**Fail (0 pt):** Missing from SBOM, or license is wrong, or only listed as a flattened component with no traceability.

> **Score: ___ / 1**

### A5. Dev vs Production Context Tagging (1 pt)

The SBOM should distinguish runtime dependencies from dev-only dependencies.

For each devDependency, look for a tag or property indicating dev scope:

| Package | Expected | CycloneDX Evidence | Correct? |
|---------|----------|-------------------|----------|
| `@license-testbed/dev-only-gpl` | Marked as dev | ___ | Y / N |
| `mocha` | Marked as dev | ___ | Y / N |
| `chai` | Marked as dev | ___ | Y / N |
| `typescript` | Marked as dev | ___ | Y / N |
| `ffmpeg-static` | **NOT** marked as dev | ___ | Y / N |

In CycloneDX 1.6, dev context is typically indicated by:
- `properties[]` with `name="dependency-type"` and `value="dev"`
- The component appearing in a `services[]` scope
- The tool's own metadata/properties extension

**Pass (1 pt):** At least 3 of 4 dev deps correctly tagged AND ffmpeg-static NOT tagged as dev.
**Partial (0.5 pt):** 2 of 4 dev deps tagged correctly.
**Fail (0 pt):** No dev/prod distinction, or incorrectly tagging prod deps as dev.

> **Score: ___ / 1**

### Part A Total: ___ / 5

---

## Part B: Policy & Classification Accuracy (5 pts)

These criteria are evaluated from the tool's UI, CLI output, or policy engine — NOT from the CycloneDX
SBOM alone. They test whether the tool *acts* on the license information it collects.

### B1. Strong Copyleft Detection (2 pts)

Does the tool correctly identify strong copyleft licenses and flag them as high-risk?

| Item | Criterion | Evidence (UI/CLI output) | Score |
|------|-----------|--------------------------|:-----:|
| 1a | `ffmpeg-static` identified as GPL-3.0 (strong copyleft) | ___ | 0.5 pt |
| 1b | `@license-testbed/agpl-pkg` identified as AGPL-3.0 (network copyleft / critical) | ___ | 0.5 pt |
| 1c | `@license-testbed/lgpl-pkg` identified as LGPL-2.1 (weak copyleft, NOT same severity as GPL) | ___ | 0.5 pt |
| 1d | Tool has a copyleft-specific risk category or badge (not just "license: GPL-3.0" in a table) | ___ | 0.5 pt |

> **Score: ___ / 2**

### B2. Non-OSI / Commercial Restriction Detection (1 pt)

Does the tool flag non-OSI-approved licenses?

| Item | Criterion | Evidence | Score |
|------|-----------|----------|:-----:|
| 2a | `@license-testbed/busl-pkg` flagged as non-OSI or commercially-restrictive | ___ | 0.5 pt |
| 2b | `@license-testbed/sspl-pkg` flagged as non-OSI or commercially-restrictive | ___ | 0.5 pt |

**Note:** SSPL and BUSL are NOT OSI-approved open source licenses. A tool that labels them as
"open source" without caveat loses points here.

> **Score: ___ / 1**

### B3. Dev vs Production Differentiation (1 pt)

This is the key differentiation test. Both `ffmpeg-static` and `@license-testbed/dev-only-gpl`
are GPL-3.0, but in different contexts:

| Package | Context | Expected Severity |
|---------|---------|-------------------|
| `ffmpeg-static` | `dependencies`, imported in `src/app.js` | HIGH — production runtime |
| `@license-testbed/dev-only-gpl` | `devDependencies`, only in `test/app.test.js` | LOWER — dev-only usage |

| Criterion | Expected | Actual | Score |
|-----------|----------|--------|:-----:|
| Tool shows HIGHER severity/priority for ffmpeg-static | Yes | ___ | 0.5 pt |
| Tool shows LOWER severity for dev-only-gpl (or at minimum notes it's dev-only) | Yes | ___ | 0.5 pt |

**Full credit:** Tool clearly distinguishes the two — e.g., "GPL-3.0 (production)" vs "GPL-3.0 (dev-only)".
**Partial:** Both flagged at same severity but dev-only-gpl has a "dev" tag.
**Zero:** Both treated identically with no context differentiation.

> **Score: ___ / 1**

### B4. Transitive Dependency Discovery (1 pt)

Does the tool surface transitive copyleft dependencies?

| Criterion | Expected | Actual | Score |
|-----------|----------|--------|:-----:|
| `@img/sharp-libvips-*` shown in dependency tree | Present | ___ | 0.5 pt |
| Clear dependency path: `sharp → @img/sharp-libvips-linux-x64` | Visible | ___ | 0.5 pt |

**Full credit:** Tool shows the transitive license AND the dependency chain.
**Partial:** Tool lists the transitive dep in the SBOM but doesn't show the chain.
**Zero:** Transitive dep not surfaced at all.

> **Score: ___ / 1**

### Part B Total: ___ / 5

---

## Summary

| Section | Max | Score |
|---------|:---:|:-----:|
| A1 — Component Completeness | 1 | ___ |
| A2 — SPDX License Accuracy | 1 | ___ |
| A3 — Dual-License Expression | 1 | ___ |
| A4 — Transitive Inclusion | 1 | ___ |
| A5 — Dev/Prod Context Tagging | 1 | ___ |
| **Part A Total (SBOM Accuracy)** | **5** | **___** |
| B1 — Strong Copyleft Detection | 2 | ___ |
| B2 — Non-OSI Detection | 1 | ___ |
| B3 — Dev/Prod Differentiation | 1 | ___ |
| B4 — Transitive Discovery | 1 | ___ |
| **Part B Total (Policy & Classification)** | **5** | **___** |
| **License Analysis Total** | **10** | **___** |

Transfer this total to `VENDOR_SCORECARD_TEMPLATE.md` → Category 6.

---

## Reference: Generating a Baseline CycloneDX SBOM

If you need a reference SBOM to compare against (e.g., to verify what the licenses should look
like in CycloneDX format):

```bash
# Using the CycloneDX CLI tool
cd /workspace/appsec-vendor-eval/license-testbed
npx @cyclonedx/bom --output /tmp/license-testbed-bom.json

# Or using npm's built-in SBOM (Node.js 22+)
npm sbom --all --format cyclonedx-json > /tmp/license-testbed-bom.json
```

The reference SBOM shows what a correct CycloneDX 1.5/1.6 document should contain. Note that
the workspace packages (`@license-testbed/*`) may appear as `file://` references rather than
npm package URLs — this is acceptable as long as their license fields are correct.
