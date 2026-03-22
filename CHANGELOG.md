# Changelog

All notable changes to the WordPress Security Benchmark.

## Unreleased

### Added
- Added a `Series review` issue form so quarterly and pre-release cross-document alignment checks can be tracked explicitly.
- Added a repo-local generated-artifact smoke validator and a dedicated `Validate Artifacts` workflow for PDF, EPUB, and DOCX outputs.
- Added a Playwright-based PDF visual smoke test and dedicated workflow with committed baselines for critical page regions.

### Changed
- Refactored the document-generation pipeline into explicit build, validate, and publish jobs so generated artifacts are validated before the bot commit step runs.
- Updated GitHub Action pins in the PDF visual validation workflow to Node 24-capable major versions to avoid runner deprecation warnings.
- Set a short PDF running header title so the benchmark subtitle no longer appears in page headers.
- Hardened GitHub release automation and metrics validation by pinning action references to immutable commits.
- Documented the maintainer edit, verification, artifact-generation, release, and cross-document review workflow for this repository and its companion document series.

## 1.1.0 — 2026-03-21

### Changed
- Standardized license metadata on the canonical Creative Commons legal text and normalized in-repo references to `CC-BY-SA-4.0`.
- Added explicit repository health files (`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, `.gitattributes`) and linked them from the README so the repo no longer relies on inherited defaults for contributor guidance.
- Replaced the stale README WordPress-version badge with a `current supported` label and aligned contributor and AI-assisted editorial copy with the rest of the security-document series.
- Replaced the hard-coded local verification path in `docs/current-metrics.md` with `git rev-parse --show-toplevel` for path-independent maintenance checks.
- Refreshed `docs/current-metrics.md` after the benchmark document line count increased to 2,423, restoring metrics-validator parity.
- Cited WordPress VIP step-up authentication as an example platform implementation of action-gated reauthentication in §5.5.
- Updated version framing for the WordPress 7.0 release cycle by removing stale `WordPress 6.x` language and aligning the PHP baseline to `8.3+` with `8.4` staged validation guidance.
- Corrected the administrator-username remediation to remove the invalid `wp user update --user_login` command, clarified the password-length recommendation around the 15-character baseline, and normalized the cross-document classification matrix wording.
- Added centered page numbering to `.github/pandoc/reference.docx` so DOCX-derived PDF output includes footer page numbers through the shared generation pipeline.
- Replaced the repo-local document-generation workflow with a caller to the shared reusable workflow in `ai-assisted-docs`, keeping the primary markdown source and generated artifact names unchanged.

### Added
- `CHANGELOG.md` — this file.
- `docs/current-metrics.md` — architectural fact counts with verification commands.

## 1.0 — 2026-03-08

### Added
- Initial public release: 50 security controls across 13 categories.
- Two security profiles: Level 1 (Essential) and Level 2 (Defense-in-Depth).
- Consistent control structure: Profile Applicability, Assessment Status, Description, Rationale, Impact, Audit, Remediation, Default Value, References.
- Audit commands for all 50 controls (PHP, Bash, Nginx, Apache, SQL, INI).
- Cross-Document Control Classification Matrix (Appendix A).
- Deprecated and Invalid Constants Guardrail (Appendix B).
- PDF, DOCX, and EPUB formats via Pandoc CI/CD pipeline.
- WP-CLI command validity fixes from Phase 1 editorial audit.
