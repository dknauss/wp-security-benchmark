# Changelog

All notable changes to the WordPress Security Benchmark.

## Unreleased

### Fixed
- Control 11.4: corrected after verification against WordPress 7.1.3 core. `wp_pre_execute_ability` bypasses the permission check only for direct PHP execution, not on the REST run endpoint; `wp_ability_permission_result` can allow even unauthenticated REST runs; `wp_ability_invoked` does not fire for REST-rejected requests. Added verified default values.

### Fixed
- Corrected findings from the 2026-10-07 documentation review and verification round. Recorded in `ai-assisted-docs/reviews/rounds/2026-10-07/`.
- §2: PHP audits query the PHP-FPM runtime and its pool overrides instead of the CLI interpreter.
- §4.4: `xmlrpc_enabled` is described as a partial measure; the audit uses a POST request; the `system.multicall` amplification rationale is marked historical (fixed in WordPress 4.4).
- §5.4: replaced the users-route remediation, which removed the routes for every non-administrator, with a tested snippet that requires authentication for reads and preserves core's permission checks.
- §5.8: rationale no longer claims code-defined roles resist database tampering; added a tested reconciliation example.
- §1.4: stated Nginx location ordering and added a behavioral audit. §1.5: covered `?rest_route=` requests.
- §5.1: audit checks enrollment and enforcement. §5.3: control scoped to maximum session lifetime, with the other measures named as separate.
- §6.1–6.2: `wp-config.php` mode follows the PHP-FPM pool user (440 in Model A).
- §4.6 and §11.1: audits no longer print salts, keys, or option values.
- §12.1: closes keyboard-interactive password authentication and audits the effective SSH configuration.
- §3.1: uses `REVOKE ALL PRIVILEGES, GRANT OPTION FROM`.

### Added
- Control 11.4, *Ensure Abilities API authorization overrides are reviewed* (Level 2, Manual), covering the WordPress 7.1 lifecycle filters and `public` exposure flag. The Benchmark now has 51 controls.
- §1.2: note on `worker-src` and WordPress 7.1 client-side media processing.

### Changed
- Regenerated the PDF, DOCX, and EPUB files from the corrected Markdown and refreshed the PDF visual baselines, which had not been updated since March 2026.
- Target Technology names WordPress 7.1.3 as current (October 7, 2026), states the support policy, and notes that 7.2 (scheduled December 8, 2026) is not covered. Reviewed for 7.1 changes.
- `CONTRIBUTING.md` describes the current manual build and release flow. `CLAUDE.md` uses portable command names.
- Updated `docs/current-metrics.md` for the above.

## 1.1.1 — 2026-06-17

### Added
- Added release-metadata validation so frontmatter version/date and the latest changelog release heading stay aligned, with optional tag/date enforcement during release publication.
- Added a `Series review` issue form so quarterly and pre-release cross-document alignment checks can be tracked explicitly.
- Added a repo-local generated-artifact smoke validator and a dedicated `Validate Artifacts` workflow for PDF, EPUB, and DOCX outputs.
- Added a Playwright-based PDF visual smoke test and dedicated workflow with committed baselines for critical page regions.
- Added a cross-format parity check so a small set of canonical phrases must remain present in the Markdown source and generated PDF, EPUB, and DOCX outputs.
- Added Learn WordPress's [Writing in the WordPress voice](https://learn.wordpress.org/course/writing-in-the-wordpress-voice/) as the recommended WordPress-specific voice and accessibility reference when benchmark findings are adapted into stakeholder communications.

### Changed
- Moved full PDF/DOCX/EPUB publication to the tag-driven release workflow and converted `generate-docs.yml` into a manual preview/build workflow instead of an automatic `main`-push publisher.
- Made the generated-artifact validator read the expected version string from the Markdown frontmatter instead of hardcoding `Version 1.1`, preventing future publish-flow failures after routine version bumps.
- Separated Playwright PDF visual validation from the artifact publish path so `generate-docs.yml` can publish after artifact checks while the dedicated visual workflow handles layout regression checks on workflow, packaging, and Pandoc changes.
- Corrected current-version framing to reflect the public WordPress 7.0 release and remove stale pre-release scheduling language.
- Tightened AI secret-management guidance for WordPress 7.0 by adding Connectors API credential-source and database-storage context to control 11.1.
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
