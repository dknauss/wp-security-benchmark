# Changelog

All notable changes to the WordPress Security Benchmark.

## Unreleased

### Changed
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
