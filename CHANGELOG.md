# Changelog

All notable changes to the WordPress Security Benchmark.

## Unreleased

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
