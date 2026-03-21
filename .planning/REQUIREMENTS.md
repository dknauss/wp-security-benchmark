# Requirements: WordPress Security Benchmark

**Defined:** 2026-03-21
**Core Value:** The benchmark must remain source-grounded, auditable, and safe to apply to current supported WordPress environments.

## Current Milestone Requirements (v1.1 Maintenance Baseline)

Requirements for the first GSD-managed milestone. The benchmark itself is already shipped; this milestone establishes disciplined maintenance around it.

### Governance

- [ ] **GOV-01**: Canonical metrics and their verification commands stay synchronized with the benchmark source after every structural edit.
- [ ] **GOV-02**: Generated publication artifacts are regenerated and reviewed whenever the benchmark source or shared document template changes.

### Editorial Integrity

- [ ] **EDIT-01**: Benchmark claims that depend on current platform or vendor behavior are verified against primary sources before merge.
- [ ] **EDIT-02**: Invalid, stale, or misleading audit and remediation steps are corrected and recorded in the changelog when discovered.

### Publication Workflow

- [ ] **PUB-01**: Repo automation for document generation and tagged releases remains aligned with the committed artifact set and repository structure.
- [ ] **PUB-02**: Substantive maintenance changes leave an operator trail through changelog, planning state, and verification notes.

### Cross-Document Positioning

- [ ] **ALIGN-01**: The README and benchmark continue to distinguish this benchmark from the related runbook, hardening guide, and style guide.
- [ ] **ALIGN-02**: The AI-assisted editorial process and authority hierarchy remain explicit enough for future reviewers to apply the same standards.

## Future Requirements

### Automation

- **AUTO-01**: Add broader automated quality checks beyond canonical metrics when they can run without generating noisy false positives.
- **AUTO-02**: Add a lightweight source-freshness review routine for time-sensitive benchmark sections.

## Out of Scope

| Feature | Reason |
|---------|--------|
| Building a WordPress security scanner or CLI | This repo publishes benchmark guidance, not executable assessment tooling. |
| Expanding into a general WordPress operations manual | The benchmark must stay focused on auditable controls. |
| Reconstructing historical v1.0 implementation phases in detail | That work predates GSD tracking and would be mostly invented history. |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| GOV-01 | Phase 1 | Pending |
| PUB-02 | Phase 1 | Pending |
| EDIT-01 | Phase 2 | Pending |
| EDIT-02 | Phase 2 | Pending |
| GOV-02 | Phase 3 | Pending |
| PUB-01 | Phase 3 | Pending |
| ALIGN-01 | Phase 4 | Pending |
| ALIGN-02 | Phase 4 | Pending |

**Coverage:**
- Current milestone requirements: 8 total
- Mapped to phases: 8
- Unmapped: 0

---
*Requirements defined: 2026-03-21*
*Last updated: 2026-03-21 after GSD initialization*
