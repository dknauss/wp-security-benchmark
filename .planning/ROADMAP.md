# Roadmap: WordPress Security Benchmark

## Overview

This roadmap starts GSD tracking for the benchmark's next maintenance cycle rather than trying to reconstruct the already shipped release history. The milestone begins by formalizing editorial governance and repeatable review habits, then audits the benchmark against current primary sources, verifies publication workflow integrity, and closes by tightening cross-document positioning while shaping the next maintenance cycle.

## Milestones

- ✅ **v1.0 Public Release** - Benchmark published with 50 controls and multi-format artifacts (shipped 2026-03-08)
- 🚧 **v1.1 Maintenance Baseline** - Editorial governance, benchmark audit, and publication hygiene under GSD tracking

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Governance Baseline** - Establish repeatable maintenance rules and repo state tracking.
- [ ] **Phase 2: Source-Grounded Editorial Audit** - Review benchmark claims and commands against current primary sources.
- [ ] **Phase 3: Publication Pipeline Assurance** - Verify artifact-generation and release workflow integrity.
- [ ] **Phase 4: Cross-Document Alignment** - Tighten document positioning and shape the next maintenance cycle.

## Phase Details

### Phase 1: Governance Baseline
**Goal:** Establish the rules and working memory needed to maintain the benchmark without silent process drift.
**Depends on:** Nothing (first phase)
**Requirements:** GOV-01, PUB-02
**Success Criteria** (what must be TRUE):
  1. A maintainer can see the current milestone scope, repo constraints, and next actionable phase from `.planning/` alone.
  2. Structural benchmark edits have a clear path to metrics validation and changelog updates.
  3. Ongoing maintenance work leaves a traceable planning and verification trail.
**Plans:** 2 plans

Plans:
- [ ] 01-01: Codify maintenance guardrails, authority hierarchy, and validation checkpoints.
- [ ] 01-02: Establish repeatable repo assessment and change-tracking conventions.

### Phase 2: Source-Grounded Editorial Audit
**Goal:** Audit time-sensitive benchmark guidance so active recommendations stay accurate and executable.
**Depends on:** Phase 1
**Requirements:** EDIT-01, EDIT-02
**Success Criteria** (what must be TRUE):
  1. Time-sensitive benchmark claims targeted by the audit are verified against current primary sources.
  2. Invalid or stale audit/remediation steps found during the review are corrected or explicitly flagged for follow-up.
  3. Editorial changes made by the audit are captured in changelog and review notes.
**Plans:** 2 plans

Plans:
- [ ] 02-01: Review version framing, platform assumptions, and current-source dependencies.
- [ ] 02-02: Audit benchmark commands and remediation steps for validity and clarity.

### Phase 3: Publication Pipeline Assurance
**Goal:** Keep published artifacts and GitHub automation aligned with the benchmark source and repo layout.
**Depends on:** Phase 2
**Requirements:** GOV-02, PUB-01
**Success Criteria** (what must be TRUE):
  1. A maintainer can explain when artifact regeneration is required and which files must stay in sync.
  2. Generation and release workflows match the current repository structure and expected output artifacts.
  3. Publication workflow assumptions that require manual verification are documented for future runs.
**Plans:** 2 plans

Plans:
- [ ] 03-01: Verify document generation triggers, inputs, and committed artifacts.
- [ ] 03-02: Verify release workflow expectations and document manual publication checks.

### Phase 4: Cross-Document Alignment
**Goal:** Keep the benchmark properly scoped within the wider WordPress security docs set and tee up the next milestone.
**Depends on:** Phase 3
**Requirements:** ALIGN-01, ALIGN-02
**Success Criteria** (what must be TRUE):
  1. README and benchmark positioning clearly differentiate this repo from the related runbook, hardening guide, and style guide.
  2. Future reviewers can identify the repo's editorial authority hierarchy and AI-assisted review rules without guesswork.
  3. Remaining gaps and likely follow-on work are captured clearly enough to start the next milestone cleanly.
**Plans:** 2 plans

Plans:
- [ ] 04-01: Review repo positioning and cross-document boundary language.
- [ ] 04-02: Capture unresolved risks, follow-on work, and next-milestone candidates.

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 2.1 -> 2.2 -> 3 -> 3.1 -> 4

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Governance Baseline | 0/2 | Not started | - |
| 2. Source-Grounded Editorial Audit | 0/2 | Not started | - |
| 3. Publication Pipeline Assurance | 0/2 | Not started | - |
| 4. Cross-Document Alignment | 0/2 | Not started | - |
