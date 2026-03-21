# WordPress Security Benchmark

## What This Is

This repository is the source of truth for the WordPress Security Benchmark: a published audit checklist for security engineers, auditors, and operators assessing enterprise WordPress environments. It maintains the primary Markdown source, the generated publication artifacts, and the repo-level rules that keep benchmark guidance auditable, current, and internally consistent.

## Core Value

The benchmark must remain source-grounded, auditable, and safe to apply to current supported WordPress environments.

## Requirements

### Validated

- ✓ Publish the benchmark as a structured hardening checklist with 50 controls across 13 categories — existing v1.0 release.
- ✓ Generate and ship Markdown, DOCX, EPUB, and PDF artifacts from the same benchmark source — existing v1.0 release.
- ✓ Validate canonical structural metrics against the benchmark source in CI — existing v1.0.1 workflow.

### Active

- [ ] Keep benchmark claims, remediation steps, and version framing aligned with current primary sources.
- [ ] Keep canonical metrics, changelog entries, and generated artifacts synchronized with source edits.
- [ ] Make editorial maintenance work traceable through milestone-scoped planning, verification, and state tracking.

### Out of Scope

- Runtime scanning, enforcement agents, or deployable WordPress software — this repo publishes benchmark guidance, not executable tooling.
- Generic WordPress operations tutorials — those belong in the related operations runbook, not this audit benchmark.
- Broad security architecture explanation beyond what the benchmark needs to justify controls — the hardening guide covers that layer.

## Context

The repository already has a public release lineage, with `v1.0` shipped on 2026-03-08 and `v1.0.1` on the current `main` branch. The benchmark explicitly positions itself as an audit checklist rather than an implementation runbook or general hardening guide, and it links to the related docs set from the README. The repo commits generated publication artifacts, validates canonical structural counts through a CI script, and uses a shared reusable document-generation workflow plus a separate tagged release workflow. The benchmark is revised through an AI-assisted editorial process, but every change still needs human review and live-source verification.

## Constraints

- **Authority hierarchy**: Prefer official WordPress and other primary vendor documentation for benchmark claims and remediation details — this is security guidance, so source drift matters.
- **Publication model**: `WordPress-Security-Benchmark.md` remains the primary source, with DOCX, EPUB, and PDF outputs derived from it — edits must preserve multi-format generation.
- **Repository scope**: The benchmark answers "what do I verify?" rather than "how do I operate WordPress?" — scope creep weakens the document's purpose.
- **Git history**: Generated artifacts and canonical maintenance docs are committed in git — maintenance work must leave a clear operator trail.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Start GSD tracking with the next maintenance milestone instead of reconstructing historical execution for the shipped benchmark. | The repo already has released work, but there is no prior `.planning/` state to recover accurately. | ✓ Good |
| Treat this repository as a documentation product with milestone-scoped maintenance work, not as a code-first software project. | The primary deliverable is security guidance plus generated publication artifacts. | ✓ Good |
| Default to validation-heavy workflow settings for future work. | Security documentation changes can silently introduce harmful drift if source checks and review gates are weak. | — Pending |

---
*Last updated: 2026-03-21 after GSD initialization*
