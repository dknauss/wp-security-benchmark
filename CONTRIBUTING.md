# Contributing

Thanks for helping improve the WordPress Security Benchmark.

## Scope

Contributions are welcome for:

- factual corrections
- outdated WordPress or security guidance
- control wording and classification improvements
- broken validation commands or repository automation issues

This repository is a prescriptive benchmark. It is not the place for
environment-specific incident procedures or broad architectural rationale unless
that context is necessary to explain or safely apply a benchmark control.

## Before You Start

Read these files first:

- `README.md`
- `WordPress-Security-Benchmark.md`
- `docs/current-metrics.md`
- `SECURITY.md`

Related repositories in this document series may also need aligned updates:

- `wp-security-hardening-guide`
- `wordpress-runbook-template`
- `wp-security-style-guide`

## Reporting Issues

- Use the GitHub issue templates for inaccurate controls, broken examples, or
  improvement requests.
- Do not use public issues for security-sensitive reports. Follow
  `SECURITY.md` instead.

When filing a documentation bug, include the affected control, the source used
to verify the issue, and whether companion repos may also need updates.

## Editing Rules

- Treat `WordPress-Security-Benchmark.md` as the canonical source.
- Keep generated artifacts aligned with the canonical Markdown source, but do
  not hand-edit binary artifacts unless the change specifically targets the
  generation pipeline or template files.
- Verify WordPress-specific claims against primary sources such as
  `developer.wordpress.org`, WordPress core documentation, or WordPress.org
  project pages.
- Verify command syntax before changing benchmark examples.
- Keep terminology aligned with the repository's existing editorial style.
- Update `CHANGELOG.md` for user-visible documentation or workflow changes.

## Metrics Verification

If your change affects controls, headings, tables, code fences, or other
structural counts, update `docs/current-metrics.md` and run:

```bash
bash .github/scripts/verify-metrics.sh docs/current-metrics.md
```

The metrics file is the canonical source of truth for the structural counts
used in this repository.

## Generated Documents

This repository tracks generated `.docx`, `.epub`, and `.pdf` artifacts.
Regenerate them through the documented GitHub Actions workflow or an equivalent
local Pandoc toolchain when required by the change.

If you cannot regenerate artifacts locally, note that in the pull request
instead of committing guessed outputs.

## Pull Requests

Pull requests should:

- describe what changed and why
- mention any source or command verification performed
- note whether metrics, changelog entries, or generated artifacts changed
- call out any cross-document follow-up needed in the hardening guide,
  runbook, or style guide repos

Keep changes focused. Separate editorial cleanup from unrelated repository or
workflow changes when practical.
