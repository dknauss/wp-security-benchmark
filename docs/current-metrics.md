# Current Metrics (Canonical)

This file is the single source of truth for architectural counts in the WordPress Security Benchmark. Check this file before writing any count in prose, and update it when adding or removing controls, sections, or structural elements.

Last verified: 2026-03-12

## Architectural Facts

| Fact | Value | Verification command | Last changed |
|---|---:|---|---|
| Document lines | 2,421 | `wc -l WordPress-Security-Benchmark.md` | v1.0 |
| Major sections (H2) | 22 | `grep -cE '^## ' WordPress-Security-Benchmark.md` | v1.0 |
| Security controls | 50 | `grep -cE '^### [0-9]+\.[0-9]+' WordPress-Security-Benchmark.md` | v1.0 |
| Audit sections | 50 | `grep -c '#### Audit' WordPress-Security-Benchmark.md` | v1.0 |
| Remediation sections | 50 | `grep -c '#### Remediation' WordPress-Security-Benchmark.md` | v1.0 |
| Code fences (total) | 248 | `grep -c '^\`\`\`' WordPress-Security-Benchmark.md` | v1.0 |
| Opening fences (with language tag) | 34 | `grep -cE '^\`\`\`[a-z]' WordPress-Security-Benchmark.md` | v1.0 |
| Bare closing fences | 214 | `grep -cE '^\`\`\`$' WordPress-Security-Benchmark.md` | v1.0 |
| Table rows | 63 | `grep -cE '^\| ' WordPress-Security-Benchmark.md` | v1.0 |
| WP-CLI commands | 4 | `grep -cE '^\s*wp ' WordPress-Security-Benchmark.md` | v1.0 |
| `[CUSTOMIZE: ...]` placeholders | 2 | `grep -c '\[CUSTOMIZE:' WordPress-Security-Benchmark.md` | v1.0 |
| Output formats | 4 | Markdown, DOCX, EPUB, PDF | v1.0 |

## Code Block Languages

| Language | Count | Verification command |
|---|---:|---|
| PHP | 13 | `grep -c '^\`\`\`php' WordPress-Security-Benchmark.md` |
| Bash | 6 | `grep -c '^\`\`\`bash' WordPress-Security-Benchmark.md` |
| Nginx | 5 | `grep -c '^\`\`\`nginx' WordPress-Security-Benchmark.md` |
| SQL | 5 | `grep -c '^\`\`\`sql' WordPress-Security-Benchmark.md` |
| Apache | 4 | `grep -c '^\`\`\`apache' WordPress-Security-Benchmark.md` |
| INI | 1 | `grep -c '^\`\`\`ini' WordPress-Security-Benchmark.md` |

## Control Categories

| Category | Section | Controls |
|---|---|---:|
| Web Server Configuration | 1.0 | 6 |
| PHP Configuration | 2.0 | 8 |
| Database Configuration | 3.0 | 5 |
| WordPress Core Configuration | 4.0 | 8 |
| Authentication and Access Control | 5.0 | 5 |
| File System Permissions | 6.0 | 4 |
| Logging and Monitoring | 7.0 | 4 |
| Supply Chain and Component Management | 8.0 | 2 |
| Web Application Firewall | 9.0 | 1 |
| Backup and Recovery | 10.0 | 2 |
| AI Integration Security | 11.0 | 1 |
| Server Access and Network | 12.0 | 3 |
| Multisite Security | 13.0 | 1 |

## Structural Integrity

| Check | Expected | Verification command |
|---|---|---|
| Every control has an Audit section | 50 = 50 | `grep -c '#### Audit' WordPress-Security-Benchmark.md` |
| Every control has a Remediation section | 50 = 50 | `grep -c '#### Remediation' WordPress-Security-Benchmark.md` |
| Opening/closing fences balanced | 34 + 214 = 248 | Opening + bare = total code fences |

## Verification Procedure

Run all verification commands after any structural edit:

```bash
cd /Users/danknauss/Documents/GitHub/wp-security-benchmark

echo "=== Document size ==="
wc -l WordPress-Security-Benchmark.md

echo "=== Structure ==="
echo "H2 sections: $(grep -cE '^## ' WordPress-Security-Benchmark.md)"
echo "Controls: $(grep -cE '^### [0-9]+\.[0-9]+' WordPress-Security-Benchmark.md)"
echo "Audit sections: $(grep -c '#### Audit' WordPress-Security-Benchmark.md)"
echo "Remediation sections: $(grep -c '#### Remediation' WordPress-Security-Benchmark.md)"

echo "=== Code ==="
echo "Fences total: $(grep -c '^```' WordPress-Security-Benchmark.md)"
echo "Opening (tagged): $(grep -cE '^```[a-z]' WordPress-Security-Benchmark.md)"
echo "Bare closing: $(grep -cE '^```$' WordPress-Security-Benchmark.md)"
echo "WP-CLI commands: $(grep -cE '^\s*wp ' WordPress-Security-Benchmark.md)"

echo "=== Tables ==="
echo "Table rows: $(grep -cE '^\| ' WordPress-Security-Benchmark.md)"
echo "CUSTOMIZE placeholders: $(grep -c '\[CUSTOMIZE:' WordPress-Security-Benchmark.md)"
```

## Update Procedure

1. After any edit to `WordPress-Security-Benchmark.md`, run the verification script above.
2. Compare results to this table. Update any changed values.
3. If a control was added, verify it has all required subsections (Audit, Remediation, etc.).
4. If code blocks were added, verify opening/closing fence balance.
5. Update `CHANGELOG.md` with the change.
