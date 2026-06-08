# code-repo-audit

A Claude Code skill that audits any third-party code repository (skill, plugin, npm/PyPI package, generic source repo) for supply-chain safety before you install it.

After the 2024 XZ Utils backdoor, the 2025 tj-actions/changed-files compromise, and the March 2026 wave of npm + PyPI compromises (Axios, LiteLLM, Telnyx, Trivy, KICS), "I trust the maintainer" is no longer a sufficient install policy. This skill gives you a systematic, repeatable audit you can run before any third-party install, plus a structured verdict with calibrated confidence at the end.

## What it checks

Six categories, run in this order (substantive evidence first, social context last):

| # | Category | Question it answers |
|---|---|---|
| 0.5 | **Prompt-injection pre-flight** | Is the target trying to manipulate the auditing AI agent itself? (Hard fail.) |
| 1 | **External surface** | Does it talk to anyone it shouldn't? Does it download new code at runtime? |
| 2 | **Local surface** | Does it touch sensitive files (`~/.ssh`, etc.)? Are credential reads scoped? |
| 3 | **Execution risks** | Hidden Unicode (Trojan Source)? Obfuscation? Unsafe shell calls? |
| 4 | **Behavioral verification** | Live-run sandbox: what hostnames does it actually hit? |
| 5 | **Project trustworthiness** | Real project? Multi-contributor? Maintainer takes security seriously? |

The bundled scripts are pure stdlib Python, with no runtime dependencies and no install-time side effects:

- `scripts/injection_scanner.py`: pre-flight regex scan for prompt-injection attempts targeting the auditor.
- `scripts/unicode_scanner.py`: Trojan Source / hidden-Unicode detector (CVE-2021-42574 class).
- `scripts/audit_runner.py`: Python-layer behavioral sandbox. Monkey-patches `urllib`, `socket`, and `subprocess` so every outbound call is logged and blocked.
- `references/grep_patterns.md`: exhaustive grep pattern library, organized by category.

## Install as a Claude Code skill

```bash
cd ~/.claude/skills
git clone https://github.com/johntay10/code-repo-audit-skill.git code-repo-audit
```

After install, trigger it by pasting any GitHub URL with a phrase like "is this safe to install" / "audit this repo" / "supply chain check", or invoke `/code-repo-audit <github-url>` directly.

**Pin to a specific commit SHA after install** (`git checkout <sha>`) so future re-pulls require re-auditing, which is the whole point.

## Confidence rubric

The skill outputs a calibrated verdict at the end:

| Confidence | Meaning |
|---|---|
| 95%+ | All 6 categories clean, behavioral sandbox showed only expected hosts, positive maintainer signals |
| 85–94% | Mostly clean with one or two structural weaknesses (e.g., moving-tag CI deps); safe for low-stakes use |
| 70–84% | Mixed signals; install only if you can sandbox it further |
| <70% | At least one real concern; do not install without deeper investigation |
| Hard fail | Author-controlled domain, RCE primitive present, wildcard credential read, obfuscated payload, **or** any HIGH-severity prompt-injection pattern targeting the auditor |

The ceiling is ~95% from static + behavioral analysis. Higher requires Docker `--network none` isolation, reproducible-build verification, or an independent reviewer. Usually overkill for skill-scale installs.

## Limitations

- **Python-layer sandbox, not kernel-level.** Monkey-patches catch `urllib`/`socket`/`subprocess`, but not `ctypes` calls into libc or raw syscalls. For high-stakes installs (credentials = catastrophic if leaked), run the target inside Docker with `--network none` instead.
- **Per-commit, not per-project.** A clean audit at SHA `X` says nothing about SHA `Y`. Re-audit on every update.
- **Best-effort, not certification.** No automated check substitutes for reading the code yourself when the install matters.

## License

MIT. See [LICENSE](LICENSE).

## Contributing

Issues and PRs welcome, especially new regex patterns for the injection scanner, additional sensitive-path entries, or coverage for non-Python target languages.
