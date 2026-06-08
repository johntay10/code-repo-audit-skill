"""Prompt injection scanner for target code repos.

Greps target text files (markdown, code comments, docstrings, READMEs) for
patterns that attempt to manipulate the auditing AI agent itself — directing
it to skip checks, report safe, mark as approved, ignore previous
instructions, impersonate system messages, etc.

This runs as a PRE-FLIGHT check before the audit's other categories — if any
HIGH-severity hit is found, the audit should hard-fail without giving the
target's documentation a chance to poison the auditor's context.

USAGE:
    python3 injection_scanner.py <directory>

Exits 0 with zero hits, 1 with any hits (HIGH/MEDIUM/LOW).
"""

from __future__ import annotations

import os
import re
import sys

# Each entry: (label, compiled regex, severity)
# Severity guide:
#   HIGH    — almost certainly malicious; no legitimate doc reason to include
#   MEDIUM  — suspicious but could appear in legit content (e.g. a roleplay skill,
#             prompt-injection documentation); requires context review
#   LOW     — worth flagging but often benign
INJECTION_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # --- Direct instruction override ---
    ("instruction-override",
     re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instruct", re.I),
     "HIGH"),
    ("instruction-override",
     re.compile(r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+instruct", re.I),
     "HIGH"),
    ("instruction-override",
     re.compile(r"forget\s+(all\s+)?(previous|prior|above|earlier)\s+instruct", re.I),
     "HIGH"),
    ("instruction-override",
     re.compile(r"new\s+instructions?\s*[:.]", re.I),
     "MEDIUM"),

    # --- Auditor-targeted directives ---
    ("auditor-directive",
     re.compile(r"(ai\s+)?(auditor|reviewer|agent)\s+(note|instruction|directive|advisory)", re.I),
     "HIGH"),
    ("auditor-directive",
     re.compile(r"\b(claude|gpt|assistant|ai\s+agent|copilot|gemini)\s*[:,]\s*(skip|ignore|trust|mark|report|do\s+not)", re.I),
     "HIGH"),
    ("auditor-directive",
     re.compile(r"pre[\s-]?(audited|approved|cleared|verified|vetted)\s+by", re.I),
     "HIGH"),
    ("auditor-directive",
     re.compile(r"\bskip\s+(categor|check|step|verification|audit|review)", re.I),
     "HIGH"),
    ("auditor-directive",
     re.compile(r"\b(mark|flag)\s+(as|the)\s+(safe|clean|verified|approved|trusted)", re.I),
     "HIGH"),
    ("auditor-directive",
     re.compile(r"report\s+(as\s+)?(safe|clean|trusted|verdict|99|100)", re.I),
     "HIGH"),
    ("auditor-directive",
     re.compile(r"no\s+need\s+to\s+(audit|check|verify|review|scan)", re.I),
     "HIGH"),
    ("auditor-directive",
     re.compile(r"audit\s+(is\s+)?(complete|done|finished|passed)", re.I),
     "MEDIUM"),
    ("auditor-directive",
     re.compile(r"already\s+(audited|verified|reviewed|checked|cleared)\s+by", re.I),
     "MEDIUM"),

    # --- Confidence manipulation ---
    ("confidence-manipulation",
     re.compile(r"(100|99)\s*%?\s*(confident|safe|clean|trusted)", re.I),
     "MEDIUM"),
    ("confidence-manipulation",
     re.compile(r"verdict\s*[:=]\s*['\"]?(safe|clean|approved|trust|pass)", re.I),
     "HIGH"),

    # --- Common jailbreak phrases ---
    ("jailbreak",
     re.compile(r"\bDAN\b.*do\s+anything", re.I),
     "HIGH"),
    ("jailbreak",
     re.compile(r"do\s+anything\s+now", re.I),
     "MEDIUM"),
    ("jailbreak",
     re.compile(r"developer\s+mode\s+(enabled|on|active)", re.I),
     "MEDIUM"),

    # --- System / role impersonation ---
    ("system-impersonation",
     re.compile(r"<\s*system\s*>"),
     "HIGH"),
    ("system-impersonation",
     re.compile(r"\[\s*SYSTEM\s*\]"),
     "HIGH"),
    ("system-impersonation",
     re.compile(r"<\|\s*im_start\s*\|>\s*system"),
     "HIGH"),
    ("system-impersonation",
     re.compile(r"###\s*SYSTEM\s*[:.]"),
     "MEDIUM"),
    ("role-manipulation",
     re.compile(r"you\s+are\s+now\s+(a|in|an)\b", re.I),
     "MEDIUM"),

    # --- Trust manipulation ---
    ("trust-manipulation",
     re.compile(r"this\s+(skill|package|code|tool)\s+is\s+(safe|trusted|verified|approved|legitimate)", re.I),
     "MEDIUM"),
    ("trust-manipulation",
     re.compile(r"this\s+is\s+(not|definitely\s+not)\s+(malicious|a\s+backdoor)", re.I),
     "MEDIUM"),
]

TEXT_EXTENSIONS = {
    ".md", ".txt", ".rst",
    ".py", ".sh", ".bash", ".zsh",
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg",
    ".html", ".css",
    ".rb", ".go", ".rs", ".c", ".h", ".cpp", ".hpp",
    ".java", ".kt", ".swift",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".tox"}


def scan(root: str) -> list[tuple[str, int, str, str, str]]:
    """Return list of (path, line_no, severity, label, snippet) hits."""
    hits: list[tuple[str, int, str, str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext not in TEXT_EXTENSIONS:
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, encoding="utf-8") as fh:
                    for line_no, line in enumerate(fh, start=1):
                        for label, pattern, severity in INJECTION_PATTERNS:
                            if pattern.search(line):
                                snippet = line.strip()[:140]
                                hits.append((path, line_no, severity, label, snippet))
            except (UnicodeDecodeError, OSError):
                continue
    return hits


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: injection_scanner.py <directory>", file=sys.stderr)
        return 2
    root = sys.argv[1]
    if not os.path.isdir(root):
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    hits = scan(root)
    if not hits:
        print(f"✓ 0 prompt-injection patterns across {root}")
        return 0

    severities = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    print(f"✗ {len(hits)} potential prompt-injection pattern(s) found:")
    print()
    for path, line_no, severity, label, snippet in hits:
        rel = os.path.relpath(path, root)
        severities[severity] += 1
        print(f"  [{severity}] {rel}:{line_no}  ({label})")
        print(f"      {snippet}")
    print()
    print(f"Summary: HIGH={severities['HIGH']}  MEDIUM={severities['MEDIUM']}  LOW={severities['LOW']}")
    print()
    print("Each hit must be reviewed in context. Distinguish:")
    print("  - Genuine injection attempt (malicious) → HARD FAIL the audit.")
    print("  - Legitimate documentation discussing prompt-injection topics")
    print("    (e.g. a skill that itself audits or defends against injection) → benign.")
    print("  - Roleplay/AI-related skill content describing its own behavior → benign.")
    print()
    print("If unsure on a HIGH hit, default to HARD FAIL. A repo that needs to")
    print("write to its auditor is suspect by definition.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
