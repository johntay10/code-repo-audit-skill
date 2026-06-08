"""Trojan Source / hidden-Unicode scanner.

Walks every text file under the target directory and flags suspect codepoints
that attackers use to hide malicious code from human reviewers:

- Zero-width characters (ZWSP, ZWNJ, ZWJ) — invisible insertions
- BOM in unexpected positions
- Bidirectional overrides (RLO, LRO, LRI, RLI, FSI, PDI) — the classic
  Trojan Source attack, which reorders code visually so what you read is
  not what the compiler executes (CVE-2021-42574)

USAGE:
    python3 unicode_scanner.py <directory>

Exits 0 with zero findings; exits 1 if any suspect codepoints are present.
"""

from __future__ import annotations

import os
import sys

SUSPECT_CODEPOINTS = {
    0x200B: "ZWSP (zero-width space)",
    0x200C: "ZWNJ (zero-width non-joiner)",
    0x200D: "ZWJ (zero-width joiner)",
    0xFEFF: "BOM (zero-width no-break space)",
    0x202A: "LRE (left-to-right embedding)",
    0x202B: "RLE (right-to-left embedding)",
    0x202C: "PDF (pop directional formatting)",
    0x202D: "LRO (left-to-right override)",
    0x202E: "RLO (right-to-left override)",
    0x2066: "LRI (left-to-right isolate)",
    0x2067: "RLI (right-to-left isolate)",
    0x2068: "FSI (first-strong isolate)",
    0x2069: "PDI (pop directional isolate)",
}

TEXT_EXTENSIONS = {
    ".md", ".py", ".sh", ".bash", ".zsh",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg",
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".rb", ".go", ".rs", ".c", ".h", ".cpp", ".hpp",
    ".java", ".kt", ".swift",
    ".html", ".css", ".scss",
    ".txt", ".rst",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".tox"}


def scan(root: str) -> list[tuple[str, int, int, str]]:
    """Return a list of (path, line, codepoint, label) hits."""
    hits: list[tuple[str, int, int, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext not in TEXT_EXTENSIONS:
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, encoding="utf-8") as fh:
                    content = fh.read()
            except (UnicodeDecodeError, OSError):
                continue
            line = 1
            for ch in content:
                cp = ord(ch)
                if cp in SUSPECT_CODEPOINTS:
                    hits.append((path, line, cp, SUSPECT_CODEPOINTS[cp]))
                if ch == "\n":
                    line += 1
    return hits


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: unicode_scanner.py <directory>", file=sys.stderr)
        return 2
    root = sys.argv[1]
    if not os.path.isdir(root):
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    hits = scan(root)
    if not hits:
        print(f"✓ 0 suspect codepoints across {root}")
        return 0
    print(f"✗ {len(hits)} suspect codepoint(s) found:")
    for path, line, cp, label in hits:
        rel = os.path.relpath(path, root)
        print(f"  {rel}:{line}  U+{cp:04X}  {label}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
