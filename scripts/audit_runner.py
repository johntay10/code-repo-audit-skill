"""Behavioral sandbox for any Python-based skill, package, or script.

Monkey-patches urlopen, socket.create_connection, and subprocess.* at the
Python module layer so every outbound call is LOGGED and BLOCKED before it
fires. Also installs sys.addaudithook to catch file opens against a sensitive-
path allowlist plus raw socket activity.

USAGE:
    python3 audit_runner.py --target-script /path/to/entry.py [-- args for target]

Example:
    python3 audit_runner.py --target-script /tmp/some-skill/main.py -- --diagnose
    python3 audit_runner.py --target-script /tmp/some-skill/main.py -- "test topic" --quick

The audit log is printed to stderr; the target's stdout is preserved so you
can pipe the audit output to a file independently of the target's output.

CAVEAT: These intercepts work at the Python module boundary. Code that calls
libc directly via ctypes, or uses raw os.write() against a pre-opened socket
fd, would bypass them. For kernel-level isolation use Docker with
`--network none` and a read-only volume mount.
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any

LOG: list[str] = []


def _log(category: str, target: str, source: str = "") -> None:
    line = f"[{category}] {target}"
    if source:
        line += f"  <- {source}"
    LOG.append(line)
    print(line, file=sys.stderr)


# --- urllib.request hooks ---

_real_urlopen = urllib.request.urlopen


def fake_urlopen(req, *args, **kwargs):
    if hasattr(req, "full_url"):
        url = req.full_url
    elif hasattr(req, "get_full_url"):
        url = req.get_full_url()
    else:
        url = str(req)
    _log("HTTP", url)
    raise urllib.error.URLError("audit-mode: network blocked")


urllib.request.urlopen = fake_urlopen


# --- socket hooks ---

_real_create_connection = socket.create_connection


def fake_create_connection(address, *args, **kwargs):
    host = f"{address[0]}:{address[1]}" if isinstance(address, tuple) else str(address)
    _log("SOCKET", host)
    raise OSError("audit-mode: socket blocked")


socket.create_connection = fake_create_connection


# --- subprocess hooks ---

_real_popen = subprocess.Popen
_real_run = subprocess.run


def _fmt_cmd(args: Any) -> str:
    if isinstance(args, (list, tuple)):
        return " ".join(str(a) for a in args)
    return str(args)


def fake_popen(args, *a, **kw):
    _log("SUBPROCESS-POPEN", _fmt_cmd(args))
    raise OSError("audit-mode: subprocess blocked")


def fake_run(args, *a, **kw):
    _log("SUBPROCESS-RUN", _fmt_cmd(args))
    raise OSError("audit-mode: subprocess blocked")


subprocess.Popen = fake_popen
subprocess.run = fake_run


# --- Python audit hook for anything else ---

HOME = os.path.expanduser("~")
SENSITIVE_PATHS = (
    f"{HOME}/.ssh",
    f"{HOME}/.aws",
    f"{HOME}/.gitconfig",
    f"{HOME}/.netrc",
    f"{HOME}/.zshrc",
    f"{HOME}/.bashrc",
    f"{HOME}/.zshenv",
    f"{HOME}/.bash_profile",
    f"{HOME}/Library/Cookies",
    f"{HOME}/Library/Keychains",
    f"{HOME}/Library/Application Support/Google/Chrome/Default/Cookies",
    f"{HOME}/Library/Application Support/Firefox",
    f"{HOME}/Library/Safari",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
)


def audit_hook(event, args):
    if event == "open" and args:
        path = str(args[0])
        if any(path.startswith(p) for p in SENSITIVE_PATHS):
            _log("SENSITIVE-OPEN", path)
    elif event in ("socket.connect", "socket.bind"):
        _log(f"AUDIT-{event}", str(args))


sys.addaudithook(audit_hook)


# --- CLI argument parsing ---

def _split_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split argv at `--` separator: ours-args, target-args."""
    if "--" in argv:
        idx = argv.index("--")
        return argv[:idx], argv[idx + 1:]
    return argv, []


def main() -> int:
    ours_argv, target_argv = _split_argv(sys.argv[1:])

    parser = argparse.ArgumentParser(
        description="Behavioral sandbox: run a Python script with network and subprocess blocked + logged.",
    )
    parser.add_argument(
        "--target-script",
        required=True,
        help="Path to the Python entry point to run inside the sandbox.",
    )
    parser.add_argument(
        "--cwd",
        default=None,
        help="Working directory for the target (default: target script's directory).",
    )
    parser.add_argument(
        "--clean-env-var",
        action="append",
        default=[],
        help="Env var to clear before running (repeatable). E.g. --clean-env-var FOO_API_KEY",
    )
    args = parser.parse_args(ours_argv)

    target = os.path.abspath(args.target_script)
    if not os.path.isfile(target):
        print(f"[AUDIT] target script not found: {target}", file=sys.stderr)
        return 2

    target_dir = args.cwd or os.path.dirname(target)
    sys.path.insert(0, target_dir)
    if os.path.isdir(target_dir):
        os.chdir(target_dir)

    for var in args.clean_env_var:
        os.environ.pop(var, None)

    sys.argv = [target] + target_argv

    print(f"[AUDIT] hooks installed. Running: {target}", file=sys.stderr)
    print(f"[AUDIT] target argv: {sys.argv}", file=sys.stderr)
    print(f"[AUDIT] cwd: {os.getcwd()}", file=sys.stderr)

    try:
        with open(target) as fh:
            code = compile(fh.read(), target, "exec")
        g = {"__name__": "__main__", "__file__": target}
        exec(code, g)
        exit_code = 0
    except SystemExit as e:
        exit_code = e.code if isinstance(e.code, int) else 0
        print(f"\n[AUDIT] target exited with code {exit_code}", file=sys.stderr)
    except Exception as e:
        exit_code = 1
        print(f"\n[AUDIT] target raised: {type(e).__name__}: {e}", file=sys.stderr)
    finally:
        print(f"\n[AUDIT] === {len(LOG)} OUTBOUND/SUBPROCESS/SENSITIVE EVENTS ===", file=sys.stderr)
        if LOG:
            for line in LOG:
                print(f"  {line}", file=sys.stderr)
        else:
            print("  (none — target made zero outbound attempts in this run)", file=sys.stderr)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
