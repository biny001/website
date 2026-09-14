#!/usr/bin/env python3
"""Supply-chain gate: fail the build when the repository carries an injected loader.

Born from the August / September 2026 incidents: an attacker with a stolen GitHub credential
re-pushed existing commits with one Node-loaded config file rewritten (postcss, tailwind, vite,
eslint, babel, metro, astro configs, .npmrc). The payload hides after a wall of whitespace and
runs during install, build or lint. This script only READS files, so it is safe to run on an
infected checkout. No dependencies beyond the Python 3 standard library.

Exit 1 on any finding (deploy must not proceed), exit 0 when clean.
"""

import os
import re
import sys
from datetime import datetime, timezone

MAX_BYTES = 2_000_000
SKIP_DIRS = {".git", "node_modules", ".next", "dist", "build", "out", ".turbo", ".vercel", "coverage", ".venv", "venv", "__pycache__"}
CODE_EXT = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".json", ".yml", ".yaml", ".toml", ".sh", ".ps1", ".bat", ".py"}
CONFIG_NAMES = re.compile(
    r"^(postcss|tailwind|vite|vitest|next|eslint|babel|metro|astro|webpack|rollup|nuxt|svelte|remix|jest|playwright|prettier|tsup|turbo)\."
    r"config\.(m?[cj]s|ts|json)$|^\.npmrc$|^\.yarnrc(\.yml)?$|^package\.json$",
    re.I,
)

# Known markers of the loader family (any hit is a hard fail).
# Patterns are assembled at runtime so this file never contains them literally (it must not flag itself
# or any verbatim copy of itself).
_J = "".join
MARKERS = [
    (_J(["A8-", "3117-3"]), "incident marker (Aug/Sep 2026 loader)"),
    (_J(["global.i", " = '"]), "loader bootstrap (global.i marker)"),
    (_J(["eth.block", "scout.com"]), "blockchain dead-drop indexer"),
    (_J(["0xa322e5f3d311d3080", "e6f0121063e9adc2490ef1a"]), "known dead-drop sender address"),
    (_J(["X-Payload", "-B64"]), "payload header used by the loader"),
    (_J(["run_", "loader("]), "loader function name"),
]
STRONG_COMBOS = [
    (_J(["spa", "wn("]), _J(["detached", ":!0"])),   # spawns a detached child
    (_J(["ev", "al("]), _J(["get", "Code("])),        # evals fetched code
]
SELF = os.path.abspath(__file__)
# Whitespace injector: a run of 200+ tabs/spaces followed by code on the same line.
INJECTOR = re.compile(r"[ \t]{200,}\S")
# Very long single lines in a config file are not normal for hand-written configs.
LONG_LINE = 4000


def iter_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if os.path.abspath(path) == SELF:
                continue
            ext = os.path.splitext(fn)[1].lower()
            is_config = bool(CONFIG_NAMES.match(fn))
            if ext in CODE_EXT or is_config:
                try:
                    if os.path.getsize(path) > MAX_BYTES:
                        continue
                except OSError:
                    continue
                yield path, is_config


def scan_file(path: str, is_config: bool) -> list[str]:
    findings: list[str] = []
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return findings
    text = raw.decode("utf-8", "replace")
    low = text.lower()
    for marker, label in MARKERS:
        if label and marker.lower() in low:
            findings.append(f"ioc-marker: {label} ({marker})")
    for a, b in STRONG_COMBOS:
        if a in text and b in text:
            findings.append(f"ioc-behaviour: {a!r} together with {b!r}")
    for i, line in enumerate(text.splitlines(), 1):
        if INJECTOR.search(line):
            findings.append(f"ioc-injector: 200+ whitespace characters followed by code (line {i})")
            break
    if is_config:
        longest = max((len(l) for l in text.splitlines()), default=0)
        if longest > LONG_LINE:
            findings.append(f"ioc-config-shape: {longest}-character line in a config file")
        if "\x00" in text:
            findings.append("ioc-config-shape: NUL byte in a text config")
    return findings


def check_commit_dates() -> list[str]:
    """Warning only: the loader re-pushes old commits, so author date << committer date."""
    a, c = os.getenv("GATE_AUTHOR_TS"), os.getenv("GATE_COMMITTER_TS")
    if not (a and c):
        return []
    try:
        gap = int(c) - int(a)
    except ValueError:
        return []
    if gap > 3 * 86400:
        return [f"warn-history: commit author date is {gap // 86400} days older than its committer date (rewritten commit?)"]
    return []


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    failures: list[tuple[str, str]] = []
    scanned = 0
    for path, is_config in iter_files(root):
        scanned += 1
        for f in scan_file(path, is_config):
            failures.append((os.path.relpath(path, root), f))
    warnings = check_commit_dates()
    print(f"supply-chain gate: scanned {scanned} files at {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    for w in warnings:
        print(f"  WARN  {w}")
    if failures:
        print(f"\nBLOCKED: {len(failures)} finding(s). Do not deploy this commit.")
        for path, f in failures:
            print(f"  FAIL  {path}: {f}")
        print("\nRestore the branch from a known-clean commit and rotate credentials. See INCIDENT notes.")
        return 1
    print("  OK    no injected loader, no known markers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
