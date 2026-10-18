"""
Enterprise MCP Gateway - ASCII Gate.

Fails on any byte outside the project ASCII class - 0x09 (tab), 0x0A (LF), 0x0D (CR) and
0x20-0x7E - in tracked and untracked-but-not-ignored text files. 0x7F (DEL) and the other C0
control bytes are findings, not content.
Uses the same file set and exclusions (``.venv/``, ``.git/``, ``.agents/``, binary files with a
NUL in the first 8 KiB) as ``scripts/anonymization_check.py``.

Output is one ``path:line:column: non-ascii`` line per offending line (first offending byte).
The offending character is never printed.

Exit codes: 0 clean, 1 findings, 2 file listing (git) error.

Usage:
    python scripts/ascii_check.py [PATH ...]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from anonymization_check import (  # noqa: E402
    BINARY_SNIFF_BYTES,
    REPO_ROOT,
    is_excluded,
    list_repo_files,
)

# ======================================================================
# Matching
# ======================================================================


def scan_bytes(data: bytes, path: str) -> list[str]:
    """Return one finding per line that contains a byte outside the project ASCII class.

    The permitted class is 0x09, 0x0A, 0x0D and 0x20-0x7E. LF never reaches the inner loop
    because it is the line separator; CR is permitted so CRLF files are not flagged.

    Args:
        data: Raw file contents.
        path: Display path used in the findings.

    Returns:
        Findings formatted as ``path:line:column: non-ascii`` (1-based line and byte column).
    """
    findings: list[str] = []
    for lineno, line in enumerate(data.split(b"\n"), start=1):
        for column, byte in enumerate(line, start=1):
            if byte > 0x7E or (byte < 0x20 and byte not in (0x09, 0x0A, 0x0D)):
                findings.append(f"{path}:{lineno}:{column}: non-ascii")
                break
    return findings


# ======================================================================
# Entry Point
# ======================================================================


def main(argv: Sequence[str] | None = None) -> int:
    """Run the gate.

    Args:
        argv: Command-line arguments (without the program name).

    Returns:
        0 when clean, 1 when findings exist, 2 when the file list cannot be obtained.
    """
    parser = argparse.ArgumentParser(description="Repository ASCII-only gate.")
    parser.add_argument("paths", nargs="*", help="files to scan (default: whole repository)")
    args = parser.parse_args(argv)

    if args.paths:
        base = Path.cwd()
        candidates = list(args.paths)
    else:
        base = REPO_ROOT
        try:
            candidates = list_repo_files(REPO_ROOT)
        except (OSError, subprocess.CalledProcessError) as exc:
            print(f"ascii_check: cannot list files ({type(exc).__name__})", file=sys.stderr)
            return 2

    findings: list[str] = []
    scanned = 0
    for candidate in candidates:
        if is_excluded(candidate):
            continue
        file_path = base / candidate
        if not file_path.is_file():
            continue
        data = file_path.read_bytes()
        if b"\0" in data[:BINARY_SNIFF_BYTES]:
            continue
        scanned += 1
        findings.extend(scan_bytes(data, Path(candidate).as_posix()))

    for finding in findings:
        print(finding)
    print(f"ascii_check: {len(findings)} finding(s) in {scanned} file(s) scanned")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
