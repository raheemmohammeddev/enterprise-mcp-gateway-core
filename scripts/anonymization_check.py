"""
Enterprise MCP Gateway - Anonymization Gate.

Scans every tracked and untracked-but-not-ignored text file in the repository for material
that must never be published: local filesystem paths, non-placeholder email addresses, real
AWS account IDs, private keys, issue-tracker ticket keys and a list of forbidden internal terms.

Forbidden terms are stored as SHA-256 hex digests of their lowercase form. Hashing keeps the
literal terms out of the repository text, so the gate can itself be committed and scanned. It is
NOT secrecy: short terms are trivially recoverable by brute force, and anyone holding the
plaintext list can confirm a guess.

Matching rules:
1. Whole-word (``TOKEN_SHA256``): text is split into alphanumeric runs, and each run is further
   split at camelCase and letter/digit boundaries (``_`` already separates runs). A run or
   sub-token whose digest is listed is a hit. Used for short acronyms that would otherwise match
   inside ordinary words.
2. Substring (``SUBSTRING_SHA256``): for each listed length L, every L-character window of every
   lowercase alphanumeric run is hashed and compared. Used for terms of length >= 5.
3. Optional plaintext extras: ``ANONYMIZATION_TERMS_FILE`` (default
   ``.agents/anonymization_terms.txt``, gitignored), one term per line, ``#`` comments,
   case-insensitive. Terms of 4 characters or fewer match whole-word; longer terms match as
   substrings of the lowercase line. A missing file is not an error.

Standard technology names (JWT, Active Directory, Neo4j, Teradata, DocumentDB, Redis,
AES-256-GCM, Kiro IDE, MCP and AWS service names) are never forbidden.

Output is one ``path:line: <category>`` line per finding. The matched text is never printed.

Exit codes: 0 clean, 1 findings, 2 file listing (git) error.

Usage:
    python scripts/anonymization_check.py [--identity] [PATH ...]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

# ======================================================================
# Configuration
# ======================================================================

REPO_ROOT = Path(__file__).resolve().parent.parent
EXCLUDED_DIRS = frozenset({".venv", ".git", ".agents"})
BINARY_SNIFF_BYTES = 8192
DEFAULT_TERMS_FILE = ".agents/anonymization_terms.txt"
SHORT_TERM_MAX_LEN = 4

# SHA-256 hex digests of lowercase forbidden terms (whole-word matching).
TOKEN_SHA256: frozenset[str] = frozenset({
    "a5d95459b53438cac1967b865251d191269d3aef7f87f654c79666ac1ff099f7",
    "7c78b3359add0493a2f205d2d13210d3a5bbd223e60ee59b4873f097aa9bd7b5",
    "16659d7e3451962529bf1177b4821f29054ab07906df8068fe044b4f100cab52",
    "9d3aeeb68d2792415d18ddf3058dc055c6b0ebbd6ea28959bb4184896a0948ad",
})

# SHA-256 hex digests of lowercase forbidden terms keyed by term length (substring matching).
SUBSTRING_SHA256: dict[int, frozenset[str]] = {
    5: frozenset({"c886ff11f6a51b611a867475e31b1e8d22a8c1eb99cec8a57c83a32164f083e0"}),
    6: frozenset({
        "7651812ab527db166e88cf62b0cfcb96ee8748b618740f6f6d339e25ceeb4379",
        "d50f722c78fceb3161241ed23d235c54c1f0bcb23d745fa3c70d5127445a4202",
    }),
    7: frozenset({"8399e57405627368722830c9ff3db81fba0afa6120a439c7a2568a5be31b8295"}),
    8: frozenset({
        "1fd6202c9bb335c65040575f892b4b9269651729adf08036bf11bc4694d9421d",
        "863498dfa3f35f634f532b3cab89b0f8b6baaf9a2a94722c52ca2ef44377efc2",
    }),
    9: frozenset({"c508cd816ef8a28f4647c7d6f76b81fd3eeb0d786ed17206017696b53e08d84b"}),
    11: frozenset({"527d6b922a54616cb81bcbf9a66132b7590d961c066a55b2d57e0d6dba3cba3e"}),
    17: frozenset({"34fd64366be959278cac26ce203921a3245f8279e9614863dccbd72cfe8a7705"}),
}

ALLOWED_EMAIL_DOMAINS = frozenset({"example.com", "users.noreply.github.com"})
# The canonical documentation placeholder account ID only. A real account ID must never be
# added here; use the <ACCOUNT_ID> placeholder in docs and templates instead.
ALLOWED_ACCOUNT_IDS = frozenset({"123456789012"})

# Standard identifiers that look like ticket keys. Extend only with public standard names.
ALLOWED_TICKET_KEYS = frozenset({
    "AES-256",
    "SHA-256",
    "RFC-7519",
    "ISO-8601",
    "UTF-8",
    "X-Amz",
})

# Project prefixes reserved for documentation and test placeholders, never real trackers.
ALLOWED_TICKET_PREFIXES = frozenset({"PROJ", "DEMO", "TEST", "EXAMPLE", "ANY", "OTHER"})

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("windows-user-path", re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+", re.IGNORECASE)),
    ("posix-user-path", re.compile(r"/(home|Users)/[a-z][\w.-]+/")),
    ("local-workspace-path", re.compile(r"Documents[\\/]+My[A-Z]\w+")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)
EMAIL_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
ARN_ACCOUNT_RE = re.compile(r"arn:aws[\w-]*:[\w-]+:[\w-]*:(\d{12}):")
TICKET_KEY_RE = re.compile(r"\b[A-Z]{2,6}-\d{3,5}\b")
RUN_RE = re.compile(r"[A-Za-z0-9]+")
LOWER_RUN_RE = re.compile(r"[a-z0-9]+")
SUBTOKEN_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")


# ======================================================================
# Data Model
# ======================================================================

@dataclass(frozen=True)
class Finding:
    """One gate hit. The matched text is deliberately not stored."""

    path: str
    line: int
    category: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.category}"


# ======================================================================
# Matching
# ======================================================================

def _sha256(term: str) -> str:
    return hashlib.sha256(term.encode("utf-8")).hexdigest()


def email_allowed(address_or_domain: str) -> bool:
    """Return True if the email address (or bare domain) uses a placeholder domain.

    Args:
        address_or_domain: ``user@domain`` or ``domain``.

    Returns:
        True for ``example.com``, any ``*.example.com`` and ``users.noreply.github.com``.
    """
    domain = address_or_domain.rsplit("@", 1)[-1].strip().lower()
    return domain in ALLOWED_EMAIL_DOMAINS or domain.endswith(".example.com")


def _ticket_key_allowed(key: str) -> bool:
    """Return True for public standard identifiers and placeholder project keys.

    Args:
        key: A token matching ``TICKET_KEY_RE`` (letters, hyphen, digits).

    Returns:
        True when the token is a standard identifier or uses a reserved
        placeholder project prefix, False when it looks like a real ticket.
    """
    return key in ALLOWED_TICKET_KEYS or key.split("-", 1)[0] in ALLOWED_TICKET_PREFIXES


def _split_extras(extra_terms: Iterable[str]) -> tuple[frozenset[str], tuple[str, ...]]:
    terms = [t.strip().lower() for t in extra_terms if t.strip()]
    short = frozenset(t for t in terms if len(t) <= SHORT_TERM_MAX_LEN)
    long = tuple(t for t in terms if len(t) > SHORT_TERM_MAX_LEN)
    return short, long


def _has_forbidden_term(
    line: str, short_extras: frozenset[str], long_extras: tuple[str, ...]
) -> bool:
    for run in RUN_RE.findall(line):
        candidates = {run.lower(), *(sub.lower() for sub in SUBTOKEN_RE.findall(run))}
        for token in candidates:
            if token in short_extras or _sha256(token) in TOKEN_SHA256:
                return True
    lower = line.lower()
    if SUBSTRING_SHA256:
        for run in LOWER_RUN_RE.findall(lower):
            for length, digests in SUBSTRING_SHA256.items():
                for start in range(len(run) - length + 1):
                    if _sha256(run[start:start + length]) in digests:
                        return True
    return any(term in lower for term in long_extras)


def _line_categories(
    line: str, short_extras: frozenset[str], long_extras: tuple[str, ...]
) -> list[str]:
    categories: list[str] = []
    for category, pattern in PATTERNS:
        if pattern.search(line):
            categories.append(category)
    if any(not email_allowed(m.group(1)) for m in EMAIL_RE.finditer(line)):
        categories.append("email")
    if any(m.group(1) not in ALLOWED_ACCOUNT_IDS for m in ARN_ACCOUNT_RE.finditer(line)):
        categories.append("aws-account-id")
    if any(not _ticket_key_allowed(m.group(0)) for m in TICKET_KEY_RE.finditer(line)):
        categories.append("ticket-key")
    if _has_forbidden_term(line, short_extras, long_extras):
        categories.append("forbidden-term")
    return categories


def scan_text(text: str, path: str, extra_terms: Sequence[str] = ()) -> list[Finding]:
    """Scan one text blob and return its findings (at most one per category per line).

    Args:
        text: File contents.
        path: Display path used in the findings.
        extra_terms: Optional plaintext forbidden terms (case-insensitive).

    Returns:
        Findings in line order.
    """
    short_extras, long_extras = _split_extras(extra_terms)
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for category in _line_categories(line, short_extras, long_extras):
            findings.append(Finding(path, lineno, category))
    return findings


# ======================================================================
# File Discovery
# ======================================================================

def list_repo_files(root: Path) -> list[str]:
    """List tracked plus untracked-but-not-ignored files (works before the first commit)."""
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        capture_output=True,
        check=True,
    )
    return [p for p in result.stdout.decode("utf-8").split("\0") if p]


def is_excluded(path: str) -> bool:
    """Return True for paths under ``.venv/``, ``.git/`` or ``.agents/``."""
    parts = Path(path).parts
    return any(part in EXCLUDED_DIRS for part in parts)


def read_text_file(path: Path) -> str | None:
    """Return the decoded file text, or None for binary (NUL in the first 8 KiB) files."""
    data = path.read_bytes()
    if b"\0" in data[:BINARY_SNIFF_BYTES]:
        return None
    return data.decode("utf-8", errors="replace")


def load_extra_terms(terms_file: Path) -> list[str]:
    """Load optional plaintext terms; a missing file yields an empty list."""
    if not terms_file.is_file():
        return []
    terms: list[str] = []
    for raw in terms_file.read_text(encoding="utf-8").splitlines():
        term = raw.strip()
        if term and not term.startswith("#"):
            terms.append(term.lower())
    return terms


def _terms_file() -> Path:
    configured = Path(os.getenv("ANONYMIZATION_TERMS_FILE", DEFAULT_TERMS_FILE))
    return configured if configured.is_absolute() else REPO_ROOT / configured


# ======================================================================
# Git Identity (read-only)
# ======================================================================

def check_identity(root: Path) -> list[Finding]:
    """Check ``git config user.email`` and commit author emails without printing them."""
    addresses: list[str] = []
    for command in (["git", "config", "user.email"], ["git", "log", "--format=%ae"]):
        result = subprocess.run(command, cwd=root, capture_output=True, text=True)
        if result.returncode == 0:
            addresses.extend(a.strip() for a in result.stdout.splitlines() if a.strip())
    if any(not email_allowed(address) for address in addresses):
        return [Finding("git-metadata", 0, "git-identity")]
    return []


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
    parser = argparse.ArgumentParser(description="Repository anonymization gate.")
    parser.add_argument(
        "--identity",
        action="store_true",
        help="also check git user.email and commit author emails (read-only)",
    )
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
            print(f"anonymization_check: cannot list files ({type(exc).__name__})", file=sys.stderr)
            return 2

    extra_terms = load_extra_terms(_terms_file())
    findings: list[Finding] = []
    scanned = 0
    for candidate in candidates:
        if is_excluded(candidate):
            continue
        file_path = base / candidate
        if not file_path.is_file():
            continue
        text = read_text_file(file_path)
        if text is None:
            continue
        scanned += 1
        findings.extend(scan_text(text, Path(candidate).as_posix(), extra_terms))

    if args.identity:
        findings.extend(check_identity(REPO_ROOT))

    for finding in findings:
        print(finding)
    print(f"anonymization_check: {len(findings)} finding(s) in {scanned} file(s) scanned")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
