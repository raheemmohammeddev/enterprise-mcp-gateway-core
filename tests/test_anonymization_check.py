"""
Enterprise MCP Gateway - Anonymization Gate Unit Tests.

Tests hashed term matching, every regex category, allow-lists, output format and exit codes.
No forbidden term appears in plaintext here: synthetic terms are used instead.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import anonymization_check as gate
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TERMS_FILE = REPO_ROOT / ".agents" / "anonymization_terms.txt"


def _digest(term: str) -> str:
    return hashlib.sha256(term.encode("utf-8")).hexdigest()


def _categories(text: str) -> list[str]:
    return [f.category for f in gate.scan_text(text, "sample.txt")]


@pytest.fixture
def synthetic_terms(monkeypatch):
    """Replace the real digest sets with synthetic terms: 'qx' (token), 'zzqterm' (substring)."""
    monkeypatch.setattr(gate, "TOKEN_SHA256", frozenset({_digest("qx")}))
    monkeypatch.setattr(gate, "SUBSTRING_SHA256", {7: frozenset({_digest("zzqterm")})})


@pytest.fixture
def no_extras(monkeypatch, tmp_path):
    monkeypatch.setenv("ANONYMIZATION_TERMS_FILE", str(tmp_path / "missing_terms.txt"))


# ======================================================================
# Hashed Term Matching
# ======================================================================

class TestForbiddenTerms:
    def test_whole_word_token_hit(self, synthetic_terms):
        assert _categories("the QX service") == ["forbidden-term"]

    def test_token_not_matched_inside_word(self, synthetic_terms):
        assert _categories("the qxample service") == []

    def test_camel_case_split(self, synthetic_terms):
        assert _categories("mcpQxRules = 1") == ["forbidden-term"]

    def test_acronym_followed_by_word_split(self, synthetic_terms):
        assert _categories("QXRules") == ["forbidden-term"]

    def test_snake_case_split(self, synthetic_terms):
        assert _categories("mcp_qx_rules") == ["forbidden-term"]

    def test_letter_digit_split(self, synthetic_terms):
        assert _categories("qx2026") == ["forbidden-term"]

    def test_substring_hit_inside_identifier(self, synthetic_terms):
        assert _categories("myZZQTERMclient") == ["forbidden-term"]

    def test_substring_not_matched_across_separator(self, synthetic_terms):
        assert _categories("zzq_term") == []

    def test_standard_technology_names_allowed(self, synthetic_terms):
        clean = (
            "The gateway validates JWT against Active Directory and reaches "
            "Neo4j, Teradata, DocumentDB and Redis; secrets use AES-256-GCM."
        )
        assert _categories(clean) == []

    def test_generic_replacement_terms_allowed(self):
        clean = (
            "Enterprise MCP Gateway, Enterprise IdP (Identity Provider), "
            "Business Rule Engine (BRE), Master Reference Data Service and "
            "Enterprise LLM Orchestrator."
        )
        assert _categories(clean) == []

    # The public author attribution is allowed as one exact phrase and nothing wider. These
    # tests build every string from the gate's own constant so no forbidden word is written
    # in plaintext here (this file is itself scanned by the gate).

    def test_public_author_name_allowed(self):
        name = gate.PUBLIC_AUTHOR_NAME
        assert _categories(f"Copyright (c) 2026 {name}") == []
        assert _categories(f"**Author:** {name}") == []
        assert _categories(f'LABEL maintainer="{name}"') == []

    def test_public_author_name_words_alone_still_forbidden(self):
        first, last = gate.PUBLIC_AUTHOR_NAME.split()
        assert _categories(f"Author: {first}") == ["forbidden-term"]
        assert _categories(f"Author: {last}") == ["forbidden-term"]

    def test_public_author_name_is_case_sensitive(self):
        name = gate.PUBLIC_AUTHOR_NAME
        assert _categories(f"Author: {name.lower()}") == ["forbidden-term"]
        assert _categories(f"Author: {name.upper()}") == ["forbidden-term"]

    def test_public_author_name_does_not_mask_other_hits_on_the_line(self):
        name = gate.PUBLIC_AUTHOR_NAME
        first = name.split()[0]
        assert _categories(f"{name} and also {first}") == ["forbidden-term"]

    def test_username_forms_still_forbidden(self):
        first, last = gate.PUBLIC_AUTHOR_NAME.lower().split()
        assert _categories(f"user r{last}") == ["forbidden-term"]
        assert _categories(f"github.com/{first}{last}dev/repo") == ["forbidden-term"]

    def test_public_author_name_does_not_allow_an_email(self):
        name = gate.PUBLIC_AUTHOR_NAME
        at = "@"  # assembled at runtime so no literal address appears in this scanned file
        assert "email" in _categories(f"{name} <someone{at}mail.invalid>")

    def test_extra_terms_short_whole_word(self, synthetic_terms):
        assert gate.scan_text("a ZY b", "f", ["zy"])[0].category == "forbidden-term"
        assert gate.scan_text("lazy", "f", ["zy"]) == []

    def test_extra_terms_long_substring(self, synthetic_terms):
        found = gate.scan_text("prefix-plaintextterm-x", "f", ["PlainTextTerm"])
        assert [f.category for f in found] == ["forbidden-term"]

    def test_real_terms_file_entries_detected(self, tmp_path):
        """Every listed term is caught by the committed digests alone (no plaintext extras)."""
        if not TERMS_FILE.is_file():
            pytest.skip("local terms file not present")
        terms = gate.load_extra_terms(TERMS_FILE)
        assert terms
        sample = tmp_path / "sample.txt"
        sample.write_text("\n".join(f"see {t} here" for t in terms), encoding="utf-8")
        findings = gate.scan_text(sample.read_text(encoding="utf-8"), "sample.txt")
        flagged = {f.line for f in findings}
        assert flagged == set(range(1, len(terms) + 1))


# ======================================================================
# Regex Categories
# ======================================================================

class TestRegexCategories:
    def test_windows_user_path(self):
        sample = "C" + ":" + "\\Users\\" + "jdoe" + "\\file.txt"
        assert _categories(sample) == ["windows-user-path"]

    def test_windows_user_path_forward_slash(self):
        assert _categories("d" + ":/" + "users/" + "jdoe") == ["windows-user-path"]

    def test_posix_user_path(self):
        assert _categories("/home/" + "jdoe/" + "project") == ["posix-user-path"]
        assert _categories("/Users/" + "jdoe/" + "project") == ["posix-user-path"]

    def test_local_workspace_path(self):
        assert _categories("Documents" + "\\" + "MyStuff") == ["local-workspace-path"]

    def test_private_key(self):
        assert _categories("-----BEGIN " + "RSA PRIVATE KEY-----") == ["private-key"]

    def test_email_non_placeholder_flagged(self):
        assert _categories("contact " + "jdoe" + "@" + "acme.test") == ["email"]

    def test_email_placeholder_allowed(self):
        assert _categories("contact jdoe@example.com or ops@mail.example.com") == []

    def test_email_github_noreply_allowed(self):
        assert _categories("12345+jdoe@users.noreply.github.com") == []

    def test_placeholder_account_id_allowed(self):
        assert _categories("arn:aws:kms:us-east-1:123456789012:key/demo") == []

    def test_other_account_id_flagged(self):
        sample = "arn:aws:kms:us-east-1:" + "210987654321" + ":key/demo"
        assert _categories(sample) == ["aws-account-id"]

    def test_ticket_key_flagged(self):
        assert _categories("see " + "ABC" + "-1234") == ["ticket-key"]

    def test_placeholder_ticket_prefixes_allowed(self):
        assert _categories("issue_key='PROJ-123', OTHER-456 and ANY-123") == []

    def test_standard_identifiers_allowed(self):
        assert _categories("AES-256-GCM, SHA-256, RFC-7519 and ISO-8601") == []

    def test_one_finding_per_category_per_line(self):
        sample = ("ABC" + "-1234 ") * 3
        assert _categories(sample) == ["ticket-key"]


# ======================================================================
# Output and Exit Codes
# ======================================================================

class TestMain:
    def test_clean_file_exits_zero(self, tmp_path, no_extras, capsys):
        clean = tmp_path / "clean.md"
        clean.write_text("Enterprise IdP (Identity Provider)\n", encoding="utf-8")
        assert gate.main([str(clean)]) == 0
        assert "0 finding(s)" in capsys.readouterr().out

    def test_dirty_file_reports_path_line_category_only(
        self, tmp_path, no_extras, synthetic_terms, capsys
    ):
        dirty = tmp_path / "dirty.md"
        secret = "zzqterm"
        dirty.write_text(f"line one\nuses {secret} here\n", encoding="utf-8")
        assert gate.main([str(dirty)]) == 1
        out = capsys.readouterr().out
        assert f"{dirty.as_posix()}:2: forbidden-term" in out
        assert secret not in out

    def test_extras_file_used_when_present(self, tmp_path, monkeypatch, capsys):
        extras = tmp_path / "terms.txt"
        extras.write_text("# comment\nzzextraterm\n", encoding="utf-8")
        monkeypatch.setenv("ANONYMIZATION_TERMS_FILE", str(extras))
        target = tmp_path / "doc.txt"
        target.write_text("mentions ZzExtraTerm\n", encoding="utf-8")
        assert gate.main([str(target)]) == 1
        assert "zzextraterm" not in capsys.readouterr().out.lower()

    def test_extras_file_missing_is_not_error(self, tmp_path):
        assert gate.load_extra_terms(tmp_path / "absent.txt") == []

    def test_binary_file_skipped(self, tmp_path, no_extras, synthetic_terms):
        blob = tmp_path / "blob.bin"
        blob.write_bytes(b"\0\1zzqterm")
        assert gate.main([str(blob)]) == 0

    def test_excluded_dirs(self):
        assert gate.is_excluded(".venv/lib/site.py")
        assert gate.is_excluded(".agents/tasks/plan.md")
        assert not gate.is_excluded("scripts/anonymization_check.py")

    def test_repository_is_clean(self, capsys):
        assert gate.main([]) == 0, capsys.readouterr().out
