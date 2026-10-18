"""
Enterprise MCP Gateway - ASCII Gate Unit Tests.

Non-ASCII sample data is built at runtime with escapes; this file itself stays ASCII-only.
"""

from __future__ import annotations

import ascii_check as gate

EM_DASH = "\u2014"
GRINNING_FACE = "\U0001F600"


class TestScanBytes:
    def test_ascii_clean(self):
        assert gate.scan_bytes(b"plain text\nline two\n", "a.txt") == []

    def test_reports_line_and_column(self):
        data = f"ok\nab{EM_DASH}cd\n".encode()
        assert gate.scan_bytes(data, "a.md") == ["a.md:2:3: non-ascii"]

    def test_one_finding_per_line(self):
        data = f"{EM_DASH}{EM_DASH} {GRINNING_FACE}\n".encode()
        assert gate.scan_bytes(data, "a.md") == ["a.md:1:1: non-ascii"]

    def test_latin1_byte_detected(self):
        assert gate.scan_bytes(b"caf\xe9", "a.txt") == ["a.txt:1:4: non-ascii"]

    def test_del_byte_detected(self):
        assert gate.scan_bytes(b"ab\x7fcd", "a.txt") == ["a.txt:1:3: non-ascii"]

    def test_control_byte_detected(self):
        assert gate.scan_bytes(b"ab\x0ccd", "a.txt") == ["a.txt:1:3: non-ascii"]

    def test_tab_and_carriage_return_allowed(self):
        assert gate.scan_bytes(b"a\tb\r\nc\td\r\n", "a.txt") == []

    def test_output_omits_offending_character(self):
        finding = gate.scan_bytes(GRINNING_FACE.encode(), "a.txt")[0]
        assert GRINNING_FACE not in finding


class TestMain:
    def test_exit_zero_on_clean_file(self, tmp_path, monkeypatch, capsys):
        (tmp_path / "clean.txt").write_bytes(b"hello\n")
        monkeypatch.chdir(tmp_path)
        assert gate.main(["clean.txt"]) == 0
        assert "0 finding(s) in 1 file(s)" in capsys.readouterr().out

    def test_exit_one_on_non_ascii(self, tmp_path, monkeypatch, capsys):
        (tmp_path / "dirty.md").write_bytes(f"x {EM_DASH} y\n".encode())
        monkeypatch.chdir(tmp_path)
        assert gate.main(["dirty.md"]) == 1
        out = capsys.readouterr().out
        assert "dirty.md:1:3: non-ascii" in out
        assert EM_DASH not in out

    def test_binary_and_excluded_files_skipped(self, tmp_path, monkeypatch, capsys):
        (tmp_path / "blob.bin").write_bytes(b"\0\xff\xfe")
        (tmp_path / ".agents").mkdir()
        (tmp_path / ".agents" / "note.md").write_bytes(EM_DASH.encode())
        monkeypatch.chdir(tmp_path)
        assert gate.main(["blob.bin", ".agents/note.md"]) == 0
        assert "0 finding(s) in 0 file(s)" in capsys.readouterr().out

    def test_repository_is_ascii_only(self, capsys):
        assert gate.main([]) == 0, capsys.readouterr().out
