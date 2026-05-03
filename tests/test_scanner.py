"""
test_scanner.py - Tests for the file-handling layer:
file iteration, exclusions, per-file scanning, and the Finding dataclass.
"""

import pytest
from pathlib import Path

from secret_scanner import (
    iter_files,
    scan_file,
    Finding,
    PATTERNS,
    DEFAULT_EXCLUDED_DIRS,
    DEFAULT_BINARY_EXTS,
    MAX_FILE_BYTES,
)


# A real-looking-but-fake GitHub token used throughout the tests.
FAKE_GH_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"


# iter_files
def test_iter_files_yields_single_file_when_given_a_file(tmp_path):
    f = tmp_path / "lonely.py"
    f.write_text("# hello\n")
    result = list(iter_files(f, DEFAULT_EXCLUDED_DIRS, DEFAULT_BINARY_EXTS))
    assert result == [f]


def test_iter_files_walks_nested_directories(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b").mkdir()
    (tmp_path / "a" / "b" / "deep.py").write_text("# deep\n")
    (tmp_path / "top.py").write_text("# top\n")

    found = {p.name for p in iter_files(tmp_path, DEFAULT_EXCLUDED_DIRS, DEFAULT_BINARY_EXTS)}
    assert found == {"deep.py", "top.py"}


def test_iter_files_skips_excluded_dirs(tmp_path):
    # Drop a "secret" inside an excluded dir; it should be ignored.
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "leaked.py").write_text(f'TOKEN = "{FAKE_GH_TOKEN}"\n')
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "ok.py").write_text("# clean\n")

    found = list(iter_files(tmp_path, DEFAULT_EXCLUDED_DIRS, DEFAULT_BINARY_EXTS))
    assert any(p.name == "ok.py" for p in found)
    assert not any(".git" in p.parts for p in found)


def test_iter_files_skips_binary_extensions(tmp_path):
    (tmp_path / "image.png").write_bytes(b"\x89PNG fake content")
    (tmp_path / "code.py").write_text("# code\n")

    names = {p.name for p in iter_files(tmp_path, DEFAULT_EXCLUDED_DIRS, DEFAULT_BINARY_EXTS)}
    assert names == {"code.py"}


def test_iter_files_skips_files_over_size_limit(tmp_path):
    big = tmp_path / "huge.txt"
    # MAX_FILE_BYTES + 1 - just over the limit. Use seek/truncate to avoid
    # actually writing megabytes of bytes to disk.
    with big.open("wb") as f:
        f.seek(MAX_FILE_BYTES + 1)
        f.write(b"\0")
    small = tmp_path / "small.txt"
    small.write_text("hello\n")

    names = {p.name for p in iter_files(tmp_path, DEFAULT_EXCLUDED_DIRS, DEFAULT_BINARY_EXTS)}
    assert names == {"small.txt"}


def test_iter_files_respects_custom_excluded_dir(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text("# vendored\n")
    (tmp_path / "src.py").write_text("# main\n")

    custom_excluded = DEFAULT_EXCLUDED_DIRS | {"vendor"}
    names = {p.name for p in iter_files(tmp_path, custom_excluded, DEFAULT_BINARY_EXTS)}
    assert names == {"src.py"}


# scan_file
def test_scan_file_finds_planted_secret(tmp_path):
    f = tmp_path / "config.py"
    f.write_text(f'TOKEN = "{FAKE_GH_TOKEN}"\n')

    findings = scan_file(f, PATTERNS)
    assert any(x.pattern_name == "GitHub Personal Access Token" for x in findings)


def test_scan_file_clean_file_returns_empty(tmp_path):
    f = tmp_path / "ok.py"
    f.write_text('def add(a, b):\n    return a + b\n')

    findings = scan_file(f, PATTERNS)
    assert findings == []


def test_scan_file_records_correct_line_number(tmp_path):
    f = tmp_path / "config.py"
    f.write_text(
        "# line 1\n"
        "# line 2\n"
        f'TOKEN = "{FAKE_GH_TOKEN}"\n'
    )

    findings = scan_file(f, PATTERNS)
    matches = [x for x in findings if x.pattern_name == "GitHub Personal Access Token"]
    assert len(matches) == 1
    assert matches[0].line_number == 3


def test_scan_file_captures_only_secret_value_for_grouped_patterns(tmp_path):
    """
    The "Generic Secret Assignment" pattern uses secret_group=2, so the
    matched_text should be just the value inside the quotes - not the
    variable name and operator.
    """
    f = tmp_path / "x.py"
    f.write_text('password = "supersecretpasswordhere"\n')

    findings = scan_file(f, PATTERNS)
    generic = [x for x in findings if x.pattern_name == "Generic Secret Assignment"]
    assert generic, "Generic Secret Assignment pattern did not fire"
    assert generic[0].matched_text == "supersecretpasswordhere"
    # The full source line is preserved separately for context
    assert "password" in generic[0].line_preview


def test_scan_file_handles_multiple_findings_in_one_file(tmp_path):
    f = tmp_path / "leaky.py"
    f.write_text(
        f'TOKEN = "{FAKE_GH_TOKEN}"\n'
        'AWS = "AKIAIOSFODNN7EXAMPLE"\n'
    )

    findings = scan_file(f, PATTERNS)
    pattern_names = {x.pattern_name for x in findings}
    assert "GitHub Personal Access Token" in pattern_names
    assert "AWS Access Key ID" in pattern_names


def test_scan_file_handles_non_utf8_bytes_gracefully(tmp_path):
    """
    The scanner opens files with errors='ignore' so a stray non-UTF-8 byte
    shouldn't crash. A planted secret in the same file should still be found.
    """
    f = tmp_path / "mixed.py"
    f.write_bytes(b'# stray byte: \xff\n' + f'TOKEN = "{FAKE_GH_TOKEN}"\n'.encode())

    findings = scan_file(f, PATTERNS)
    assert any(x.pattern_name == "GitHub Personal Access Token" for x in findings)


# Finding.redacted

def _make_finding(matched: str) -> Finding:
    return Finding(
        file="x.py",
        line_number=1,
        pattern_name="test",
        matched_text=matched,
        line_preview="",
    )


def test_redacted_short_string():
    # Anything 8 chars or shorter shows the first char and stars the rest
    f = _make_finding("abcd")
    assert f.redacted() == "a***"


def test_redacted_long_string_keeps_first_and_last_4():
    f = _make_finding("ghp_abcdefghijklmnop")
    r = f.redacted()
    assert r.startswith("ghp_")
    assert r.endswith("mnop")
    # Same length as original - masking should not change the length
    assert len(r) == len("ghp_abcdefghijklmnop")
    # Middle is fully starred
    assert set(r[4:-4]) == {"*"}


def test_redacted_empty_string():
    f = _make_finding("")
    # Should not raise and should return something sensible
    assert f.redacted() == ""
