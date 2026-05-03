"""
test_cli.py - End-to-end tests of the CLI via the `main()` entry point.

You invoke main() directly with an argv list rather than spawning a subprocess.
This is faster and lets you use pytest's capsys fixture to capture stdout.
"""

import json
import pytest

from secret_scanner import main


FAKE_GH_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"


# Exit codes
def test_clean_directory_exits_zero(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("print('hi')\n")
    rc = main([str(tmp_path)])
    assert rc == 0


def test_dirty_directory_exits_one(tmp_path, capsys):
    (tmp_path / "leaky.py").write_text(f'TOKEN = "{FAKE_GH_TOKEN}"\n')
    rc = main([str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "GitHub Personal Access Token" in out


def test_nonexistent_path_exits_two(tmp_path):
    missing = tmp_path / "does_not_exist"
    rc = main([str(missing)])
    assert rc == 2


# Output formats
def test_text_output_contains_file_and_line(tmp_path, capsys):
    f = tmp_path / "leaky.py"
    f.write_text(f'TOKEN = "{FAKE_GH_TOKEN}"\n')

    main([str(tmp_path)])
    out = capsys.readouterr().out

    assert str(f) in out
    assert "Line:" in out
    assert "GitHub Personal Access Token" in out


def test_json_output_is_valid_and_well_shaped(tmp_path, capsys):
    f = tmp_path / "leaky.py"
    f.write_text(f'TOKEN = "{FAKE_GH_TOKEN}"\n')

    rc = main([str(tmp_path), "--json"])
    out = capsys.readouterr().out

    assert rc == 1
    parsed = json.loads(out)
    assert isinstance(parsed, list)
    assert len(parsed) >= 1

    # Every record should have these fields
    expected_fields = {"file", "line_number", "pattern_name", "matched_text", "line_preview"}
    for record in parsed:
        assert expected_fields.issubset(record.keys())


def test_json_output_on_clean_dir_is_empty_list(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("print('hi')\n")
    rc = main([str(tmp_path), "--json"])
    out = capsys.readouterr().out

    assert rc == 0
    assert json.loads(out) == []


# Redaction
def test_default_output_is_redacted(tmp_path, capsys):
    (tmp_path / "leaky.py").write_text(f'TOKEN = "{FAKE_GH_TOKEN}"\n')
    main([str(tmp_path)])
    out = capsys.readouterr().out

    # Full token should NOT appear
    assert FAKE_GH_TOKEN not in out
    # But the prefix and suffix should - and there should be stars between
    assert "ghp_" in out
    assert "*" in out


def test_show_full_includes_unredacted_secret(tmp_path, capsys):
    (tmp_path / "leaky.py").write_text(f'TOKEN = "{FAKE_GH_TOKEN}"\n')
    main([str(tmp_path), "--show-full"])
    out = capsys.readouterr().out

    assert FAKE_GH_TOKEN in out


# File output
def test_output_to_file_writes_report(tmp_path):
    (tmp_path / "leaky.py").write_text(f'TOKEN = "{FAKE_GH_TOKEN}"\n')
    out_file = tmp_path / "report.txt"

    rc = main([str(tmp_path), "-o", str(out_file)])

    assert rc == 1
    assert out_file.exists()
    contents = out_file.read_text()
    assert "GitHub Personal Access Token" in contents


def test_output_file_with_json_flag(tmp_path):
    (tmp_path / "leaky.py").write_text(f'TOKEN = "{FAKE_GH_TOKEN}"\n')
    out_file = tmp_path / "report.json"

    main([str(tmp_path), "--json", "-o", str(out_file)])

    parsed = json.loads(out_file.read_text())
    assert isinstance(parsed, list)
    assert len(parsed) >= 1


# Exclusions

def test_exclude_dir_flag_skips_specified_directory(tmp_path, capsys):
    (tmp_path / "skipme").mkdir()
    (tmp_path / "skipme" / "leak.py").write_text(f'TOKEN = "{FAKE_GH_TOKEN}"\n')

    rc = main([str(tmp_path), "--exclude-dir", "skipme"])
    assert rc == 0


def test_default_excludes_skip_git_directory(tmp_path, capsys):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "leak.py").write_text(f'TOKEN = "{FAKE_GH_TOKEN}"\n')

    rc = main([str(tmp_path)])
    assert rc == 0


# Single-file scanning
def test_can_scan_a_single_file_path(tmp_path, capsys):
    f = tmp_path / "leaky.py"
    f.write_text(f'TOKEN = "{FAKE_GH_TOKEN}"\n')

    rc = main([str(f)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "GitHub Personal Access Token" in out
