#!/usr/bin/env python3
"""
secret_scanner.py - Scan files or directories for hardcoded secrets.

Detects common patterns: API keys, tokens, passwords, private keys.
Pure stdlib. No external dependencies.

Exit codes:
    0 - scan completed, no findings
    1 - scan completed, one or more findings
    2 - invalid input or runtime error
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Iterator, List, Pattern


# Detection patterns
# 
# Each pattern has:
#   name      - human-readable label shown in the report
#   regex     - compiled regex
#   secret_group - which capture group contains the actual secret value
#                  (0 = whole match; useful when the regex also matches the
#                  surrounding context like a variable name)

@dataclass(frozen=True)
class SecretPattern:
    name: str
    regex: Pattern[str]
    secret_group: int = 0


PATTERNS: list[SecretPattern] = [
    # --- Cloud / SaaS keys with distinctive prefixes ---
    SecretPattern(
        name="AWS Access Key ID",
        regex=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    SecretPattern(
        name="GitHub Personal Access Token",
        regex=re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    ),
    SecretPattern(
        name="Google API Key",
        regex=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    SecretPattern(
        name="Slack Token",
        regex=re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}\b"),
    ),

    # --- Cryptographic key blocks ---
    SecretPattern(
        name="Private Key Block",
        regex=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
    ),

    # --- Generic assignment heuristic ---
    # Catches things like:   api_key = "abc123..."
    #                        password: "hunter2hunter2"
    # Group 2 captures the value. Tunable: minimum length is 12 to cut down
    # on noise from short test strings.
    SecretPattern(
        name="Generic Secret Assignment",
        regex=re.compile(
            r"(?i)(api[_-]?key|apikey|secret|token|passwd|password|auth[_-]?token)"
            r"\s*[:=]\s*[\"']([A-Za-z0-9_\-\.=+/]{12,})[\"']"
        ),
        secret_group=2,
    ),
]


# File traversal config
DEFAULT_EXCLUDED_DIRS: set[str] = {
    ".git", ".hg", ".svn",
    "node_modules", "__pycache__",
    ".venv", "venv", "env",
    "dist", "build", "target",
    ".mypy_cache", ".pytest_cache", ".tox",
    ".idea", ".vscode",
}

# Skip files we know are binary by extension to avoid wasting time on them.
DEFAULT_BINARY_EXTS: set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".pyc", ".pyo", ".class", ".jar", ".war",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".flac",
    ".ttf", ".otf", ".woff", ".woff2",
}

# Soft cap on file size to avoid loading huge files
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB


# Data classes
@dataclass
class Finding:
    file: str
    line_number: int
    pattern_name: str
    matched_text: str
    line_preview: str  # the source line, trimmed

    def redacted(self) -> str:
        """Mask the middle of a secret so it's safe to log."""
        s = self.matched_text
        if len(s) <= 8:
            return s[0] + "*" * (len(s) - 1) if s else ""
        return f"{s[:4]}{'*' * (len(s) - 8)}{s[-4:]}"


# Core scanning logic
def iter_files(
    root: Path,
    excluded_dirs: set[str],
    binary_exts: set[str],
) -> Iterator[Path]:
    """Yield candidate files under root, skipping excluded dirs and binaries."""
    if root.is_file():
        yield root
        return

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        # Skip if any directory component matches an excluded name
        if any(part in excluded_dirs for part in p.parts):
            continue
        if p.suffix.lower() in binary_exts:
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                logging.debug("Skipping large file: %s", p)
                continue
        except OSError as e:
            logging.warning("Could not stat %s: %s", p, e)
            continue
        yield p


def scan_file(path: Path, patterns: Iterable[SecretPattern]) -> List[Finding]:
    """Scan one file line-by-line, returning all matches."""
    findings: list[Finding] = []
    try:
        # errors="ignore" lets you read mixed-encoding text files without crashing.
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, start=1):
                for pat in patterns:
                    for m in pat.regex.finditer(line):
                        try:
                            matched = m.group(pat.secret_group)
                        except IndexError:
                            matched = m.group(0)
                        findings.append(Finding(
                            file=str(path),
                            line_number=lineno,
                            pattern_name=pat.name,
                            matched_text=matched,
                            line_preview=line.rstrip("\n")[:200],
                        ))
    except (OSError, UnicodeDecodeError) as e:
        logging.warning("Could not read %s: %s", path, e)
    return findings


# Reporting
def format_text_report(findings: list[Finding], show_full: bool) -> str:
    if not findings:
        return "No potential secrets found."

    out: list[str] = [
        f"Found {len(findings)} potential secret(s):",
        "=" * 60,
        "",
    ]
    for f in findings:
        secret = f.matched_text if show_full else f.redacted()
        # Redact the source line too, otherwise the Context line leaks
        # the unredacted secret straight back to the reader.
        context = (
            f.line_preview if show_full
            else f.line_preview.replace(f.matched_text, secret)
        )
        out.append(f"[{f.pattern_name}]")
        out.append(f"  File:    {f.file}")
        out.append(f"  Line:    {f.line_number}")
        out.append(f"  Match:   {secret}")
        out.append(f"  Context: {context.strip()}")
        out.append("")
    return "\n".join(out)


def format_json_report(findings: list[Finding], show_full: bool) -> str:
    payload = []
    for f in findings:
        d = asdict(f)
        if not show_full:
            redacted = f.redacted()
            d["matched_text"] = redacted
            d["line_preview"] = f.line_preview.replace(f.matched_text, redacted)
        payload.append(d)
    return json.dumps(payload, indent=2)


# CLI
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secret_scanner",
        description=(
            "Scan files or directories for hardcoded secrets "
            "(API keys, tokens, passwords, private keys)."
        ),
    )
    p.add_argument(
        "path",
        help="File or directory to scan",
    )
    p.add_argument(
        "-o", "--output",
        help="Write report to this file (default: stdout)",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Output report as JSON instead of plain text",
    )
    p.add_argument(
        "--show-full",
        action="store_true",
        help="Show full matched secret in report (default: redacted)",
    )
    p.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        metavar="NAME",
        help="Additional directory name to exclude (repeatable)",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug-level logging",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    target = Path(args.path)
    if not target.exists():
        logging.error("Path does not exist: %s", target)
        return 2

    excluded = DEFAULT_EXCLUDED_DIRS | set(args.exclude_dir)

    logging.info("Scanning: %s", target.resolve())
    logging.debug("Excluded directories: %s", sorted(excluded))

    all_findings: list[Finding] = []
    files_scanned = 0
    for fp in iter_files(target, excluded, DEFAULT_BINARY_EXTS):
        files_scanned += 1
        logging.debug("Scanning file: %s", fp)
        all_findings.extend(scan_file(fp, PATTERNS))

    logging.info(
        "Scan complete: %d file(s) scanned, %d finding(s)",
        files_scanned, len(all_findings),
    )

    if args.json:
        report = format_json_report(all_findings, args.show_full)
    else:
        report = format_text_report(all_findings, args.show_full)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        logging.info("Report written to %s", args.output)
    else:
        print(report)

    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())
