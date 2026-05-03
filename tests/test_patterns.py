"""
test_patterns.py - Verify each detection regex matches what it should
and does NOT match things it shouldn't.

"""

import pytest
from secret_scanner import PATTERNS


# Build a name -> pattern lookup so cases reference patterns by their
# human-readable name. If a pattern is renamed in secret_scanner.py and not
# here, the test will fail with a clear KeyError pointing to the mismatch.
PATTERN_BY_NAME = {p.name: p for p in PATTERNS}


# Positive cases: (pattern_name, line, expected_substring_in_match)
#
# `expected_substring_in_match` is the part we expect to find inside the
# pattern's secret-capture group. We use `in` rather than `==` so the test
# tolerates regexes that match a slightly larger context.

POSITIVE_CASES = [
    # AWS Access Key ID
    ("AWS Access Key ID",
     'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
     "AKIAIOSFODNN7EXAMPLE"),
    ("AWS Access Key ID",
     'temp = "ASIAIOSFODNN7EXAMPLE"',
     "ASIAIOSFODNN7EXAMPLE"),

    # GitHub PAT - the modern prefixed format
    ("GitHub Personal Access Token",
     'TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"',
     "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),

    # Google - total length must be AIza + exactly 35 chars (39 total)
    ("Google API Key",
     'GOOGLE = "AIzaSyA-abcdefghijklmnopqrstuvwxyz01234"',
     "AIzaSyA-abcdefghijklmnopqrstuvwxyz01234"),

    # Slack
    ("Slack Token",
     'token = "xoxb-1234567890-abcdefghijklmnop"',
     "xoxb-1234567890-abcdefghijklmnop"),

    # Private key headers - covers RSA, EC, plain, OPENSSH, and PGP variants
    ("Private Key Block",
     "-----BEGIN RSA PRIVATE KEY-----",
     "BEGIN RSA PRIVATE KEY"),
    ("Private Key Block",
     "-----BEGIN PRIVATE KEY-----",
     "BEGIN PRIVATE KEY"),
    ("Private Key Block",
     "-----BEGIN OPENSSH PRIVATE KEY-----",
     "BEGIN OPENSSH PRIVATE KEY"),
    ("Private Key Block",
     "-----BEGIN EC PRIVATE KEY-----",
     "BEGIN EC PRIVATE KEY"),

    # Generic assignment - case insensitive, multiple variable names
    ("Generic Secret Assignment",
     'password = "supersecretpasswordhere"',
     "supersecretpasswordhere"),
    ("Generic Secret Assignment",
     'API_KEY = "abc123def456ghi"',
     "abc123def456ghi"),
    ("Generic Secret Assignment",
     'auth_token: "longvaluethatisover12chars"',
     "longvaluethatisover12chars"),
    ("Generic Secret Assignment",
     "token = 'singlequotedlongvalue'",
     "singlequotedlongvalue"),
]


@pytest.mark.parametrize("pattern_name,line,expected", POSITIVE_CASES)
def test_pattern_matches_positive_case(pattern_name, line, expected):
    pat = PATTERN_BY_NAME[pattern_name]
    m = pat.regex.search(line)
    assert m is not None, (
        f"Expected {pattern_name!r} to match line: {line!r}"
    )
    matched = m.group(pat.secret_group)
    assert expected in matched, (
        f"Match {matched!r} did not contain expected substring {expected!r}"
    )


# Negative cases: (pattern_name, line)
#
# The named pattern should NOT match the line. These guard against regex
# loosening - e.g. accidentally allowing lowercase in an AWS key prefix.

NEGATIVE_CASES = [
    # AWS Access Key ID requires exactly 16 uppercase/digit chars after prefix
    ("AWS Access Key ID", 'KEY = "AKIA12345"'),                # too short
    ("AWS Access Key ID", 'KEY = "akiaiosfodnn7example"'),     # lowercase
    ("AWS Access Key ID", 'KEY = "BKIAIOSFODNN7EXAMPLE"'),     # wrong prefix

    # GitHub PAT requires exactly ghp_ + 36 alphanumeric chars
    ("GitHub Personal Access Token", 'tok = "ghp_short"'),
    ("GitHub Personal Access Token", 'tok = "gh_abcdefghijklmnopqrstuvwxyz0123456789"'),

    # Slack token - must start with one of the known sub-prefixes
    ("Slack Token", 'tok = "xoxz-foo"'),

    # Private key - public keys and certificates should NOT match
    ("Private Key Block", "-----BEGIN PUBLIC KEY-----"),
    ("Private Key Block", "-----BEGIN CERTIFICATE-----"),

    # Generic assignment - under min length or non-matching variable name
    ("Generic Secret Assignment", 'password = "short"'),       # under 12 chars
    ("Generic Secret Assignment", 'name = "Patrick Langford"'), # variable not in list
    ("Generic Secret Assignment", 'username = "abcdefghijklmnop"'),  # 'username' not in list
]


@pytest.mark.parametrize("pattern_name,line", NEGATIVE_CASES)
def test_pattern_does_not_match_negative_case(pattern_name, line):
    pat = PATTERN_BY_NAME[pattern_name]
    m = pat.regex.search(line)
    assert m is None, (
        f"Pattern {pattern_name!r} should NOT have matched {line!r} "
        f"but matched: {m.group(0) if m else None!r}"
    )


def test_every_pattern_has_at_least_one_positive_case():
    """Coverage check: every pattern in PATTERNS should be exercised at least once."""
    covered = {name for name, _, _ in POSITIVE_CASES}
    missing = {p.name for p in PATTERNS} - covered
    assert not missing, f"Patterns with no positive test case: {missing}"
