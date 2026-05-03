# Secret Scanner

Python CLI tool that scans files or directories for hardcoded secrets - API keys, tokens, passwords, and private keys. Pure standard library, no dependencies.

## Quick start

```bash
# Scan a directory
python secret_scanner.py ./my-project

# Scan a single file
python secret_scanner.py ./config/settings.py

# Write a JSON report to disk
python secret_scanner.py ./my-project --json -o findings.json

# See full matches (use carefully - writes real secrets to output)
python secret_scanner.py ./my-project --show-full

# Exclude additional directories
python secret_scanner.py . --exclude-dir tests --exclude-dir fixtures

# Verbose logging
python secret_scanner.py . -v
```

Make it executable if you prefer:

```bash
chmod +x secret_scanner.py
./secret_scanner.py ./my-project
```

## Exit codes

The tool follows the convention used by linters and security scanners so it slots cleanly into pre-commit hooks or CI pipelines:

- `0` — scan completed, no findings
- `1` — scan completed, one or more findings
- `2` — invalid input or runtime error

Example pre-commit usage: a non-zero exit blocks the commit.

## Detection logic

The scanner reads each file line by line and applies a list of regex patterns. There are two categories:

### 1. High-confidence prefix patterns

Many cloud and SaaS providers issue keys with a distinctive prefix and a fixed length. These have very low false-positive rates because random text rarely matches both the prefix and the length:

| Pattern           | What it matches                                                       | Notes                                               |
| ----------------- | --------------------------------------------------------------------- | --------------------------------------------------- |
| AWS Access Key ID | `AKIA...` (long-term) or `ASIA...` (temporary), 16 chars after prefix | Documented format                                   |
| GitHub PAT        | `ghp_` + 36 alphanumeric chars                                        | Modern GitHub token format                          |
| Google API Key    | `AIza` + 35 chars                                                     |                                                     |
| Slack Token       | `xoxa-`, `xoxb-`, `xoxp-`, `xoxr-` + payload                          | Demonstrates prefix alternation                     |
| Private Key Block | `-----BEGIN ... PRIVATE KEY-----`                                     | Catches RSA, EC, DSA, OpenSSH, and PGP private keys |

### 2. Heuristic pattern

This trades higher recall for more false positives. Treat its findings as "investigate" rather than "definitely a leak."

**Generic Secret Assignment.** Looks for assignments where the variable name contains `api_key`, `apikey`, `secret`, `token`, `password`, `passwd`, or `auth_token`, followed by `=` or `:`, followed by a quoted string of 12+ characters. Catches a lot of real secrets but produces noise from things like:

- Test fixtures with placeholder values
- Documentation examples
- Variables that happen to be named "secret" but hold something else

The minimum length of 12 is a tunable knob in the source — raise it to cut noise, lower it to catch shorter keys.

## Output format

Default text output, redacted:

```
Found 2 potential secret(s):
============================================================

[GitHub Personal Access Token]
  File:    /home/patrick/proj/config.py
  Line:    14
  Match:   ghp_*****************************4xYz
  Context: GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123454xYz"

[Generic Secret Assignment]
  File:    /home/patrick/proj/db.py
  Line:    7
  Match:   sup3****************er123
  Context: password = "sup3rsecretdbpasswordhunter123"
```

Redaction shows the first 4 and last 4 characters with the middle masked. Useful for sharing reports without leaking the secret itself. Pass `--show-full` to see the unmasked match — only do this when the output stays on a trusted machine.

JSON output (`--json`) returns a list of objects:

```json
[
  {
    "file": "/home/patrick/proj/config.py",
    "line_number": 14,
    "pattern_name": "GitHub Personal Access Token",
    "matched_text": "ghp_*****************************4xYz",
    "line_preview": "GITHUB_TOKEN = \"ghp_abc...4xYz\""
  }
]
```

## What it skips

By default the scanner skips:

- `.git`, `.hg`, `.svn`, `node_modules`, `__pycache__`, `.venv`, `venv`, `env`, `dist`, `build`, `target`, `.mypy_cache`, `.pytest_cache`, `.tox`, `.idea`, `.vscode`
- Common binary extensions (`.png`, `.jpg`, `.pdf`, `.zip`, `.exe`, `.so`, `.pyc`, etc.)
- Files larger than 5 MB (configurable in source via `MAX_FILE_BYTES`)

You can add more directory names with `--exclude-dir`.

## Honest limitations

Worth being upfront about, since regex-based secret scanning has well-known weak spots:

1. **Regex misses obfuscation.** A secret split across string concatenations (`"ghp_" + "abc..."`) will not match. Base64-encoded or env-substituted secrets will not match.
2. **High-entropy strings without a known prefix.** Real-world tools like [TruffleHog](https://github.com/trufflesecurity/trufflehog) and [detect-secrets](https://github.com/Yelp/detect-secrets) supplement regex with Shannon entropy analysis to catch random-looking strings. This scanner does not - it would catch more secrets but also produce a lot more noise.
3. **No verification.** Some scanners try to hit the provider's API to confirm a token is _live_. This one only matches the shape. A finding could be a real expired token, a fake test value, or genuinely active.
4. **No git history.** The scanner only sees the current file contents. Secrets in old commits will not be found. Specialized tools like `gitleaks` walk git history.
5. **Encoding.** Files are read as UTF-8 with errors ignored. A secret in an exotic encoding might be silently mangled.
6. **Generic-assignment false positives.** Expect noise from this rule. The trade-off was made deliberately - better to investigate a few dummy values than miss a real password.

## Architecture / how it works

```
main()
 └─ build_parser()          ← argparse CLI
 └─ iter_files()            ← walks the path, filters dirs/extensions/size
     └─ scan_file()         ← reads file, applies every pattern to each line
         └─ Finding         ← dataclass; one per match
 └─ format_*_report()       ← serializes findings to text or JSON
```

A few design notes that might be useful as you read the code:

- **Patterns are data, not code.** Each pattern is a `SecretPattern` dataclass with the regex and the capture group that holds the actual secret. Adding a new pattern is one entry in the `PATTERNS` list - no changes to the scanning logic.
- **Line-by-line scanning.** Simple and memory-light. The trade-off: regex patterns can't span lines, so multi-line constructs like a full PEM block are detected by their `BEGIN` header only.
- **Redaction is a method on `Finding`.** Keeps the masking logic with the data it operates on. The CLI flag flips between calling `f.matched_text` and `f.redacted()`.
- **`errors="ignore"`** when opening files so a stray non-UTF-8 byte doesn't kill the scan. Acceptable for source code; less appropriate for forensics.
