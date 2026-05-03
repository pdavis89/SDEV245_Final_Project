"""
Pytest configuration for the secret_scanner test suite.

Adds the project root (parent of this tests/ directory) to sys.path so that
`import secret_scanner` works regardless of where pytest is invoked from.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
