"""Shared test setup: make the project's script directories importable.

The detector, traffic and API code are plain scripts that import their
neighbours by name, so the tests put each directory on the path the same way
the scripts do.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

for sub in ("", "detector", "traffic", "api"):
    path = os.path.join(ROOT, sub) if sub else ROOT
    if path not in sys.path:
        sys.path.insert(0, path)
