"""Make the package importable when tests are run without ``python -m pytest``."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
