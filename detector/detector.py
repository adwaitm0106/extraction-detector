"""Entry point for scoring: `python detector/detector.py --log ...`

The implementation lives in score.py. This file exists so the obvious name
works too; both accept exactly the same arguments.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from score import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
