"""Entry point for calibration: `python detector/baseline.py --log ...`

The implementation lives in calibrate.py. This file exists so the obvious
name works too; both accept exactly the same arguments.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from calibrate import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
