#!/usr/bin/env python3
"""Wrapper entrypoint for the section 10.4 gate (bd-261k)."""

from gate_section_10_4 import main
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


if __name__ == "__main__":
    main()
