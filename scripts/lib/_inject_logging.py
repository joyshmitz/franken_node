#!/usr/bin/env python3
"""One-shot migration: inject test_logger into all check_*.py / verify_*.py scripts.

For each script:
1. After the ``ROOT = Path(...)`` line, insert ``sys.path`` setup + import.
2. Add ``logger = configure_test_logging("<script_stem>")`` as first line
   inside ``def main():``.

Idempotent: skips scripts that already contain ``configure_test_logging``.

Usage:
    python3 scripts/lib/_inject_logging.py          # dry-run (default)
    python3 scripts/lib/_inject_logging.py --apply   # write changes
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = ROOT / "scripts"

# We insert after the ROOT line so sys.path.insert uses the already-defined ROOT.
IMPORT_BLOCK = """\
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging"""


def inject(path: Path) -> str | None:
    """Return modified source or None if no change needed."""
    text = path.read_text(encoding="utf-8")

    if "configure_test_logging" in text:
        return None  # already done

    lines = text.split("\n")
    stem = path.stem

    # ── Step 1: find ROOT = Path(...) line ────────────────────────
    root_idx = None
    for i, line in enumerate(lines):
        if re.match(r'^ROOT\s*=\s*Path\(', line):
            root_idx = i
            break

    if root_idx is None:
        # No ROOT definition — inject after last import instead.
        last_import_idx = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")):
                last_import_idx = i
        # Add import sys if missing
        if "import sys" not in text:
            lines.insert(last_import_idx + 1, "import sys")
            last_import_idx += 1
        # Insert the import block after a blank line
        for block_line in reversed(IMPORT_BLOCK.split("\n")):
            lines.insert(last_import_idx + 1, block_line)
        # We need ROOT defined — add a fallback
        lines.insert(last_import_idx + 1, 'ROOT = Path(__file__).resolve().parent.parent')
    else:
        # Ensure ``import sys`` is present
        if "import sys" not in text:
            # Insert before ROOT line
            lines.insert(root_idx, "import sys")
            root_idx += 1
        # Insert import block after ROOT line (skip blank line if present)
        insert_at = root_idx + 1
        for block_line in reversed(IMPORT_BLOCK.split("\n")):
            lines.insert(insert_at, block_line)

    # ── Step 2: find ``def main():`` and inject logger ───────────
    for i, line in enumerate(lines):
        if re.match(r"^def main\(\)", line):
            body_indent = "    "
            for j in range(i + 1, min(i + 5, len(lines))):
                if lines[j].strip():
                    body_indent = re.match(r"^(\s*)", lines[j]).group(1)
                    break
            logger_line = f'{body_indent}logger = configure_test_logging("{stem}")'
            lines.insert(i + 1, logger_line)
            break

    result = "\n".join(lines)
    if result == text:
        return None
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="Write changes to disk")
    args = parser.parse_args()

    scripts = sorted(SCRIPTS_DIR.glob("check_*.py")) + sorted(SCRIPTS_DIR.glob("verify_*.py"))
    modified = 0
    skipped = 0

    for path in scripts:
        new_text = inject(path)
        if new_text is None:
            skipped += 1
            continue
        modified += 1
        if args.apply:
            path.write_text(new_text, encoding="utf-8")
        else:
            print(f"  would modify {path.name}")

    print(f"\n{'Applied' if args.apply else 'Dry-run'}: {modified} modified, {skipped} skipped")


if __name__ == "__main__":
    main()
