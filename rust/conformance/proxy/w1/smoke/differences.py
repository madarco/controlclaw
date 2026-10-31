#!/usr/bin/env python3
"""Where cc-proxy differs from mitmproxy on purpose, the copied smoke scripts expect cc-proxy's
behaviour (owner, 2026-10-28: gaps are fixed in Rust only, and the old code is not changed).

Each entry replaces one exact block of a script; a block that is not found fails the run, so a
change to the script is noticed rather than skipped.

  python3 differences.py <copied smoke folder>
"""
import pathlib
import sys

# Empty since main #564: the scripts expect the control plane and the backup store inspected, as
# cc-proxy does. Add a (script, old block, new block) entry for the next intentional difference.
DIFFERENCES: list[tuple[str, str, str]] = []


def main() -> int:
    root = pathlib.Path(sys.argv[1])
    for name, old, new in DIFFERENCES:
        path = root / name
        text = path.read_text()
        if old not in text:
            print(f"differences.py: the block to replace is not in {name}", file=sys.stderr)
            return 1
        path.write_text(text.replace(old, new, 1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
