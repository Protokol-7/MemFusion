#!/usr/bin/env python3
"""Patch the installed Volatility 3 to stop a circular-import crash.

Why this exists
----------------
Loading this app's custom plugin directories via `vol -p <dir>` can make
`vol -h` (or any run) crash outright instead of just refusing individual
plugins:

    File ".../volatility3/framework/symbols/windows/extensions/pool.py",
    line 31, in POOL_HEADER
        constraint: poolscanner.PoolConstraint,
    AttributeError: partially initialized module
    'volatility3.plugins.windows.poolscanner' ... has no attribute
    'PoolConstraint' (most likely due to a circular import)

This is not caused by anything specific to this app's plugins — it can be
triggered by any `-p` plugin that imports `volatility3.plugins.windows`
before vol3's own bootstrap has finished importing
`volatility3.framework.symbols.windows.extensions.pool`, whose class body
evaluates a `poolscanner.PoolConstraint` type annotation eagerly at
class-definition time. `-p` changes plugin import order enough to hit that
window; a bare `vol -h` normally doesn't.

The standard fix for this class of bug is PEP 563: adding
`from __future__ import annotations` to pool.py makes every annotation in
that module a lazy string instead of something evaluated immediately, so the
still-initializing `poolscanner` module is never dereferenced. It changes
nothing about the module's runtime behaviour beyond that.

This app's own catalog probe (internal/volatility/discover.go) already
tolerates this crash by retrying without -p, so custom plugins simply don't
appear rather than the whole catalog failing. This script is for restoring
those custom plugins by fixing it at the source, since the retry has no way
to patch a third-party package.

Because this edits files inside the installed volatility3 package rather
than this repo, it is NOT applied automatically and needs to be re-run after
every volatility3 upgrade (pip may overwrite the file).

Usage:
    python3 scripts/patch_vol3_pool_circular_import.py [--check]

    --check   report whether patching is needed without writing

Run it with the interpreter that has volatility3 installed — the same one
`vol`/`vol.exe` on your PATH resolves to.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

MODULE = "volatility3.framework.symbols.windows.extensions.pool"
FUTURE_IMPORT = "from __future__ import annotations"


def find_module_path() -> Path | None:
    try:
        spec = importlib.util.find_spec(MODULE)
    except ModuleNotFoundError:
        return None
    if spec is None or spec.origin is None:
        return None
    return Path(spec.origin)


def insertion_line(text: str) -> int:
    """Line index (0-based) to insert the future import at.

    `from __future__ import annotations` must come before any other code but
    after the module docstring, if there is one. A plain source scan for the
    first statement is enough here — pool.py is a normal module, not
    something with unusual leading comment/encoding tricks.
    """
    lines = text.splitlines(keepends=True)
    i = 0
    # Skip leading blank/comment lines.
    while i < len(lines) and (lines[i].strip() == "" or lines[i].lstrip().startswith("#")):
        i += 1
    if i >= len(lines):
        return i
    stripped = lines[i].lstrip()
    quote = None
    for q in ('"""', "'''"):
        if stripped.startswith(q):
            quote = q
            break
    if quote is None:
        return i  # no docstring — insert right before the first statement
    # Docstring may be a single line or span multiple lines.
    first = lines[i]
    after_open = first[first.find(quote) + 3:]
    if quote in after_open:
        return i + 1  # single-line docstring
    for j in range(i + 1, len(lines)):
        if quote in lines[j]:
            return j + 1
    return i + 1  # unterminated string; give up gracefully


def patch(text: str) -> tuple[str, bool]:
    if FUTURE_IMPORT in text:
        return text, False
    lines = text.splitlines(keepends=True)
    idx = insertion_line(text)
    lines[idx:idx] = [FUTURE_IMPORT + "\n", "\n"]
    return "".join(lines), True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="report only, don't write")
    args = parser.parse_args()

    path = find_module_path()
    if path is None:
        print(f"could not locate {MODULE} — run this with the same interpreter "
              f"that has volatility3 installed (the one 'vol'/'vol.exe' resolves to)",
              file=sys.stderr)
        return 2

    original = path.read_text(encoding="utf-8")
    patched, changed = patch(original)

    if not changed:
        print(f"{path} already patched — nothing to do")
        return 0

    if args.check:
        print(f"WOULD PATCH {path}")
        return 1

    path.write_text(patched, encoding="utf-8")
    print(f"PATCHED {path}")
    print("Re-run this after every volatility3 upgrade — pip may overwrite the file.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
