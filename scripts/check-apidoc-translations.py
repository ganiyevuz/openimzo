#!/usr/bin/env python3
"""Fails when the API reference page would show an untranslated description.

The `apidoc` RPC reply is a wire contract: every plugin, function and argument description in it
is the original's own text, and websites receive it unchanged. Our own page translates it on the
way to the screen using the table in `crates/openimzo-server/src/apidoc_text.rs`, keyed by that
Russian source string.

The failure mode that table has is silent. A string with no entry falls through and renders in
Russian, which is correct behaviour for an unknown string and indistinguishable from a
translation someone forgot to add — the exact bug this check exists to catch, found once by a
person reading the page and noticing that the headings translated and the content did not.

So this asks the dispatcher for the real document, collects every description in it, and compares
that against the table's keys. Adding a function to a plugin without translating its description
fails here rather than shipping a half-Russian page.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TABLE_PATH = REPO_ROOT / "crates" / "openimzo-server" / "src" / "apidoc_text.rs"


def descriptions_the_page_receives() -> set[str]:
    """Every description in the live `apidoc` reply, asked of the dispatcher itself."""
    result = subprocess.run(
        ["cargo", "run", "--quiet", "-p", "openimzo-cli", "--", "rpc", '{"plugin":"","name":"apidoc"}'],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    if result.returncode != 0:
        print("error: could not ask the dispatcher for the apidoc document", file=sys.stderr)
        print(result.stderr.strip()[-2000:], file=sys.stderr)
        raise SystemExit(1)
    document = json.loads(result.stdout.strip().splitlines()[0])

    found: set[str] = set()
    for plugin in document:
        if plugin.get("description"):
            found.add(plugin["description"])
        for function in plugin.get("functions") or []:
            if function.get("description"):
                found.add(function["description"])
            for argument in function.get("arguments") or []:
                if argument.get("description"):
                    found.add(argument["description"])
    return found


def table_keys() -> set[str]:
    """The Russian source strings the table has entries for.

    Read out of the source rather than by running Rust: the keys are plain literals, and parsing
    them keeps this script a check on the table rather than another thing that has to be built.
    """
    source = TABLE_PATH.read_text(encoding="utf-8")
    return set(re.findall(r'\(\s*"((?:[^"\\]|\\.)+)"\s*,', source))


def main() -> int:
    needed = descriptions_the_page_receives()
    have = table_keys()
    missing = sorted(needed - have)

    if missing:
        print(f"check-apidoc-translations: {len(missing)} description(s) have no translation:", file=sys.stderr)
        for text in missing:
            print(f"  - {text}", file=sys.stderr)
        print(f"\nAdd each one to {TABLE_PATH.relative_to(REPO_ROOT)} with its Uzbek and English.", file=sys.stderr)
        print("Without an entry the page shows the Russian, which looks like a page that is only", file=sys.stderr)
        print("half translated rather than like a missing entry.", file=sys.stderr)
        return 1

    # An entry for a string the document no longer contains is dead weight, not a failure: a
    # plugin's wording can change between versions of the original and the old key does no harm.
    stale = len(have - needed)
    note = f", {stale} unused entr{'y' if stale == 1 else 'ies'}" if stale else ""
    print(f"check-apidoc-translations: OK — {len(needed)} descriptions, all translated{note}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
