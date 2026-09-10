#!/usr/bin/env python3
"""Fails if a chrome string this app uses has no entry in Localizable.xcstrings, or a catalogue
entry has a missing or empty translation for any of the app's three languages (en/ru/uz).

Why this script exists rather than relying on `SWIFT_EMIT_LOC_STRINGS: YES` (macos/project.yml):
that setting makes the build extract real `LocalizedStringKey`/`String(localized:)` usage into
`.stringsdata` files, which is what lets *Xcode's own editor* cross-check a string against the
catalogue and flag one that's missing. Confirmed by inspecting a full `xcodebuild build` log with
the setting on: it produces the `.stringsdata` files, but a plain command-line build does not
itself fail, or print anything, when a key is used in code but absent from the catalogue. That is
a real, useful signal inside Xcode's UI — but nothing in an automated pipeline, or in an agent's
own verification pass, ever sees it. This script is the actual gate: it is what caught four real
missing catalogue keys (three custom-view sheet headlines and one settings label) that a hand
re-read of the code, and a clean build with that setting on, both missed.

Usage — from anywhere, no arguments, no setup (only the standard library):
    python3 scripts/check-localization.py

Scope, and what to do when it doesn't reach far enough: this finds every string literal passed
as (a) the first argument to a fixed list of SwiftUI initializers that localize their first
argument (Text, Button, Label, ...), and (b) a labeled argument on a short, explicit list of this
app's own view types that carry a `LocalizedStringKey`-typed parameter (PasswordPromptSheet's
`title`/`confirmTitle`, RequestPanelHeader's `subtitle`, PasswordRuleRow's `text`, PortStatusRow's
`label`) — exactly the class of gap that slipped through task 6's first pass, since a scan of only
the built-in SwiftUI names never looks inside a custom type's own constructor call. When a NEW
custom view type gains a `LocalizedStringKey`-typed field, add its (type name, parameter label)
pair to CUSTOM_LOCALIZED_PARAMS below, or this script will not see it either — the same way it
would not have seen the ones it was just extended to catch.

This is a source-level heuristic, not a type checker: it does not know a field's declared type,
only the label it is called with. It is deliberately scoped to this app's own code
(macos/OpenImzo/), not the generated FFI bindings (macos/Generated/), which carry no user-
facing chrome text.
"""
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_DIR = REPO_ROOT / "macos" / "OpenImzo"
CATALOG_PATH = APP_DIR / "Localizable.xcstrings"
LANGUAGES = ("en", "ru", "uz")

# SwiftUI initializers whose *first* argument is the localizable text.
BUILTIN_IDENTIFIERS = [
    "Text", "Button", "Label", "Toggle", "Section", "ContentUnavailableView",
    "Picker", "SecureField", "TextField", "LabeledContent", "Menu",
    ".navigationTitle", ".accessibilityLabel",
    # Not a SwiftUI initializer: this app's own `Locale.localizedAppString(_:_:)`
    # (macos/OpenImzo/Core/AppLanguage.swift), which resolves a catalogue key from imperative
    # code — `CoreEngine`'s error messages, `MainWindow`'s window title, `UpdateChecker`'s
    # failure sentences. Its first argument is the key, same shape as the initializers above,
    # and until it was listed here every string reached that way was unchecked.
    ".localizedAppString",
]

# (type name, labeled parameter) pairs, for this app's own view types whose named parameter is
# `LocalizedStringKey`, not plain `String` — see the module doc comment above.
CUSTOM_LOCALIZED_PARAMS = [
    ("PasswordPromptSheet", "title"),
    ("PasswordPromptSheet", "confirmTitle"),
    ("RequestPanelHeader", "subtitle"),
    ("PasswordRuleRow", "text"),
    ("PortStatusRow", "label"),
]


def scan_argument_value(text: str, start: int) -> str:
    """From `start`, return the source span of one argument's expression: everything up to the
    next comma or closing paren at the SAME nesting depth as `start` itself (depth 0, relative to
    here) — i.e. one call argument, whether it's the first of several or the last one before the
    call's own closing paren. Quote- and paren-aware, so a nested call or a `\\(...)` string
    interpolation inside the argument doesn't end the scan early.
    """
    depth = 0
    i = start
    in_string = False
    while i < len(text):
        c = text[i]
        if in_string:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
        elif c == "(":
            depth += 1
        elif c == ")":
            if depth == 0:
                break
            depth -= 1
        elif c == "," and depth == 0:
            break
        i += 1
    return text[start:i]


def call_argument_list_span(text: str, open_paren_pos: int) -> str:
    """Given the index of a call's opening '(', return everything up to (not including) its
    matching ')' — the full argument list, for searching a labeled argument that isn't
    necessarily first.
    """
    depth = 1
    i = open_paren_pos + 1
    in_string = False
    start = i
    while i < len(text) and depth > 0:
        c = text[i]
        if in_string:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        i += 1
    return text[start : i - 1]


VERBATIM_RE = re.compile(r"\s*verbatim\s*:")


def literals_in_span(span: str) -> list[str]:
    """Every double-quoted string literal directly in `span` — NOT nested inside a further call
    within it (so `Text(String(format: "0:%02d", n))`'s `"0:%02d"` is correctly ignored: that
    argument's own type is `String`, not a literal, so it picks `Text`'s verbatim overload and is
    never looked up in the catalogue at all). Does not stop at the first literal it finds, so a
    ternary between two literals (`cond ? "A" : "B"`) yields both. Skips a span that opts out of
    catalogue lookup with `verbatim:` (a product name, or a language's own name for itself — see
    AppIdentity.swift and AppLanguage.swift).
    """
    if VERBATIM_RE.match(span):
        return []
    literals = []
    depth = 0
    i = 0
    in_string = False
    buf = ""
    while i < len(span):
        c = span[i]
        if in_string:
            if c == "\\":
                buf += span[i : i + 2]
                i += 2
                continue
            if c == '"':
                in_string = False
                if depth == 0:
                    literals.append(buf)
                buf = ""
                i += 1
                continue
            buf += c
            i += 1
            continue
        if c == '"':
            in_string = True
            i += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        i += 1
    return literals


def normalize_key(literal: str) -> str:
    """Swift's `LocalizedStringKey`/`String.LocalizationValue` interpolation turns each
    `\\(...)` segment into a `%@` placeholder in the catalogue key — this mirrors that so a
    literal like `"\\(a): \\(b)"` is checked against the catalogue as `"%@: %@"`, matching how
    Localizable.xcstrings itself is keyed.
    """
    out = []
    i = 0
    buf = ""
    while i < len(literal):
        if literal[i : i + 2] == "\\(":
            out.append(buf)
            buf = ""
            depth = 1
            i += 2
            while i < len(literal) and depth > 0:
                if literal[i] == "(":
                    depth += 1
                elif literal[i] == ")":
                    depth -= 1
                i += 1
            out.append("%@")
        else:
            buf += literal[i]
            i += 1
    out.append(buf)
    return "".join(out)


def find_used_keys(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    used: set[str] = set()

    for ident in BUILTIN_IDENTIFIERS:
        for m in re.finditer(re.escape(ident) + r"\(", text):
            span = scan_argument_value(text, m.end())
            for lit in literals_in_span(span):
                used.add(normalize_key(lit))

    for type_name, label in CUSTOM_LOCALIZED_PARAMS:
        for m in re.finditer(re.escape(type_name) + r"\(", text):
            args = call_argument_list_span(text, m.end() - 1)
            for lm in re.finditer(r"(?<![A-Za-z0-9_])" + re.escape(label) + r"\s*:\s*", args):
                span = scan_argument_value(args, lm.end())
                for lit in literals_in_span(span):
                    used.add(normalize_key(lit))

    return used


def main() -> int:
    if not CATALOG_PATH.exists():
        print(f"error: catalogue not found at {CATALOG_PATH}", file=sys.stderr)
        return 1
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    catalog_keys = set(catalog.get("strings", {}).keys())

    errors: list[str] = []

    # Every catalogue entry must have a non-empty translation for all three languages — a
    # present-but-empty entry fails the same way a missing one does.
    for key, entry in catalog.get("strings", {}).items():
        locs = entry.get("localizations", {})
        for lang in LANGUAGES:
            loc = locs.get(lang)
            value = loc.get("stringUnit", {}).get("value") if loc else None
            if not value:
                errors.append(f"catalogue entry {key!r} is missing its {lang!r} translation")

    # Every string this app's own code uses must be in the catalogue.
    used_by_file: dict[str, set[str]] = {}
    for path in sorted(APP_DIR.rglob("*.swift")):
        used_by_file[str(path.relative_to(REPO_ROOT))] = find_used_keys(path)

    for rel_path, keys in used_by_file.items():
        for key in sorted(keys - catalog_keys):
            errors.append(f"{rel_path}: {key!r} is used but has no catalogue entry")

    if errors:
        print(f"check-localization: {len(errors)} problem(s) found:\n", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    total_used = len({k for keys in used_by_file.values() for k in keys})
    print(f"check-localization: OK — {total_used} strings used, {len(catalog_keys)} catalogued, all three languages present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
