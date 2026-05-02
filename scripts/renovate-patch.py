#!/usr/bin/env python3
"""Apply Renovate's planned updates to the working tree.

Reads Renovate's structured JSON debug logs from stdin, finds the
`packageFiles with updates` event, and applies each dep's first update
by performing a targeted substitution on the exact `replaceString`
Renovate would have edited. Formatting, comments, and indentation are
preserved byte-for-byte outside the substitution range.

Best-effort by design — when anything is ambiguous (replaceString
missing, not unique, not present in the file, currentValue not unique
inside it, etc.) the dep is SKIPPED with a diagnostic on stderr.
Better to do nothing than to corrupt a file in a way that confuses
Renovate's own delta logic on the next run.

Output (stdout, one line per applied change):
    updated  <file>: <dep> <old-snippet> -> <new-snippet>
Diagnostics on stderr:
    skipped  <file>: <dep>: <reason>

Exit code is 0 unless the JSON event was missing entirely.

Usage:
    docker run ... renovate/renovate ... | python3 scripts/renovate-patch.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def main() -> int:
    event = _read_event(sys.stdin)
    if event is None:
        sys.stderr.write(
            "renovate-patch: no `packageFiles with updates` event on stdin\n"
        )
        return 1

    applied = 0
    skipped = 0
    for _manager, files in (event.get("config") or {}).items():
        for f in files or []:
            path = Path(f.get("packageFile", ""))
            for dep in f.get("deps") or []:
                ok, msg = _apply_first_update(path, dep)
                if ok:
                    sys.stdout.write(f"updated  {path}: {msg}\n")
                    applied += 1
                elif msg is not None:
                    sys.stderr.write(
                        f"skipped  {path}: {dep.get('depName', '?')}: {msg}\n"
                    )
                    skipped += 1

    sys.stderr.write(f"renovate-patch: {applied} applied, {skipped} skipped\n")
    return 0


def _read_event(stream) -> dict[str, Any] | None:
    """Find the `packageFiles with updates` event in Renovate's JSON log stream."""
    for raw in stream:
        raw = raw.strip()
        if not raw or not raw.startswith("{"):
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if obj.get("msg") == "packageFiles with updates":
            return obj
    return None


def _apply_first_update(path: Path, dep: dict[str, Any]) -> tuple[bool, str | None]:
    """Apply the first update for `dep` to `path`.

    Returns (True, summary) on success, (False, reason) on skip,
    (False, None) when there is nothing to do (no updates, silently ignored).
    """
    updates = dep.get("updates") or []
    if not updates:
        return False, None
    update = updates[0]

    # Skip rollbacks — Renovate sometimes proposes them, but they're
    # never what we want to apply blindly.
    if update.get("updateType") == "rollback":
        return False, "first update is a rollback; bailing"

    old = dep.get("replaceString")
    if not old:
        return False, "no replaceString — manager not supported by patch"

    cur_value = dep.get("currentValue") or ""
    new_value = update.get("newValue") or cur_value
    cur_digest = dep.get("currentDigest") or ""
    new_digest = update.get("newDigest") or ""

    # `pinDigest` on a previously-unpinned dep adds a digest where there
    # was none. The new replaceString needs to be reconstructed from
    # `autoReplaceStringTemplate` (Handlebars), which we can't evaluate
    # safely without a real templating engine. Skip — Renovate will pick
    # this up on its next run.
    if not cur_digest and new_digest:
        return False, "pinDigest on unpinned dep — needs template eval, leaving to Renovate"

    new = old
    # Replace digest first (longer + more specific). currentDigest cannot
    # appear inside currentValue (sha256:<64hex> vs a tag like vN.M.P).
    if cur_digest and new_digest and cur_digest != new_digest:
        if old.count(cur_digest) != 1:
            return False, "currentDigest not unique in replaceString"
        new = new.replace(cur_digest, new_digest)
    if cur_value and new_value and cur_value != new_value:
        # Count against the post-digest-substitution string: the digest
        # might overlap nothing, but checking on `new` is the safe form.
        if new.count(cur_value) != 1:
            return False, f"currentValue {cur_value!r} not unique in replaceString"
        new = new.replace(cur_value, new_value)

    if new == old:
        return False, None  # nothing to do, e.g. update arrived without a delta

    if not path.is_file():
        return False, f"file does not exist: {path}"

    content = path.read_text()
    occurrences = content.count(old)
    if occurrences == 0:
        return False, "replaceString not found in file (already edited?)"
    if occurrences > 1:
        return False, f"replaceString appears {occurrences}× in file, ambiguous"

    path.write_text(content.replace(old, new, 1))
    return True, f"{dep.get('depName', '?')} {_snippet(old)} -> {_snippet(new)}"


def _snippet(s: str, limit: int = 80) -> str:
    s = s.strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


if __name__ == "__main__":
    sys.exit(main())
