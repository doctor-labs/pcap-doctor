"""Notice framework: per-code action, dedup and rate-limit, configured in `[notice.CODE]` (issue #273).

Modelled on Zeek's notice framework, which lets an operator decide per notice type what happens to it:

    [notice.TLS_CIPHER_WEAK]
    action = "log"        # report (default) | log: notes only, not in findings | suppress: dropped, count noted
    dedup = true          # one finding per (code, flow, subjects): the worst severity is kept
    max = 20              # rate-limit: at most N findings of this code per run; the rest are counted

Runs after `disable`/`[[allow]]`/`[severity]` and before `--category` / `--min-severity` filtering. Every effect is
written to the report notes, so nothing disappears silently. Without a `[notice]` table nothing changes.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .models import SEVERITY_ORDER, Finding
from .rules import RULES

ACTIONS = ("report", "log", "suppress")
_KEYS = ("action", "dedup", "max")


class NoticeConfigError(ValueError):
    """A `[notice.CODE]` table with an unknown code, key or value."""


@dataclass(frozen=True)
class NoticeRule:
    action: str = "report"
    dedup: bool = False
    max: int | None = None


def parse_rules(table: Any, source: str) -> dict[str, NoticeRule]:
    """Validate the `[notice]` table (code -> rule table); raise NoticeConfigError naming the bad key or value."""
    if not isinstance(table, dict):
        raise NoticeConfigError(f"{source}: [notice] must be a table of [notice.CODE] tables")
    rules: dict[str, NoticeRule] = {}
    for code, body in table.items():
        where = f"{source}: [notice.{code}]"
        if code not in RULES:
            raise NoticeConfigError(f"{where}: unknown code {code}; see `pcap-doctor rules list`")
        if not isinstance(body, dict):
            raise NoticeConfigError(f"{where} must be a table")
        extra = sorted(set(body) - set(_KEYS))
        if extra:
            raise NoticeConfigError(f"{where}: unknown key(s) {', '.join(extra)}; valid: {', '.join(_KEYS)}")
        action = body.get("action", "report")
        if action not in ACTIONS:
            raise NoticeConfigError(f"{where}: action {action} invalid; valid: {', '.join(ACTIONS)}")
        dedup = body.get("dedup", False)
        if not isinstance(dedup, bool):
            raise NoticeConfigError(f"{where}: dedup must be true or false")
        limit = body.get("max")
        if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit < 1):
            raise NoticeConfigError(f"{where}: max must be a whole number of at least 1")
        rules[code] = NoticeRule(action=action, dedup=dedup, max=limit)
    return rules


def apply(findings: list[Finding], rules: Mapping[str, NoticeRule]) -> tuple[list[Finding], list[str]]:
    """Apply action, then dedup, then rate-limit per code; return the kept findings and one note per effect."""
    if not rules:
        return findings, []
    notes: list[str] = []
    logged: dict[str, list[str]] = {}
    suppressed: dict[str, int] = {}
    deduped: dict[str, int] = {}
    limited: dict[str, int] = {}

    remaining: list[Finding] = []
    for f in findings:
        rule = rules.get(f.code)
        if rule is None or rule.action == "report":
            remaining.append(f)
        elif rule.action == "log":
            logged.setdefault(f.code, []).append(f.id)
        else:
            suppressed[f.code] = suppressed.get(f.code, 0) + 1

    kept: list[Finding] = []
    seen: dict[tuple[str, str | None, tuple[str, ...]], int] = {}
    for f in remaining:
        rule = rules.get(f.code)
        if rule is None or not rule.dedup:
            kept.append(f)
            continue
        key = (f.code, f.flow_key, tuple(f.subjects))
        if key not in seen:
            seen[key] = len(kept)
            kept.append(f)
            continue
        i = seen[key]
        deduped[f.code] = deduped.get(f.code, 0) + 1
        if SEVERITY_ORDER.get(f.severity, 9) < SEVERITY_ORDER.get(kept[i].severity, 9):
            kept[i] = f

    result: list[Finding] = []
    counted: dict[str, int] = {}
    for f in kept:
        rule = rules.get(f.code)
        if rule is not None and rule.max is not None:
            counted[f.code] = counted.get(f.code, 0) + 1
            if counted[f.code] > rule.max:
                limited[f.code] = limited.get(f.code, 0) + 1
                continue
        result.append(f)

    for code, ids in logged.items():
        notes.append(f"[notice] logged {len(ids)} {code} finding(s) instead of reporting them: {', '.join(ids)}")
    for code, n in suppressed.items():
        notes.append(f"[notice] suppressed {n} finding(s) of {code} by action = \"suppress\"")
    for code, n in deduped.items():
        notes.append(f"[notice] deduplicated {n} {code} finding(s) onto the worst occurrence per flow and subject")
    for code, n in limited.items():
        notes.append(f"[notice] rate-limited {n} {code} finding(s) above max = {rules[code].max} for this run")
    return result, notes
