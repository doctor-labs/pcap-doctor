"""Suricata-style file rules: match extracted files by name, size, magic and md5 (issue #275).

A file rule is a small declarative object -- like Suricata's ``file_name``,
``file_size``, ``file_magic`` and ``file_md5`` keywords -- that is tested against
the file records produced by :mod:`pcap_doctor.extract`.  The matcher is a pure
function of a list of :class:`~pcap_doctor.extract.ExtractedFile` and a list of
:class:`FileRule`: no file I/O, no network, no globals, so it is cheap to unit
test on hand-built records.

``FileRule`` is intentionally a plain dataclass, not a detector: it carries no
finding ``code`` that the rule catalog or report needs to know about.  Callers
that want to turn a match into a :class:`~pcap_doctor.models.Finding` do so
themselves, using the returned :class:`FileMatch` records.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from .extract import ExtractedFile


@dataclass(frozen=True)
class FileRule:
    """One Suricata-style file keyword.

    Only the fields you set take part in the match; unset fields are wildcards.
    At least one field must be set, otherwise the rule matches nothing (it would
    be useless and almost certainly a mistake).
    """

    code: str
    name: str | None = None  # case-insensitive glob, e.g. "*.exe"
    min_size: int | None = None
    max_size: int | None = None
    magic: str | None = None  # MIME type from the filetypes magic table
    md5: str | None = None

    def __post_init__(self) -> None:
        if not any((self.name, self.min_size is not None, self.max_size is not None, self.magic, self.md5)):
            raise ValueError(f"FileRule({self.code!r}) has no match fields; set at least one of "
                             "name, min_size, max_size, magic or md5")


@dataclass(frozen=True)
class FileMatch:
    """One rule that matched one file."""

    code: str
    file_name: str
    matched: list[str] = field(default_factory=list)  # the keyword(s) that fired, e.g. ["name", "size"]


class _RuleMatcher:
    """Applies a single FileRule to a single file."""

    __slots__ = ("rule",)

    def __init__(self, rule: FileRule) -> None:
        self.rule = rule

    def match(self, f: ExtractedFile) -> list[str]:
        """Return the list of keyword names that matched, or an empty list."""
        matched: list[str] = []
        rule = self.rule

        if rule.name is not None and fnmatch.fnmatch(f.name.lower(), rule.name.lower()):
            matched.append("name")

        if rule.min_size is not None and f.size < rule.min_size:
            return []  # size out of range -> no match at all
        if rule.max_size is not None and f.size > rule.max_size:
            return []
        if rule.min_size is not None or rule.max_size is not None:
            matched.append("size")

        if rule.magic is not None:
            info = f.info
            if info is not None and info.mime_type == rule.magic:
                matched.append("magic")
            else:
                return []  # magic mismatch kills the match

        if rule.md5 is not None:
            info = f.info
            if info is not None and info.md5.lower() == rule.md5.lower():
                matched.append("md5")
            else:
                return []  # md5 mismatch kills the match

        return matched


def file_rules_match(
    files: list[ExtractedFile], rules: list[FileRule]
) -> dict[str, list[FileMatch]]:
    """Match Suricata-style file rules against extracted file records.

    Parameters
    ----------
    files:
        The :class:`~pcap_doctor.extract.ExtractedFile` records produced by
        :func:`pcap_doctor.extract.extract`.  Only ``name``, ``size`` and
        ``info`` (a :class:`~pcap_doctor.filetypes.FileInfo`) are read; the
        on-disk file is never opened again.
    rules:
        The :class:`FileRule` set to test.  Each rule is independent.

    Returns
    -------
    dict
        Mapping ``file_name -> list[FileMatch]``.  Files with no matching rule
        get an empty list.  Files that appear in the input but do not match are
        still present as keys with ``[]``.
    """
    matchers = [_RuleMatcher(r) for r in rules]
    by_name: dict[str, list[FileMatch]] = {}
    for f in files:
        hits: list[FileMatch] = []
        for matcher in matchers:
            keywords = matcher.match(f)
            if keywords:
                hits.append(FileMatch(code=matcher.rule.code, file_name=f.name, matched=keywords))
        by_name[f.name] = hits
    return by_name
