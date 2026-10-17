"""Pipeline: capture -> index -> detectors -> artifacts."""

from __future__ import annotations

import re
import ssl
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from . import policy
from .config import Config
from .config import apply as apply_config
from .geoip import GeoIpDb
from .index import CaptureIndex, IndexBuilder
from .keymaterial import KeyMaterial
from .models import SEVERITY_ORDER, ArtifactRef, Finding, Report
from .registry import enabled_detectors
from .render import markdown
from .tshark import TsharkRunner

ARTIFACT_NAMES = ("index.md", "01-flows.md", "02-ciphers.md", "03-findings.md", "04-diagrams.md", "report.json")


@dataclass(frozen=True)
class ProgressEvent:
    """A single structured event emitted during a scan (issue #332).

    ``kind`` discriminates the event shape:

    * ``"pass"``    -- a tshark decode pass started/finished. ``name`` is the
      pass key (e.g. ``"tls"``), ``phase`` is ``"started"``/``"finished"``,
      ``index``/``total`` are the pass position, ``elapsed`` is seconds since
      ``started`` (only set on ``finished``).
    * ``"detector"`` -- a detector started/finished. ``name`` is the detector
      name, ``index``/``total`` its position among the run detectors.
    * ``"finding"`` -- a finding was produced. ``severity`` is its severity,
      ``title``/``code`` identify it.
    """

    kind: str
    name: str
    phase: str = ""
    index: int = 0
    total: int = 0
    elapsed: float | None = None
    severity: str | None = None
    code: str | None = None
    title: str | None = None


@dataclass
class RunResult:
    report: Report
    index: CaptureIndex
    outdir: Path
    artifacts: list[Path]

    @property
    def findings(self) -> list[Finding]:
        return self.report.findings

    def worst(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))[:10]


_DECODE_AS_RE = re.compile(r"^[a-z][a-z0-9_.]*==[0-9]{1,5}(-[0-9]{1,5})?,[a-z][a-z0-9_.-]+$")


class DecodeAsError(ValueError):
    """A --decode-as spec that is not <layer>==<port>,<protocol>."""


def validate_decode_as(specs: tuple[str, ...] | list[str]) -> None:
    """Refuse a malformed decode-as spec before it reaches tshark's argv."""
    for spec in specs:
        if not _DECODE_AS_RE.match(spec):
            raise DecodeAsError(
                f"bad decode-as spec {spec!r}: expected <layer>==<port>,<protocol>, e.g. tcp.port==2121,ftp"
            )


def analyze(
    pcap: Path,
    outdir: Path | None = None,
    *,
    only: tuple[str, ...] = (),
    min_severity: str | None = None,
    categories: tuple[str, ...] = (),
    use_cache: bool = True,
    config: Config | None = None,
    progress: Callable[[str], None] | None = None,
    on_event: Callable[[ProgressEvent], None] | None = None,
    keys: KeyMaterial | None = None,
    firmware_keys: dict[str, str] | None = None,
    signatures: tuple[Path, ...] = (),
    signature_vars: dict[str, str] | None = None,
    iocs: tuple[Path, ...] = (),
    decode_as: tuple[str, ...] = (),
    fast: bool = False,
    jobs: int | None = None,
    geoip: GeoIpDb | None = None,
) -> RunResult:
    policy.validate(only=only, categories=categories, min_severity=min_severity)
    pcap = Path(pcap)
    outdir = Path(outdir or pcap.with_suffix(".pf-report"))
    outdir.mkdir(parents=True, exist_ok=True)

    validate_decode_as(decode_as)
    runner = TsharkRunner(
        pcap,
        use_cache=use_cache,
        extra_args=tuple(arg for spec in decode_as for arg in ("-d", spec)),
        fast=fast,
        jobs=jobs,
    )
    decrypt_args = tuple(keys.tshark_args()) if keys is not None and not keys.is_empty() else ()
    builder = IndexBuilder(runner, decrypt_args=decrypt_args, geoip=geoip, on_event=on_event)
    if progress:
        progress("Reading the capture with tshark")
    index = builder.build()
    if firmware_keys:
        index.firmware_keys = firmware_keys

    if fast:
        note = runner.fast_fallback_note()
        if note:
            index.add_note(note)
        else:
            index.add_note(
                "--fast: port-based passes (DNS/SSH/SIP/Telnet/SMB/NTP) ran on a tcpdump "
                "BPF-filtered sub-capture; protocols on non-standard ports are not covered."
            )

    # Export every TLS certificate seen as PEM, named by its SHA-256 (#212).
    if index.cert_der:
        cert_dir = outdir / "certificates"
        cert_dir.mkdir(parents=True, exist_ok=True)
        for fp in sorted(index.cert_der):
            der = index.cert_der[fp]
            pem = ssl.DER_cert_to_PEM_cert(bytes(der))
            (cert_dir / f"{fp}.pem").write_text(pem)

    if signatures:
        from .signatures import load_rules, match

        rules, rule_warnings = load_rules(list(signatures), signature_vars)
        for warning in rule_warnings:
            index.add_note(f"[signatures] {warning}")
        index.signature_hits = match(index, rules)
        index.add_note(f"[signatures] {len(rules)} rule(s) loaded, {len(index.signature_hits)} match(es)")

    if iocs:
        from .ioc import load_hash_iocs, load_iocs, match_file_hashes, match_iocs

        indicators, ioc_warnings = load_iocs(list(iocs))
        for warning in ioc_warnings:
            index.add_note(warning)
        index.ioc_hits = match_iocs(index, indicators)
        hashes = load_hash_iocs(list(iocs))
        if hashes:
            # Hashes need the objects themselves: extract to a temp dir, hash, match; the bytes are discarded (#236).
            from .extract import PROTOCOLS, extract

            with tempfile.TemporaryDirectory() as tmp:
                extracted = extract(pcap, Path(tmp), PROTOCOLS, decrypt_args)
                index.ioc_hits += match_file_hashes(index, hashes, extracted)
            index.add_note(f"[ioc] {len(hashes)} hash indicator(s) checked against {len(extracted)} extracted object(s)")
        index.add_note(f"[ioc] {len(indicators)} indicator(s) loaded, {len(index.ioc_hits)} match(es)")

    detectors = enabled_detectors(include=only)
    findings: list[Finding] = []
    total_detectors = len(detectors)
    for di, detector in enumerate(detectors, start=1):
        if progress:
            progress(f"Checking {detector.title}")
        if on_event:
            on_event(ProgressEvent(
                kind="detector", name=detector.name, phase="started",
                index=di, total=total_detectors,
            ))
        t0 = time.monotonic()
        try:
            found = detector.detect(index)
        except Exception as exc:  # one bad detector must not sink the run
            index.add_note(
                f"[{detector.name}] detector raised {type(exc).__name__}: {exc} -- other detectors still ran"
            )
            if on_event:
                on_event(ProgressEvent(
                    kind="detector", name=detector.name, phase="finished",
                    index=di, total=total_detectors, elapsed=time.monotonic() - t0,
                ))
            continue
        index.add_note(f"[{detector.name}] ran v{detector.version}: {len(found)} finding(s)")
        findings.extend(found)
        if on_event:
            for f in found:
                on_event(ProgressEvent(
                    kind="finding", name=f.code or "", phase="produced",
                    severity=str(f.severity), code=f.code, title=f.title,
                ))
            on_event(ProgressEvent(
                kind="detector", name=detector.name, phase="finished",
                index=di, total=total_detectors, elapsed=time.monotonic() - t0,
            ))

    if config is not None:
        findings, config_notes = apply_config(findings, config)
        for note in config_notes:
            index.add_note(note)
    kept = policy.apply(findings, categories=categories, min_severity=min_severity)
    if len(kept) < len(findings):
        index.add_note(f"[policy] dropped {len(findings) - len(kept)} finding(s) outside the selected filters")
    findings = kept

    stats = builder.compute_stats(findings)
    report = Report(
        generated_at=datetime.now(UTC).replace(microsecond=0).isoformat(),
        capture=index.capture,
        stats=stats,
        flows=sorted(index.flows.values(), key=lambda f: -f.bytes),
        tls_sessions=sorted(index.tls.values(), key=lambda s: s.key),
        findings=findings,
        detector_versions={d.name: d.version for d in detectors},
        notes=list(index.notes),
    )
    report.artifacts = [
        ArtifactRef(name=name, path=str(outdir / name), kind="markdown" if name.endswith(".md") else "json")
        for name in ARTIFACT_NAMES
    ]

    artifacts = [
        markdown.render_flows(report, index),
        markdown.render_ciphers(report, index),
        markdown.render_findings(report, index),
        markdown.render_diagrams(report, index),
        markdown.render_json(report, outdir / "report.json"),
        markdown.render_index(report, index),
    ]
    return RunResult(report=report, index=index, outdir=outdir, artifacts=artifacts)
