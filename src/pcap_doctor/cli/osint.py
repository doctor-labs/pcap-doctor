"""``osint``: compute capture indicators locally and optionally query an explicit endpoint (issue #277)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast
from urllib import error, request

import typer

from ..index import IndexBuilder
from ..models import Report, Stats
from ..output import json_envelope
from ..tshark import TsharkRunner
from ._console import console, tshark_errors


def _collect_indicators(index: Any, extra_hashes: list[str], extra_domains: list[str]) -> dict[str, Any]:
    file_sha = index.capture.sha256
    names: set[str] = set()
    for q in index.dns:
        if q.name:
            names.add(q.name.rstrip(".").lower())
    for sess in index.tls.values():
        if sess.sni:
            names.add(sess.sni.rstrip(".").lower())
    for ex in index.http:
        if ex.host:
            names.add(ex.host.split(":", 1)[0].rstrip(".").lower())
    for ex in getattr(index, "http2", []):
        if ex.authority:
            names.add(ex.authority.split(":", 1)[0].rstrip(".").lower())
    for cert in (c for s in index.tls.values() for c in s.certs):
        for san in cert.san_dns:
            if san:
                names.add(san.lstrip("*.").rstrip(".").lower())
        for cn in cert.common_names:
            if cn:
                names.add(cn.lstrip("*.").rstrip(".").lower())
    ordered_names = sorted(n for n in names if n)
    hashes = sorted({file_sha, *(h.strip().lower() for h in extra_hashes if h.strip())})
    domains = sorted({*ordered_names, *(d.strip().lower() for d in extra_domains if d.strip())})
    return {"file_sha256": file_sha, "hashes": hashes, "domains": domains}


def _contact_endpoint(endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with request.urlopen(req, timeout=10) as resp:  # nosec - explicit operator opt-in
        raw = resp.read()
    try:
        return cast(dict[str, Any], json.loads(raw.decode("utf-8")))
    except Exception:
        return {"raw": raw.decode("utf-8", errors="replace")}


def osint_cmd(
    pcap: Path = typer.Argument(..., exists=True, readable=True, help="pcap or pcapng file"),
    hash_value: list[str] = typer.Option(None, "--hash", help="hash indicator to include (repeatable)"),
    domain: list[str] = typer.Option(None, "--domain", help="domain/hostname indicator to include (repeatable)"),
    endpoint: str | None = typer.Option(
        None, "--endpoint", help="explicit lookup endpoint to contact; when set, this query leaves the machine"
    ),
    as_json: bool = typer.Option(False, "--json", help="print the doctor/1 envelope as JSON"),
) -> None:
    """Compute capture hashes and indicators locally; contact an endpoint only with explicit --endpoint."""
    with tshark_errors():
        runner = TsharkRunner(pcap)
        index = IndexBuilder(runner).build()

    indicators = _collect_indicators(index, hash_value or [], domain or [])
    payload = {
        "capture": index.capture.name,
        "sha256": indicators["file_sha256"],
        "hashes": indicators["hashes"],
        "domains": indicators["domains"],
    }

    lookups: list[dict[str, Any]] = []
    endpoint_error: str | None = None
    if endpoint:
        msg = "OSINT lookup: this query left the machine (explicit --endpoint)."
        if as_json:
            typer.echo(msg, err=True)
        else:
            console.print(f"[yellow]{msg}[/yellow]")
        try:
            response = _contact_endpoint(endpoint, payload)
        except (error.URLError, TimeoutError, OSError, ValueError) as exc:
            endpoint_error = str(exc)
            response = {"error": endpoint_error}
        contacted = f"Contacted endpoint: {endpoint}"
        if as_json:
            typer.echo(contacted, err=True)
        else:
            console.print(f"[yellow]{contacted}[/yellow]")
        result_text = json.dumps(response, sort_keys=True)
        for h in indicators["hashes"]:
            lookups.append({"kind": "hash", "indicator": h, "endpoint": endpoint, "result": result_text, "frame": 1})
        for d in indicators["domains"]:
            lookups.append({"kind": "domain", "indicator": d, "endpoint": endpoint, "result": result_text, "frame": 1})

    if lookups:
        cast(Any, index).osint_lookups = lookups
        from ..detectors.osint import OsintDetector

        findings = OsintDetector().detect(index)
    else:
        findings = []

    notes = list(index.notes)
    notes.append("OSINT indicators computed locally from the capture; no network contact without --endpoint.")
    if endpoint:
        notes.append(f"OSINT lookup contacted explicit endpoint {endpoint}; this query left the machine.")
    if endpoint_error:
        notes.append(f"OSINT lookup endpoint error: {endpoint_error}")

    stats = Stats(
        packets=index.capture.packets,
        bytes=index.capture.bytes,
        flows=len(index.flows),
        hosts=len(index.hosts),
        tls_sessions=len(index.tls),
        quic_sessions=len(index.quic),
        sip_messages=len(index.sip),
        rtp_streams=len(index.rtp),
        dns_queries=len(index.dns),
        http_exchanges=len(index.http),
        http2_exchanges=len(index.http2),
        ssh_sessions=len(index.ssh),
    )
    report = Report(
        generated_at=index.capture.last_seen.__class__.__name__ and __import__("datetime").datetime.now(__import__("datetime").UTC).replace(microsecond=0).isoformat(),
        capture=index.capture,
        stats=stats,
        flows=sorted(index.flows.values(), key=lambda f: -f.bytes),
        tls_sessions=sorted(index.tls.values(), key=lambda s: s.key),
        findings=sorted(findings, key=lambda f: f.id),
        notes=notes,
        artifacts=[],
    )

    envelope = json_envelope(report, 0)
    envelope["data"]["osint"] = {
        "endpoint_contacted": bool(endpoint),
        "endpoint": endpoint,
        "indicators": indicators,
    }
    if as_json:
        typer.echo(json.dumps(envelope, indent=2))
        return

    # Show local indicators plainly (always).
    console.print(f"Capture SHA-256: {indicators['file_sha256']}")
    console.print(f"Hashes ({len(indicators['hashes'])}): {', '.join(indicators['hashes']) or '-'}")
    console.print(f"Domains/hostnames ({len(indicators['domains'])}): {', '.join(indicators['domains']) or '-'}")
    if not endpoint:
        console.print("No --endpoint provided: no external lookup was performed and nothing left the machine.")
    console.print_json(data=envelope)


def register(app: typer.Typer) -> None:
    app.command("osint")(osint_cmd)
