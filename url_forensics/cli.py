"""Command line UI for metadata and optional browser inspection."""
from __future__ import annotations

import argparse
import hashlib
import asyncio
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .network import ProbeError, canonical_url, metadata_probe, http_probe, CLIENT_PROFILES
from .evidence import (_final_response, destination_stats, is_decoy_page, page_destination,
                       response_shape)

MATRIX_CELLS = (
    ('tool, no referer', 'tool', None),
    ('chrome-windows, no referer', 'chrome-windows', None),
    ('chrome-windows, Gmail referer', 'chrome-windows', 'https://mail.google.com/'),
    ('chrome-linux, no referer', 'chrome-linux', None),
)


def _cell_summary(label, profile, referer, captures):
    """Summarize one matrix cell by response shape, not by (rotating) destination."""
    signatures, statuses, sizes, destinations, errors = set(), {}, [], [], 0
    for capture in captures:
        response = _final_response(capture)
        if not response:
            errors += 1
            continue
        body = response.get('payload', {})
        if body.get('encoding') == 'utf-8':
            shape = 'text:' + response_shape(body.get('data', ''))
        else:
            shape = 'binary:' + str(body.get('sha256_captured', 'unknown'))
        statuses[response['status']] = statuses.get(response['status'], 0) + 1
        signatures.add(f"{response['status']}:{shape}")
        sizes.append(body.get('captured_bytes', 0))
        if is_decoy_page(response) and page_destination(response):
            destinations.append(page_destination(response))
    return {'label': label, 'client_profile': profile, 'referer': referer, 'captures': len(captures),
            'errors': errors, 'statuses': statuses, 'body_bytes': [min(sizes), max(sizes)] if sizes else None,
            'signatures': sorted(signatures), 'destinations': destination_stats(destinations)}


def _safe_markdown(value: object) -> str:
    return str(value).replace("<", "&lt;").replace(">", "&gt;").replace("`", "'").replace("\n", " ")[:1000]


def _render(report: dict) -> str:
    lines = ["# URL Forensics report", "", f"Generated (UTC): {_safe_markdown(report['time_utc'])}",
             f"Target: `{_safe_markdown(report['url'])}`", f"Mode: **{report['mode']}**", "",
             "## Metadata probe", ""]
    a = report.get("assessment", {})
    lines.extend(["## Risk triage", "", f"Observed risk: **{a.get('risk_level', 'unknown')}**", "", a.get("basis", ""), ""])
    lines.extend([f"Delivery stage observed: **{_safe_markdown(a.get('delivery_stage', 'unknown'))}**", ""])
    for ident in a.get("identifiers", []):
        lines.append(f"- Indicator `{_safe_markdown(ident['kind'])}`: `{_safe_markdown(ident['token'])}` (from {_safe_markdown(ident['source'])})")
    stats = a.get("destination_stats") or {}
    if stats.get("samples"):
        lines.extend(["", f"Client-side redirect destinations: {stats['samples']} samples, {stats['distinct']} distinct hosts, "
                      f"estimated pool about {stats['estimated_pool_size']}. " + _safe_markdown(stats['limitation']), ""])
        lines.extend(f"- `{_safe_markdown(host)}`: {count}" for host, count in stats["counts"].items())
        lines.append("")
    matrix = report.get("matrix")
    if matrix:
        lines.extend(["### Client profile matrix", "", "| Profile | Captures | Statuses | Body bytes | Response shapes | Distinct destinations |", "|---|---:|---|---|---:|---:|"])
        for cell in matrix["cells"]:
            lines.append(f"| {_safe_markdown(cell['label'])} | {cell['captures']} | {_safe_markdown(cell['statuses'])} | "
                         f"{_safe_markdown(cell['body_bytes'])} | {len(cell['signatures'])} | {cell['destinations']['distinct']} |")
        lines.append("")
    for finding in a.get("findings", []):
        lines.append(f"- **{finding['severity']} / {finding['code']}**: {_safe_markdown(finding['detail'])} (`{_safe_markdown(finding['evidence'])}`)")
    lines.extend(["", "### Collection gaps", ""])
    for gap in a.get("collection_gaps", []):
        lines.append(f"- {_safe_markdown(gap['reason'])} (`{_safe_markdown(gap['evidence'])}`)")
    lines.extend(["", "Payloads and complete envelopes: `report.json`. Treat captured content as untrusted data.", ""])
    p = report.get("http", report.get("metadata", {}))
    for item in p.get("requests", []):
        http = item.get("http") or {}
        lines.extend([f"### Hop {item['hop']}", "",
                      f"URL: `{_safe_markdown(item['url'])}`", "",
                      f"Resolved IPs: `{_safe_markdown(', '.join(item.get('dns_ips', [])))}`", "",
                      f"TLS: `{_safe_markdown((item.get('tls') or {}).get('status', 'n/a'))}`", "",
                      f"HTTP: `{_safe_markdown(http.get('status', item.get('error', 'n/a')))}`", ""])
        for key, val in http.get("headers", {}).items():
            lines.append(f"- `{_safe_markdown(key)}`: {_safe_markdown(val)}")
        lines.append("")
    lines.extend([f"Stop reason: `{_safe_markdown(p.get('stop_reason', 'n/a'))}`", ""])
    for entry in report.get("browser", []):
        lines.extend([f"## Browser visit: {_safe_markdown(entry['profile'])}", "",
                      f"Final URL: `{_safe_markdown(entry.get('final_url', 'n/a'))}`", "",
                      f"Page title: {_safe_markdown(entry.get('title', 'n/a'))}", "",
                      f"Requests: **{len(entry.get('requests', []))}**; "
                      f"responses: **{len(entry.get('responses', []))}**; "
                      f"blocked: **{len(entry.get('blocked', []))}**; "
                      f"downloads cancelled: **{len(entry.get('downloads_cancelled', []))}**", ""])
        if entry.get("navigation_error"):
            lines.extend([f"Navigation error: {_safe_markdown(entry['navigation_error'])}", ""])
        if entry.get("downloads_cancelled"):
            lines.append("### Cancelled downloads")
            for d in entry["downloads_cancelled"][:20]:
                lines.append(f"- `{_safe_markdown(d['suggested_filename'])}` from `{_safe_markdown(d['url'])}`")
            lines.append("")
        lines.append(f"Detailed evidence: `browser/{entry['profile']}/traffic.har`, plus `report.json`.")
        lines.append("")
    lines.extend(["## Interpretation boundaries", "",
                  "- No malware classification or attribution can be established from these probes alone.",
                  "- Browser JavaScript can execute inside the disposable browser. Downloads are cancelled, not analyzed.",
                  "- Browser URL filtering is not a substitute for VM-level egress isolation.",
                  "- A Windows user-agent is not a Windows VM; servers may still fingerprint Linux.",
                  "- A refused, blank, or error response does not demonstrate the URL is safe.", ""])
    return "\n".join(lines)


def run(args: argparse.Namespace) -> tuple[Path, dict]:
    url = canonical_url(args.url)
    output = Path(args.output).expanduser().resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("Output directory must be empty or nonexistent, to avoid overwriting evidence")
    output.mkdir(parents=True, exist_ok=True)
    report: dict = {
        "url": url, "mode": args.mode,
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "schema_version": "0.2.0",
        "metadata": metadata_probe(url, max_redirects=args.max_redirects, timeout=args.timeout) if args.mode == "passive" else {},
        "browser": [],
    }
    def probe(profile=None, referer=None, language=None):
        return http_probe(url, max_redirects=args.max_redirects, timeout=args.timeout,
                          max_body_bytes=args.max_body_bytes,
                          client_profile=profile or args.client_profile,
                          referer=referer if referer is not None else args.referer,
                          accept_language=language or args.accept_language)

    if args.mode in {"http", "browser"}:
        report["http"] = probe()
    if args.mode in {"http", "browser"} and args.repeat > 1:
        captures = [report["http"]] + [probe() for _ in range(args.repeat - 1)]
        report["http_repeats"] = captures
        hashes, targets = {}, {}
        for i, capture in enumerate(captures):
            for hop in capture.get("requests", []):
                response = hop.get("http", {})
                digest = response.get("payload", {}).get("sha256_captured")
                if digest:
                    hashes.setdefault(digest, []).append(i + 1)
                for item in response.get("content_indicators", {}).get("links_and_forms", []):
                    if item.get("refresh"):
                        targets.setdefault(item["refresh"], []).append(i + 1)
                    if item.get("js_navigation"):
                        targets.setdefault(item["js_navigation"], []).append(i + 1)
                if hop.get("redirect"):
                    targets.setdefault(hop["redirect"]["to"], []).append(i + 1)
        report["repeat_comparison"] = {"body_hashes": hashes, "redirect_targets": targets, "limitation": "Same configuration; variability does not prove cloaking or identify its cause."}
    if args.matrix and args.mode in {"http", "browser"}:
        per_cell = min(10, max(args.repeat, 5))
        cells = []
        for label, profile, referer in MATRIX_CELLS:
            captures = []
            for _ in range(per_cell):
                captures.append(probe(profile=profile, referer=referer or "", language=None))
                time.sleep(0.25)
            cells.append(_cell_summary(label, profile, referer, captures))
        report["matrix"] = {"captures_per_cell": per_cell, "cells": cells,
                            "limitation": "Header-level differences only: Python's TLS fingerprint and header order are unchanged, and the exit IP is constant."}
    if args.mode == "browser":
        from .browser import observe
        profiles = ["linux", "windows-ua"] if args.profile == "both" else [args.profile]
        for profile in profiles:
            target_dir = output / "browser" / profile
            try:
                result = asyncio.run(observe(url, target_dir, profile=profile,
                                  timeout_ms=int(args.timeout * 1000), max_requests=args.max_requests,
                                  settle_ms=args.settle_ms, max_body_bytes=args.max_body_bytes,
                                  ignore_https_errors=args.ignore_https_errors, screenshot=args.screenshot,
                                  referer=args.referer, locale=args.locale, timezone_id=args.timezone))
            except Exception as exc:
                result = {"profile": profile, "error": f"{type(exc).__name__}: {str(exc)[:500]}",
                          "requests": [], "responses": [], "blocked": [], "downloads_cancelled": []}
            report["browser"].append(result)
    from .evidence import analyze
    report["assessment"] = analyze(report)
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    (output / "report.md").write_text(_render(report), encoding="utf-8")
    manifest = []
    for artifact in sorted(output.rglob("*")):
        if artifact.is_file():
            manifest.append({"path": str(artifact.relative_to(output)), "bytes": artifact.stat().st_size,
                             "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()})
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return output, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect public URLs in a disposable cloud environment")
    parser.add_argument("--url", required=True, help="Public http(s) URL. Never supply credentials.")
    parser.add_argument("--mode", choices=["passive", "http", "browser"], default="passive",
                        help="passive=DNS/TLS/HEAD; http=bounded GET payloads; browser=GET plus JS-enabled Chromium")
    parser.add_argument("--output", default="./reports/inspection", help="New/empty report directory")
    parser.add_argument("--profile", choices=["linux", "windows-ua", "both"], default="both")
    parser.add_argument("--timeout", type=float, default=12.0, help="Per-network step timeout in seconds")
    parser.add_argument("--max-requests", type=int, default=100)
    parser.add_argument("--max-redirects", type=int, default=6)
    parser.add_argument("--settle-ms", type=int, default=2000)
    parser.add_argument("--max-body-bytes", type=int, default=262144, help="Payload bytes captured per response (1–1048576)")
    parser.add_argument("--ignore-https-errors", action="store_true", help="Allow invalid browser TLS certificates")
    parser.add_argument("--screenshot", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--repeat", type=int, default=1, help="Number of HTTP captures (1-10)")
    parser.add_argument("--client-profile", choices=CLIENT_PROFILES, default="tool",
                        help="Header set for GET captures: tool (identifying) or Chrome-like navigation headers")
    parser.add_argument("--referer", default=None, help="Referer to send, e.g. https://mail.google.com/")
    parser.add_argument("--accept-language", default=None, help="Accept-Language value, e.g. en-CA,en;q=0.9")
    parser.add_argument("--locale", default=None, help="Browser locale, e.g. en-CA")
    parser.add_argument("--timezone", default=None, help="Browser timezone id, e.g. America/Edmonton")
    parser.add_argument("--matrix", action="store_true",
                        help="Compare response shapes across header/referrer profiles (http/browser modes; max 4 x 10 GETs)")
    args = parser.parse_args(argv)
    if not 1 <= args.repeat <= 10:
        parser.error("repeat must be 1-10")
    if args.matrix and args.mode == "passive":
        parser.error("--matrix needs --mode http or browser")
    if not 1 <= args.max_body_bytes <= 1048576:
        parser.error("max-body-bytes must be 1–1048576")
    if args.timeout < 1 or args.timeout > 60 or not 1 <= args.max_requests <= 500 or not 0 <= args.max_redirects <= 12 or not 0 <= args.settle_ms <= 10000:
        parser.error("Out-of-range timeout, request, redirect or settle limit")
    try:
        path, report = run(args)
    except (ProbeError, ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(f"Report: {path / 'report.md'}\nEvidence: {path / 'report.json'}")
    for browser in report["browser"]:
        if browser.get("error"):
            print(f"Browser [{browser['profile']}] error: {browser['error']}", file=sys.stderr)
    return 0 if not any(item.get("error") for item in report["browser"]) else 1


if __name__ == "__main__":
    sys.exit(main())
