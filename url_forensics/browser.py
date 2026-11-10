"""Instrumented Playwright observation. Browser JS executes; files do not.

This is reconnaissance, NOT malware detonation. Use only inside a dedicated
throwaway cloud VM/container with egress controls and no credentials.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

from .network import ProbeError, canonical_url, resolve_public

WINDOWS_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
LINUX_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def safe_headers(headers: dict) -> dict:
    """Don't persist authentication, authorization or cookie values."""
    sensitive = {"set-cookie", "cookie", "authorization", "proxy-authorization", "x-api-key"}
    return {k.lower(): ("[REDACTED]" if k.lower() in sensitive else str(v)[:2048])
            for k, v in headers.items() if len(k) < 100}


async def observe(raw_url: str, output: Path, profile: str = "linux",
                  timeout_ms: int = 15000, max_requests: int = 100,
                  settle_ms: int = 2000) -> dict:
    """Observe a single site visit with no clicks, form posts or stored downloads."""
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError("Browser extras missing: pip install -e '.[browser]'") from exc

    url = canonical_url(raw_url)
    # Do initial DNS validation before the browser starts.
    await asyncio.to_thread(resolve_public, url)
    output.mkdir(parents=True, exist_ok=True)
    report: dict = {
        "profile": profile, "requested_url": url, "requests": [], "responses": [],
        "blocked": [], "downloads_cancelled": [], "console": [], "page_errors": [],
        "websockets_blocked": [], "popups_closed": 0, "screenshot": None,
        "mode": "browser", "warning": (
            "Playwright route interception cannot enforce IP pinning on browser DNS/"
            "redirects. A VM-level deny-private firewall is needed for strong isolation. "
            "The Windows profile only changes the user-agent, not the operating system."
        ),
    }
    ua = WINDOWS_UA if profile == "windows-ua" else LINUX_UA
    request_counter = 0
    pending_downloads = []
    start = time.monotonic()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent=ua, accept_downloads=False, service_workers="block",
            permissions=[], ignore_https_errors=False, java_script_enabled=True,
            viewport={"width": 1280, "height": 900},
            record_har_path=str(output / "traffic.har"), record_har_content="omit",
            record_har_mode="full",
        )
        context.set_default_timeout(timeout_ms)

        async def gate(route):
            nonlocal request_counter
            req = route.request
            request_counter += 1
            reason = None
            if request_counter > max_requests:
                reason = "request_budget_exceeded"
            elif req.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
                reason = "non_read_only_method"
            else:
                try:
                    target = canonical_url(req.url)
                    # Check DNS answers for *each* first-party / third-party request.
                    await asyncio.wait_for(asyncio.to_thread(resolve_public, target), timeout=5)
                except (ProbeError, OSError, TimeoutError, asyncio.TimeoutError) as exc:
                    reason = f"unsafe_or_unresolvable_destination: {str(exc)[:160]}"
            if reason:
                report["blocked"].append({"url": req.url[:2048], "method": req.method,
                                          "reason": reason})
                await route.abort("blockedbyclient")
            else:
                await route.continue_()

        await context.route("**/*", gate)

        # Playwright exposes a separate websocket route API in modern versions.
        if hasattr(context, "route_web_socket"):
            async def refuse_ws(socket_route):
                report["websockets_blocked"].append(str(socket_route.url)[:2048])
                await socket_route.close()
            await context.route_web_socket("**/*", refuse_ws)

        page = await context.new_page()

        def on_request(req):
            report["requests"].append({
                "url": req.url[:2048], "method": req.method,
                "type": req.resource_type,
                "redirected_from": req.redirected_from.url[:2048] if req.redirected_from else None,
            })

        def on_response(resp):
            report["responses"].append({
                "url": resp.url[:2048], "status": resp.status,
                "headers": safe_headers(resp.headers),
            })

        def on_download(download):
            report["downloads_cancelled"].append({
                "url": download.url[:2048], "suggested_filename": download.suggested_filename[:255]
            })
            pending_downloads.append(asyncio.create_task(download.cancel()))

        def on_popup(popup):
            report["popups_closed"] += 1
            asyncio.create_task(popup.close())

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("download", on_download)
        page.on("popup", on_popup)
        page.on("console", lambda msg: report["console"].append({
            "type": msg.type, "text": msg.text[:500]}) if len(report["console"]) < 100 else None)
        page.on("pageerror", lambda err: report["page_errors"].append(str(err)[:500])
                if len(report["page_errors"]) < 100 else None)
        page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            await page.wait_for_timeout(min(settle_ms, 10000))
        except Exception as exc:
            report["navigation_error"] = f"{type(exc).__name__}: {str(exc)[:500]}"
        try:
            report["final_url"] = page.url
            report["title"] = (await page.title())[:500]
            report["visible_text"] = (await page.locator("body").inner_text(timeout=2000))[:10000]
            screenshot_path = output / "screenshot.png"
            await page.screenshot(path=str(screenshot_path), full_page=False, timeout=3000)
            report["screenshot"] = screenshot_path.name
        except Exception as exc:
            report["page_capture_error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
        if pending_downloads:
            await asyncio.gather(*pending_downloads, return_exceptions=True)
        # HAR is flushed when context closes. No downloaded bodies are persisted.
        await context.close()
        await browser.close()
    report["elapsed_seconds"] = round(time.monotonic() - start, 2)
    report["request_count"] = request_counter
    return report
