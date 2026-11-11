"""Real-Chrome DevTools recorder.

Launches (or passively attaches to) an installed Chrome and records what the
DevTools panels would show: network with initiators, redirect chains, raw
headers, certificates, response bodies, navigation reasons, console, cookies,
storage, scripts, and a fingerprint self-report. It never clicks, types or
submits anything (the CDP client refuses Input.* commands), denies downloads,
closes popups, and dismisses dialogs.

This is reconnaissance, NOT malware detonation. Run it only inside a
disposable VM or sandbox with no credentials. Page content is untrusted.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .cdp import CdpConnection, CdpError
from .evidence import extract_content, header_list, payload
from .network import ProbeError, canonical_url, resolve_public

CDP_LEVELS = ("quiet", "full")
BODY_TYPES_ALWAYS = {"Document"}
BODY_TYPES_TEXTUAL = {"Script", "XHR", "Fetch", "Other"}
BINDING = "__cdp_forensics"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
SAFE_FLAG_MESSAGE = ("DevTools mode launches a real browser that executes page JavaScript. Confirm you are in a "
                     "disposable VM or sandbox with no credentials by passing --i-am-in-a-disposable-vm "
                     "(or set URL_FORENSICS_DISPOSABLE=1).")

FINGERPRINT_JS = """(async () => {
  const out = {}, n = navigator;
  out.userAgent = n.userAgent; out.platform = n.platform; out.vendor = n.vendor;
  out.language = n.language; out.languages = Array.from(n.languages || []);
  out.webdriver = n.webdriver; out.hardwareConcurrency = n.hardwareConcurrency;
  out.deviceMemory = n.deviceMemory; out.maxTouchPoints = n.maxTouchPoints;
  out.pluginsLength = n.plugins ? n.plugins.length : null; out.cookieEnabled = n.cookieEnabled;
  out.screen = {width: screen.width, height: screen.height, availWidth: screen.availWidth,
                availHeight: screen.availHeight, colorDepth: screen.colorDepth, dpr: devicePixelRatio};
  out.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  out.timezoneOffsetMinutes = new Date().getTimezoneOffset();
  out.hasChromeObject = typeof window.chrome === 'object';
  out.notificationPermission = typeof Notification !== 'undefined' ? Notification.permission : null;
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    const ext = gl && gl.getExtension('WEBGL_debug_renderer_info');
    out.webgl = ext ? {vendor: gl.getParameter(ext.UNMASKED_VENDOR_WEBGL), renderer: gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)} : null;
  } catch (e) { out.webgl = 'error'; }
  if (n.userAgentData) {
    try {
      out.userAgentData = {brands: n.userAgentData.brands, mobile: n.userAgentData.mobile,
        platform: n.userAgentData.platform,
        high: await n.userAgentData.getHighEntropyValues(['platformVersion', 'architecture', 'bitness', 'fullVersionList'])};
    } catch (e) { out.userAgentData = 'error'; }
  }
  return out;
})()"""

STORAGE_JS = """(() => { const d = {};
  for (const [name, s] of [['local', 'localStorage'], ['session', 'sessionStorage']]) {
    try { const st = window[s]; d[name] = Object.keys(st).slice(0, 50).map(k => [k, String(st.getItem(k)).slice(0, 200)]); }
    catch (e) { d[name] = 'error'; } }
  return d; })()"""

DOM_JS = "document.documentElement ? document.documentElement.outerHTML.slice(0, 262144) : ''"


# --------------------------------------------------------------------------- helpers

def cookie_names(header_value: str, set_cookie: bool) -> list[str]:
    """Cookie names only; values are never stored."""
    names = []
    for line in str(header_value).split("\n" if set_cookie else ";"):
        name = line.split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name[:128])
    return names[:50]


def fingerprint_tells(fp) -> list[str]:
    """Page-visible traits a filter could use to recognise automation, VMs or headless runs."""
    if not isinstance(fp, dict):
        return []
    tells = []
    ua, platform = str(fp.get("userAgent", "")), str(fp.get("platform", ""))
    if fp.get("webdriver") is True:
        tells.append("navigator.webdriver is true")
    if "HeadlessChrome" in ua:
        tells.append("user agent contains HeadlessChrome")
    if "Windows" in ua and not platform.startswith("Win"):
        tells.append(f"user agent says Windows but navigator.platform is {platform!r}")
    if "Macintosh" in ua and not platform.startswith("Mac"):
        tells.append(f"user agent says macOS but navigator.platform is {platform!r}")
    if fp.get("pluginsLength") == 0:
        tells.append("no plugins reported (real Chrome lists its PDF viewers)")
    if not fp.get("languages"):
        tells.append("empty navigator.languages")
    if fp.get("hasChromeObject") is False:
        tells.append("window.chrome is missing")
    webgl = fp.get("webgl")
    renderer = str(webgl.get("renderer", "")) if isinstance(webgl, dict) else ""
    if any(s in renderer for s in ("SwiftShader", "llvmpipe", "Basic Render", "WARP")):
        tells.append(f"software WebGL renderer ({renderer[:80]}): typical of VMs, sandboxes and headless runs")
    return tells


def find_chrome(explicit: str | None = None) -> str:
    if explicit:
        if os.path.isfile(explicit):
            return explicit
        raise RuntimeError(f"Chrome not found at {explicit}")
    candidates = []
    if os.environ.get("URL_FORENSICS_CHROME"):
        candidates.append(os.environ["URL_FORENSICS_CHROME"])
    if sys.platform == "win32":
        for var in ("ProgramFiles", "ProgramFiles(x86)", "LocalAppData"):
            if os.environ.get(var):
                candidates.append(os.path.join(os.environ[var], "Google", "Chrome", "Application", "chrome.exe"))
    elif sys.platform == "darwin":
        candidates.append("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    raise RuntimeError("Chrome not found. Install Google Chrome or pass --chrome-path.")


def chrome_args(profile_dir: str, *, headless: bool = False, no_sandbox: bool = False,
                proxy: str | None = None, ignore_https_errors: bool = False,
                locale: str | None = None) -> list[str]:
    args = [f"--user-data-dir={profile_dir}", "--remote-debugging-port=0", "--no-first-run",
            "--no-default-browser-check", "--disable-extensions", "--disable-sync"]
    if headless:
        args.append("--headless=new")
    if no_sandbox:
        args.append("--no-sandbox")
    if proxy:
        args.append(f"--proxy-server={proxy}")
    if ignore_https_errors:
        args.append("--ignore-certificate-errors")
    if locale:
        args.append(f"--lang={locale}")
    return args


def validate_endpoint(endpoint: str) -> str:
    """Only attach to a DevTools endpoint on this machine."""
    parts = urlsplit(endpoint)
    if parts.scheme not in {"http", "ws"} or (parts.hostname or "") not in LOOPBACK_HOSTS:
        raise ValueError("--cdp-endpoint must be an http:// or ws:// URL on localhost / 127.0.0.1")
    return endpoint


def _iso(epoch) -> str | None:
    try:
        return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _span(a, b):
    if a is None or b is None or a < 0 or b < 0:
        return None
    return round(b - a, 2)


# --------------------------------------------------------------------------- recorder

class CdpRecorder:
    """Pure aggregator of CDP events. on_event returns follow-up actions for the driver."""

    def __init__(self, max_requests: int = 100, max_body_bytes: int = 262144, max_bodies: int = 40,
                 level: str = "quiet", close_popups: bool = True):
        if level not in CDP_LEVELS:
            raise ValueError(f"Unknown CDP level: {level}")
        self.max_requests, self.max_body_bytes, self.max_bodies = max_requests, max_body_bytes, max_bodies
        self.level, self.close_popups = level, close_popups
        self.records: dict[str, dict] = {}
        self.dropped = 0
        self._dropped_keys: set[str] = set()
        self._extra_req: dict[str, list] = {}
        self._extra_resp: dict[str, list] = {}
        self.bodies: dict[str, dict] = {}
        self._bodies_requested = 0
        self.navigations, self.lifecycle, self.console, self.page_errors = [], [], [], []
        self.scripts: dict[str, dict] = {}
        self.script_sources: list[dict] = []
        self.breakpoint_hits, self.hook_events = [], []
        self.downloads, self.popups, self.dialogs, self.websockets = [], [], [], []
        self.inflight: set[str] = set()
        self.last_activity = time.monotonic()

    # -- plumbing
    @staticmethod
    def _key(session, request_id) -> str:
        return f"{session or ''}:{request_id}"

    def touch(self) -> None:
        self.last_activity = time.monotonic()

    def on_event(self, method: str, params: dict, session=None) -> list[dict]:
        handler = getattr(self, "_h_" + method.replace(".", "_"), None)
        if handler is None:
            return []
        return handler(params, session) or []

    # -- network
    @staticmethod
    def _initiator(initiator: dict) -> dict:
        frames = ((initiator.get("stack") or {}).get("callFrames") or [])[:6]
        return {"type": initiator.get("type"), "url": str(initiator.get("url", ""))[:2048],
                "line": initiator.get("lineNumber"), "column": initiator.get("columnNumber"),
                "stack": [{"function": f.get("functionName", "")[:128], "url": str(f.get("url", ""))[:2048],
                           "line": f.get("lineNumber")} for f in frames]}

    @staticmethod
    def _security(details) -> dict | None:
        if not details:
            return None
        return {"protocol": details.get("protocol"), "key_exchange": details.get("keyExchange"),
                "cipher": details.get("cipher"), "subject": details.get("subjectName"),
                "san": list(details.get("sanList") or [])[:20], "issuer": details.get("issuer"),
                "valid_from": _iso(details.get("validFrom")), "valid_to": _iso(details.get("validTo"))}

    def _response(self, resp: dict) -> dict:
        timing = resp.get("timing") or {}
        return {"status": resp.get("status"), "status_text": resp.get("statusText"),
                "url": str(resp.get("url", ""))[:4096], "mime_type": resp.get("mimeType"),
                "protocol": resp.get("protocol"), "remote_ip": resp.get("remoteIPAddress"),
                "remote_port": resp.get("remotePort"), "from_disk_cache": resp.get("fromDiskCache"),
                "from_service_worker": resp.get("fromServiceWorker"),
                "headers": header_list((resp.get("headers") or {}).items()),
                "security": self._security(resp.get("securityDetails")),
                "timing_ms": {"dns": _span(timing.get("dnsStart"), timing.get("dnsEnd")),
                              "connect": _span(timing.get("connectStart"), timing.get("connectEnd")),
                              "ssl": _span(timing.get("sslStart"), timing.get("sslEnd")),
                              "send": _span(timing.get("sendStart"), timing.get("sendEnd")),
                              "wait": _span(timing.get("sendEnd"), timing.get("receiveHeadersEnd"))}}

    def _h_Network_requestWillBeSent(self, params, session):
        key = self._key(session, params["requestId"])
        if key in self._dropped_keys:
            return []
        request = params.get("request") or {}
        hop = {"url": str(request.get("url", ""))[:4096], "method": request.get("method"),
               "request_headers": header_list((request.get("headers") or {}).items()),
               "has_post_data": bool(request.get("hasPostData")), "wall_time": _iso(params.get("wallTime"))}
        record = self.records.get(key)
        if record is None:
            if len(self.records) >= self.max_requests:
                self._dropped_keys.add(key)
                self.dropped += 1
                return []
            record = {"id": key, "request_id": params["requestId"], "session": session,
                      "type": params.get("type"), "frame_id": params.get("frameId"),
                      "document_url": str(params.get("documentURL", ""))[:4096],
                      "initiator": self._initiator(params.get("initiator") or {}),
                      "has_user_gesture": params.get("hasUserGesture"), "hops": [], "failed": None,
                      "finished": False}
            self.records[key] = record
        elif params.get("redirectResponse") and record["hops"]:
            record["hops"][-1]["response"] = self._response(params["redirectResponse"])
        record["hops"].append(hop)
        self.inflight.add(key)
        self.touch()
        return []

    def _h_Network_requestWillBeSentExtraInfo(self, params, session):
        self._extra_req.setdefault(self._key(session, params["requestId"]), []).append(params)

    def _h_Network_responseReceivedExtraInfo(self, params, session):
        self._extra_resp.setdefault(self._key(session, params["requestId"]), []).append(params)

    def _h_Network_responseReceived(self, params, session):
        record = self.records.get(self._key(session, params["requestId"]))
        if record and record["hops"]:
            record["hops"][-1]["response"] = self._response(params.get("response") or {})
            record["type"] = params.get("type", record["type"])
        self.touch()

    @staticmethod
    def _textual_mime(mime: str) -> bool:
        mime = (mime or "").lower()
        return (not mime or mime.startswith("text/") or any(t in mime for t in ("json", "javascript", "xml", "html")))

    def _h_Network_loadingFinished(self, params, session):
        key = self._key(session, params["requestId"])
        record = self.records.get(key)
        self.inflight.discard(key)
        self.touch()
        if record is None:
            return []
        record["finished"] = True
        record["encoded_data_length"] = params.get("encodedDataLength")
        response = (record["hops"][-1].get("response") if record["hops"] else None) or {}
        status = response.get("status")
        wanted = (record["type"] in BODY_TYPES_ALWAYS
                  or (record["type"] in BODY_TYPES_TEXTUAL and self._textual_mime(response.get("mime_type"))))
        if (status and not 300 <= status < 400 and wanted and self._bodies_requested < self.max_bodies):
            self._bodies_requested += 1
            return [{"kind": "body", "key": key, "request_id": record["request_id"], "session": session}]
        return []

    def _h_Network_loadingFailed(self, params, session):
        key = self._key(session, params["requestId"])
        record = self.records.get(key)
        self.inflight.discard(key)
        self.touch()
        if record is not None:
            record["failed"] = {"error": params.get("errorText"), "canceled": params.get("canceled"),
                                "blocked_reason": params.get("blockedReason"),
                                "cors_error": (params.get("corsErrorStatus") or {}).get("corsError")}

    def _h_Network_webSocketCreated(self, params, session):
        if len(self.websockets) < 20:
            self.websockets.append({"id": self._key(session, params.get("requestId")),
                                    "url": str(params.get("url", ""))[:2048],
                                    "initiator": self._initiator(params.get("initiator") or {}),
                                    "frames_sent": 0, "frames_received": 0, "samples": []})

    def _ws_frame(self, params, session, field):
        key = self._key(session, params.get("requestId"))
        for item in self.websockets:
            if item["id"] == key:
                item[field] += 1
                if len(item["samples"]) < 5:
                    item["samples"].append({"direction": field, "data": str((params.get("response") or {}).get("payloadData", ""))[:200]})

    def _h_Network_webSocketFrameSent(self, params, session):
        self._ws_frame(params, session, "frames_sent")

    def _h_Network_webSocketFrameReceived(self, params, session):
        self._ws_frame(params, session, "frames_received")

    # -- bodies (called by the driver)
    def on_body(self, key: str, body: str, base64_encoded: bool) -> None:
        data = base64.b64decode(body) if base64_encoded else str(body).encode("utf-8", errors="replace")
        record = self.records.get(key) or {}
        response = (record.get("hops") or [{}])[-1].get("response") or {}
        self.bodies[key] = payload(data, self.max_body_bytes, response.get("mime_type") or "")

    def on_body_error(self, key: str, reason: str) -> None:
        self.bodies[key] = {"status": "unavailable", "reason": str(reason)[:200]}

    def set_script_source(self, key: str, text: str) -> None:
        info = self.scripts.get(key, {})
        item = payload(text.encode("utf-8", errors="replace"), self.max_body_bytes, "text/javascript")
        item.update(script_id=info.get("script_id"), url=info.get("url"), kind=info.get("kind"))
        self.script_sources.append(item)

    # -- page / target
    def _h_Page_frameRequestedNavigation(self, params, session):
        self.navigations.append({"kind": "requested", "reason": params.get("reason"),
                                 "url": str(params.get("url", ""))[:4096], "frame_id": params.get("frameId"),
                                 "disposition": params.get("disposition")})
        self.touch()

    def _h_Page_frameNavigated(self, params, session):
        frame = params.get("frame") or {}
        self.navigations.append({"kind": "committed", "url": str(frame.get("url", ""))[:4096],
                                 "frame_id": frame.get("id"), "parent_id": frame.get("parentId"),
                                 "mime_type": frame.get("mimeType"), "loader_id": frame.get("loaderId")})
        self.touch()

    def _h_Page_navigatedWithinDocument(self, params, session):
        self.navigations.append({"kind": "same_document", "url": str(params.get("url", ""))[:4096],
                                 "frame_id": params.get("frameId"), "navigation_type": params.get("navigationType")})

    def _h_Page_lifecycleEvent(self, params, session):
        if params.get("name") in {"DOMContentLoaded", "load", "networkIdle", "firstPaint"} and len(self.lifecycle) < 100:
            self.lifecycle.append({"name": params["name"], "frame_id": params.get("frameId"),
                                   "timestamp": params.get("timestamp")})
        self.touch()

    def _h_Page_javascriptDialogOpening(self, params, session):
        self.dialogs.append({"type": params.get("type"), "message": str(params.get("message", ""))[:500],
                             "url": str(params.get("url", ""))[:2048]})
        return [{"kind": "cdp", "method": "Page.handleJavaScriptDialog", "params": {"accept": False}, "session": session}]

    def _h_Target_targetCreated(self, params, session):
        info = params.get("targetInfo") or {}
        if info.get("type") == "page" and info.get("openerId"):
            self.popups.append({"url": str(info.get("url", ""))[:2048], "target_id": info.get("targetId"),
                                "opener_id": info.get("openerId")})
            if self.close_popups:
                return [{"kind": "cdp", "method": "Target.closeTarget",
                         "params": {"targetId": info.get("targetId")}, "session": None}]

    def _h_Browser_downloadWillBegin(self, params, session):
        self.downloads.append({"url": str(params.get("url", ""))[:4096],
                               "suggested_filename": str(params.get("suggestedFilename", ""))[:255],
                               "frame_id": params.get("frameId")})

    # -- runtime / log / debugger (full level)
    @staticmethod
    def _arg_text(arg: dict) -> str:
        return str(arg.get("value", arg.get("description", arg.get("type", ""))))

    def _h_Runtime_consoleAPICalled(self, params, session):
        if len(self.console) < 100:
            text = " ".join(self._arg_text(a) for a in params.get("args", []))[:500]
            self.console.append({"type": params.get("type"), "text": text})

    def _h_Runtime_exceptionThrown(self, params, session):
        details = params.get("exceptionDetails") or {}
        if len(self.page_errors) < 100:
            description = (details.get("exception") or {}).get("description") or details.get("text", "")
            self.page_errors.append({"text": str(description)[:500], "url": str(details.get("url", ""))[:2048],
                                     "line": details.get("lineNumber")})

    def _h_Log_entryAdded(self, params, session):
        entry = params.get("entry") or {}
        if len(self.console) < 100:
            self.console.append({"type": f"log:{entry.get('source')}/{entry.get('level')}",
                                 "text": str(entry.get("text", ""))[:500], "url": str(entry.get("url", ""))[:2048]})

    def _h_Runtime_bindingCalled(self, params, session):
        if params.get("name") != BINDING or len(self.hook_events) >= 200:
            return
        try:
            kind, value = json.loads(params.get("payload", "[]"))
        except (ValueError, TypeError):
            return
        self.hook_events.append({"kind": str(kind)[:64], "value": str(value)[:4096]})

    def _h_Debugger_scriptParsed(self, params, session):
        if len(self.scripts) >= 500:
            return
        url = str(params.get("url", ""))
        self.scripts[self._key(session, params.get("scriptId"))] = {
            "script_id": params.get("scriptId"), "url": url[:2048], "length": params.get("length"),
            "hash": params.get("hash"), "is_module": params.get("isModule"),
            "source_map_url": str(params.get("sourceMapURL", ""))[:2048], "session": session,
            "kind": "external" if url else "inline_or_eval"}

    def _h_Debugger_paused(self, params, session):
        data = params.get("data") or {}
        if len(self.breakpoint_hits) < 100:
            frames = [{"function": f.get("functionName", "")[:128], "url": str(f.get("url", ""))[:2048],
                       "line": (f.get("location") or {}).get("lineNumber")}
                      for f in (params.get("callFrames") or [])[:5]]
            self.breakpoint_hits.append({"reason": params.get("reason"), "event": data.get("eventName"),
                                         "frames": frames})
        return [{"kind": "cdp", "method": "Debugger.resume", "params": {}, "session": session}]

    # -- output
    def summary(self) -> dict:
        requests, responses = [], []
        for key, record in self.records.items():
            hops = []
            for i, hop in enumerate(record["hops"]):
                item = dict(hop)
                extra_req, extra_resp = self._extra_req.get(key, []), self._extra_resp.get(key, [])
                if i < len(extra_req):
                    headers = extra_req[i].get("headers") or {}
                    item["raw_request_headers"] = header_list(headers.items())
                    cookie = next((v for k, v in headers.items() if k.lower() == "cookie"), "")
                    item["request_cookie_names"] = cookie_names(cookie, False) if cookie else []
                if i < len(extra_resp):
                    headers = extra_resp[i].get("headers") or {}
                    item["raw_response_headers"] = header_list(headers.items())
                    cookie = next((v for k, v in headers.items() if k.lower() == "set-cookie"), "")
                    item["set_cookie_names"] = cookie_names(cookie, True) if cookie else []
                    item["blocked_cookies"] = [{"reasons": b.get("blockedReasons")}
                                               for b in (extra_resp[i].get("blockedCookies") or [])[:20]]
                hops.append(item)
            body = self.bodies.get(key)
            requests.append({"id": key, "type": record["type"], "frame_id": record["frame_id"],
                             "document_url": record["document_url"], "initiator": record["initiator"],
                             "hops": hops, "failed": record["failed"], "finished": record["finished"],
                             "encoded_data_length": record.get("encoded_data_length"),
                             "body": {k: v for k, v in body.items() if k != "data"} if body else None})
            final = (record["hops"][-1].get("response") if record["hops"] else None)
            if final and final.get("status"):
                headers = {h["name"]: h["value"] for h in final["headers"]}
                entry = {"url": final["url"], "status": final["status"], "headers": headers,
                         "request_id": key, "type": record["type"], "protocol": final.get("protocol"),
                         "remote_ip": final.get("remote_ip"), "payload": body or {"status": "omitted"}}
                if (body and body.get("encoding") == "utf-8" and "html" in str(final.get("mime_type", "")).lower()):
                    entry["content_indicators"] = extract_content(body.get("data", ""), final["url"])
                responses.append(entry)
        return {"requests": requests, "responses": responses, "navigations": self.navigations,
                "lifecycle": self.lifecycle, "console": self.console, "page_errors": self.page_errors,
                "scripts": list(self.scripts.values()), "script_sources": self.script_sources,
                "breakpoint_hits": self.breakpoint_hits, "hook_events": self.hook_events,
                "downloads": self.downloads, "popups": self.popups, "dialogs": self.dialogs,
                "websockets": self.websockets, "dropped_requests": self.dropped,
                "inflight_at_end": len(self.inflight)}


# --------------------------------------------------------------------------- driver

def _hooks_source() -> str:
    hooks = Path(__file__).with_name("hooks.js").read_text(encoding="utf-8")
    preamble = (f"Object.defineProperty(window, '__forensics_log', {{enumerable: false, configurable: true, "
                f"value: (kind, value) => {{ try {{ window.{BINDING}(JSON.stringify([kind, String(value)])); }} catch (_) {{}} }}}});\n")
    return preamble + hooks


async def _wait_idle(recorder: CdpRecorder, max_wait: float, idle_s: float = 0.8, stall_s: float = 3.0) -> bool:
    """Idle = no network activity for idle_s; requests that stay in flight (favicon, long polls) only block for stall_s."""
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        quiet = time.monotonic() - recorder.last_activity
        if quiet >= (stall_s if recorder.inflight else idle_s):
            return True
        await asyncio.sleep(0.1)
    return False


def _fetch_json(url: str) -> dict:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never via an environment proxy
    with opener.open(url, timeout=10) as response:
        return json.loads(response.read(1 << 20))


async def _wait_for_devtools_port(profile_dir: str, proc, timeout: float = 20.0) -> tuple[int, str]:
    port_file = Path(profile_dir) / "DevToolsActivePort"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.returncode is not None:
            raise RuntimeError(f"Chrome exited early with code {proc.returncode}")
        if port_file.exists():
            lines = port_file.read_text().split("\n")
            if len(lines) >= 2 and lines[0].isdigit() and lines[1]:
                return int(lines[0]), lines[1]
        await asyncio.sleep(0.1)
    raise RuntimeError("Timed out waiting for Chrome's DevTools port")


async def record(raw_url: str, output: Path, *, level: str = "quiet", chrome_path: str | None = None,
                 headless: bool = False, no_sandbox: bool = False, timeout_ms: int = 20000,
                 settle_ms: int = 2000, max_requests: int = 100, max_body_bytes: int = 262144,
                 referer: str | None = None, locale: str | None = None, timezone_id: str | None = None,
                 ignore_https_errors: bool = False, screenshot: bool = True, endpoint: str | None = None,
                 observe_seconds: float = 30.0, use_env_proxy: bool = True,
                 enforce_dns_policy: bool = True) -> dict:
    """Record one visit (launch mode) or watch a Chrome you started (attach mode)."""
    if level not in CDP_LEVELS:
        raise ValueError(f"Unknown CDP level: {level}")
    url = canonical_url(raw_url)
    referer = canonical_url(referer) if referer else None
    proxy = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")) if use_env_proxy else None
    if endpoint is None and enforce_dns_policy and not proxy:
        await asyncio.to_thread(resolve_public, url)
    output.mkdir(parents=True, exist_ok=True)

    recorder = CdpRecorder(max_requests=max_requests, max_body_bytes=max_body_bytes, level=level,
                           close_popups=endpoint is None)
    started = time.monotonic()
    loop = asyncio.get_running_loop()
    pending: set[asyncio.Task] = set()
    sessions: dict[str, str] = {}      # sessionId -> targetId
    attaching: set[str] = set()
    connection: CdpConnection | None = None
    proc = None
    profile_dir = None
    errors: list[str] = []

    async def run_action(action: dict) -> None:
        try:
            if action["kind"] == "body":
                try:
                    result = await connection.send("Network.getResponseBody", {"requestId": action["request_id"]},
                                                   session_id=action["session"])
                    recorder.on_body(action["key"], result.get("body", ""), bool(result.get("base64Encoded")))
                except CdpError as exc:
                    recorder.on_body_error(action["key"], str(exc))
            else:
                await connection.send(action["method"], action.get("params"), session_id=action.get("session"))
        except CdpError:
            pass

    def handle_event(method: str, params: dict, session) -> None:
        if method == "Target.attachedToTarget":
            return
        if method in {"Target.targetCreated", "Target.targetInfoChanged"} and endpoint is not None:
            info = params.get("targetInfo") or {}
            if info.get("type") == "page":
                task = loop.create_task(attach(info["targetId"]))
                pending.add(task)
                task.add_done_callback(pending.discard)
        for action in recorder.on_event(method, params, session):
            task = loop.create_task(run_action(action))
            pending.add(task)
            task.add_done_callback(pending.discard)

    async def enable(session: str) -> None:
        send = lambda m, p=None: connection.send(m, p, session_id=session)
        await send("Network.enable", {"maxTotalBufferSize": 64 * 1024 * 1024, "maxResourceBufferSize": 16 * 1024 * 1024})
        await send("Network.setCacheDisabled", {"cacheDisabled": True})
        await send("Page.enable")
        await send("Page.setLifecycleEventsEnabled", {"enabled": True})
        await send("Log.enable")
        if timezone_id:
            await send("Emulation.setTimezoneOverride", {"timezoneId": timezone_id})
        if level == "full":
            await send("Runtime.enable")
            await send("Runtime.addBinding", {"name": BINDING})
            await send("Page.addScriptToEvaluateOnNewDocument", {"source": _hooks_source()})
            await send("Debugger.enable")
            for event_name in ("copy", "cut"):
                await send("DOMDebugger.setEventListenerBreakpoint", {"eventName": event_name})

    async def attach(target_id: str) -> str | None:
        if target_id in attaching:
            return None
        attaching.add(target_id)
        result = await connection.send("Target.attachToTarget", {"targetId": target_id, "flatten": True})
        session = result["sessionId"]
        sessions[session] = target_id
        await enable(session)
        return session

    try:
        if endpoint:
            endpoint = validate_endpoint(endpoint)
            ws_url = endpoint if endpoint.startswith("ws") else _fetch_json(endpoint.rstrip("/") + "/json/version")["webSocketDebuggerUrl"]
            mode = "attach"
        else:
            chrome = find_chrome(chrome_path)
            profile_dir = tempfile.mkdtemp(prefix="url-forensics-chrome-")
            args = chrome_args(profile_dir, headless=headless, no_sandbox=no_sandbox, proxy=proxy,
                               ignore_https_errors=ignore_https_errors, locale=locale)
            proc = await asyncio.create_subprocess_exec(chrome, *args, "about:blank",
                                                        stdout=asyncio.subprocess.DEVNULL,
                                                        stderr=asyncio.subprocess.DEVNULL)
            port, path = await _wait_for_devtools_port(profile_dir, proc)
            ws_url = f"ws://127.0.0.1:{port}{path}"
            mode = "launch"

        connection = CdpConnection(ws_url, handle_event)
        await connection.connect()
        version = await connection.send("Browser.getVersion")
        await connection.send("Browser.setDownloadBehavior", {"behavior": "deny", "eventsEnabled": True})
        await connection.send("Target.setDiscoverTargets", {"discover": True})
        targets = (await connection.send("Target.getTargets")).get("targetInfos", [])
        pages = [t for t in targets if t.get("type") == "page"]
        if not pages:
            raise RuntimeError("No page target to record")
        first_session = None
        for target in pages:
            session = await attach(target["targetId"])
            first_session = first_session or session

        if mode == "launch":
            navigate = {"url": url}
            if referer:
                navigate["referrer"] = referer
            result = await connection.send("Page.navigate", navigate, session_id=first_session)
            if result.get("errorText"):
                errors.append(f"navigation: {result['errorText']}")
            await _wait_idle(recorder, timeout_ms / 1000)
            await asyncio.sleep(settle_ms / 1000)
            await _wait_idle(recorder, timeout_ms / 1000)
        else:
            await asyncio.sleep(observe_seconds)
        if pending:
            await asyncio.gather(*list(pending), return_exceptions=True)

        # ---- collect final state (after the page has settled, so probes cannot affect the visit)
        final: dict = {"pages": []}
        artifacts: dict = {}
        for session, target_id in list(sessions.items()):
            page: dict = {"target_id": target_id}
            send = lambda m, p=None, s=session: connection.send(m, p, session_id=s)
            try:
                tree = await send("Page.getFrameTree")
                frames, stack = [], [tree["frameTree"]]
                while stack and len(frames) < 50:
                    node = stack.pop()
                    frame = node["frame"]
                    frames.append({"id": frame.get("id"), "parent_id": frame.get("parentId"),
                                   "url": str(frame.get("url", ""))[:4096], "mime_type": frame.get("mimeType"),
                                   "security_origin": frame.get("securityOrigin")})
                    stack.extend(node.get("childFrames", []))
                page["frames"] = frames
                page["url"] = frames[0]["url"] if frames else None
                world = await send("Page.createIsolatedWorld", {"frameId": tree["frameTree"]["frame"]["id"],
                                                                 "worldName": "url_forensics_probe"})
                context_id = world.get("executionContextId")

                async def evaluate(expression):
                    result = await send("Runtime.evaluate", {"expression": expression, "contextId": context_id,
                                                             "returnByValue": True, "awaitPromise": True, "timeout": 5000})
                    if "exceptionDetails" in result:
                        raise CdpError(str(result["exceptionDetails"])[:200])
                    return (result.get("result") or {}).get("value")

                for name, expression in (("fingerprint", FINGERPRINT_JS), ("storage", STORAGE_JS), ("dom", DOM_JS)):
                    try:
                        page[name] = await evaluate(expression)
                    except CdpError as exc:
                        page[name + "_error"] = str(exc)[:200]
                if isinstance(page.get("dom"), str):
                    dom_path = output / f"dom-{len(final['pages'])}.html.txt"
                    dom_path.write_text(page.pop("dom"), encoding="utf-8")
                    artifacts.setdefault("dom", []).append(dom_path.name)
                page["fingerprint_tells"] = fingerprint_tells(page.get("fingerprint"))
                if screenshot:
                    shot = await send("Page.captureScreenshot", {"format": "png"})
                    shot_path = output / f"screenshot-{len(final['pages'])}.png"
                    shot_path.write_bytes(base64.b64decode(shot.get("data", "")))
                    artifacts.setdefault("screenshots", []).append(shot_path.name)
                if level == "full":
                    for key, info in list(recorder.scripts.items())[:500]:
                        if info.get("session") == session and info["kind"] == "inline_or_eval" and len(recorder.script_sources) < 40:
                            try:
                                source = await send("Debugger.getScriptSource", {"scriptId": info["script_id"]})
                                recorder.set_script_source(key, source.get("scriptSource", ""))
                            except CdpError:
                                pass
            except CdpError as exc:
                page["collection_error"] = str(exc)[:300]
            final["pages"].append(page)
        try:
            cookies = (await connection.send("Network.getAllCookies", session_id=first_session)).get("cookies", [])
            final["cookies"] = [{"name": c.get("name"), "domain": c.get("domain"), "path": c.get("path"),
                                 "secure": c.get("secure"), "http_only": c.get("httpOnly"),
                                 "same_site": c.get("sameSite"), "expires": c.get("expires"),
                                 "value_length": len(str(c.get("value", "")))} for c in cookies[:100]]
        except CdpError as exc:
            errors.append(f"cookies: {exc}")
        if pending:
            await asyncio.gather(*list(pending), return_exceptions=True)

        result = recorder.summary()
        pages = final["pages"]
        result.update({
            "mode": mode, "level": level, "requested_url": url,
            "settings": {"headless": headless, "referer": referer, "locale": locale, "timezone_id": timezone_id,
                         "proxy": bool(proxy), "ignore_https_errors": ignore_https_errors,
                         "timezone_override_is_a_tell": bool(timezone_id)},
            "browser": {"product": version.get("product"), "user_agent": version.get("userAgent"),
                        "protocol_version": version.get("protocolVersion")},
            "pages": pages, "cookies": final.get("cookies", []), "artifacts": artifacts,
            "fingerprint": pages[0].get("fingerprint") if pages else None,
            "fingerprint_tells": sorted({t for p in pages for t in p.get("fingerprint_tells", [])}),
            "errors": errors, "elapsed_seconds": round(time.monotonic() - started, 2),
            "limitations": ["Chrome was driven over the DevTools Protocol; sites can detect some CDP/automation traits.",
                            "Bodies are fetched per resource and can be unavailable after fast navigations.",
                            "Header/cookie values are redacted; cookie names, sizes and flags are kept.",
                            "Fingerprint values are read after the visit from an isolated world; page scripts may spoof their own view."],
        })
        return result
    finally:
        if connection is not None:
            try:
                await connection.send("Browser.close", timeout=5)
            except Exception:
                pass
            await connection.close()
        if proc is not None:
            try:
                await asyncio.wait_for(proc.wait(), 8)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
        if profile_dir:
            for _ in range(5):  # Windows may hold file locks briefly
                shutil.rmtree(profile_dir, ignore_errors=True)
                if not os.path.exists(profile_dir):
                    break
                await asyncio.sleep(0.5)
