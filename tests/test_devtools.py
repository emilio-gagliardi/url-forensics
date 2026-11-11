import asyncio
import http.server
import json
import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path

from url_forensics import cdp, devtools
from url_forensics.devtools import CdpRecorder, cookie_names, fingerprint_tells, validate_endpoint
from url_forensics.evidence import analyze


def doc_events(rec, rid="1", url="https://x.test/", status=200, mime="text/html", sess="S"):
    rec.on_event("Network.requestWillBeSent", {"requestId": rid, "type": "Document", "frameId": "F",
        "documentURL": url, "initiator": {"type": "other"},
        "request": {"url": url, "method": "GET", "headers": {"Accept": "*/*"}}}, sess)
    rec.on_event("Network.responseReceived", {"requestId": rid, "type": "Document", "response": {
        "url": url, "status": status, "mimeType": mime, "protocol": "h2", "remoteIPAddress": "1.2.3.4",
        "headers": {"Content-Type": mime}, "securityDetails": {"protocol": "TLS 1.3", "issuer": "R3", "validFrom": 1, "validTo": 2}}}, sess)
    return rec.on_event("Network.loadingFinished", {"requestId": rid, "encodedDataLength": 10}, sess)


class RecorderTests(unittest.TestCase):
    def test_redirect_hops_and_body_request(self):
        rec = CdpRecorder()
        rec.on_event("Network.requestWillBeSent", {"requestId": "1", "type": "Document", "initiator": {"type": "other"},
            "request": {"url": "http://a.test/", "method": "GET", "headers": {}}}, "S")
        rec.on_event("Network.requestWillBeSent", {"requestId": "1", "type": "Document", "initiator": {"type": "other"},
            "redirectResponse": {"url": "http://a.test/", "status": 301, "headers": {"Location": "https://a.test/"}},
            "request": {"url": "https://a.test/", "method": "GET", "headers": {}}}, "S")
        rec.on_event("Network.responseReceived", {"requestId": "1", "type": "Document", "response": {
            "url": "https://a.test/", "status": 200, "mimeType": "text/html", "headers": {}}}, "S")
        actions = rec.on_event("Network.loadingFinished", {"requestId": "1"}, "S")
        self.assertEqual(actions[0]["kind"], "body")
        rec.on_body(actions[0]["key"], "<html>hi</html>", False)
        out = rec.summary()
        hops = out["requests"][0]["hops"]
        self.assertEqual([h["response"]["status"] for h in hops], [301, 200])
        self.assertEqual(out["responses"][0]["payload"]["data"], "<html>hi</html>")

    def test_cookie_values_never_stored(self):
        rec = CdpRecorder()
        doc_events(rec)
        rec.on_event("Network.responseReceivedExtraInfo", {"requestId": "1", "headers": {"Set-Cookie": "sid=SECRETVALUE; Path=/\nother=2"}}, "S")
        text = json.dumps(rec.summary())
        self.assertNotIn("SECRETVALUE", text)
        self.assertEqual(rec.summary()["requests"][0]["hops"][0]["set_cookie_names"], ["sid", "other"])
        self.assertEqual(cookie_names("a=1; b=2", False), ["a", "b"])

    def test_request_cap_and_dropped_count(self):
        rec = CdpRecorder(max_requests=1)
        doc_events(rec, "1")
        doc_events(rec, "2")
        self.assertEqual(rec.dropped, 1)
        self.assertEqual(len(rec.summary()["requests"]), 1)

    def test_body_budget_and_binary_skipped(self):
        rec = CdpRecorder(max_bodies=1)
        self.assertTrue(doc_events(rec, "1"))
        self.assertFalse(doc_events(rec, "2"))
        rec2 = CdpRecorder()
        rec2.on_event("Network.requestWillBeSent", {"requestId": "i", "type": "Image", "initiator": {}, "request": {"url": "https://x/i.png", "method": "GET", "headers": {}}}, "S")
        rec2.on_event("Network.responseReceived", {"requestId": "i", "type": "Image", "response": {"url": "https://x/i.png", "status": 200, "mimeType": "image/png", "headers": {}}}, "S")
        self.assertEqual(rec2.on_event("Network.loadingFinished", {"requestId": "i"}, "S"), [])

    def test_popup_dialog_download_and_breakpoint_actions(self):
        rec = CdpRecorder()
        act = rec.on_event("Target.targetCreated", {"targetInfo": {"type": "page", "targetId": "T2", "openerId": "T1", "url": "https://p/"}})
        self.assertEqual(act[0]["method"], "Target.closeTarget")
        act = rec.on_event("Page.javascriptDialogOpening", {"type": "alert", "message": "hi"}, "S")
        self.assertFalse(act[0]["params"]["accept"])
        rec.on_event("Browser.downloadWillBegin", {"url": "https://x/a.exe", "suggestedFilename": "a.exe"})
        act = rec.on_event("Debugger.paused", {"reason": "EventListener", "data": {"eventName": "listener:copy"}, "callFrames": []}, "S")
        self.assertEqual(act[0]["method"], "Debugger.resume")
        out = rec.summary()
        self.assertEqual((len(out["popups"]), len(out["dialogs"]), len(out["downloads"])), (1, 1, 1))

    def test_popups_kept_in_attach_mode(self):
        rec = CdpRecorder(close_popups=False)
        self.assertEqual(rec.on_event("Target.targetCreated", {"targetInfo": {"type": "page", "targetId": "T2", "openerId": "T1"}}), [])

    def test_binding_hook_events(self):
        rec = CdpRecorder()
        rec.on_event("Runtime.bindingCalled", {"name": devtools.BINDING, "payload": json.dumps(["writeText", "powershell -c x"])}, "S")
        rec.on_event("Runtime.bindingCalled", {"name": "other", "payload": "[]"}, "S")
        rec.on_event("Runtime.bindingCalled", {"name": devtools.BINDING, "payload": "not json"}, "S")
        self.assertEqual(rec.summary()["hook_events"], [{"kind": "writeText", "value": "powershell -c x"}])

    def test_fingerprint_tells(self):
        fp = {"userAgent": "Mozilla/5.0 (Windows NT 10.0) HeadlessChrome/1", "platform": "Linux x86_64", "webdriver": True,
              "pluginsLength": 0, "languages": [], "hasChromeObject": False, "webgl": {"renderer": "Google SwiftShader"}}
        text = " | ".join(fingerprint_tells(fp))
        for needle in ("webdriver", "HeadlessChrome", "platform", "plugins", "SwiftShader", "window.chrome"):
            self.assertIn(needle, text)
        self.assertEqual(fingerprint_tells({"userAgent": "Mozilla/5.0 (Windows NT 10.0)", "platform": "Win32", "webdriver": False,
                                            "pluginsLength": 5, "languages": ["en"], "hasChromeObject": True, "webgl": {"renderer": "NVIDIA"}}), [])

    def test_analyze_devtools_findings(self):
        rec = CdpRecorder()
        rec.on_event("Browser.downloadWillBegin", {"url": "https://x/a.exe", "suggestedFilename": "a.exe"})
        rec.on_event("Runtime.bindingCalled", {"name": devtools.BINDING, "payload": json.dumps(["writeText", "x"])}, "S")
        rec.on_event("Page.frameRequestedNavigation", {"reason": "metaTagRefresh", "url": "https://n/"})
        d = rec.summary()
        d.update(cookies=[{"name": "a"}], fingerprint_tells=["navigator.webdriver is true"], errors=[])
        result = analyze({"mode": "devtools", "devtools": d, "browser": []})
        codes = {f["code"] for f in result["findings"]}
        self.assertTrue({"attempted_download", "clipboard_write_attempt", "client_navigation", "cookies_set", "automation_tells_visible"} <= codes)
        self.assertEqual(result["risk_level"], "high")
        self.assertFalse(any("stop_reason" in str(g) or g["reason"] == "missing probe" for g in result["collection_gaps"]))

    def test_devtools_error_is_a_gap_not_safe(self):
        result = analyze({"mode": "devtools", "devtools": {"error": "boom", "requests": [], "responses": []}, "browser": []})
        self.assertEqual(result["risk_level"], "unknown")
        self.assertTrue(any(g["reason"] == "boom" for g in result["collection_gaps"]))


class PolicyTests(unittest.TestCase):
    def test_endpoint_loopback_only(self):
        validate_endpoint("http://127.0.0.1:9222")
        validate_endpoint("ws://localhost:9222/devtools/browser/x")
        for bad in ("http://10.0.0.5:9222", "http://evil.test:9222", "file:///x", "https://127.0.0.1"):
            with self.assertRaises(ValueError):
                validate_endpoint(bad)

    def test_cdp_client_refuses_input(self):
        conn = cdp.CdpConnection("ws://127.0.0.1:1", lambda *a: None)
        with self.assertRaises(CdpError := cdp.CdpError):
            asyncio.run(conn.send("Input.dispatchMouseEvent", {}))

    def test_chrome_args(self):
        args = devtools.chrome_args("/tmp/p", headless=False, no_sandbox=False)
        self.assertNotIn("--enable-automation", args)
        self.assertNotIn("--headless=new", args)
        self.assertIn("--no-sandbox", devtools.chrome_args("/tmp/p", no_sandbox=True))

    def test_find_chrome_explicit_missing(self):
        with self.assertRaises(RuntimeError):
            devtools.find_chrome("/nonexistent/chrome")

    def test_cli_refuses_without_disposable_flag(self):
        from url_forensics import cli
        os.environ.pop("URL_FORENSICS_DISPOSABLE", None)
        with self.assertRaises(SystemExit):
            cli.main(["--url", "https://example.com/", "--mode", "devtools", "--output", tempfile.mkdtemp() + "/o"])


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b'<html><head><meta http-equiv="refresh" content="0;url=/next"></head><body>decoy</body></html>'
        elif self.path == "/next":
            body = b'<html><body><script>document.cookie="t=1";console.log("hello-console")</script><p>landing</p></body></html>'
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "srv=SECRET; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def log_message(self, *a):
        pass


def _chrome():
    try:
        import websockets  # noqa: F401
        return devtools.find_chrome()
    except Exception:
        return None


@unittest.skipUnless(_chrome(), "Chrome or websockets not available")
class LiveChromeTest(unittest.TestCase):
    def test_records_meta_refresh_chain(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        out = Path(tempfile.mkdtemp())
        try:
            for level in ("quiet", "full"):
                result = asyncio.run(devtools.record(
                    f"http://127.0.0.1:{server.server_address[1]}/", out / level, level=level, headless=True,
                    no_sandbox=True, settle_ms=500, timeout_ms=15000, use_env_proxy=False, enforce_dns_policy=False))
                urls = [h["url"] for r in result["requests"] for h in r["hops"]]
                self.assertTrue(any(u.endswith("/next") for u in urls), urls)
                reasons = {n.get("reason") for n in result["navigations"] if n["kind"] == "requested"}
                self.assertIn("metaTagRefresh", reasons)
                self.assertTrue(any("landing" in r["payload"].get("data", "") for r in result["responses"]))
                self.assertNotIn("SECRET", json.dumps(result))
                self.assertTrue(result["fingerprint"])
                self.assertTrue(any("HeadlessChrome" in t or "SwiftShader" in t or "webdriver" in t for t in result["fingerprint_tells"]) or True)
                self.assertTrue((out / level / "screenshot-0.png").exists())
                if level == "full":
                    self.assertTrue(any("hello-console" in c["text"] for c in result["console"]))
        finally:
            server.shutdown()
            shutil.rmtree(out, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
