import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from argparse import Namespace

from url_forensics.network import (
    ProbeError, canonical_url, is_public_ip, metadata_probe, resolve_public,
)
from url_forensics.cli import _render


class UrlValidationTests(unittest.TestCase):
    def test_accepts_public_https(self):
        self.assertEqual(canonical_url("https://example.org"), "https://example.org/")

    def test_rejects_non_http(self):
        for url in ["file:///etc/passwd", "data:text/html,hi", "javascript:alert(1)"]:
            with self.subTest(url=url), self.assertRaises(ProbeError):
                canonical_url(url)

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ProbeError):
            canonical_url("https://me:pw@example.org/path")

    def test_rejects_local_names(self):
        for url in ["http://localhost/", "http://host.local/", "http://service.internal/"]:
            with self.subTest(url=url), self.assertRaises(ProbeError):
                canonical_url(url)

    def test_rejects_newline(self):
        with self.assertRaises(ProbeError):
            canonical_url("https://example.org/\r\nHi")

    def test_private_ip_blocks(self):
        for ip in ["127.0.0.1", "10.4.0.1", "169.254.169.254", "192.168.0.1",
                   "::1", "fc00::1", "fe80::1", "0.0.0.0", "224.0.0.1"]:
            with self.subTest(ip=ip):
                self.assertFalse(is_public_ip(ip))
        self.assertTrue(is_public_ip("1.1.1.1"))
        self.assertTrue(is_public_ip("2606:4700:4700::1111"))

    @patch("url_forensics.network.socket.getaddrinfo")
    def test_dns_mixed_public_private_rejected(self, getaddrinfo):
        getaddrinfo.return_value = [(2, 1, 6, "", ("8.8.8.8", 443)),
                                    (2, 1, 6, "", ("127.0.0.1", 443))]
        with self.assertRaises(ProbeError):
            resolve_public("https://example.org/")

    @patch("url_forensics.network.head_request")
    @patch("url_forensics.network.tls_info", return_value={"status": "verified"})
    @patch("url_forensics.network.resolve_public", return_value=("8.8.8.8", ["8.8.8.8"]))
    def test_redirect_revalidation_blocks_file_scheme(self, resolve, tls, head):
        head.return_value = {"status": 302, "headers": {"location": "file:///etc/passwd"}}
        result = metadata_probe("https://example.org/")
        self.assertEqual(result["stop_reason"], "error")
        self.assertEqual(len(result["requests"]), 1)
        self.assertIn("ProbeError", result["requests"][0]["error"])

    @patch("url_forensics.network.head_request")
    @patch("url_forensics.network.tls_info", return_value={"status": "verified"})
    @patch("url_forensics.network.resolve_public", return_value=("8.8.8.8", ["8.8.8.8"]))
    def test_relative_redirect_followed(self, resolve, tls, head):
        head.side_effect = [
            {"status": 302, "headers": {"location": "/more"}},
            {"status": 200, "headers": {"content-type": "text/html"}},
        ]
        result = metadata_probe("https://example.org/start")
        self.assertEqual([r["url"] for r in result["requests"]], [
            "https://example.org/start", "https://example.org/more"])
        self.assertEqual(result["stop_reason"], "final_response")

    def test_markdown_escapes_page_content(self):
        report = {"url": "https://example.org/", "time_utc": "now", "mode": "passive",
                  "metadata": {"requests": [], "stop_reason": "complete"}, "browser": []}
        self.assertIn("## Metadata probe", _render(report))


if __name__ == "__main__":
    unittest.main()

class AdditionalSafetyTests(unittest.TestCase):
    def test_response_header_redaction(self):
        from url_forensics.browser import safe_headers
        headers = {"Set-Cookie": "SESSION=secret", "Authorization": "Bearer token",
                   "Content-Type": "text/html"}
        result = safe_headers(headers)
        self.assertEqual(result["set-cookie"], "[REDACTED]")
        self.assertEqual(result["authorization"], "[REDACTED]")
        self.assertEqual(result["content-type"], "text/html")

    @patch("url_forensics.network._PinnedHTTPS")
    def test_http_probe_uses_head_only(self, connection_cls):
        from url_forensics.network import head_request
        conn = connection_cls.return_value
        conn.getresponse.return_value.status = 200
        conn.getresponse.return_value.reason = "OK"
        conn.getresponse.return_value.getheaders.return_value = [("Content-Type", "text/plain")]
        result = head_request("https://example.org/anything?q=1", "8.8.8.8")
        self.assertEqual(result["status"], 200)
        self.assertEqual(conn.request.call_args.args[0], "HEAD")
        self.assertEqual(conn.request.call_args.args[1], "/anything?q=1")
        conn.getresponse.return_value.read.assert_not_called()
