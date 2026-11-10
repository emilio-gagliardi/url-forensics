"""Pinned-IP HTTP HEAD / TLS metadata probes with public-address checks.

Only HEAD is sent; there are no response-body reads. All redirects are revalidated.
The target *does* see the probe: 'passive' here means no browser execution,
not a passive intelligence-source lookup.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit, urlunsplit

MAX_REDIRECTS = 6
HEADERS_OF_INTEREST = {
    "server", "content-type", "content-length", "content-disposition",
    "location", "cache-control", "x-powered-by", "strict-transport-security",
    "content-security-policy", "x-frame-options", "www-authenticate",
    "refresh", "permissions-policy", "x-content-type-options",
}


class ProbeError(ValueError):
    """Unsafe URL or network-probe failure."""


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        ip.is_global and not ip.is_private and not ip.is_reserved
        and not ip.is_loopback and not ip.is_link_local
        and not ip.is_multicast and not ip.is_unspecified
    )


def canonical_url(raw: str) -> str:
    """Reject local/file targets, credentials and malformed URLs before DNS."""
    if not raw or any(ord(c) < 32 or ord(c) == 127 for c in raw):
        raise ProbeError("URL is missing or contains control characters")
    try:
        parts = urlsplit(raw)
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ProbeError(f"Invalid URL: {exc}") from exc
    if parts.scheme not in {"http", "https"} or not hostname:
        raise ProbeError("Only explicit http:// and https:// URLs are supported")
    if parts.username is not None or parts.password is not None:
        raise ProbeError("Embedded user credentials are forbidden")
    if port is not None and not (1 <= port <= 65535):
        raise ProbeError("Invalid port")
    if len(raw) > 4096:
        raise ProbeError("URL is excessively long")
    try:
        host_ascii = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ProbeError("Invalid domain name") from exc
    if not host_ascii or host_ascii in {"localhost", "localhost.localdomain"} or host_ascii.endswith((".localhost", ".local", ".internal")):
        raise ProbeError("Local names are prohibited")
    try:
        ipv6 = isinstance(ipaddress.ip_address(host_ascii), ipaddress.IPv6Address)
    except ValueError:
        ipv6 = False
    authority = f"[{host_ascii}]" if ipv6 else host_ascii
    if port is not None:
        authority += f":{port}"
    return urlunsplit((parts.scheme, authority, parts.path or "/", parts.query, ""))


def resolve_public(url: str) -> tuple[str, list[str]]:
    """Require every DNS answer to be public, and pin one address for probes."""
    parts = urlsplit(canonical_url(url))
    host = parts.hostname
    try:
        answers = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ProbeError(f"DNS resolution failed for {host}: {exc}") from exc
    ips = sorted({entry[4][0] for entry in answers})
    if not ips:
        raise ProbeError("DNS produced no IP addresses")
    denied = [ip for ip in ips if not is_public_ip(ip)]
    if denied:
        raise ProbeError(f"DNS returned private, special-use or non-public IP(s): {', '.join(denied)}")
    return ips[0], ips


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float):
        super().__init__(host=host, port=port, timeout=timeout)
        self._connect_ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._connect_ip, self.port), timeout=self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float):
        super().__init__(host=host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._connect_ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._connect_ip, self.port), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def tls_info(url: str, ip: str, timeout: float = 8.0) -> dict:
    parts = urlsplit(url)
    if parts.scheme != "https":
        return {"status": "skipped", "reason": "non-HTTPS URL"}
    host, port = parts.hostname, parts.port or 443
    conn = None
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        conn = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        cert = conn.getpeercert()
        der = conn.getpeercert(binary_form=True)
        return {
            "status": "verified", "protocol": conn.version(), "cipher": conn.cipher()[0],
            "cert_sha256": hashlib.sha256(der).hexdigest(),
            "subject": cert.get("subject"), "issuer": cert.get("issuer"),
            "subject_alt_names": cert.get("subjectAltName"),
            "not_before": cert.get("notBefore"), "not_after": cert.get("notAfter"),
        }
    except (OSError, ssl.SSLError) as exc:
        return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
    finally:
        if conn is not None:
            conn.close()


def head_request(url: str, ip: str, timeout: float = 8.0) -> dict:
    parts = urlsplit(url)
    host, port = parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
    connection_cls = _PinnedHTTPS if parts.scheme == "https" else _PinnedHTTP
    conn = connection_cls(host, port, ip, timeout)
    try:
        conn.request("HEAD", (parts.path or "/") + (f"?{parts.query}" if parts.query else ""),
                     headers={"User-Agent": "URL-Forensics/0.1 (metadata-only; no body)",
                              "Accept": "*/*", "Connection": "close"})
        response = conn.getresponse()
        headers = {k.lower(): v[:2048] for k, v in response.getheaders()
                   if k.lower() in HEADERS_OF_INTEREST}
        return {"status": response.status, "reason": response.reason, "headers": headers}
    finally:
        conn.close()


def metadata_probe(raw_url: str, max_redirects: int = MAX_REDIRECTS, timeout: float = 8.0) -> dict:
    url = canonical_url(raw_url)
    result = {"target_url": url, "method": "HEAD", "requests": [],
              "disclaimer": "This probe contacts the target. It never requests response bodies."}
    visited: set[str] = set()
    for hop in range(max_redirects + 1):
        if url in visited:
            result["stop_reason"] = "redirect_loop"
            break
        visited.add(url)
        record = {"url": url, "hop": hop, "time_utc": datetime.now(timezone.utc).isoformat()}
        result["requests"].append(record)
        try:
            ip, ips = resolve_public(url)
            record["dns_ips"] = ips
            record["connected_ip"] = ip
            record["tls"] = tls_info(url, ip, timeout)
            record["http"] = head_request(url, ip, timeout)
            response = record["http"]
            location = response["headers"].get("location")
            if response["status"] not in (301, 302, 303, 307, 308) or not location:
                result["stop_reason"] = "final_response"
                break
            url = canonical_url(urljoin(url, location))
        except (ProbeError, OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"
            result["stop_reason"] = "error"
            break
    else:
        result["stop_reason"] = "redirect_limit"
    return result
