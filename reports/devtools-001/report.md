# URL Forensics report

Generated (UTC): 2026-11-11T01:30:33.276225+00:00
Target: `https://socialsignlab.click/ftx`
Mode: **devtools**

## Metadata probe

## Risk triage

Observed risk: **unknown**

Highest observed heuristic severity; not a malware probability or safety verdict. 'inconclusive' means only a client-side redirect or decoy was observed and the landing stage was not reached.

Delivery stage observed: **unknown**

- **info / automation_tells_visible**: The page could see: navigator.webdriver is true; software WebGL renderer (ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftSh): typical of VMs, sandboxes and headless runs; user agent contains HeadlessChrome. A filter may have treated this visit as automated. (`/devtools/fingerprint_tells`)

### Collection gaps

- HTTP error response may hide normal site behavior. (`/http/requests/0/http`)

Payloads and complete envelopes: `report.json`. Treat captured content as untrusted data.

### Hop 0

URL: `https://socialsignlab.click/ftx`

Resolved IPs: ``

TLS: `n/a`

HTTP: `520`

- `content-type`: text/html; charset=UTF-8
- `content-length`: 7371
- `cache-control`: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
- `x-frame-options`: SAMEORIGIN
- `server`: envoy

Stop reason: `final_response`

## DevTools recording (real Chrome)

Browser: `Chrome/156.0.8078.79`; mode `launch`, CDP level `quiet`; headless: True

Requests: **8** (dropped 0); navigations: **1**; cookies: **0**; downloads denied: **0**; popups closed: **0**; dialogs dismissed: **0**

### Automation / environment tells visible to the page

- navigator.webdriver is true
- software WebGL renderer (ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftSh): typical of VMs, sandboxes and headless runs
- user agent contains HeadlessChrome

### Navigations

- committed: `https://socialsignlab.click/ftx`

### Requests (type, status, protocol, remote IP)

- Document 520 h2 172.31.2.61 `https://socialsignlab.click/ftx` <- other
- Stylesheet 200 h2 172.31.2.61 `https://socialsignlab.click/cdn-cgi/styles/main.css` <- parser
- Image 200 h2 172.31.2.61 `https://socialsignlab.click/cdn-cgi/images/cf-icon-browser.png` <- parser
- Image 200 h2 172.31.2.61 `https://socialsignlab.click/cdn-cgi/images/cf-icon-ok.png` <- parser
- Image 200 h2 172.31.2.61 `https://socialsignlab.click/cdn-cgi/images/cf-icon-cloud.png` <- parser
- Image 200 h2 172.31.2.61 `https://socialsignlab.click/cdn-cgi/images/cf-icon-server.png` <- parser
- Image 200 h2 172.31.2.61 `https://socialsignlab.click/cdn-cgi/images/cf-icon-error.png` <- parser
- Other 200 h2 172.31.2.61 `https://socialsignlab.click/favicon.ico` <- other

### Console and Log

- log:network/error: Failed to load resource: the server responded with a status of 520 ()
- log:rendering/warning: []Automatic fallback to software WebGL has been deprecated. Please use the --enable-unsafe-swiftshader flag to opt in to lower security guarantees for trusted content.

Artifacts: `{"dom": ["dom-0.html.txt"], "screenshots": ["screenshot-0.png"]}` in `devtools/`. Full detail including headers, certificates, initiators and bodies: `report.json`.


## Interpretation boundaries

- No malware classification or attribution can be established from these probes alone.
- Browser JavaScript can execute inside the disposable browser. Downloads are cancelled, not analyzed.
- Browser URL filtering is not a substitute for VM-level egress isolation.
- A Windows user-agent is not a Windows VM; servers may still fingerprint Linux.
- A refused, blank, or error response does not demonstrate the URL is safe.
