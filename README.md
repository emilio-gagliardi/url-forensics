# URL Forensics

A small **defensive URL-reconnaissance toolkit** for investigating suspicious links from a disposable Linux environment. It performs DNS/TLS/HTTP metadata inspection and can optionally observe a page in headless Chromium using Playwright.

**Status:** Python CLI implemented; offline unit tests available. Live investigation of `socialsignlab.click` has **not** been performed or verified by this project. This is an **on-demand command-line program**, not a website, server, scheduled monitor, or malware-detonation sandbox.

> **Security warning:** Never run this against a suspicious URL on your ordinary Windows workstation. The `browser` mode **executes website JavaScript** inside Chromium; cancelling downloads does not make a potentially exploited browser safe. Codex Cloud is convenient for installing and testing the project and for an initial metadata probe, but it is **not a hardened malware-analysis environment**. For browser visits to suspected malware delivery sites, use a **dedicated, disposable VM**, with firewall-enforced isolation, no credentials or trusted repository connections, and network monitoring. See [Security model](#security-model-and-limitations).

## Start here: from ZIP to operational Codex Cloud project

**You do not need to create a local Git repository, run Python on Windows, or leave a server running.** The recommended workflow is:

1. Download and extract the project ZIP on your computer. *Extraction only; do not execute the contents locally.*
2. Create an **empty private GitHub repository** and upload the extracted project files using the GitHub website.
3. Create and **publish** a Codex Cloud environment that uses this repository.
4. Run the automated installation and offline tests in cloud setup.
5. Start a **new cloud task** for the **metadata-only** investigation.
6. Review/download the report; end the task when done.

**What makes it "live"?** Installing or publishing the environment only makes the toolkit **ready**. It does not launch a scan or create a publicly accessible endpoint. An investigation begins **only when you explicitly run** `inspect_url.py` in a cloud task. Each new investigation needs its own task/command, and no work runs indefinitely by default.

### Step 1. Unzip the package and create a private GitHub repository (no terminal required)

1. Download the project ZIP and **extract** it (do not upload the ZIP file itself; GitHub does not automatically unpack it into source files).
2. Open <https://github.com/new> and sign in.
3. Repository name: `url-forensics`; visibility: **Private**.
4. Leave **Add a README**, **Add .gitignore**, and **Choose a license** unchecked, because these files are already in the project. Select **Create repository**.
5. On the empty repository page, choose **uploading an existing file**, or use **Add file → Upload files**. Drag the **contents of the extracted `url-forensics/` directory**, keeping its directory structure. GitHub supports drag-and-drop of folders in the web upload interface.
6. Commit the upload to `main`.
7. **Verify these paths exist in GitHub** before continuing (files starting with `.` can be easy to overlook):

   ```text
   README.md
   inspect_url.py
   pyproject.toml
   url_forensics/cli.py
   url_forensics/network.py
   url_forensics/browser.py
   tests/test_network.py
   .codex/setup.sh
   .github/workflows/test.yml
   AGENTS.md
   ```

   If `.codex/setup.sh` is missing, upload its directory separately using GitHub's **Add file → Upload files**, or use **Add file → Create new file** and enter the relative path `.codex/setup.sh`, copying the contents from the extracted project.

This browser upload is the **only local step**. No `git init`, local clone, WSL setup, or `git push` is necessary.

**Alternative (optional Git CLI):** If you prefer working locally, see [Git CLI alternative](#git-cli-alternative) below.

### Step 2. Connect GitHub to Codex Cloud

1. Open Codex on the [ChatGPT web app](https://chatgpt.com/) or supported desktop app.
2. In a new Codex task choose **Work in → Cloud → Select environment → Create environment**. You can also open **Settings → Codex Cloud → Environments → Create environment**.
3. Connect your GitHub account if prompted, granting access to your **private `url-forensics` repository**. Avoid granting unnecessary access to other repositories.
4. Select only `url-forensics` for this environment. Keep its sharing setting at **Only me / Private**.
5. Select **Get started**. Codex will inspect the repository and prepare the environment.

The exact labels can vary with product updates. Use the [official Codex Cloud guide](https://learn.chatgpt.com/docs/environments/cloud-environments) if the menu differs.

### Step 3. Configure and test the cloud environment

In the environment **setup conversation**, paste this instruction:

> Prepare this repository as an on-demand defensive URL-inspection toolkit. Install Python 3.11 or newer and run `bash .codex/setup.sh` from the repository root. Confirm the offline unit tests pass and that `python inspect_url.py --help` works. Do **not** fetch or visit `socialsignlab.click`, or any suspicious URL, during setup. Configure no secrets, no personal browser profile, no VPN, no cloud-provider credentials, no production repositories, and no persistent mounts. Do not create a server or background job. Keep the environment private and report any missing network permissions for dependency installation.

The repository already contains this **install script**:

```bash
bash .codex/setup.sh
```

It runs:

```bash
python -m pip install -e '.[browser]'
python -m playwright install --with-deps chromium
python -m unittest discover -s tests -v
```

If Codex asks for the **Install script** field, use `bash .codex/setup.sh`. A **Start skill** is *not required*: this project runs only when instructed. If the setup script cannot install Chromium, diagnose the blocked dependency host or missing operating-system package privileges; do not silently skip installation and report success.

**Network settings:** Under the environment's public-internet settings, allow the package-manager domains needed for installation; Playwright's browser-binary download host may require additional allowlisting. Prefer a short allowlist to broad internet access. No target website is needed during setup. If broader access is temporarily necessary to install dependencies, narrow it again before the live task. Do **not** add HTTP secrets, personal vault values, Tailscale/VPN access, or other connected services.

Verify the setup report and then select **Publish**. A saved draft is **not** the same as a published, reusable environment. Publishing by itself does not visit a target website.

### Step 4. Start your first cloud task (offline readiness check)

From the newly **published** environment, choose **Start a new task**. Ask Codex to run:

```bash
python -m unittest discover -s tests -v
python inspect_url.py --help
```

These checks do **not** contact the suspicious site. If they fail, fix setup first. Codex Cloud tasks are isolated workspaces; changing an environment's installation later requires republishing it for **new** tasks.

### Step 5. Run the first live investigation: metadata only

**This step contacts the suspicious server.** It can record your cloud environment's public egress IP and may alert an attacker. It does **not** download a response body or execute page JavaScript.

In a **new Codex Cloud task**, paste:

> Run the repository's metadata-only URL inspection against `https://socialsignlab.click/ftx`. Use `--mode passive` and the output directory `reports/socialsignlab-passive-001`. Do not launch a browser, issue GET requests for page bodies, click links, execute payloads, or submit forms. Report the DNS addresses, TLS certificate details, HTTP HEAD status and response headers, automatic redirect chain, errors, and uncertainties. Do not treat a failed probe or missing response as proof of safety. Make the resulting report files available for review, without committing evidence to Git.

Equivalent command to run **inside Codex Cloud**, not on your Windows computer:

```bash
python inspect_url.py \
  --url 'https://socialsignlab.click/ftx' \
  --mode passive \
  --output ./reports/socialsignlab-passive-001
```

Expected output, **if the probe runs successfully**:

```text
reports/socialsignlab-passive-001/
├── report.json
└── report.md
```

Open `report.md` to read the findings. Review `report.json` if you want to inspect the original structured evidence. The tool follows metadata `HEAD` redirects up to its configured limit and rejects non-public IP destinations at this layer. Some sites reject `HEAD` or return different content for `GET`; such a result is inconclusive.

### Step 6. Retrieve your evidence and finish

1. In the Codex task, ask it to show you `report.md` and summarize the redirect chain and certificate findings.
2. Ask it to package the **report directory only** as a downloadable artifact/archive if the task UI supports file export. If file export is unavailable, copy the report text/JSON from the task rather than pushing it to the source repository.
3. Do not commit screenshots, HARs, logs, or case reports to GitHub. The `.gitignore` already excludes `reports/`.
4. Finish the task. The environment can be reused later; there is **no always-running watcher** or new public endpoint.

If you run another investigation, use a **new empty output directory**. This is intentional: the program refuses to overwrite an existing evidence directory.

## Optional: browser observation (higher risk)

**Do not treat the following command as safe to run against suspected malware merely because it uses Codex Cloud.** The browser mode executes page JavaScript, initiates HTTP requests, and may expose a Chromium attack surface. The code prevents some unsafe actions, but it is not a security boundary. For a potentially malicious site, run this only from a purpose-built, throwaway **Ubuntu VM** with no GitHub identity, tokens, credentials, attached files, internal-network routes, or valuable data; apply **firewall-enforced deny-private egress rules** outside the process. Use snapshots and dispose of the VM afterward.

Install into the dedicated Ubuntu VM (Python 3.11+):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[browser]'
python -m playwright install --with-deps chromium
python -m unittest discover -s tests -v
```

After applying VM/network isolation and explicitly deciding to conduct a browser visit:

```bash
python inspect_url.py \
  --url 'https://socialsignlab.click/ftx' \
  --mode browser \
  --profile both \
  --output ./reports/socialsignlab-browser-001
```

This starts **two sequential Chromium contexts**: a Linux user-agent and a Windows user-agent, both **running on Linux**. It does **not** emulate a Windows OS or execute downloaded Windows programs. The program does not click, type, submit forms, persist downloads, or intentionally collect response bodies. An initial download response or transfer can still begin before cancellation; it is **not** a guarantee of zero-byte contact with the server.

Expected output, subject to browser/network success:

```text
reports/socialsignlab-browser-001/
├── report.md
├── report.json
└── browser/
    ├── linux/
    │   ├── traffic.har
    │   └── screenshot.png
    └── windows-ua/
        ├── traffic.har
        └── screenshot.png
```

The browser report records request/response metadata, resource types, statuses, limited console output, redirect relationships, blocked requests, attempted downloads and screenshots. **Do not assume the HAR is completely sanitized.** Although response bodies are omitted, attacker-controlled URLs, query parameters, and some headers may contain sensitive values. Keep these artifacts private.

### CLI flags

```text
--mode passive|browser    Passive here means metadata-only, not offline
--profile linux|windows-ua|both
--timeout 12              Seconds per network step/navigation (range 1–60)
--max-requests 100        Browser request budget (range 1–500)
--max-redirects 6         Metadata HEAD redirects (range 0–12)
--settle-ms 2000          Post-navigation wait in browser (range 0–10000)
--output ./reports/new    Output must be absent or empty
```

## How the probes work

| Capability | `passive` | `browser` |
|---|---|---|
| DNS resolution | Yes | Yes |
| Verified TLS handshake/certificate details | Yes | Yes, plus browser TLS connections |
| HTTP HEAD and selected response headers | Yes | Yes, before browser visit |
| Follows server HEAD redirects | Yes, limited | Yes, plus browser navigation/requests |
| Downloads response bodies intentionally | **No** | Website responses load in Chromium; **bodies are omitted from HAR** |
| Executes website JavaScript | **No** | **Yes** |
| Observes JS requests, page errors and screenshots | No | Yes |
| Persists files offered for download | No | Attempts logged, downloads cancelled |
| Executes downloaded files | No | No |
| Contacts target public server | **Yes** | **Yes** |

The tool's `passive` label is shorthand for **metadata-only active probing**. It is **not** passive threat intelligence. Either mode may be visible to the destination site, and a site can condition its behavior on source IP, browser fingerprint or user-agent. A blank/error response is not proof of safety.

## Security model and limitations

1. **Codex Cloud is a development environment, not malware detonation.** Repository access and the Codex task context are part of its trust model. Even a private repository does not transform the environment into an air-gapped security lab. Prefer metadata-only inspection there.
2. **Only the metadata probe pins the checked public IP.** `network.py` validates DNS and denies private, loopback, link-local, non-global, reserved and multicast destinations for each metadata redirect hop. This reduces SSRF risk at the HTTP client layer.
3. **Browser routing is not complete network isolation.** `browser.py` prechecks destinations and blocks non-GET/HEAD/OPTIONS methods, but it cannot guarantee address pinning for every browser connection, internal redirect, protocol, background activity or DNS rebinding. Enforce isolation with VM/cloud firewall rules; do not give the VM a VPN, internal routes or cloud instance-identity access.
4. **WebSockets, service workers and popups are constrained in code**, but browser vulnerabilities and platform-level traffic cannot be excluded. Chromium may be fingerprinted or targeted.
5. **Downloads are cancelled, not analyzed.** The toolkit does not fetch files for hashing, reverse-engineer binaries, execute downloaded content, or attribute malware. Use a specialist analysis VM if that becomes necessary.
6. **No credentials.** Do not provide account logins, SSH keys, browser profiles, GitHub tokens, API keys, persistent mounted volumes, Docker sockets, Kubernetes credentials, cloud metadata endpoints, or local/private services to an inspection VM.
7. **No interaction.** Inspect only publicly accessible material you are authorized to inspect, respect rate limits, do not bypass access controls, submit forms, or run suspicious scripts outside the instrumented browser.
8. **Report safety.** Treat HARs, screenshots, page text and HTTP headers as untrusted, and avoid opening generated HTML or scripts in a trusted browser. `report.json` is descriptive evidence, not a malware verdict.
9. **Not always online.** Codex Cloud environment publication does not launch a server, scheduled scanner, webhook, background observer, or public-facing endpoint. Trigger scans manually unless you intentionally build and secure automation later.

## Troubleshooting

| Symptom | Likely cause / next step |
|---|---|
| `python: command not found` | Ensure Python 3.11+ is installed; use `python3` as available and update the setup instruction accordingly. |
| Missing `playwright` | Run `bash .codex/setup.sh` in the project root; check network access to Python packages. |
| Chromium installation fails | Check blocked browser-download or Ubuntu package hosts, permission errors, and Codex environment setup logs. |
| Codex cannot find `url-forensics` | Confirm GitHub connection permissions, repository visibility, and that you selected the right Codex Cloud environment. |
| `Environment unpublished` | Review setup and select **Publish** before starting a task. |
| DNS error, `403`, `405`, timeout | This may be a genuine response, `HEAD` restriction, blocked domain, bot-detection or connectivity failure. Preserve the error; do not label the link safe. |
| Browser fails to load | The environment may lack Chromium, public-network access or display/runtime dependencies; use only on a properly isolated VM. |
| `Output directory must be empty` | Choose a new `--output` path. |
| Missing HAR/screenshot | A browser error or navigation failure can prevent capture. Inspect `report.json` and the cloud task logs. |

## Git CLI alternative

If you **prefer** a local Git workflow, from the extracted `url-forensics` directory:

```bash
git init
git add .
git commit -m "Initial defensive URL forensics toolkit"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/url-forensics.git
git push -u origin main
```

Or, if the GitHub CLI is already installed and authenticated:

```bash
git init
git add .
git commit -m "Initial defensive URL forensics toolkit"
gh repo create url-forensics --private --source=. --remote=origin --push
```

Neither route is necessary if you used GitHub's **Upload files** interface. The included GitHub Actions workflow runs **offline unit tests only**; it must **not** be modified to automatically browse hostile URLs on GitHub-hosted runners.

## Project structure

```text
url-forensics/
├── .codex/setup.sh                 # Cloud environment installation + offline tests
├── .github/workflows/test.yml     # Offline tests only
├── AGENTS.md                      # Agent safety instructions
├── README.md                      # This guide
├── inspect_url.py                 # Standalone CLI entrypoint
├── pyproject.toml
├── tests/test_network.py          # Offline test suite
└── url_forensics/
    ├── cli.py                     # Command parsing + reports
    ├── network.py                 # DNS, TLS, HEAD, redirects, public-IP filtering
    └── browser.py                 # Instrumented Playwright observations
```

## Official documentation

- [Codex Cloud environments, installation, publishing and network settings](https://learn.chatgpt.com/docs/environments/cloud-environments)
- [Using Codex Cloud](https://help.openai.com/en/articles/20001545-using-codex-cloud)
- [GitHub: create a repository](https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-new-repository)
- [GitHub: upload files and folders](https://docs.github.com/en/repositories/working-with-files/managing-files/adding-a-file-to-a-repository)
- [Playwright: install Chromium](https://playwright.dev/python/docs/browsers)
- [Playwright: intercept network requests](https://playwright.dev/python/docs/network)
- [Playwright: handle downloads](https://playwright.dev/python/docs/downloads)

## Roadmap

This is a first-stage reconnaissance tool, not a production malware-analysis pipeline. Possible future improvements include VM-level egress-proxy enforcement, packet capture, passive certificate-transparency checks, controlled redirect graphs, browser fingerprint comparisons, threat-intelligence lookups, extracted indicators of compromise, and STIX/JSON export. Avoid adding automatic arbitrary file execution or unsafe interaction with attacker-controlled pages.
